"""
NetLogic — OIDC / JWKS verification for IdP-issued tokens (Clerk and any OIDC IdP).

This is the HUMAN-login verification path. The dashboard logs the user in via the
IdP (Clerk owns password/MFA/passkey/recovery), receives a short-lived RS256 JWT,
and sends it as a Bearer token. Here we verify that token against the IdP's
published JWKS and validate its standard claims. Programmatic callers keep the
in-house API-key path (see api_keys.py) — the two are dispatched in require_org.

IdP-agnostic by design: we only speak OIDC (RS256 + JWKS), so Clerk, Auth0, or
WorkOS all work via configuration alone.

Configuration (env)
───────────────────
  NETLOGIC_OIDC_ISSUER              Required to enable. Clerk: your Frontend API
                                   URL, e.g. https://your-app.clerk.accounts.dev
  NETLOGIC_OIDC_JWKS_URL           Default: {issuer}/.well-known/jwks.json
  NETLOGIC_OIDC_AUDIENCE           Optional; enforced only when set. (Clerk's
                                   default session token has no aud.)
  NETLOGIC_OIDC_AUTHORIZED_PARTIES Optional CSV of allowed `azp` values (origins)
                                   — Clerk stamps azp with the requesting origin.

Fail-soft: any verification problem returns None (never raises), so a bad token
is a clean 401 upstream, never a 500.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("netlogic.oidc")

# Small clock-skew tolerance for exp/nbf/iat (seconds).
_LEEWAY = 30


@dataclass
class OIDCConfig:
    issuer: str = ""
    jwks_url: str = ""
    audience: str = ""
    authorized_parties: tuple[str, ...] = ()

    @property
    def enabled(self) -> bool:
        return bool(self.issuer)


def get_oidc_config() -> OIDCConfig:
    """Resolve OIDC config from the environment (cheap; read per call so a
    test/operator can change it without reimport)."""
    issuer = (os.environ.get("NETLOGIC_OIDC_ISSUER") or "").strip().rstrip("/")
    if not issuer:
        return OIDCConfig()
    jwks_url = (os.environ.get("NETLOGIC_OIDC_JWKS_URL") or "").strip()
    if not jwks_url:
        jwks_url = f"{issuer}/.well-known/jwks.json"
    audience = (os.environ.get("NETLOGIC_OIDC_AUDIENCE") or "").strip()
    raw_azp = (os.environ.get("NETLOGIC_OIDC_AUTHORIZED_PARTIES") or "").strip()
    azp = tuple(p.strip() for p in raw_azp.split(",") if p.strip())
    return OIDCConfig(issuer=issuer, jwks_url=jwks_url, audience=audience,
                      authorized_parties=azp)


# ── JWKS client (cached) ───────────────────────────────────────────────────────
# PyJWKClient fetches the IdP's signing keys and caches them, refetching when it
# sees an unknown `kid` (key rotation). We cache one client per JWKS URL.

_jwks_clients: dict = {}


def _get_jwks_client(jwks_url: str):
    import jwt  # noqa: PLC0415 — optional API-layer dep
    client = _jwks_clients.get(jwks_url)
    if client is None:
        client = jwt.PyJWKClient(jwks_url, cache_keys=True)
        _jwks_clients[jwks_url] = client
    return client


def _get_signing_key(token: str, cfg: OIDCConfig):
    """Return the public signing key for this token's `kid`. Isolated so tests
    can stub it with a local key instead of hitting the network."""
    client = _get_jwks_client(cfg.jwks_url)
    return client.get_signing_key_from_jwt(token).key


def _reset_caches() -> None:
    """Test helper — drop cached JWKS clients."""
    _jwks_clients.clear()


# ── Public API ─────────────────────────────────────────────────────────────────


def verify_idp_token(token: str, cfg: Optional[OIDCConfig] = None) -> Optional[dict]:
    """Verify an IdP-issued OIDC JWT. Returns claims on success, else None.

    Checks: RS256 signature against the IdP JWKS, `iss` == configured issuer,
    `exp`/`nbf`/`iat` (with small leeway), `aud` (only if configured), and `azp`
    (only if authorized_parties configured). Returns None — never raises — on any
    failure, so callers translate it to a clean 401.
    """
    cfg = cfg or get_oidc_config()
    if not cfg.enabled or not token:
        return None

    import jwt  # noqa: PLC0415

    try:
        key = _get_signing_key(token, cfg)
    except Exception as exc:  # noqa: BLE001 — unknown kid, network, malformed token
        log.warning("OIDC: could not resolve signing key: %s", exc)
        return None

    decode_kwargs = {
        "algorithms": ["RS256"],          # pin: never honor the token's own alg
        "issuer": cfg.issuer,
        "leeway": _LEEWAY,
        "options": {
            "require": ["exp", "iat"],
            "verify_aud": bool(cfg.audience),
        },
    }
    if cfg.audience:
        decode_kwargs["audience"] = cfg.audience

    try:
        claims = jwt.decode(token, key, **decode_kwargs)
    except Exception as exc:  # noqa: BLE001 — expired/tampered/wrong-issuer/etc.
        log.warning("OIDC: token verification failed: %s", exc)
        return None

    # Clerk stamps `azp` with the requesting origin; pin it when configured so a
    # token minted for another origin can't be replayed against us.
    if cfg.authorized_parties:
        azp = claims.get("azp")
        if azp and azp not in cfg.authorized_parties:
            log.warning("OIDC: azp %r not in authorized parties", azp)
            return None

    if not claims.get("sub"):
        return None  # no subject → can't map to a user
    return claims


def org_id_from_claims(claims: dict) -> Optional[str]:
    """Resolve the NetLogic tenant (org_id) from verified IdP claims.

    Resolution order:
      1. An active-organization claim from the IdP (Clerk Organizations). Clerk
         puts this in `org_id`/`org_slug`, or the compact `o: {id, slg, rol}`.
         The org id is a stable unique tenant key, so we use it directly — when
         Postgres lands we attach org metadata keyed by this id (no remapping).
      2. NETLOGIC_OIDC_DEFAULT_ORG — for single-tenant / dev deployments.
      3. A personal workspace = the user's subject (`sub`), so a signed-in user
         with no organization still gets an isolated tenant. (Clerk subs look like
         `user_…` and org ids like `org_…`, so they never collide, and `sub` is a
         valid org slug — unlike a `user:<sub>` form, which the DB slug check and
         JWT org_id would reject.)
    Returns None only when there are no usable claims.
    """
    for key in ("org_id", "org_slug"):
        val = claims.get(key)
        if val:
            return str(val)
    o = claims.get("o")
    if isinstance(o, dict) and o.get("id"):
        return str(o["id"])
    default = (os.environ.get("NETLOGIC_OIDC_DEFAULT_ORG") or "").strip()
    if default:
        return default
    sub = claims.get("sub")
    return str(sub) if sub else None
