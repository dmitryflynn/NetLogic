"""Offline tests for OIDC/JWKS verification (api/auth/oidc.py).

No network, no Clerk account: we generate a local RSA keypair, mint RS256 tokens
like an IdP would, and stub the signing-key resolution with the matching public
key. This exercises the exact verification path Clerk tokens take.
"""

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from api.auth import oidc

_ISSUER = "https://test-app.clerk.accounts.dev"


@pytest.fixture
def keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key()


@pytest.fixture
def configured(monkeypatch, keypair):
    """Enable OIDC for the issuer and stub JWKS resolution to the local pubkey."""
    priv, pub = keypair
    monkeypatch.setenv("NETLOGIC_OIDC_ISSUER", _ISSUER)
    monkeypatch.delenv("NETLOGIC_OIDC_AUDIENCE", raising=False)
    monkeypatch.delenv("NETLOGIC_OIDC_AUTHORIZED_PARTIES", raising=False)
    monkeypatch.setattr(oidc, "_get_signing_key", lambda token, cfg: pub)
    return priv, pub


def _mint(priv, *, iss=_ISSUER, sub="user_123", extra=None, exp_delta=300, **hdr):
    now = int(time.time())
    payload = {"iss": iss, "sub": sub, "iat": now, "exp": now + exp_delta}
    if extra:
        payload.update(extra)
    headers = {"kid": "test-key-1", **hdr}
    return jwt.encode(payload, priv, algorithm="RS256", headers=headers)


def test_valid_token_accepted(configured):
    priv, _ = configured
    claims = oidc.verify_idp_token(_mint(priv, sub="user_abc"))
    assert claims is not None
    assert claims["sub"] == "user_abc"


def test_disabled_when_no_issuer(monkeypatch):
    monkeypatch.delenv("NETLOGIC_OIDC_ISSUER", raising=False)
    # Even a structurally fine token returns None when the feature is off.
    assert oidc.verify_idp_token("anything") is None
    assert oidc.get_oidc_config().enabled is False


def test_wrong_issuer_rejected(configured):
    priv, _ = configured
    tok = _mint(priv, iss="https://evil.example.com")
    assert oidc.verify_idp_token(tok) is None


def test_expired_token_rejected(configured):
    priv, _ = configured
    tok = _mint(priv, exp_delta=-3600)  # expired an hour ago
    assert oidc.verify_idp_token(tok) is None


def test_bad_signature_rejected(configured, keypair):
    # Sign with a DIFFERENT key than the stubbed JWKS public key.
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tok = _mint(other)
    assert oidc.verify_idp_token(tok) is None


def test_missing_sub_rejected(configured):
    priv, _ = configured
    now = int(time.time())
    tok = jwt.encode({"iss": _ISSUER, "iat": now, "exp": now + 300}, priv,
                     algorithm="RS256", headers={"kid": "test-key-1"})
    assert oidc.verify_idp_token(tok) is None


def test_audience_enforced_only_when_configured(configured, monkeypatch):
    priv, _ = configured
    # No aud configured → a token without aud still passes.
    assert oidc.verify_idp_token(_mint(priv)) is not None
    # Configure an audience → a token lacking it is now rejected…
    monkeypatch.setenv("NETLOGIC_OIDC_AUDIENCE", "netlogic-api")
    assert oidc.verify_idp_token(_mint(priv)) is None
    # …and one carrying the right aud passes.
    tok = _mint(priv, extra={"aud": "netlogic-api"})
    assert oidc.verify_idp_token(tok) is not None


def test_authorized_party_pinning(configured, monkeypatch):
    priv, _ = configured
    monkeypatch.setenv("NETLOGIC_OIDC_AUTHORIZED_PARTIES",
                       "https://app.netlogic.io, http://localhost:8000")
    # azp not in the allow-list → rejected.
    assert oidc.verify_idp_token(_mint(priv, extra={"azp": "https://evil.com"})) is None
    # azp in the allow-list → accepted.
    tok = _mint(priv, extra={"azp": "http://localhost:8000"})
    assert oidc.verify_idp_token(tok) is not None
    # No azp claim at all → not blocked (Clerk may omit it in some flows).
    assert oidc.verify_idp_token(_mint(priv)) is not None


def test_org_id_from_claims_prefers_active_org(monkeypatch):
    monkeypatch.delenv("NETLOGIC_OIDC_DEFAULT_ORG", raising=False)
    assert oidc.org_id_from_claims({"sub": "u1", "org_id": "org_42"}) == "org_42"
    assert oidc.org_id_from_claims({"sub": "u1", "org_slug": "acme"}) == "acme"
    # Clerk compact org claim
    assert oidc.org_id_from_claims({"sub": "u1", "o": {"id": "org_99", "slg": "x"}}) == "org_99"


def test_org_id_from_claims_default_then_personal(monkeypatch):
    monkeypatch.setenv("NETLOGIC_OIDC_DEFAULT_ORG", "default-tenant")
    assert oidc.org_id_from_claims({"sub": "u1"}) == "default-tenant"
    monkeypatch.delenv("NETLOGIC_OIDC_DEFAULT_ORG", raising=False)
    # No org + no default → isolated personal workspace = the subject itself
    # (slug-valid; Clerk subs are `user_…`, orgs are `org_…`, so no collision).
    assert oidc.org_id_from_claims({"sub": "u1"}) == "u1"
    assert oidc.org_id_from_claims({}) is None


def test_require_org_dispatches_clerk_token(monkeypatch):
    """require_org accepts a verified Clerk token and resolves its org."""
    from types import SimpleNamespace
    from api.auth import dependencies

    monkeypatch.delenv("NETLOGIC_OIDC_DEFAULT_ORG", raising=False)
    # Self-issued JWT path says "not mine"; Clerk path verifies.
    monkeypatch.setattr(dependencies, "verify_token", lambda t: None)
    monkeypatch.setattr(dependencies, "verify_idp_token",
                        lambda t: {"sub": "user_7", "org_id": "org_7"})
    creds = SimpleNamespace(credentials="clerk-token")
    assert dependencies.require_org(creds) == "org_7"


def test_require_org_rejects_unknown_token(monkeypatch):
    from types import SimpleNamespace
    from fastapi import HTTPException
    from api.auth import dependencies

    monkeypatch.setattr(dependencies, "verify_token", lambda t: None)
    monkeypatch.setattr(dependencies, "verify_idp_token", lambda t: None)
    creds = SimpleNamespace(credentials="garbage")
    with pytest.raises(HTTPException) as ei:
        dependencies.require_org(creds)
    assert ei.value.status_code == 401


def test_alg_confusion_hs256_rejected(configured):
    """A token signed HS256 (alg-confusion attempt) must be rejected — we pin RS256.

    The verifier passes algorithms=["RS256"], so an HS256 token (regardless of
    the secret an attacker chose) is refused before any signature check.
    """
    now = int(time.time())
    forged = jwt.encode({"iss": _ISSUER, "sub": "attacker", "iat": now, "exp": now + 300},
                        "attacker-chosen-secret", algorithm="HS256",
                        headers={"kid": "test-key-1"})
    assert oidc.verify_idp_token(forged) is None
