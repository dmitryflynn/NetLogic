"""
NetLogic — Stdlib-only HS256 JWT handler.

No third-party dependencies.  Uses hashlib + hmac + base64 from the Python
standard library.

Environment variables
─────────────────────
  NETLOGIC_JWT_SECRET   Signing secret.  Must be overridden in production.
                        Default "changeme-in-production" is intentionally weak
                        so the server never silently accepts it in real use.
  NETLOGIC_JWT_EXPIRY   Token lifetime in seconds (default: 3600).

Public API
──────────
  create_token(org_id, sub, expiry_seconds) → str
  verify_token(token)                        → Optional[dict]  (None = invalid)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from typing import Optional

log = logging.getLogger(__name__)

JWT_SECRET_MIN_LENGTH = 32
# Placeholder secrets that must never be used to sign real tokens.
_DEFAULT_JWT_SECRETS = {"", "changeme-in-production", "changeme", "change-me-use-a-long-random-string-here"}


def _resolve_jwt_secret() -> str:
    """Resolve the JWT signing secret at import WITHOUT terminating the process.

    A module-level sys.exit() here made the whole API unimportable (and broke the
    test suite) whenever the env var was absent. Instead:
      * an empty/placeholder secret → a random EPHEMERAL secret is generated so
        the server still runs and signs unforgeable tokens, but they do not
        survive a restart (operator is warned to set a real secret);
      * a too-short secret is used as-is with a warning.
    Use require_strong_jwt_secret() at startup to hard-enforce a strong secret.
    """
    secret = os.environ.get("NETLOGIC_JWT_SECRET", "")
    if secret in _DEFAULT_JWT_SECRETS:
        log.warning(
            "NETLOGIC_JWT_SECRET is unset or a default placeholder — using a random "
            "ephemeral secret for this process. Tokens will NOT survive a restart. "
            'Set a strong secret (python -c "import secrets; print(secrets.token_hex(32))").'
        )
        return secrets.token_hex(32)
    if len(secret) < JWT_SECRET_MIN_LENGTH:
        log.warning(
            "NETLOGIC_JWT_SECRET is shorter than %d characters (got %d) — "
            "use a stronger secret in production.", JWT_SECRET_MIN_LENGTH, len(secret),
        )
    return secret


JWT_SECRET: str = _resolve_jwt_secret()
JWT_DEFAULT_EXPIRY: int = int(os.environ.get("NETLOGIC_JWT_EXPIRY", "3600"))


def require_strong_jwt_secret() -> None:
    """Enforce a production-grade JWT secret. Call at server startup.

    Raises RuntimeError (never sys.exit) so the caller decides how to react.
    Validates the configured environment value, not the possibly-ephemeral global.
    """
    secret = os.environ.get("NETLOGIC_JWT_SECRET", "")
    if secret in _DEFAULT_JWT_SECRETS:
        raise RuntimeError(
            "NETLOGIC_JWT_SECRET must be set to a secure value. Generate one with: "
            'python -c "import secrets; print(secrets.token_hex(32))"'
        )
    if len(secret) < JWT_SECRET_MIN_LENGTH:
        raise RuntimeError(
            f"NETLOGIC_JWT_SECRET must be at least {JWT_SECRET_MIN_LENGTH} characters "
            f"(got {len(secret)})."
        )
    weak = [p for p in ("password", "123456", "qwerty") if p in secret.lower()]
    if weak:
        raise RuntimeError(f"NETLOGIC_JWT_SECRET contains weak patterns: {', '.join(weak)}")

_HEADER_B64 = (
    base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    .rstrip(b"=")
    .decode()
)


# ── Internal helpers ──────────────────────────────────────────────────────────


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _sign(header_b64: str, payload_b64: str) -> str:
    msg = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(JWT_SECRET.encode(), msg, hashlib.sha256).digest()
    return _b64url_encode(sig)


# ── Public API ────────────────────────────────────────────────────────────────


def create_token(
    org_id: str,
    sub: str,
    expiry_seconds: int = JWT_DEFAULT_EXPIRY,
) -> str:
    """Sign and return a JWT carrying org_id and sub."""
    now = int(time.time())
    payload = _b64url_encode(
        json.dumps(
            {"sub": sub, "org_id": org_id, "iat": now, "exp": now + expiry_seconds}
        ).encode()
    )
    sig = _sign(_HEADER_B64, payload)
    return f"{_HEADER_B64}.{payload}.{sig}"


def verify_token(token: str) -> Optional[dict]:
    """
    Verify signature and expiry.  Returns the decoded claims dict on success,
    or None if the token is malformed, tampered, or expired.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig = parts
        # Enforce algorithm before verifying signature (prevents alg=none attack)
        try:
            header = json.loads(_b64url_decode(header_b64))
        except Exception:
            return None
        if header.get("alg") != "HS256":
            return None
        expected = _sign(header_b64, payload_b64)
        if not hmac.compare_digest(sig, expected):
            return None
        claims = json.loads(_b64url_decode(payload_b64))
        if claims.get("exp", 0) < time.time():
            return None
        return claims
    except Exception:  # noqa: BLE001
        return None
