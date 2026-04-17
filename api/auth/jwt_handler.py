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
import os
import time
from typing import Optional

JWT_SECRET: str = os.environ.get("NETLOGIC_JWT_SECRET", "changeme-in-production")
JWT_DEFAULT_EXPIRY: int = int(os.environ.get("NETLOGIC_JWT_EXPIRY", "3600"))

import warnings as _warnings
if JWT_SECRET in ("changeme-in-production", "changeme", ""):
    _warnings.warn(
        "NETLOGIC_JWT_SECRET is set to a weak default — override in production!",
        stacklevel=2,
    )
elif len(JWT_SECRET) < 32:
    _warnings.warn(
        f"NETLOGIC_JWT_SECRET is only {len(JWT_SECRET)} chars — use 32+ chars in production!",
        stacklevel=2,
    )

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
