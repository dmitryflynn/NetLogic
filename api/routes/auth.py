"""
NetLogic API — Authentication endpoints.

Flow
────
1. Operator provisions an API key for their org via POST /auth/keys
   (requires the admin credential in X-Admin-Key header).

2. Client exchanges their API key for a short-lived JWT via POST /auth/token.

3. Client includes the JWT as a Bearer token on every subsequent request.

REST surface
────────────
  POST   /auth/token           API key → JWT  (public)
  POST   /auth/keys            Create a new API key for an org  (admin only)
  GET    /auth/keys            List all API keys (masked)  (admin only)
  DELETE /auth/keys            Revoke an API key (key in body)  (admin only)
"""

from __future__ import annotations

import re

from fastapi import APIRouter, Header, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator

from api.auth.api_keys import api_key_store, verify_admin
from api.auth.jwt_handler import create_token, JWT_DEFAULT_EXPIRY
from api.auth.rate_limit import token_limiter, token_fail_limiter, ban_list, admin_limiter
from api.middleware.audit import audit_log

router = APIRouter(prefix="/auth", tags=["auth"])

# org_id becomes a tenant boundary and is embedded in signed tokens, so constrain
# it to a safe identifier rather than accepting arbitrary strings.
_ORG_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def _key_hint(key: str) -> str:
    """Non-secret identifier for a key (first 8 chars), for tokens/audit logs.

    NEVER embed the full API key anywhere that travels (JWT payloads are base64,
    not encrypted, and ride on every request) — only this short, non-reversible
    prefix, matching how list_keys() masks keys for display.
    """
    return f"{key[:8]}…" if key else "—"


def _require_admin(request: Request, key: str) -> None:
    """Shared admin gate: rate-limit by IP, audit failures, then verify the key."""
    ip = request.client.host if request.client else "unknown"
    if not admin_limiter.allow(ip):
        audit_log("admin_rate_limited", ip=ip, severity="warning")
        raise HTTPException(status_code=429, detail="Too many admin requests. Try again later.")
    if not verify_admin(key):
        audit_log("admin_auth_failed", ip=ip, severity="warning")
        raise HTTPException(status_code=403, detail="Invalid admin key.")


# ── Request / response models ─────────────────────────────────────────────────


class TokenRequest(BaseModel):
    # Real keys are 32 hex chars; cap input so a giant body can't be probed.
    api_key: str = Field(min_length=1, max_length=256)


class KeyCreateRequest(BaseModel):
    org_id: str = Field(min_length=1, max_length=64)

    @field_validator("org_id")
    @classmethod
    def _validate_org_id(cls, v: str) -> str:
        v = (v or "").strip()
        if not _ORG_ID_RE.match(v):
            raise ValueError(
                "org_id must be 1–64 chars of letters, digits, '.', '_', or '-'."
            )
        return v


class KeyDeleteRequest(BaseModel):
    key: str = Field(min_length=1, max_length=256)


# ── POST /auth/token ──────────────────────────────────────────────────────────


@router.post(
    "/token",
    summary="Exchange API key for JWT",
    response_description="Signed JWT and expiry",
)
async def get_token(request: Request, body: TokenRequest) -> dict:
    """
    Exchange a valid API key for a short-lived JWT.

    The returned `token` must be included as a `Bearer` credential in the
    `Authorization` header of every subsequent API call.
    """
    ip = request.client.host if request.client else "unknown"
    if ban_list.check_ban(ip):
        audit_log("token_banned", ip=ip)
        raise HTTPException(status_code=429, detail="Too many failed attempts. Try again later.")
    if not token_limiter.allow(ip):
        audit_log("token_rate_limited", ip=ip)
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again later.")
    org_id = api_key_store.lookup(body.api_key)
    if org_id is None:
        audit_log("token_exchange_failed", ip=ip, reason="invalid_api_key")
        if not token_fail_limiter.allow(ip):
            ban_list.add_ban(ip, duration_hours=1)
            audit_log("token_auto_banned", ip=ip, reason="too_many_failures")
        raise HTTPException(status_code=401, detail="Invalid API key.")
    # sub carries a non-secret key HINT, never the raw API key — a leaked JWT must
    # not expose the long-lived credential it was minted from.
    token = create_token(org_id=org_id, sub=f"apikey:{_key_hint(body.api_key)}")
    audit_log("token_exchange_ok", ip=ip, org_id=org_id)
    return {
        "token": token,
        "token_type": "bearer",
        "expires_in": JWT_DEFAULT_EXPIRY,
        "org_id": org_id,
    }


# ── POST /auth/keys ───────────────────────────────────────────────────────────


@router.post(
    "/keys",
    status_code=201,
    summary="Create API key for an organisation (admin only)",
    response_description="New API key — shown only once",
)
async def create_key(
    request: Request,
    body: KeyCreateRequest,
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
) -> dict:
    """
    Create a new API key for the given `org_id`.

    Requires the `X-Admin-Key` header to match `NETLOGIC_ADMIN_KEY`.
    The plaintext key is returned **once** — store it securely.
    """
    _require_admin(request, x_admin_key)
    key = api_key_store.create(body.org_id)
    audit_log("key_created", org_id=body.org_id, key_hint=_key_hint(key))
    return {
        "api_key": key,
        "org_id": body.org_id,
        "message": "API key created. Store it securely — it is shown only once.",
    }


# ── GET /auth/keys ────────────────────────────────────────────────────────────


@router.get(
    "/keys",
    summary="List API keys (admin only)",
    response_description="Array of masked key entries",
)
async def list_keys(
    request: Request,
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
) -> list[dict]:
    """Return all API keys (key prefix masked) with their org_id."""
    _require_admin(request, x_admin_key)
    return api_key_store.list_keys()


# ── DELETE /auth/keys ──────────────────────────────────────────────────────────


@router.delete(
    "/keys",
    status_code=204,
    summary="Revoke an API key (admin only)",
)
async def revoke_key(
    body: KeyDeleteRequest,
    request: Request,
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
):
    """Permanently revoke an API key. Key is sent in request body, not URL,
    to avoid leaking it into proxy/access logs."""
    _require_admin(request, x_admin_key)
    if not api_key_store.revoke(body.key):
        raise HTTPException(status_code=404, detail="API key not found.")
    audit_log("key_revoked", key_hint=_key_hint(body.key))
    return Response(status_code=204)
