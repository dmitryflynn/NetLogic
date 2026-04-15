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
  DELETE /auth/keys/{key}      Revoke an API key  (admin only)
"""

from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from api.auth.api_keys import api_key_store, verify_admin
from api.auth.jwt_handler import create_token, JWT_DEFAULT_EXPIRY

router = APIRouter(prefix="/auth", tags=["auth"])


# ── Request / response models ─────────────────────────────────────────────────


class TokenRequest(BaseModel):
    api_key: str


class KeyCreateRequest(BaseModel):
    org_id: str


# ── POST /auth/token ──────────────────────────────────────────────────────────


@router.post(
    "/token",
    summary="Exchange API key for JWT",
    response_description="Signed JWT and expiry",
)
async def get_token(body: TokenRequest) -> dict:
    """
    Exchange a valid API key for a short-lived JWT.

    The returned `token` must be included as a `Bearer` credential in the
    `Authorization` header of every subsequent API call.
    """
    org_id = api_key_store.lookup(body.api_key)
    if org_id is None:
        raise HTTPException(status_code=401, detail="Invalid API key.")
    token = create_token(org_id=org_id, sub=body.api_key)
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
    body: KeyCreateRequest,
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
) -> dict:
    """
    Create a new API key for the given `org_id`.

    Requires the `X-Admin-Key` header to match `NETLOGIC_ADMIN_KEY`.
    The plaintext key is returned **once** — store it securely.
    """
    if not verify_admin(x_admin_key):
        raise HTTPException(status_code=403, detail="Invalid admin key.")
    key = api_key_store.create(body.org_id)
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
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
) -> list[dict]:
    """Return all API keys (key prefix masked) with their org_id."""
    if not verify_admin(x_admin_key):
        raise HTTPException(status_code=403, detail="Invalid admin key.")
    return api_key_store.list_keys()


# ── DELETE /auth/keys/{key} ───────────────────────────────────────────────────


@router.delete(
    "/keys/{key}",
    status_code=204,
    summary="Revoke an API key (admin only)",
)
async def revoke_key(
    key: str,
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
):
    """Permanently revoke an API key."""
    if not verify_admin(x_admin_key):
        raise HTTPException(status_code=403, detail="Invalid admin key.")
    if not api_key_store.revoke(key):
        raise HTTPException(status_code=404, detail="API key not found.")
