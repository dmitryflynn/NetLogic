"""
NetLogic — FastAPI auth dependencies.

require_org
───────────
Extracts the caller's org_id from a signed JWT Bearer token.

Usage in a route:

    from api.auth.dependencies import require_org

    @router.get("/things")
    async def list_things(org_id: str = Depends(require_org)) -> list:
        return thing_store.list(org_id=org_id)

Raises HTTP 401 if the Authorization header is missing, the token cannot be
verified, or the decoded claims lack an org_id.
"""

from __future__ import annotations

from typing import Annotated, Optional

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from api.auth.jwt_handler import verify_token
from api.auth.oidc import verify_idp_token, org_id_from_claims

_bearer = HTTPBearer(auto_error=False)


def require_org(
    creds: Annotated[Optional[HTTPAuthorizationCredentials], Depends(_bearer)],
) -> str:
    """FastAPI dependency — resolve a Bearer token to its org_id.

    Two token kinds are accepted, checked in this order so existing behavior is
    unchanged:
      1. A NetLogic-issued HS256 JWT (from POST /auth/token).
      2. A Clerk-issued OIDC token (human login). Only meaningful when OIDC is
         configured (NETLOGIC_OIDC_ISSUER set); verify_idp_token returns None
         otherwise, so this path stays inert until Clerk is wired.
    """
    if not creds:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header (Bearer token required).",
        )

    # 1. NetLogic self-issued JWT (existing path, unchanged).
    claims = verify_token(creds.credentials)
    if claims is not None:
        org_id = claims.get("org_id")
        if not org_id:
            raise HTTPException(status_code=401, detail="Token does not carry an org_id claim.")
        return org_id

    # 2. Clerk OIDC token (human login). When Postgres is enabled, provision the
    #    user/org and return the persisted org_id; otherwise fall back to the
    #    claim-derived org. Both yield the same org_id value.
    idp_claims = verify_idp_token(creds.credentials)
    if idp_claims is not None:
        from api.auth.provisioning import provision_user_and_org  # noqa: PLC0415
        org_id = provision_user_and_org(idp_claims) or org_id_from_claims(idp_claims)
        if not org_id:
            raise HTTPException(
                status_code=401,
                detail="Authenticated, but no organization could be resolved for this user.",
            )
        return org_id

    raise HTTPException(status_code=401, detail="Invalid or expired token.")
