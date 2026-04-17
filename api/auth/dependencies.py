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

_bearer = HTTPBearer(auto_error=False)


def require_org(
    creds: Annotated[Optional[HTTPAuthorizationCredentials], Depends(_bearer)],
) -> str:
    """FastAPI dependency — resolve JWT Bearer token to org_id."""
    if not creds:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header (Bearer token required).",
        )
    claims = verify_token(creds.credentials)
    if claims is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token.",
        )
    org_id = claims.get("org_id")
    if not org_id:
        raise HTTPException(
            status_code=401,
            detail="Token does not carry an org_id claim.",
        )
    return org_id
