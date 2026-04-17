"""
License endpoints — no authentication required (pre-auth layer).

GET  /v1/license            → current license status
POST /v1/license/activate   → activate a license key
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from api.auth.license import license_manager
from api.middleware.audit import audit_log

router = APIRouter(prefix="/license", tags=["license"])


class ActivateRequest(BaseModel):
    key: str


@router.get(
    "",
    summary="License status",
    response_description="Current license state (plan, key hint)",
)
async def get_license_status() -> dict:
    """Returns whether the server is licensed and which plan is active."""
    return license_manager.status()


@router.post(
    "/activate",
    summary="Activate a license key",
    response_description="Updated license status on success",
)
async def activate_license(payload: ActivateRequest) -> dict:
    """
    Validate and persist a license key.  Returns 402 if the key is invalid.

    On success the license is saved to ~/.netlogic/secrets.json and all
    subsequent API requests are unblocked immediately (no restart needed).
    """
    if not license_manager.activate(payload.key):
        raise HTTPException(
            status_code=402,
            detail="Invalid license key. Purchase one at https://netlogic.io/pricing",
        )
    audit_log("license_activated", key_hint=license_manager.status().get("key_hint"))
    return license_manager.status()
