"""
License endpoints — no authentication required (pre-auth layer).

GET  /v1/license            → current license status
POST /v1/license/activate   → activate a license key

Activation is rate-limited per source IP to prevent brute-forcing license keys.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from api.auth.license import license_manager
from api.auth.rate_limit import license_activate_limiter
from api.middleware.audit import audit_log

router = APIRouter(prefix="/license", tags=["license"])

# Upper bound on accepted key length — real keys are short; anything larger is
# garbage/abuse and should be rejected before touching the validator.
_MAX_KEY_LENGTH = 256


class ActivateRequest(BaseModel):
    key: str = Field(min_length=1, max_length=_MAX_KEY_LENGTH)


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
async def activate_license(request: Request, payload: ActivateRequest) -> dict:
    """
    Validate and persist a license key.  Returns 402 if the key is invalid.

    On success the license is saved to ~/.netlogic/secrets.json and all
    subsequent API requests are unblocked immediately (no restart needed).
    """
    ip = request.client.host if request.client else "unknown"
    if not license_activate_limiter.allow(ip):
        audit_log("license_activate_rate_limited", ip=ip)
        raise HTTPException(
            status_code=429,
            detail="Too many activation attempts. Try again later.",
        )

    key = payload.key.strip()
    if not key:
        raise HTTPException(status_code=422, detail="License key must not be empty.")

    ok, msg = license_manager.activate(key)
    if not ok:
        audit_log("license_activation_failed", ip=ip)
        raise HTTPException(
            status_code=402,
            detail="Invalid license key. Purchase one at https://netlogic.io/pricing",
        )
    if "disk write failed" in msg:
        audit_log("license_activated_ephemeral", key_hint=license_manager.status().get("key_hint"))
    else:
        audit_log("license_activated", key_hint=license_manager.status().get("key_hint"))
    return license_manager.status()
