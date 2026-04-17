"""NetLogic API — Health / readiness endpoints."""

from __future__ import annotations

import os
import tempfile
import time

from fastapi import APIRouter

router = APIRouter(tags=["system"])

_START_TIME: float = time.time()

_DEFAULT_JWT_SECRET = "change-me-use-a-long-random-string-here"
_MIN_SECRET_LENGTH = 32


@router.get(
    "/health",
    summary="Health check",
    response_description="Service status, uptime, and readiness checks",
)
async def health() -> dict:
    """Returns 200 OK when the service is ready to accept requests.

    Checks:
    - storage: scans directory is writable
    - config: JWT secret is set and non-default
    """
    checks: dict[str, str] = {}

    # Check 1: storage directory is writable
    from api.storage.json_store import SCANS_DIR  # noqa: PLC0415
    try:
        os.makedirs(SCANS_DIR, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=SCANS_DIR, delete=True):
            pass
        checks["storage"] = "ok"
    except Exception as exc:
        checks["storage"] = f"error: {exc}"

    # Check 2: JWT secret is configured and non-default
    jwt_secret = os.environ.get("NETLOGIC_JWT_SECRET", "")
    if not jwt_secret or jwt_secret == _DEFAULT_JWT_SECRET or len(jwt_secret) < _MIN_SECRET_LENGTH:
        checks["config"] = "warning: weak or default JWT secret"
    else:
        checks["config"] = "ok"

    overall = "ok" if all(v == "ok" for v in checks.values()) else "degraded"

    return {
        "status": overall,
        "uptime_s": round(time.time() - _START_TIME, 1),
        "checks": checks,
    }
