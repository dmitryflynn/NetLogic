"""NetLogic API — Health / readiness endpoints."""

from __future__ import annotations

import time

from fastapi import APIRouter

router = APIRouter(tags=["system"])

_START_TIME: float = time.time()


@router.get(
    "/health",
    summary="Health check",
    response_description="Service status and uptime",
)
async def health() -> dict:
    """Returns 200 OK when the service is ready to accept requests.

    Version information is intentionally omitted from this public endpoint
    to reduce information disclosure.
    """
    return {
        "status": "ok",
        "uptime_s": round(time.time() - _START_TIME, 1),
    }
