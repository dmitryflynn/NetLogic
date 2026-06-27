"""NetLogic API — Health / readiness endpoints."""

from __future__ import annotations

import os
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

    # Check 1: storage directory is present and writable.
    # NOTE: /health is public (unauthenticated, used by Docker/LB probes), so we
    # must NOT leak internal details. Report only "ok"/"error" — never the
    # SCANS_DIR absolute path or the raw exception text.
    # PERF: this endpoint is hammered by load balancers, and the handler is async
    # (single-worker event loop). A per-probe tempfile create+fsync+delete blocks
    # the loop and serializes ALL concurrent requests (~2s p50 under load). Use a
    # cheap stat-based writability check instead — no blocking write per probe.
    from api.storage.json_store import SCANS_DIR  # noqa: PLC0415
    try:
        checks["storage"] = "ok" if (os.path.isdir(SCANS_DIR) and os.access(SCANS_DIR, os.W_OK)) else "error"
    except Exception:
        checks["storage"] = "error"

    # Check 2: JWT secret is configured and non-default.
    # Reported as "ok"/"error" only — telling an anonymous caller the secret is
    # "weak or default" hands a probing attacker a misconfiguration hint.
    jwt_secret = os.environ.get("NETLOGIC_JWT_SECRET", "")
    if not jwt_secret or jwt_secret == _DEFAULT_JWT_SECRET or len(jwt_secret) < _MIN_SECRET_LENGTH:
        checks["config"] = "error"
    else:
        checks["config"] = "ok"

    overall = "ok" if all(v == "ok" for v in checks.values()) else "degraded"

    return {
        "status": overall,
        "uptime_s": round(time.time() - _START_TIME, 1),
        "checks": checks,
    }
