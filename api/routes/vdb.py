"""
VDB (Vulnerability Database) management endpoints.

GET  /v1/vdb/status   → Offline CVE database stats + freshness + NVD reachability
POST /v1/vdb/sync     → Refresh the local offline CVE database from NVD (background)

Both endpoints require a valid org JWT and are rate-limited per org (the sync in
particular kicks off an expensive, NVD-rate-limited crawl).
"""

from __future__ import annotations

import threading

from fastapi import APIRouter, Depends, HTTPException, Request

from api.auth.dependencies import require_org
from api.auth.rate_limit import vdb_query_limiter
from api.middleware.audit import audit_log

router = APIRouter(prefix="/vdb", tags=["vdb"])


# Module-level guard so concurrent /sync calls don't kick off overlapping crawls.
_sync_lock = threading.Lock()
_sync_state: dict = {"running": False, "last_result": None, "last_error": None}


def _rate_limit(request: Request, org_id: str) -> None:
    """Per-org sliding-window rate limit for VDB endpoints."""
    if not vdb_query_limiter.allow(org_id):
        audit_log("vdb_rate_limited", org_id=org_id)
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded for VDB endpoints. Try again shortly.",
        )


def _run_sync_background(limit: int) -> None:
    """Run the (long, NVD-rate-limited) offline VDB sync off the request path."""
    from src.vdb_syncer import run_vdb_sync  # noqa: PLC0415
    try:
        result = run_vdb_sync(limit=limit)
        with _sync_lock:
            _sync_state["last_result"] = result
            _sync_state["last_error"] = None
    except Exception as exc:  # noqa: BLE001 — record, never crash the worker
        with _sync_lock:
            _sync_state["last_error"] = str(exc)
    finally:
        with _sync_lock:
            _sync_state["running"] = False


@router.get(
    "/status",
    summary="Offline VDB status",
    response_description="Local CVE database stats, freshness, sync state, and NVD reachability",
)
async def vdb_status(request: Request, org_id: str = Depends(require_org)) -> dict:
    """Return offline CVE database statistics plus NVD cache/connectivity status.

    The response is flat so the dashboard can read ``entries``/``size_kb``/
    ``cache_dir``/``nvd_available``/``synced`` directly, with the richer offline
    VDB stats and sync state attached for callers that want them.
    """
    _rate_limit(request, org_id)

    from src.nvd_lookup import cache_stats, nvd_is_available  # noqa: PLC0415
    from src.vdb_engine import vdb_engine  # noqa: PLC0415

    with _sync_lock:
        sync_running = _sync_state["running"]
        last_result = _sync_state["last_result"]
        last_error = _sync_state["last_error"]

    # cache_stats() may fail/return partial; coerce to a dict and default fields
    # so the dashboard never sees `undefined`.
    cache = cache_stats() or {}
    offline = vdb_engine.get_stats() or {}

    return {
        # ── Flat fields the dashboard's VdbStatus consumes ──
        "entries": cache.get("entries", 0),
        "size_kb": cache.get("size_kb", 0.0),
        "cache_dir": cache.get("cache_dir", ""),
        "nvd_available": nvd_is_available(),
        "synced": not sync_running and last_error is None,
        # ── Richer detail for API callers ──
        "offline_vdb": offline,
        "nvd_cache": cache,
        "sync_running": sync_running,
        "last_sync_result": last_result,
        "last_sync_error": last_error,
    }


@router.post(
    "/sync",
    summary="Sync offline CVE database from NVD",
    response_description="Confirmation that the background sync has started (or was already running)",
)
async def vdb_sync(
    request: Request, limit: int = 0, org_id: str = Depends(require_org)
) -> dict:
    """
    Refresh the local offline CVE database (~/.netlogic/vdb) from NVD.

    This is what keeps a user's local CVE data current. A full sync crawls every
    focus product across NVD (rate-limited: 5 req/30 s without an API key, 50 with
    one), so it runs in the background — this call returns immediately. Poll
    GET /v1/vdb/status for progress, counts, and freshness. Pass ``limit`` to sync
    only the first N products (handy for a quick refresh/test).

    The stale NVD response cache is cleared first so the sync pulls fresh data.
    """
    _rate_limit(request, org_id)

    # Validate input — limit must be a sane non-negative bound.
    if limit < 0 or limit > 100_000:
        raise HTTPException(
            status_code=422,
            detail="limit must be between 0 and 100000 (0 = sync all products).",
        )

    from src.nvd_lookup import clear_cache  # noqa: PLC0415

    # Claim the running flag atomically so two concurrent callers can't both
    # start a crawl and corrupt/double-write the DB.
    with _sync_lock:
        if _sync_state["running"]:
            return {
                "status": "already_running",
                "message": "An offline VDB sync is already in progress. Poll /v1/vdb/status.",
            }
        _sync_state["running"] = True
        _sync_state["last_error"] = None

    # From here we own the flag; if anything fails before the worker thread is
    # running we MUST release it, or no future sync can ever start.
    try:
        clear_cache()
        audit_log("vdb_sync", org_id=org_id)
        thread = threading.Thread(target=_run_sync_background, args=(limit,), daemon=True)
        thread.start()
    except Exception as exc:  # noqa: BLE001
        with _sync_lock:
            _sync_state["running"] = False
            _sync_state["last_error"] = str(exc)
        raise HTTPException(
            status_code=503,
            detail="Failed to start offline VDB sync. Please retry shortly.",
        ) from exc

    return {
        "status": "sync_started",
        "message": "Offline VDB sync started in the background. Poll GET /v1/vdb/status for progress.",
        "limit": limit,
    }
