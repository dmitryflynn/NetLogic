"""
VDB (Vulnerability Database) management endpoints.

GET  /v1/vdb/status   → NVD availability + cache statistics
POST /v1/vdb/sync     → Clear stale NVD cache so next scan re-fetches fresh CVE data
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from api.auth.dependencies import require_org
from api.middleware.audit import audit_log

router = APIRouter(prefix="/vdb", tags=["vdb"])


@router.get(
    "/status",
    summary="NVD cache status",
    response_description="Cache entry count, size, and NVD reachability",
)
async def vdb_status(org_id: str = Depends(require_org)) -> dict:
    """Return the current NVD cache statistics and connectivity status."""
    from src.nvd_lookup import cache_stats, nvd_is_available  # noqa: PLC0415
    stats = cache_stats()
    stats["nvd_available"] = nvd_is_available()
    return stats


@router.post(
    "/sync",
    summary="Clear NVD cache",
    response_description="Confirmation with new cache stats",
)
async def vdb_sync(org_id: str = Depends(require_org)) -> dict:
    """
    Delete all cached NVD responses so the next scan fetches fresh CVE data.

    Scans run immediately after this call will query the NVD API live
    (rate-limited to 5 req/30 s without an API key, 50 req/30 s with one).
    """
    from src.nvd_lookup import clear_cache, cache_stats, nvd_is_available  # noqa: PLC0415
    clear_cache()
    audit_log("vdb_sync", org_id=org_id)
    stats = cache_stats()
    stats["nvd_available"] = nvd_is_available()
    stats["synced"] = True
    return stats
