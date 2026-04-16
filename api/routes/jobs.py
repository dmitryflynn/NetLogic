"""
NetLogic API — Job management endpoints.

REST surface:
  POST   /jobs              Start a new scan (returns job_id, status 202)
  GET    /jobs              List recent jobs
  GET    /jobs/{id}         Inspect a single job (status, progress, counts)
  GET    /jobs/{id}/stream  Server-Sent Events stream of live scan events
  POST   /jobs/{id}/cancel  Cancel a queued/running job
  DELETE /jobs/{id}         Remove a job from memory (cleanup)

All endpoints require a valid JWT Bearer token.  The org_id embedded in the
token scopes every operation: jobs created by one organisation are never
visible to another.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse

from api.auth.dependencies import require_org
from api.auth.rate_limit import jobs_limiter
from api.jobs.executor import submit_scan
from api.jobs.manager import ScanJob, job_manager
from api.middleware.audit import audit_log
from api.models.scan_request import ScanRequest

router = APIRouter(prefix="/jobs", tags=["jobs"])

# ── POST /jobs ───────────────────────────────────────────────────────────────


@router.post(
    "",
    status_code=202,
    summary="Start a new scan job",
    response_description="Job ID and initial status",
)
async def create_job(
    request: Request,
    body: ScanRequest,
    org_id: str = Depends(require_org),
) -> dict:
    """
    Kick off an async scan. Returns immediately with a `job_id`.
    The job is scoped to the caller's organisation.
    """
    if not jobs_limiter.allow(org_id):
        raise HTTPException(status_code=429, detail="Job submission rate limit exceeded.")
    job = job_manager.create(body, org_id=org_id)
    await submit_scan(job)
    audit_log("job_created", job_id=job.job_id, org_id=org_id, target=body.target)
    return _job_summary(job)


# ── GET /jobs ────────────────────────────────────────────────────────────────


@router.get(
    "",
    summary="List recent jobs",
    response_description="Array of job summaries, newest first",
)
async def list_jobs(
    limit: int = Query(default=20, ge=1, le=200, description="Max jobs to return"),
    org_id: str = Depends(require_org),
) -> list[dict]:
    """Return up to `limit` jobs for the caller's organisation, sorted newest-first."""
    return [_job_summary(j) for j in job_manager.list(limit=limit, org_id=org_id)]


# ── GET /jobs/{id} ───────────────────────────────────────────────────────────


@router.get(
    "/{job_id}",
    summary="Get job status / results",
    response_description="Full job detail",
)
async def get_job(
    job_id: str,
    org_id: str = Depends(require_org),
) -> dict:
    """
    Returns the current job state including progress and result counts.
    Returns 404 if the job does not exist or belongs to a different organisation.
    """
    job = _get_or_404(job_id, org_id)
    return _job_detail(job)


# ── GET /jobs/{id}/stream ────────────────────────────────────────────────────


@router.get(
    "/{job_id}/stream",
    summary="Stream job events (SSE)",
    response_description="text/event-stream of events",
)
async def stream_job(
    job_id: str,
    org_id: str = Depends(require_org),
) -> StreamingResponse:
    """
    Opens an SSE connection for real-time updates.
    """
    job = _get_or_404(job_id, org_id)
    return StreamingResponse(
        _sse_generator(job),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ── POST /jobs/{id}/cancel ───────────────────────────────────────────────────


@router.post(
    "/{job_id}/cancel",
    summary="Cancel a running job",
)
async def cancel_job(
    job_id: str,
    org_id: str = Depends(require_org),
) -> dict:
    """
    Request cancellation of a queued or running job.
    """
    job = _get_or_404(job_id, org_id)
    if job.status in ("completed", "failed", "cancelled"):
        return {"job_id": job_id, "status": job.status, "cancelled": False,
                "detail": "Job already in terminal state."}

    job.status = "cancelled"
    job.completed_at = time.time()
    job.error = "Cancelled by user request."

    # Notify SSE consumers; the agent will receive a 409 / ignored response
    # on its next complete_task call since the job is already terminal.
    job.push_event({"type": "error", "message": job.error})
    job.push_sentinel()

    job_manager.persist_job(job)

    return {"job_id": job_id, "status": job.status, "cancelled": True}


# ── DELETE /jobs/{id} ────────────────────────────────────────────────────────


@router.delete(
    "/{job_id}",
    summary="Delete a job (manual cleanup)",
    status_code=204,
)
async def delete_job(
    job_id: str,
    org_id: str = Depends(require_org),
):
    """
    Remove a job from the in-memory registry. If the job is running, it will be cancelled first.
    """
    job = job_manager.get(job_id, org_id=org_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    job_manager.delete(job_id)
    return Response(status_code=204)


# ── SSE event generator ───────────────────────────────────────────────────────


async def _sse_generator(job: ScanJob) -> AsyncGenerator[str, None]:
    """
    Resilient SSE generator with cursor-based replay and non-blocking queue.
    """
    idx = 0
    while True:
        # 1. Drain available events from history (replay/catch-up)
        snapshot = job.events[idx:]
        for event in snapshot:
            idx += 1
            yield f"data: {json.dumps(event, default=str)}\n\n"
            # If we just yielded a 'done' or 'error' from history, we're finished.
            if event.get("type") in ("done", "error"):
                return

        # 2. Check if job finished while we were processing history
        if job.status in ("completed", "failed", "cancelled"):
            # Final catch-up for any events added after the last snapshot
            for event in job.events[idx:]:
                idx += 1
                yield f"data: {json.dumps(event, default=str)}\n\n"
            return

        # 3. Wait for new events (wake-up signal)
        if job._queue is None:
            await asyncio.sleep(0.2)
            continue

        try:
            # Keep-alive ping every 30s to prevent proxy timeouts
            signal = await asyncio.wait_for(job._queue.get(), timeout=30.0)
        except asyncio.TimeoutError:
            yield 'data: {"type":"ping"}\n\n'
            continue
        except asyncio.CancelledError:
            return  # Client disconnected

        # 4. Sentinel received: scan thread is finished
        if signal is None:
            # One final pass to ensure zero data loss
            for event in job.events[idx:]:
                idx += 1
                yield f"data: {json.dumps(event, default=str)}\n\n"
            return

        # 5. Signal received: loop back to Phase 1 to drain the new event(s)


# ── Shared helpers ────────────────────────────────────────────────────────────


def _get_or_404(job_id: str, org_id: str = "") -> ScanJob:
    job = job_manager.get(job_id, org_id=org_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")
    return job


def _job_summary(job: ScanJob) -> dict:
    # Calculate counts from events
    ports_count = sum(1 for e in job.events if e.get("type") == "port")
    vulns_count = sum(1 for e in job.events if e.get("type") == "vuln")

    return {
        "job_id": job.job_id,
        "org_id": job.org_id,
        "status": job.status,
        "progress": job.progress,
        "target": job.config.target,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "result_counts": {
            "ports": ports_count,
            "vulnerabilities": vulns_count,
        },
        "error": job.error,
    }


def _job_detail(job: ScanJob) -> dict:
    detail = _job_summary(job)
    detail["config"] = job.config.model_dump()
    if job.status in ("completed", "failed", "cancelled"):
        detail["events"] = job.events
    return detail
