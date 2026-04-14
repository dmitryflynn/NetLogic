"""
NetLogic API — Scan endpoints.

REST surface:
  POST   /scans              Start a new scan (returns job_id, status 202)
  GET    /scans              List recent scan jobs
  GET    /scans/{id}         Inspect a single job (status + full event list when done)
  GET    /scans/{id}/stream  Server-Sent Events stream of live scan events
  DELETE /scans/{id}         Cancel a queued/running job (best-effort)

SSE stream format
─────────────────
Each line: data: <JSON>\n\n
Event types mirror the existing json_bridge.py emit() vocabulary:
  progress, host, port, vuln, tls, headers, stack, dns, osint, takeover,
  service_probes, vuln_probes, done, error, log, ping (keep-alive)

The SSE stream is designed for resilient reconnection:
  • Late-connecting clients receive a full replay of all events emitted so far.
  • After the replay the generator awaits the job's asyncio.Queue for new events.
  • A keep-alive ping is sent every 30 s of inactivity so proxies don't time out.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import AsyncGenerator

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from api.jobs.executor import submit_scan
from api.jobs.manager import ScanJob, job_manager
from api.models.scan_request import ScanRequest

router = APIRouter(prefix="/scans", tags=["scans"])

# ── POST /scans ───────────────────────────────────────────────────────────────


@router.post(
    "",
    status_code=202,
    summary="Start a new scan",
    response_description="Job ID and initial status",
)
async def create_scan(request: ScanRequest) -> dict:
    """
    Kick off an async scan.  Returns immediately with a `job_id` that can be
    used to poll status (`GET /scans/{id}`) or stream events in real-time
    (`GET /scans/{id}/stream`).
    """
    job = job_manager.create(request)
    await submit_scan(job)
    return _job_summary(job)


# ── GET /scans ────────────────────────────────────────────────────────────────


@router.get(
    "",
    summary="List recent scans",
    response_description="Array of job summaries, newest first",
)
async def list_scans(
    limit: int = Query(default=20, ge=1, le=200, description="Max jobs to return"),
) -> list[dict]:
    """Return up to `limit` scan jobs, sorted newest-first."""
    return [_job_summary(j) for j in job_manager.list(limit=limit)]


# ── GET /scans/{id} ───────────────────────────────────────────────────────────


@router.get(
    "/{job_id}",
    summary="Get scan status / results",
    response_description="Full job detail including all events once complete",
)
async def get_scan(job_id: str) -> dict:
    """
    Returns the current job state.

    * While running: `status`, `started_at`, and a `event_count` field.
    * When completed or failed: includes the full `events` array so callers
      that missed the SSE stream can reconstruct the complete scan output.
    """
    job = _get_or_404(job_id)
    return _job_detail(job)


# ── GET /scans/{id}/stream ────────────────────────────────────────────────────


@router.get(
    "/{job_id}/stream",
    summary="Stream scan events (SSE)",
    response_description="text/event-stream of scan events",
)
async def stream_scan(job_id: str) -> StreamingResponse:
    """
    Opens a Server-Sent Events connection that delivers every scan event as it
    happens.  Clients that connect after the scan has started will receive a
    full replay of all past events before the live stream continues.

    The stream ends when a `done` or `error` event is delivered.
    """
    job = _get_or_404(job_id)
    return StreamingResponse(
        _sse_generator(job),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx response buffering
            "Connection": "keep-alive",
        },
    )


# ── DELETE /scans/{id} ────────────────────────────────────────────────────────


@router.delete(
    "/{job_id}",
    summary="Cancel a scan job",
    response_description="Cancellation acknowledgement",
)
async def cancel_scan(job_id: str) -> dict:
    """
    Best-effort cancellation.  If the scan thread has already started the
    network scan it will run to completion (the engine does not support
    mid-scan interruption), but the asyncio Task wrapper is cancelled.
    """
    job = _get_or_404(job_id)
    if job.status in ("completed", "failed"):
        return {"job_id": job_id, "status": job.status, "cancelled": False,
                "detail": "Job already finished."}

    if job._task and not job._task.done():
        job._task.cancel()

    job.status = "failed"
    job.error = "Cancelled by client request."
    job.completed_at = time.time()
    # Emit synthetic events so any connected SSE consumers exit cleanly.
    error_event = {"type": "error", "message": job.error}
    job.push_event(error_event)
    job.push_sentinel()

    return {"job_id": job_id, "status": job.status, "cancelled": True}


# ── SSE event generator ───────────────────────────────────────────────────────


async def _sse_generator(job: ScanJob) -> AsyncGenerator[str, None]:
    """
    Async generator that yields SSE-formatted lines.

    Strategy (cursor + queue):
    ──────────────────────────
    1. Replay all events already in job.events using an integer cursor (idx).
       This handles clients that connect mid-scan or after completion.
    2. Await the job's asyncio.Queue for wake signals from the scan thread.
       On each wake we loop back to step 1 to drain any new events.
    3. When the scan finishes, the thread pushes a None sentinel into the queue.
       The generator detects this (or job.status becoming terminal) and returns.

    Race-condition analysis
    ───────────────────────
    Appending to job.events and putting to the queue are separate operations in
    the scan thread (emit_callback → push_event).  The cursor approach is safe:
    even if the asyncio.Queue signal arrives *before* the event is visible in
    job.events, the generator will loop and re-check the list — worst case it
    waits for the next queue item.  In practice the list append completes first
    (same thread, no preemption between the two statements).
    """
    idx = 0

    while True:
        # ── Phase A: drain stored events ──────────────────────────────────────
        # Read a snapshot of the list up to its current length.  We take
        # `job.events[idx:]` which creates a new list object (GIL-safe slice).
        snapshot = job.events[idx:]
        for event in snapshot:
            idx += 1
            try:
                yield f"data: {json.dumps(event, default=str)}\n\n"
            except Exception:  # noqa: BLE001
                # Serialisation should never fail (default=str handles all types),
                # but guard against any unexpected object to keep the stream alive.
                yield f'data: {{"type":"log","data":{{"text":"serialisation error","level":"warn"}}}}\n\n'
            # Terminal event — close the stream.
            if event.get("type") in ("done", "error"):
                return

        # ── Phase B: check terminal status ────────────────────────────────────
        # The scan might have finished between our last queue wait and now.
        if job.status in ("completed", "failed"):
            # One final drain to catch any events emitted between the last
            # snapshot and the status change.
            for event in job.events[idx:]:
                idx += 1
                yield f"data: {json.dumps(event, default=str)}\n\n"
                if event.get("type") in ("done", "error"):
                    return
            return

        # ── Phase C: wait for next wake signal ───────────────────────────────
        if job._queue is None:
            # Job is still in the queued state and _queue hasn't been set yet.
            await asyncio.sleep(0.2)
            continue

        try:
            signal = await asyncio.wait_for(job._queue.get(), timeout=30.0)
        except asyncio.TimeoutError:
            # No events for 30 s — send a keep-alive ping so the HTTP connection
            # is not closed by proxies or load-balancers.
            yield 'data: {"type":"ping"}\n\n'
            continue
        except asyncio.CancelledError:
            # HTTP client disconnected; exit the generator cleanly.
            return

        # None sentinel means the scan thread has finished.
        if signal is None:
            # Final drain before closing.
            for event in job.events[idx:]:
                idx += 1
                yield f"data: {json.dumps(event, default=str)}\n\n"
                if event.get("type") in ("done", "error"):
                    return
            return
        # Otherwise signal is the latest event; the cursor loop above will
        # pick it up from job.events on the next iteration.


# ── Shared helpers ────────────────────────────────────────────────────────────


def _get_or_404(job_id: str) -> ScanJob:
    job = job_manager.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Scan job '{job_id}' not found.")
    return job


def _job_summary(job: ScanJob) -> dict:
    return {
        "job_id": job.job_id,
        "status": job.status,
        "target": job.config.target,
        "ports": job.config.ports,
        "do_full": job.config.do_full,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "event_count": len(job.events),
        "error": job.error,
    }


def _job_detail(job: ScanJob) -> dict:
    detail = _job_summary(job)
    detail["config"] = job.config.model_dump()
    # Include full event list for terminal jobs so callers don't have to
    # reconnect to the SSE stream just to retrieve completed results.
    if job.status in ("completed", "failed"):
        detail["events"] = job.events
    return detail
