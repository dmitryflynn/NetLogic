"""
NetLogic API — Scan executor.

Bridges the synchronous NetLogic scan engine with asyncio:

  1. submit_scan(job)        — called from the async route handler.
                               Sets up the asyncio Queue, captures the running
                               event loop, then schedules _run_async as an
                               asyncio Task (fire-and-forget, doesn't block the
                               HTTP response).

  2. _run_async(job)         — async coroutine that acquires the concurrency
                               semaphore then offloads the blocking scan to a
                               ThreadPoolExecutor via loop.run_in_executor().

  3. _run_scan_thread(job)   — runs inside an OS thread.  Calls
                               run_streaming_scan() with an emit_callback that
                               writes events to job.events (list append, GIL-safe)
                               and wakes the SSE consumer via
                               loop.call_soon_threadsafe().

Thread-safety guarantees
────────────────────────
• job.events — append-only list; CPython's GIL makes append atomic.
• job.status / job.started_at / … — simple attribute assignments; atomic under GIL.
• job._queue / job._loop — written once before the thread starts, then read-only.
• emit_callback uses call_soon_threadsafe to schedule queue writes on the event
  loop thread, so asyncio.Queue is only touched from the correct thread.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import os
import sys
import time
from typing import TYPE_CHECKING

# ── Project Path Bootstrap ────────────────────────────────────────────────────
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# ── Core Engine Imports ───────────────────────────────────────────────────────
from src.json_bridge import run_streaming_scan
from src.scanner import COMMON_PORTS, EXTENDED_PORTS

if TYPE_CHECKING:
    from api.jobs.manager import ScanJob

# ── Concurrency Enforcement ───────────────────────────────────────────────────
# _MAX_CONCURRENT is enforced at two levels:
# 1. API Level: asyncio.Semaphore(10) ensures only 10 scan tasks are scheduled.
# 2. Execution Level: ThreadPoolExecutor(max_workers=10) ensures only 10 OS
#    threads are actually running in the background.
# This prevents OOM/CPU saturation on the server.
_MAX_CONCURRENT = 10
_thread_pool = concurrent.futures.ThreadPoolExecutor(
    max_workers=_MAX_CONCURRENT,
    thread_name_prefix="netlogic-scan",
)

# ── Asyncio concurrency guard ─────────────────────────────────────────────────
# Lazily created so it is bound to whatever event loop is running at first use.
_semaphore: asyncio.Semaphore | None = None

# Keep a strong reference to every background Task so GC cannot collect them
# before they finish.
_live_tasks: set[asyncio.Task] = set()


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(_MAX_CONCURRENT)
    return _semaphore


# ── Public entry point ────────────────────────────────────────────────────────

async def submit_scan(job: ScanJob) -> None:
    """Schedule `job` for execution.  Returns immediately (non-blocking).

    The job's _queue and _loop are always configured here so SSE consumers
    can start waiting before the first event arrives — regardless of whether
    the scan runs locally or on a remote agent.

    Remote agent path (job.config.agent_id is set):
      The job is pushed onto the agent's pending task queue.  The agent will
      pick it up the next time it polls GET /agents/{id}/tasks, run the scan
      locally, and stream events back via POST /agents/{id}/tasks/{id}/events.

    Local execution path (no agent_id):
      The scan runs in a ThreadPoolExecutor on the controller (Phase 1 behaviour).
    """
    loop = asyncio.get_running_loop()
    job._loop = loop
    job._queue = asyncio.Queue(maxsize=1000)

    if job.config.agent_id:
        # ── Remote agent dispatch ─────────────────────────────────────────
        from api.agents.registry import agent_registry  # avoid circular import
        agent = agent_registry.get(job.config.agent_id)
        if agent is None or agent.status == "offline":
            job.status = "failed"
            job.error = (
                f"Agent '{job.config.agent_id}' is not available "
                f"(not registered or offline)."
            )
            job.completed_at = time.time()
            job.push_event({"type": "error", "message": job.error})
            job.push_sentinel()
            return
        agent_registry.assign_task(job.config.agent_id, job.job_id)
        # Job remains "queued" — the agent drives it from here.
        return

    # ── Local execution ───────────────────────────────────────────────────
    task = asyncio.create_task(_run_async(job, loop))
    job._task = task
    _live_tasks.add(task)
    task.add_done_callback(_live_tasks.discard)


# ── Internal coroutine ────────────────────────────────────────────────────────

async def _run_async(job: ScanJob, loop: asyncio.AbstractEventLoop) -> None:
    """Async wrapper: acquires semaphore then runs the blocking scan in a thread."""
    sem = _get_semaphore()
    # Global timeout for the entire scan job (e.g. 1 hour) to prevent zombie scans.
    # The scan engine doesn't support mid-scan interruption of the OS thread,
    # but the API Task will be cancelled and resources reclaimed.
    GLOBAL_SCAN_TIMEOUT = 3600  # 1 hour

    try:
        async with sem:
            await asyncio.wait_for(
                loop.run_in_executor(_thread_pool, _run_scan_thread, job),
                timeout=GLOBAL_SCAN_TIMEOUT
            )
    except asyncio.TimeoutError:
        job.status = "failed"
        job.error = f"Scan timed out after {GLOBAL_SCAN_TIMEOUT}s."
        job.push_event({"type": "error", "message": job.error})
    except asyncio.CancelledError:
        # Client cancelled the job
        job.status = "cancelled"
        job.error = "Scan cancelled by user."
        # We cannot kill the OS thread in the pool immediately, but we can
        # mark the job as failed and stop streaming.
        job.push_event({"type": "error", "message": job.error})
        raise
    except Exception as e:
        job.status = "failed"
        job.error = str(e)
        job.push_event({"type": "error", "message": str(e)})
    finally:
        job.completed_at = time.time()
        job.push_sentinel()


# ── Blocking scan thread ──────────────────────────────────────────────────────

def _run_scan_thread(job: ScanJob) -> None:
    """Blocking function that runs inside a ThreadPoolExecutor worker thread.

    Calls run_streaming_scan() with an emit_callback that:
      1. Appends the event to job.events (GIL-safe).
      2. Wakes SSE consumers via loop.call_soon_threadsafe().
    """
    job.status = "running"
    job.started_at = time.time()

    def emit_callback(event_type: str, data, message: str | None) -> None:
        """Called by emit() inside the scan engine (on this OS thread)."""
        # If the task has been cancelled, we should stop processing events
        # from the engine, even if the thread is still technically running.
        if job.status == "failed" and "cancelled" in (job.error or "").lower():
            return

        event: dict = {"type": event_type}
        if message is not None:
            event["message"] = message
        else:
            event["data"] = data
        job.push_event(event)

    try:
        ports = _resolve_ports(job.config.ports)

        run_streaming_scan(
            target=job.config.target,
            ports=ports,
            timeout=job.config.timeout,
            threads=job.config.threads,
            # The engine handles the do_full flag internally, but we still pass
            # individual flags so partial scans work correctly.
            do_osint=job.config.do_osint or job.config.do_full,
            cidr=job.config.cidr,
            do_tls=job.config.do_tls or job.config.do_full,
            do_headers=job.config.do_headers or job.config.do_full,
            do_stack=job.config.do_stack or job.config.do_full,
            do_dns=job.config.do_dns or job.config.do_full,
            do_full=job.config.do_full,
            do_probe=job.config.do_probe or job.config.do_full,
            do_takeover=job.config.do_takeover or job.config.do_full,
            min_cvss=job.config.min_cvss,
            emit_callback=emit_callback,
        )
        if job.status == "running":
            job.status = "completed"

    except Exception as exc:  # noqa: BLE001
        if job.status == "running":
            job.status = "failed"
            job.error = str(exc)
            # Emit a synthetic error event so SSE consumers can terminate cleanly.
            error_event: dict = {"type": "error", "message": str(exc)}
            job.push_event(error_event)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _resolve_ports(ports_arg: str) -> list[int]:
    """Convert the ports string (quick / full / custom=...) to a port list."""
    if ports_arg == "quick":
        return list(COMMON_PORTS)
    if ports_arg == "full":
        return list(EXTENDED_PORTS)
    # 'custom=21,22,80' (already normalised by Pydantic validator)
    raw = ports_arg[len("custom="):]
    return [int(p) for p in raw.split(",") if p.strip().isdigit()]

