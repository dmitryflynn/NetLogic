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

if TYPE_CHECKING:
    pass

# ── Thread pool ───────────────────────────────────────────────────────────────
# Hard-cap at 10 concurrent scans.  Each scan can itself use up to 100 threads
# (configurable), so the real thread ceiling is 10 × 100 = 1 000 which is
# already generous for a single server.
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

async def submit_scan(job) -> None:
    """Schedule `job` for execution.  Returns immediately (non-blocking).

    The job's _queue and _loop are configured here (synchronously, before the
    task starts) so that the SSE generator can begin waiting on the queue even
    before the first scan event is emitted.
    """
    loop = asyncio.get_event_loop()
    job._loop = loop
    # maxsize=1000: if consumers are slow we still store ≤1000 wake signals;
    # the cursor-based replay always recovers the full event list.
    job._queue = asyncio.Queue(maxsize=1000)

    task = asyncio.ensure_future(_run_async(job, loop))
    job._task = task
    _live_tasks.add(task)
    task.add_done_callback(_live_tasks.discard)


# ── Internal coroutine ────────────────────────────────────────────────────────

async def _run_async(job, loop: asyncio.AbstractEventLoop) -> None:
    """Async wrapper: acquires semaphore then runs the blocking scan in a thread."""
    sem = _get_semaphore()
    async with sem:
        await loop.run_in_executor(_thread_pool, _run_scan_thread, job)


# ── Blocking scan thread ──────────────────────────────────────────────────────

def _run_scan_thread(job) -> None:
    """Blocking function that runs inside a ThreadPoolExecutor worker thread.

    Calls run_streaming_scan() with an emit_callback that:
      1. Appends the event to job.events (GIL-safe).
      2. Wakes SSE consumers via loop.call_soon_threadsafe().
    """
    # Make sure the project root is importable (important when the worker
    # thread's sys.path differs from the main thread's).
    _ensure_project_on_path()

    job.status = "running"
    job.started_at = time.time()

    def emit_callback(event_type: str, data, message: str | None) -> None:
        """Called by emit() inside the scan engine (on this OS thread)."""
        event: dict = {"type": event_type}
        if message is not None:
            event["message"] = message
        else:
            event["data"] = data
        job.push_event(event)

    try:
        from src.json_bridge import run_streaming_scan  # noqa: PLC0415

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
        job.status = "completed"

    except Exception as exc:  # noqa: BLE001
        job.status = "failed"
        job.error = str(exc)
        # Emit a synthetic error event so SSE consumers can terminate cleanly.
        error_event: dict = {"type": "error", "message": str(exc)}
        job.push_event(error_event)

    finally:
        job.completed_at = time.time()
        # Push sentinel (None) so SSE generators know the stream is finished.
        job.push_sentinel()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _resolve_ports(ports_arg: str) -> list[int]:
    """Convert the ports string (quick / full / custom=...) to a port list."""
    from src.scanner import COMMON_PORTS, EXTENDED_PORTS  # noqa: PLC0415

    if ports_arg == "quick":
        return list(COMMON_PORTS)
    if ports_arg == "full":
        return list(EXTENDED_PORTS)
    # 'custom=21,22,80' (already normalised by Pydantic validator)
    raw = ports_arg[len("custom="):]
    return [int(p) for p in raw.split(",") if p.strip().isdigit()]


def _ensure_project_on_path() -> None:
    """Add the project root to sys.path if it isn't already there.

    Necessary because ThreadPoolExecutor workers inherit sys.path from the
    spawning thread, but in some deployment configurations (e.g. uvicorn with
    --app-dir) the root may not be present.
    """
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if root not in sys.path:
        sys.path.insert(0, root)
