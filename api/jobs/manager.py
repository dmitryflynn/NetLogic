"""
NetLogic API — In-memory job registry.

ScanJob is the single source of truth for a running or completed scan.
JobManager is a process-wide singleton that stores all jobs in memory and is
safe for concurrent access by multiple asyncio tasks and OS threads.

Design notes
────────────
• events list   – append-only; CPython's GIL makes list.append() atomic, so no
                  explicit lock is needed for the scan thread's writes or the
                  SSE generator's reads (cursor-based, no deletions).
• status field  – a single string assignment; also atomic under the GIL.
• _queue        – an asyncio.Queue used to wake SSE consumers when a new event
                  arrives.  The scan thread writes via loop.call_soon_threadsafe;
                  the SSE generator reads with await queue.get().
• _loop         – captured once at job-submission time so the thread can safely
                  schedule work on the running event loop.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from api.models.scan_request import ScanRequest


@dataclass
class ScanJob:
    # ── Identity ──────────────────────────────────────────────────────────────
    job_id: str
    config: ScanRequest

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    status: str = "queued"          # queued | running | completed | failed
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    error: Optional[str] = None

    # ── Event store (append-only) ─────────────────────────────────────────────
    # All emitted events are stored here so late-connecting SSE clients can
    # replay from the beginning.  The list itself is never mutated except via
    # append(), which is atomic under the GIL.
    events: list = field(default_factory=list)

    # ── Async wakeup channel ──────────────────────────────────────────────────
    # Set by executor.submit_scan() before the scan thread starts.
    # The scan thread writes via loop.call_soon_threadsafe(queue.put_nowait, ev).
    # SSE generators await queue.get() to be woken when new events arrive.
    _queue: Optional[asyncio.Queue] = field(default=None, repr=False, compare=False)
    _loop: Optional[asyncio.AbstractEventLoop] = field(
        default=None, repr=False, compare=False
    )
    # Background task reference: kept alive so it is not garbage-collected before
    # it finishes (asyncio tasks can be GC'd if no reference is held).
    _task: Optional[asyncio.Task] = field(default=None, repr=False, compare=False)

    # ─────────────────────────────────────────────────────────────────────────

    def push_event(self, event: dict) -> None:
        """Append an event and wake all SSE consumers.

        Called from a background OS thread via the scan engine's emit_callback.
        Uses call_soon_threadsafe so asyncio objects are only touched from the
        event loop thread.
        """
        self.events.append(event)          # GIL-safe append
        if self._loop and self._queue:
            try:
                self._loop.call_soon_threadsafe(self._queue.put_nowait, event)
            except asyncio.QueueFull:
                # Queue full means SSE consumers are slow — they will catch up
                # via the cursor-based replay of self.events.
                pass
            except RuntimeError:
                # Event loop may have closed (e.g. server shutting down).
                pass

    def push_sentinel(self) -> None:
        """Signal all SSE consumers that the stream is finished (None = sentinel)."""
        if self._loop and self._queue:
            try:
                self._loop.call_soon_threadsafe(self._queue.put_nowait, None)
            except (asyncio.QueueFull, RuntimeError):
                pass


class JobManager:
    """Process-wide in-memory registry of scan jobs."""

    # Maximum jobs kept in memory.  Oldest completed jobs are evicted when this
    # limit is reached (running/queued jobs are never evicted).
    MAX_JOBS = 500

    def __init__(self) -> None:
        self._jobs: dict[str, ScanJob] = {}

    # ── Create ────────────────────────────────────────────────────────────────

    def create(self, config: ScanRequest) -> ScanJob:
        """Allocate a new job, register it, and return it."""
        self._maybe_evict()
        job = ScanJob(job_id=str(uuid.uuid4()), config=config)
        self._jobs[job.job_id] = job
        return job

    # ── Query ─────────────────────────────────────────────────────────────────

    def get(self, job_id: str) -> Optional[ScanJob]:
        return self._jobs.get(job_id)

    def list(self, limit: int = 50) -> list[ScanJob]:
        """Return up to `limit` jobs, newest first."""
        jobs = sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)
        return jobs[:limit]

    # ── Housekeeping ──────────────────────────────────────────────────────────

    def _maybe_evict(self) -> None:
        """Remove the oldest completed/failed jobs when the registry is full."""
        if len(self._jobs) < self.MAX_JOBS:
            return
        terminal = [
            j for j in self._jobs.values()
            if j.status in ("completed", "failed")
        ]
        terminal.sort(key=lambda j: j.created_at)
        # Evict oldest 10 % to amortise the cost.
        evict_count = max(1, len(terminal) // 10)
        for j in terminal[:evict_count]:
            del self._jobs[j.job_id]


# Module-level singleton — imported by executor and routes.
job_manager = JobManager()
