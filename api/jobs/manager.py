"""
NetLogic API — In-memory job registry with disk persistence.

ScanJob is the single source of truth for a running or completed scan.
JobManager is a process-wide singleton that stores all jobs in memory and
synchronises them with the filesystem for persistence across restarts.

Design notes
────────────
• events list   – append-only; CPython's GIL makes list.append() atomic.
• persistence   – Jobs are saved to disk when created and when they reach a
                  terminal state (completed / failed / cancelled).
• reload        – On startup, JobManager scans the storage directory and
                  re-hydrates the in-memory registry.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional

from api.models.scan_request import ScanRequest
from api.storage.json_store import JsonScanStore, SCANS_DIR


@dataclass
class ScanJob:
    # ── Identity ──────────────────────────────────────────────────────────────
    job_id: str
    config: ScanRequest

    # ── Constants ─────────────────────────────────────────────────────────────
    # Cap event history per job to 10,000 events to prevent OOM on long scans.
    EVENT_CAP = 10000

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    status: str = "queued"          # queued | running | completed | failed | cancelled
    progress: float = 0.0           # 0.0 to 100.0
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    error: Optional[str] = None

    # ── Event store (capped history) ──────────────────────────────────────────
    # All emitted events are stored here so late-connecting SSE clients can
    # replay from the beginning.
    events: list = field(default_factory=list)

    # ── Async wakeup channel ──────────────────────────────────────────────────
    _queue: Optional[asyncio.Queue] = field(default=None, repr=False, compare=False)
    _loop: Optional[asyncio.AbstractEventLoop] = field(
        default=None, repr=False, compare=False
    )
    _task: Optional[asyncio.Task] = field(default=None, repr=False, compare=False)

    # ─────────────────────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Serialise job state for disk storage."""
        return {
            "job_id": self.job_id,
            "config": self.config.model_dump(),
            "status": self.status,
            "progress": self.progress,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error": self.error,
            "events": self.events,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ScanJob:
        """Re-hydrate a job from disk storage."""
        job = cls(
            job_id=data["job_id"],
            config=ScanRequest(**data["config"]),
            status=data["status"],
            progress=data.get("progress", 0.0),
            created_at=data["created_at"],
            started_at=data.get("started_at"),
            completed_at=data.get("completed_at"),
            error=data.get("error"),
            events=data.get("events", []),
        )
        # Only if we reload a job that was still actively running/queued, mark it as failed (zombie)
        if job.status in ("queued", "running"):
            job.status = "failed"
            job.error = "Scan interrupted by server restart."
            if job.completed_at is None:
                job.completed_at = time.time()
        return job

    def push_event(self, event: dict) -> None:
        """Append an event and wake all SSE consumers."""
        # 1. Update progress if applicable
        if event.get("type") == "progress":
            data = event.get("data")
            if isinstance(data, dict) and "percent" in data:
                try:
                    self.progress = float(data["percent"])
                except (TypeError, ValueError):
                    pass

        # 2. Enforce event cap (sliding window)
        self.events.append(event)
        if len(self.events) > self.EVENT_CAP:
            self.events.pop(0)

        # 3. Signal SSE consumers
        if self._loop and self._queue:
            try:
                self._loop.call_soon_threadsafe(self._queue.put_nowait, event)
            except asyncio.QueueFull:
                pass
            except RuntimeError:
                pass

        # 4. Persistence: save on terminal events
        if event.get("type") in ("done", "error"):
            # We use the singleton job_manager to trigger a background save
            if job_manager:
                job_manager.persist_job(self)

    def push_sentinel(self) -> None:
        """Signal all SSE consumers that the stream is finished."""
        if self._loop and self._queue:
            try:
                self._loop.call_soon_threadsafe(self._queue.put_nowait, None)
            except (asyncio.QueueFull, RuntimeError):
                pass


class JobManager:
    """Registry of scan jobs with disk persistence."""

    MAX_JOBS = 500
    JOB_TTL_SECONDS = 12 * 3600

    def __init__(self) -> None:
        self._jobs: dict[str, ScanJob] = {}
        self.store = JsonScanStore(SCANS_DIR)
        self._load_from_storage()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load_from_storage(self) -> None:
        """Synchronously scan storage and reload jobs into memory."""
        if not os.path.exists(SCANS_DIR):
            return
        
        # We perform a synchronous read here because this only runs once at startup
        for fname in os.listdir(SCANS_DIR):
            if not fname.endswith(".json") or fname.endswith(".tmp"):
                continue
            
            path = os.path.join(SCANS_DIR, fname)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                    job = ScanJob.from_dict(data)
                    self._jobs[job.job_id] = job
            except Exception:
                continue
        
        # Cleanup any jobs that are over the TTL or MAX_JOBS limit after reload
        self._maybe_evict()

    def persist_job(self, job: ScanJob) -> None:
        """Trigger an asynchronous save of the job state."""
        if self.store:
            # 1. Background thread: schedule on captured loop
            if job._loop:
                try:
                    job._loop.call_soon_threadsafe(
                        lambda: asyncio.create_task(self.store.save_scan(job.job_id, job.to_dict()))
                    )
                    return
                except RuntimeError:
                    pass # Loop closing
            
            # 2. Main thread with loop: schedule task
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self.store.save_scan(job.job_id, job.to_dict()))
            except RuntimeError:
                # 3. No loop running: perform synchronous write fallback
                # (prevents coroutine-never-awaited warnings in tests/scripts)
                path = os.path.join(self.store.directory, f"{job.job_id}.json")
                self.store._write(path, job.to_dict())

    # ── Create ────────────────────────────────────────────────────────────────

    def create(self, config: ScanRequest) -> ScanJob:
        """Allocate a new job, register it, and return it."""
        self._maybe_evict()
        job = ScanJob(job_id=str(uuid.uuid4()), config=config)
        self._jobs[job.job_id] = job
        # Save initial metadata
        self.persist_job(job)
        return job

    # ── Query ─────────────────────────────────────────────────────────────────

    def get(self, job_id: str) -> Optional[ScanJob]:
        return self._jobs.get(job_id)

    def list(self, limit: int = 50) -> list[ScanJob]:
        """Return up to `limit` jobs, newest first."""
        self._maybe_evict()
        jobs = sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)
        return jobs[:limit]

    # ── Delete ────────────────────────────────────────────────────────────────

    def delete(self, job_id: str) -> bool:
        """Remove a job from memory and disk."""
        if job_id in self._jobs:
            del self._jobs[job_id]
            
            # Remove from disk
            path = os.path.join(SCANS_DIR, f"{job_id}.json")
            if os.path.exists(path):
                try:
                    os.unlink(path)
                except OSError:
                    pass
            return True
        return False

    # ── Housekeeping ──────────────────────────────────────────────────────────

    def _maybe_evict(self) -> None:
        """
        Housekeeping:
        1. Remove jobs older than JOB_TTL_SECONDS (TTL Cleanup).
        2. If count still > MAX_JOBS, remove oldest terminal jobs.
        """
        now = time.time()
        
        # 1. TTL Cleanup: remove any terminal job older than TTL
        to_delete = [
            jid for jid, j in self._jobs.items()
            if j.status in ("completed", "failed", "cancelled") and (now - j.created_at) > self.JOB_TTL_SECONDS
        ]
        for jid in to_delete:
            self.delete(jid)

        # 2. Capacity Enforcement: if still too many, evict oldest terminal jobs
        if len(self._jobs) >= self.MAX_JOBS:
            terminal = [
                j for j in self._jobs.values()
                if j.status in ("completed", "failed", "cancelled")
            ]
            terminal.sort(key=lambda j: j.created_at)
            
            needed = len(self._jobs) - self.MAX_JOBS + 1
            for j in terminal[:needed]:
                self.delete(j.job_id)


# Module-level singleton — imported by executor and routes.
job_manager = JobManager()
