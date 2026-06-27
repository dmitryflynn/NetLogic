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
import collections
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from api.models.scan_request import ScanRequest
from api.storage.json_store import JsonScanStore, SCANS_DIR


class JobCancelled(Exception):
    """Raised inside the scan thread (via push_event) when a job is cancelled.

    Python cannot force-kill an OS thread, so cooperative cancellation works by
    raising at the next event emission. The scan engine calls emit_callback ->
    job.push_event() frequently, so this unwinds the scan stack promptly. The
    scan worker is expected to treat this as a clean stop, NOT as a scan error,
    and must not overwrite the already-terminal 'cancelled' status.
    """


@dataclass
class ScanJob:
    # ── Identity ──────────────────────────────────────────────────────────────
    job_id: str
    config: ScanRequest

    # ── Constants ─────────────────────────────────────────────────────────────
    # Cap event history per job to 10,000 events to prevent OOM on long scans.
    EVENT_CAP = 10000

    # ── Multi-tenancy ─────────────────────────────────────────────────────────
    org_id: str = ""                 # owning organisation — empty string = no tenant

    # ── Dispatch tracking ─────────────────────────────────────────────────────
    # Which agent is actually executing this job.  May differ from
    # config.agent_id when the controller auto-assigned to any available agent.
    # Set by executor.py; read by agent routes for ownership verification.
    assigned_agent_id: Optional[str] = None
    # How many times this job has been (re)dispatched to an agent. Incremented
    # each time it is reclaimed from a dead agent; capped so a permanently
    # unschedulable job fails instead of looping forever.
    dispatch_attempts: int = 0

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    status: str = "queued"          # queued | running | completed | failed | cancelled
    progress: float = 0.0           # 0.0 to 100.0
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    error: Optional[str] = None

    # ── Event store (capped history) ──────────────────────────────────────────
    # All emitted events are stored here so late-connecting SSE clients can
    # replay from the beginning.  deque(maxlen) gives O(1) append+cap vs O(n)
    # list.pop(0) on the previous implementation.
    events: collections.deque = field(
        default_factory=lambda: collections.deque(maxlen=ScanJob.EVENT_CAP)
    )

    # Monotonic count of every event ever appended (NOT len(events), which is
    # capped and shrinks as old events are evicted from the deque's left). SSE
    # consumers use this as a stable absolute cursor: the event at deque[i]
    # has absolute index (_total_events - len(events) + i). Without it a slow
    # consumer that falls more than EVENT_CAP behind would silently skip every
    # event past the cap, because list(events)[idx:] indexes the *current*
    # (already-evicted) deque rather than the absolute stream position.
    _total_events: int = field(default=0, repr=False, compare=False)

    # ── Async wakeup channel ──────────────────────────────────────────────────
    _queue: Optional[asyncio.Queue] = field(default=None, repr=False, compare=False)
    _loop: Optional[asyncio.AbstractEventLoop] = field(
        default=None, repr=False, compare=False
    )
    _task: Optional[asyncio.Task] = field(default=None, repr=False, compare=False)

    # ── Cooperative cancellation flag ─────────────────────────────────────────
    # Set by cancel_job(); checked by emit_callback() in the scan thread.
    # Python cannot force-kill an OS thread, but raising inside emit_callback
    # unwinds the scan stack at the next emission — typically within
    # milliseconds on an active scan.
    _stop_flag: threading.Event = field(
        default_factory=threading.Event, repr=False, compare=False
    )

    # ── Periodic persistence ──────────────────────────────────────────────────
    # Persist the job every N events so a crash during a running scan doesn't
    # lose all partial results.  Counter is only bumped during running scans.
    _save_interval: int = 50
    _save_counter: int = field(default=0, repr=False, compare=False)

    # ─────────────────────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Serialise job state for disk storage."""
        return {
            "job_id": self.job_id,
            "config": self.config.persisted_dump(),
            "org_id": self.org_id,
            "assigned_agent_id": self.assigned_agent_id,
            "dispatch_attempts": self.dispatch_attempts,
            "status": self.status,
            "progress": self.progress,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error": self.error,
            "events": list(self.events),  # deque → list for JSON serialisation
        }

    @classmethod
    def from_dict(cls, data: dict) -> ScanJob:
        """Re-hydrate a job from disk storage."""
        job = cls(
            job_id=data["job_id"],
            config=ScanRequest(**data["config"]),
            org_id=data.get("org_id", ""),
            assigned_agent_id=data.get("assigned_agent_id"),
            dispatch_attempts=data.get("dispatch_attempts", 0),
            status=data["status"],
            progress=data.get("progress", 0.0),
            created_at=data["created_at"],
            started_at=data.get("started_at"),
            completed_at=data.get("completed_at"),
            error=data.get("error"),
            events=collections.deque(data.get("events", []), maxlen=ScanJob.EVENT_CAP),
        )
        # Seed the absolute cursor from the persisted history length. Terminal
        # jobs don't emit further events, so this only needs to be self-consistent
        # for any late SSE replay against the reloaded deque.
        job._total_events = len(job.events)
        # Only if we reload a job that was still actively running, mark it as failed (zombie)
        # Queued jobs that were waiting for an agent survive restart.
        if job.status == "running":
            job.status = "failed"
            job.error = "Scan interrupted by server restart."
            if job.completed_at is None:
                job.completed_at = time.time()
        return job

    def push_event(self, event: dict) -> None:
        """Append an event and wake all SSE consumers.

        If the job has been cancelled, raise JobCancelled *after* recording this
        event so the scan thread unwinds at the next emission. This is the
        cooperative-cancellation mechanism described on _stop_flag: cancel_job()
        sets the flag and the in-thread scan stops here.
        """
        # 0. Cooperative cancellation: stop the scan thread at the next emit.
        #    Record the event first (so consumers still see it), then unwind.
        cancelled = self._stop_flag.is_set()

        # 1. Update progress if applicable
        if event.get("type") == "progress":
            data = event.get("data")
            if isinstance(data, dict) and "percent" in data:
                try:
                    self.progress = float(data["percent"])
                except (TypeError, ValueError):
                    pass

        # 2. Append and enforce the event cap. The deque's maxlen is fixed at
        #    construction, so honor the current (possibly runtime-adjusted)
        #    EVENT_CAP explicitly — otherwise a per-job cap override is ignored.
        #    _total_events tracks the absolute stream position for SSE cursors.
        self.events.append(event)
        self._total_events += 1
        cap = self.EVENT_CAP
        while len(self.events) > cap:
            self.events.popleft()

        # 3. Signal SSE consumers
        if self._loop and self._queue:
            try:
                self._loop.call_soon_threadsafe(self._queue.put_nowait, event)
            except asyncio.QueueFull:
                pass
            except RuntimeError:
                pass

        # 4. Persistence: save on terminal events and periodically while running
        #    so a server crash during a scan doesn't lose all partial results.
        if event.get("type") in ("done", "error"):
            if job_manager:
                job_manager.persist_job(self)
        elif self.status == "running" and job_manager:
            self._save_counter += 1
            if self._save_counter >= self._save_interval:
                self._save_counter = 0
                job_manager.persist_job(self)

        # 5. Unwind the scan stack if cancellation was requested. Done last so
        #    the event above is delivered/persisted before we abort.
        #
        #    Only raise on the SCAN WORKER thread (cooperative cancellation). The
        #    cancel/delete routes run on the asyncio event-loop thread and call
        #    push_event() to emit the terminal event themselves *after* setting
        #    _stop_flag — raising there would escape into the request handler and
        #    return HTTP 500. Detect the loop thread by checking for a running
        #    event loop; the scan worker is a plain thread with no loop.
        if cancelled:
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                # No running loop on this thread → we are the scan worker. Unwind.
                raise JobCancelled(self.job_id)

    def push_sentinel(self) -> None:
        """Signal all SSE consumers that the stream is finished."""
        if self._loop and self._queue:
            try:
                self._loop.call_soon_threadsafe(self._queue.put_nowait, None)
            except (asyncio.QueueFull, RuntimeError):
                pass


class JobManager:
    """Registry of scan jobs with durable persistence (Postgres or JSON files)."""

    MAX_JOBS = 500
    JOB_TTL_SECONDS = 12 * 3600

    # Class-level defaults so an instance built via __new__ (used by some tests)
    # is safe before __init__ runs; __init__ sets the real backend selection.
    _pg = False
    _pg_store = None

    def __init__(self) -> None:
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.RLock()
        self.store = JsonScanStore(SCANS_DIR)
        # Durable backend selection (mirrors api_key_store / org_settings_store):
        # Postgres when configured (multi-tenant: survives restart, shared across
        # instances, no 500-job history loss), else the JSON store (desktop).
        from api import db  # noqa: PLC0415
        self._pg = db.is_enabled()
        self._pg_store = None
        if self._pg:
            from api.storage.pg_store import PgScanStore  # noqa: PLC0415
            self._pg_store = PgScanStore()
        # JSON backend: safe to warm the cache now (no schema needed). Postgres
        # backend: DEFER — this singleton is built at import time, BEFORE the app
        # lifespan runs apply_migrations(), so scan_jobs may not exist yet. The
        # lifespan calls warm_cache() after migrations instead.
        if not self._pg:
            self._load_from_storage()

    def warm_cache(self) -> None:
        """Warm the in-memory cache from the durable Postgres store.

        Called from the app lifespan AFTER apply_migrations() (the singleton is
        constructed at import time, before migrations create scan_jobs). Active
        (queued/running) jobs are always recent, so dispatch/reclaim work; full
        history stays in the DB and is served on demand by get()/list(). No-op for
        the JSON backend, which warmed its cache in __init__."""
        if not (self._pg and self._pg_store is not None):
            return
        for data in self._pg_store.load_recent_sync(self.MAX_JOBS):
            try:
                job = ScanJob.from_dict(data)
                with self._lock:
                    self._jobs[job.job_id] = job
            except Exception:
                continue
        self._maybe_evict()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load_from_storage(self) -> None:
        """Synchronously reload jobs from the JSON store into memory at startup."""
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
        # Do not resurrect a job that has been deleted from the registry.
        with self._lock:
            if job.job_id not in self._jobs:
                return

        # Postgres backend: durable upsert. Prefer the captured/running loop so
        # the blocking DB write happens off the event loop; fall back to a sync
        # write when no loop is available (CLI/tests), same 3-case logic as JSON.
        if self._pg and self._pg_store is not None:
            record = job.to_dict()
            if job._loop:
                try:
                    job._loop.call_soon_threadsafe(
                        lambda: asyncio.create_task(self._pg_store.save_scan(job.job_id, record))
                    )
                    return
                except RuntimeError:
                    pass
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._pg_store.save_scan(job.job_id, record))
            except RuntimeError:
                self._pg_store.save_sync(record)
            return

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

    def create(self, config: ScanRequest, org_id: str = "") -> ScanJob:
        """Allocate a new job, register it, and return it."""
        self._maybe_evict()
        job = ScanJob(job_id=str(uuid.uuid4()), config=config, org_id=org_id)
        with self._lock:
            self._jobs[job.job_id] = job
        # Save initial metadata
        self.persist_job(job)
        return job

    # ── Query ─────────────────────────────────────────────────────────────────

    def try_claim(self, job_id: str, org_id: str = "") -> Optional[ScanJob]:
        """Atomically transition a queued job to running, else None.

        Prevents the cancelled-job race: check + assign happen under the lock so
        a concurrent cancel_job cannot slip in between.
        """
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None
            if org_id and job.org_id != org_id:
                return None
            if job.status != "queued":
                return None
            job.status = "running"
            return job

    def get(self, job_id: str, org_id: str = "") -> Optional[ScanJob]:
        """Return the job if it exists and belongs to org_id (or org_id is unset)."""
        with self._lock:
            job = self._jobs.get(job_id)
        # Postgres backend: a job evicted from the in-memory cache still lives in
        # the DB — fall back to it so history stays retrievable (durability).
        if job is None and self._pg and self._pg_store is not None:
            data = self._pg_store.get_sync(job_id)
            if data is not None:
                try:
                    job = ScanJob.from_dict(data)
                except Exception:
                    job = None
        if job is None:
            return None
        if org_id and job.org_id != org_id:
            return None  # treat as not found — prevents cross-org enumeration
        return job

    def list(self, limit: int = 50, org_id: str = "") -> list[ScanJob]:
        """Return up to `limit` jobs, newest first, optionally filtered by org."""
        self._maybe_evict()
        # Postgres backend: list from the durable store so the full org history
        # is shown, not just the in-memory cache. Prefer the live in-memory job
        # object when present (freshest progress/status for active scans).
        if self._pg and self._pg_store is not None:
            out: list[ScanJob] = []
            for data in self._pg_store.list_sync(limit=limit, org_id=org_id):
                jid = data.get("job_id")
                with self._lock:
                    live = self._jobs.get(jid)
                if live is not None:
                    out.append(live)
                else:
                    try:
                        out.append(ScanJob.from_dict(data))
                    except Exception:
                        continue
            return out

        with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)
        if org_id:
            jobs = [j for j in jobs if j.org_id == org_id]
        return jobs[:limit]

    def list_queued_unassigned(self, org_id: str = "") -> list[ScanJob]:
        """Return queued jobs that have no assigned agent yet, oldest first.

        Used by try_dispatch_queued() to find work for newly available agents.
        Does NOT trigger eviction (intentional — called on every heartbeat).
        """
        with self._lock:
            jobs = [
                j for j in self._jobs.values()
                if j.status == "queued"
                and not j.assigned_agent_id
                and (not org_id or j.org_id == org_id)
            ]
        return sorted(jobs, key=lambda j: j.created_at)

    def list_dispatched_active(self, org_id: str = "") -> list[ScanJob]:
        """Return non-terminal jobs that are pinned to an agent (queued or running).

        Used by the reclaimer to find work stranded on agents that have since
        gone offline. Oldest first.
        """
        with self._lock:
            jobs = [
                j for j in self._jobs.values()
                if j.status in ("queued", "running")
                and j.assigned_agent_id
                and (not org_id or j.org_id == org_id)
            ]
        return sorted(jobs, key=lambda j: j.created_at)

    # ── Delete ────────────────────────────────────────────────────────────────

    def delete(self, job_id: str, _evict_only: bool = False) -> bool:
        """Remove a job from memory and durable storage.

        _evict_only=True drops the in-memory cache entry but KEEPS the durable
        record — used by capacity eviction on the Postgres backend so trimming
        RAM never destroys job history (the JSON backend has no such distinction
        and always removes the file).
        """
        with self._lock:
            if job_id not in self._jobs:
                return False
            del self._jobs[job_id]

        if self._pg and self._pg_store is not None:
            if not _evict_only:
                self._pg_store.delete_sync(job_id)   # explicit user delete only
            return True

        # JSON backend: remove the on-disk record.
        path = os.path.join(SCANS_DIR, f"{job_id}.json")
        if os.path.exists(path):
            try:
                os.unlink(path)
            except OSError:
                pass
        return True

    # ── Housekeeping ──────────────────────────────────────────────────────────

    def _maybe_evict(self) -> None:
        """
        Housekeeping (bounds the in-memory cache):
        1. Remove jobs older than JOB_TTL_SECONDS (TTL Cleanup).
        2. If count still > MAX_JOBS, remove oldest terminal jobs.

        On the Postgres backend these are CACHE evictions only (_evict_only): the
        durable record is retained so full job history survives — MAX_JOBS / TTL
        bound RAM, not retention. The JSON backend deletes the on-disk record.
        """
        now = time.time()
        evict_only = self._pg

        with self._lock:
            # 1. TTL Cleanup: remove any terminal job older than TTL
            to_delete = [
                jid for jid, j in self._jobs.items()
                if j.status in ("completed", "failed", "cancelled") and (now - j.created_at) > self.JOB_TTL_SECONDS
            ]
        for jid in to_delete:
            self.delete(jid, _evict_only=evict_only)

        jids: list[str] = []
        with self._lock:
            # 2. Capacity Enforcement: if still too many, evict oldest terminal jobs
            if len(self._jobs) >= self.MAX_JOBS:
                terminal = [
                    j for j in self._jobs.values()
                    if j.status in ("completed", "failed", "cancelled")
                ]
                terminal.sort(key=lambda j: j.created_at)
                needed = len(self._jobs) - self.MAX_JOBS + 1
                jids = [j.job_id for j in terminal[:needed]]
        for jid in jids:
            self.delete(jid, _evict_only=evict_only)


# Module-level singleton — imported by executor and routes.
job_manager = JobManager()
