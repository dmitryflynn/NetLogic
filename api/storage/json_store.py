"""
NetLogic API — JSON-file scan store.

Persists completed scan records as individual JSON files under
~/.netlogic/scans/<job_id>.json  (same directory convention as the NVD cache).

This is the Phase-1 storage backend.  The public interface (save / get / list)
matches the ScanStore Protocol in base.py, so it can be swapped for a Postgres
backend in a later phase with no changes to routes or executor code.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from typing import Optional

log = logging.getLogger("netlogic.storage")

# Honor NETLOGIC_SCANS_DIR (the same data-dir override the agent registry uses)
# so the whole NetLogic state — agents.json, caches, and scan JSONs — relocates
# together. Tests point this at a temp dir to avoid polluting ~/.netlogic.
SCANS_DIR: str = os.path.join(
    os.environ.get("NETLOGIC_SCANS_DIR", os.path.join(os.path.expanduser("~"), ".netlogic")),
    "scans",
)

# Safety limits — prevent unbounded memory usage when loading scan records.
_MAX_FILE_BYTES: int = 10 * 1024 * 1024   # 10 MB per file
_MAX_SCAN_FILES: int = 500                  # keep only the 500 newest files


class JsonScanStore:
    """Store scan records as individual JSON files on disk."""

    def __init__(self, directory: str = SCANS_DIR) -> None:
        # Resolve once so traversal checks compare against a canonical, absolute root.
        self.directory = os.path.abspath(directory)
        try:
            os.makedirs(self.directory, exist_ok=True)
        except OSError:
            # Directory creation can fail (permissions, disk-full, racing process).
            # Fail soft: individual reads/writes guard themselves and degrade
            # gracefully rather than crashing construction of the store.
            log.warning("could not create scans dir %s", self.directory, exc_info=True)

    # ── Path safety ────────────────────────────────────────────────────────────

    def _safe_path(self, job_id: str) -> Optional[str]:
        """
        Resolve ``<directory>/<job_id>.json`` and guarantee it stays inside the
        scans directory.

        Defense-in-depth: although job_ids are server-generated UUIDs, a job_id
        containing ``..``, ``/``, ``\\``, a NUL byte, or an absolute path must
        never be able to read or write outside the scans dir. Returns the
        validated absolute path, or ``None`` if the id is unsafe.
        """
        if not isinstance(job_id, str) or not job_id or "\x00" in job_id:
            return None
        # Reject any path separators or parent refs outright — a valid UUID has none.
        if "/" in job_id or "\\" in job_id or os.path.sep in job_id:
            return None
        if (os.path.altsep and os.path.altsep in job_id) or job_id in (".", ".."):
            return None
        candidate = os.path.abspath(os.path.join(self.directory, f"{job_id}.json"))
        # Final containment check: candidate must live directly under self.directory.
        if os.path.dirname(candidate) != self.directory:
            return None
        return candidate

    # ── Write ────────────────────────────────────────────────────────────────

    async def save_scan(self, job_id: str, record: dict) -> None:
        """Persist a scan record asynchronously (runs blocking I/O in a thread)."""
        path = self._safe_path(job_id)
        if path is None:
            log.warning("refusing to save scan with unsafe job_id: %r", job_id)
            return
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._write, path, record)

    def _write(self, path: str, record: dict) -> None:
        """
        Atomically write ``record`` as JSON to ``path``.

        Writes to a unique temp file then ``os.replace``s it into place, so a
        crash or concurrent read never sees a half-written or empty file, and
        concurrent writers never clobber each other's temp file. Any OSError
        (disk full, permissions, read-only fs) is swallowed so a failed persist
        never crashes the scan that triggered it.
        """
        # Defense-in-depth: _write is also called directly by JobManager with a
        # pre-built path. Verify it still resolves inside the scans directory.
        resolved = os.path.abspath(path)
        if os.path.dirname(resolved) != self.directory:
            log.warning("refusing to write outside scans dir: %r", path)
            return
        tmp = f"{resolved}.{uuid.uuid4().hex}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(record, fh, default=str, indent=2, ensure_ascii=False)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, resolved)   # atomic replace on POSIX and Windows
        except (OSError, TypeError, ValueError):
            # OSError: disk-full / permissions. TypeError/ValueError: a record
            # field that json cannot serialize even with default=str. Fail soft.
            log.warning("failed to persist scan to %s", resolved, exc_info=True)
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    # ── Read ─────────────────────────────────────────────────────────────────

    async def get_scan(self, job_id: str) -> Optional[dict]:
        """Return a stored scan record, or None if not found."""
        path = self._safe_path(job_id)
        if path is None or not os.path.exists(path):
            return None
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._read, path)

    def _read(self, path: str) -> Optional[dict]:
        try:
            size = os.path.getsize(path)
            if size > _MAX_FILE_BYTES:
                log.warning("scan file too large (%d bytes, max %d): %s", size, _MAX_FILE_BYTES, path)
                return None  # skip oversized files
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            return None

    # ── List ─────────────────────────────────────────────────────────────────

    async def list_scans(self, limit: int = 50) -> list[dict]:
        """Return the most recent `limit` scan summaries (newest first)."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._list, limit)

    def _list(self, limit: int) -> list[dict]:
        if not os.path.exists(self.directory):
            return []
        try:
            entries = os.listdir(self.directory)
        except OSError:
            return []

        # Best-effort cleanup of stale temp files from crashed writes. Only
        # removes .tmp files older than 60 seconds so a concurrent _write's
        # uniquely-named temp file is never unlinked before os.replace.
        now = time.time()
        for f in entries:
            if f.endswith(".tmp"):
                try:
                    tmp_path = os.path.join(self.directory, f)
                    if now - os.path.getmtime(tmp_path) > 60:
                        os.unlink(tmp_path)
                except OSError:
                    pass

        files = [f for f in entries if f.endswith(".json")]

        # Sort newest first by mtime; cap at _MAX_SCAN_FILES before reading.
        # A file may vanish between listdir and getmtime (concurrent delete);
        # treat that as oldest rather than letting the sort crash.
        def _mtime(f: str) -> float:
            try:
                return os.path.getmtime(os.path.join(self.directory, f))
            except OSError:
                return 0.0

        files.sort(key=_mtime, reverse=True)
        files = files[:_MAX_SCAN_FILES]

        results: list[dict] = []
        for fname in files[:limit]:
            path = os.path.join(self.directory, fname)
            record = self._read(path)
            if record is not None:
                results.append(record)
        return results
