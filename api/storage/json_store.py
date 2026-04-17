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
import os
from typing import Optional

SCANS_DIR: str = os.path.join(os.path.expanduser("~"), ".netlogic", "scans")

# Safety limits — prevent unbounded memory usage when loading scan records.
_MAX_FILE_BYTES: int = 10 * 1024 * 1024   # 10 MB per file
_MAX_SCAN_FILES: int = 500                  # keep only the 500 newest files


class JsonScanStore:
    """Store scan records as individual JSON files on disk."""

    def __init__(self, directory: str = SCANS_DIR) -> None:
        self.directory = directory
        os.makedirs(directory, exist_ok=True)

    # ── Write ────────────────────────────────────────────────────────────────

    async def save_scan(self, job_id: str, record: dict) -> None:
        """Persist a scan record asynchronously (runs blocking I/O in a thread)."""
        path = os.path.join(self.directory, f"{job_id}.json")
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._write, path, record)

    def _write(self, path: str, record: dict) -> None:
        import uuid
        # Use a unique temporary filename to prevent race conditions during concurrent writes
        tmp = f"{path}.{uuid.uuid4()}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(record, fh, default=str, indent=2)
            os.replace(tmp, path)   # atomic on POSIX
        except Exception:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
            raise

    # ── Read ─────────────────────────────────────────────────────────────────

    async def get_scan(self, job_id: str) -> Optional[dict]:
        """Return a stored scan record, or None if not found."""
        path = os.path.join(self.directory, f"{job_id}.json")
        if not os.path.exists(path):
            return None
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._read, path)

    def _read(self, path: str) -> Optional[dict]:
        try:
            size = os.path.getsize(path)
            if size > _MAX_FILE_BYTES:
                return None  # silently skip oversized files
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            return None

    # ── List ─────────────────────────────────────────────────────────────────

    async def list_scans(self, limit: int = 50) -> list[dict]:
        """Return the most recent `limit` scan summaries (newest first)."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._list, limit)

    def _list(self, limit: int) -> list[dict]:
        if not os.path.exists(self.directory):
            return []
        try:
            files = [
                f for f in os.listdir(self.directory)
                if f.endswith(".json") and not f.endswith(".tmp")
            ]
        except OSError:
            return []

        # Sort newest first by mtime; cap at _MAX_SCAN_FILES before reading.
        files.sort(
            key=lambda f: os.path.getmtime(os.path.join(self.directory, f)),
            reverse=True,
        )
        files = files[:_MAX_SCAN_FILES]

        results: list[dict] = []
        for fname in files[:limit]:
            path = os.path.join(self.directory, fname)
            record = self._read(path)
            if record is not None:
                results.append(record)
        return results
