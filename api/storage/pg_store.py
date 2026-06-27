"""
NetLogic API — Postgres-backed scan store (durable jobs).

Same role as JsonScanStore but backed by the scan_jobs table, so jobs survive a
restart, are shared across API instances, and are never dropped by the in-memory
500-job cap. Selected by JobManager only when db.is_enabled(); psycopg is
imported lazily inside each method so this module is import-safe without a DB
(mirrors PgApiKeyStore / PgOrgSettingsStore).

The full job dict (ScanJob.to_dict()) is stored in the `record` JSONB column;
org_id / status / target / created_at are denormalized for indexed, org-scoped
queries. Methods are synchronous (psycopg is sync); the async save_scan wrapper
runs the write in a thread so it never blocks the event loop.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

log = logging.getLogger("netlogic.storage.pg")


def _created_at(record: dict) -> float:
    try:
        return float(record.get("created_at") or 0.0)
    except (TypeError, ValueError):
        return 0.0


class PgScanStore:
    """scan_jobs table store. Interface mirrors JsonScanStore plus sync helpers
    JobManager needs (save_sync / get_sync / list_sync / delete_sync / load_recent_sync)."""

    # ── Write ────────────────────────────────────────────────────────────────

    def save_sync(self, record: dict) -> None:
        """Upsert a job record. Fail-soft: a persistence error never crashes the
        scan that triggered it (matches JsonScanStore._write)."""
        job_id = record.get("job_id")
        if not job_id:
            return
        org_id = record.get("org_id") or ""
        status = record.get("status") or "queued"
        target = (record.get("config") or {}).get("target")
        payload = json.dumps(record, default=str)
        # epoch seconds → timestamptz, keeping the record's own created_at.
        created = _created_at(record)
        try:
            from api import db  # noqa: PLC0415
            with db.connection() as conn:
                conn.execute(
                    "INSERT INTO scan_jobs (job_id, org_id, status, target, record, created_at, updated_at) "
                    "VALUES (%s, %s, %s, %s, %s::jsonb, to_timestamp(%s), now()) "
                    "ON CONFLICT (job_id) DO UPDATE SET "
                    "org_id=EXCLUDED.org_id, status=EXCLUDED.status, target=EXCLUDED.target, "
                    "record=EXCLUDED.record, updated_at=now()",
                    (job_id, org_id, status, target, payload, created),
                )
        except Exception:  # noqa: BLE001 — durability is best-effort, never fatal
            log.warning("failed to persist scan job %s to Postgres", job_id, exc_info=True)

    async def save_scan(self, job_id: str, record: dict) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self.save_sync, record)

    # ── Read ─────────────────────────────────────────────────────────────────

    def get_sync(self, job_id: str) -> Optional[dict]:
        try:
            from api import db  # noqa: PLC0415
            with db.connection() as conn:
                row = conn.execute(
                    "SELECT record FROM scan_jobs WHERE job_id = %s", (job_id,)
                ).fetchone()
            return row[0] if row else None      # jsonb → dict (psycopg auto-parses)
        except Exception:  # noqa: BLE001
            log.warning("failed to read scan job %s from Postgres", job_id, exc_info=True)
            return None

    def list_sync(self, limit: int = 50, org_id: str = "") -> list[dict]:
        try:
            from api import db  # noqa: PLC0415
            with db.connection() as conn:
                if org_id:
                    rows = conn.execute(
                        "SELECT record FROM scan_jobs WHERE org_id = %s "
                        "ORDER BY created_at DESC LIMIT %s",
                        (org_id, int(limit)),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT record FROM scan_jobs ORDER BY created_at DESC LIMIT %s",
                        (int(limit),),
                    ).fetchall()
            return [r[0] for r in rows]
        except Exception:  # noqa: BLE001
            log.warning("failed to list scan jobs from Postgres", exc_info=True)
            return []

    def load_recent_sync(self, limit: int = 500) -> list[dict]:
        """Warm the in-memory cache at startup with the most recent jobs. Active
        (queued/running) jobs are always recent, so dispatch/reclaim keep working."""
        return self.list_sync(limit=limit, org_id="")

    # ── Delete ─────────────────────────────────────────────────────────────────

    def delete_sync(self, job_id: str) -> bool:
        try:
            from api import db  # noqa: PLC0415
            with db.connection() as conn:
                cur = conn.execute("DELETE FROM scan_jobs WHERE job_id = %s", (job_id,))
                return cur.rowcount > 0
        except Exception:  # noqa: BLE001
            log.warning("failed to delete scan job %s from Postgres", job_id, exc_info=True)
            return False
