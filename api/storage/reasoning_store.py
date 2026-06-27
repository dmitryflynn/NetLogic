"""
NetLogic API — reasoning-state store (Phase 1).

Persists the per-scan ReasoningState built by src/reasoning. Mirrors the established
dual-store pattern (PgScanStore / PgOrgSettingsStore): a Postgres backend when
db.is_enabled(), an in-memory fallback otherwise. psycopg is imported lazily so this module
is import-safe without a DB. All writes are best-effort and fail-soft — persistence never
crashes the scan that produced the state.

The full ReasoningState.to_dict() is stored in the `state` JSONB column; job_id / org_id /
target / schema_version are denormalized for indexed, org-scoped lookup and change detection.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Optional

log = logging.getLogger("netlogic.storage.reasoning")


class InMemoryReasoningStore:
    """Process-local fallback (desktop / dev / tests)."""

    def __init__(self) -> None:
        self._by_job: dict[str, dict] = {}
        self._order: list[str] = []   # insertion order for latest_for_target

    def persist(self, job_id: str, org_id: str, target: str, state: dict) -> None:
        if not job_id:
            return
        self._by_job[job_id] = {"org_id": org_id or "", "target": target or "",
                                "schema_version": int(state.get("schema_version", 1)),
                                "state": state, "created_at": time.time()}
        self._order.append(job_id)

    def get(self, job_id: str) -> Optional[dict]:
        rec = self._by_job.get(job_id)
        return rec["state"] if rec else None

    def latest_for_target(self, org_id: str, target: str) -> Optional[dict]:
        for job_id in reversed(self._order):
            rec = self._by_job.get(job_id)
            if rec and rec["org_id"] == (org_id or "") and rec["target"] == target:
                return rec["state"]
        return None


class PgReasoningStore:
    """reasoning_state table store. Same interface as the in-memory store."""

    def persist(self, job_id: str, org_id: str, target: str, state: dict) -> None:
        if not job_id:
            return
        payload = json.dumps(state, default=str)
        schema_version = int(state.get("schema_version", 1))
        try:
            from api import db  # noqa: PLC0415
            with db.connection() as conn:
                conn.execute(
                    "INSERT INTO reasoning_state (job_id, org_id, target, schema_version, state, created_at, updated_at) "
                    "VALUES (%s, %s, %s, %s, %s::jsonb, now(), now()) "
                    "ON CONFLICT (job_id) DO UPDATE SET "
                    "org_id=EXCLUDED.org_id, target=EXCLUDED.target, "
                    "schema_version=EXCLUDED.schema_version, state=EXCLUDED.state, updated_at=now()",
                    (job_id, org_id or "", target, schema_version, payload),
                )
        except Exception:  # noqa: BLE001 — durability is best-effort, never fatal
            log.warning("failed to persist reasoning state for job %s", job_id, exc_info=True)

    def get(self, job_id: str) -> Optional[dict]:
        try:
            from api import db  # noqa: PLC0415
            with db.connection() as conn:
                row = conn.execute(
                    "SELECT state FROM reasoning_state WHERE job_id = %s", (job_id,)
                ).fetchone()
            return row[0] if row else None
        except Exception:  # noqa: BLE001
            log.warning("failed to load reasoning state for job %s", job_id, exc_info=True)
            return None

    def latest_for_target(self, org_id: str, target: str) -> Optional[dict]:
        try:
            from api import db  # noqa: PLC0415
            with db.connection() as conn:
                row = conn.execute(
                    "SELECT state FROM reasoning_state WHERE org_id = %s AND target = %s "
                    "ORDER BY created_at DESC LIMIT 1", (org_id or "", target)
                ).fetchone()
            return row[0] if row else None
        except Exception:  # noqa: BLE001
            return None


def _build_store():
    try:
        from api import db  # noqa: PLC0415
        if db.is_enabled():
            return PgReasoningStore()
    except Exception:  # noqa: BLE001
        pass
    return InMemoryReasoningStore()


reasoning_store = _build_store()


def persist_from_art(job_id: str, org_id: str, target: str, art: dict) -> None:
    """Persist the reasoning state attached to an artifacts dict, fail-soft.

    `run_scan` attaches `art["reasoning"]` (ReasoningState.to_dict()); the job layer calls
    this once it knows the job_id/org_id. A no-op if no reasoning state was built.
    """
    state = (art or {}).get("reasoning")
    if not state:
        return
    try:
        reasoning_store.persist(job_id, org_id, target, state)
    except Exception:  # noqa: BLE001
        log.warning("reasoning persistence skipped for job %s", job_id, exc_info=True)
