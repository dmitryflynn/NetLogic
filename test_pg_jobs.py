"""
Durable Postgres job store — offline tests (no live DB, mirrors test_db.py).

A live Postgres exercises the actual queries; here we verify:
  • JobManager selects the Postgres backend when NETLOGIC_DATABASE_URL is set,
  • it stays on the JSON backend otherwise (desktop default unchanged),
  • the store + manager are import-safe and fail soft when psycopg is absent
    (so a misconfigured/unreachable DB degrades, never crashes a scan),
  • the 0003 migration SQL parses into executable statements.
  • user DELETE reaches Postgres even after the job has been cache-evicted
    (get/list serve history from the DB without rehydrating `_jobs`).
"""
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

from api.jobs.manager import JobManager, ScanJob
from api.models.scan_request import ScanRequest
from api.storage.pg_store import PgScanStore


# ── Backend selection ───────────────────────────────────────────────────────────

def test_manager_uses_json_backend_without_db(monkeypatch):
    monkeypatch.delenv("NETLOGIC_DATABASE_URL", raising=False)
    from api.jobs.manager import JobManager
    m = JobManager()
    assert m._pg is False and m._pg_store is None


def test_manager_selects_postgres_when_enabled(monkeypatch):
    monkeypatch.setenv("NETLOGIC_DATABASE_URL", "postgresql://u:p@localhost:5432/x")
    from api.jobs.manager import JobManager
    m = JobManager()                       # builds even with psycopg absent (fail-soft load)
    assert m._pg is True
    assert isinstance(m._pg_store, PgScanStore)


# ── Fail-soft when psycopg / DB is unavailable ──────────────────────────────────

def test_store_methods_fail_soft_without_psycopg(monkeypatch):
    monkeypatch.setenv("NETLOGIC_DATABASE_URL", "postgresql://u:p@localhost:5432/x")
    s = PgScanStore()
    # No psycopg installed here → every method degrades to a safe default, no raise.
    assert s.get_sync("00000000-0000-0000-0000-000000000000") is None
    assert s.list_sync(limit=10) == []
    assert s.load_recent_sync(10) == []
    assert s.delete_sync("00000000-0000-0000-0000-000000000000") is False
    s.save_sync({"job_id": "x", "org_id": "o", "status": "queued", "config": {"target": "h"}})  # no raise


def test_save_sync_ignores_record_without_job_id():
    PgScanStore().save_sync({"status": "queued"})   # no job_id → no-op, no raise


# ── Migration parses ────────────────────────────────────────────────────────────

def test_scan_jobs_migration_parses():
    from api.db import _split_sql
    sql = (Path(__file__).parent / "db" / "migrations" / "0003_scan_jobs.sql").read_text(encoding="utf-8")
    stmts = _split_sql(sql)
    assert any("CREATE TABLE scan_jobs" in s for s in stmts)
    assert any("scan_jobs_org_created_idx" in s for s in stmts)


# ── User delete vs cache-evicted Postgres history ──────────────────────────────


class _FakePgStore:
    """In-memory stand-in for PgScanStore so delete/get paths can be asserted
    without a live database."""

    def __init__(self):
        self.records: dict[str, dict] = {}
        self.delete_calls: list[str] = []

    def get_sync(self, job_id: str):
        rec = self.records.get(job_id)
        return dict(rec) if rec is not None else None

    def list_sync(self, limit: int = 50, org_id: str = ""):
        rows = list(self.records.values())
        if org_id:
            rows = [r for r in rows if r.get("org_id") == org_id]
        rows.sort(key=lambda r: r.get("created_at") or 0, reverse=True)
        return [dict(r) for r in rows[:limit]]

    def load_recent_sync(self, limit: int = 500):
        return self.list_sync(limit=limit)

    def delete_sync(self, job_id: str) -> bool:
        self.delete_calls.append(job_id)
        return self.records.pop(job_id, None) is not None

    def save_sync(self, record: dict) -> None:
        jid = record.get("job_id")
        if jid:
            self.records[jid] = dict(record)


def _pg_manager(store: _FakePgStore) -> JobManager:
    m = JobManager.__new__(JobManager)
    m._jobs = {}
    m._lock = threading.RLock()
    m._pg = True
    m._pg_store = store
    m.store = MagicMock()
    return m


def _completed_job(job_id: str = "job-evicted", org_id: str = "org-a") -> ScanJob:
    job = ScanJob(
        job_id=job_id,
        config=ScanRequest(target="scanme.example.com"),
        org_id=org_id,
        status="completed",
        created_at=time.time() - 13 * 3600,
        completed_at=time.time() - 100,
    )
    return job


def test_delete_cache_evicted_job_removes_postgres_row():
    """SaaS history lives in Postgres after RAM eviction. DELETE must still
    remove the durable row — otherwise the API returns 204 and the scan
    reappears on the next list/get."""
    store = _FakePgStore()
    mgr = _pg_manager(store)
    job = _completed_job()
    store.save_sync(job.to_dict())
    # Simulate TTL/capacity eviction: gone from RAM, row still in PG.
    assert job.job_id not in mgr._jobs

    assert mgr.get(job.job_id, org_id=job.org_id) is not None
    assert mgr.delete(job.job_id) is True
    assert store.delete_calls == [job.job_id]
    assert store.get_sync(job.job_id) is None
    assert mgr.get(job.job_id, org_id=job.org_id) is None


def test_delete_missing_postgres_job_returns_false():
    store = _FakePgStore()
    mgr = _pg_manager(store)
    assert mgr.delete("no-such-job") is False
    assert store.delete_calls == ["no-such-job"]


def test_evict_only_does_not_delete_postgres_row():
    store = _FakePgStore()
    mgr = _pg_manager(store)
    job = _completed_job("job-cached")
    store.save_sync(job.to_dict())
    mgr._jobs[job.job_id] = job

    assert mgr.delete(job.job_id, _evict_only=True) is True
    assert job.job_id not in mgr._jobs
    assert store.delete_calls == []
    assert store.get_sync(job.job_id) is not None
