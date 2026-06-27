"""
Durable Postgres job store — offline tests (no live DB, mirrors test_db.py).

A live Postgres exercises the actual queries; here we verify:
  • JobManager selects the Postgres backend when NETLOGIC_DATABASE_URL is set,
  • it stays on the JSON backend otherwise (desktop default unchanged),
  • the store + manager are import-safe and fail soft when psycopg is absent
    (so a misconfigured/unreachable DB degrades, never crashes a scan),
  • the 0003 migration SQL parses into executable statements.
"""
import threading
from pathlib import Path

import pytest

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
