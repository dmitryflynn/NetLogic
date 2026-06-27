"""Tests for the opt-in Postgres layer (api/db.py + provisioning + key store).

These run WITHOUT a database: they verify the layer is inert when
NETLOGIC_DATABASE_URL is unset, that the right store/impl is selected by the flag,
and that the migration SQL parses into statements (validating the runner offline).
A live Postgres is required only to exercise the actual queries.
"""

from pathlib import Path

from api import db
from api.auth import api_keys, provisioning


def test_db_disabled_by_default(monkeypatch):
    monkeypatch.delenv("NETLOGIC_DATABASE_URL", raising=False)
    assert db.is_enabled() is False
    assert db.apply_migrations() == []   # no-op, never imports psycopg


def test_db_enabled_flag(monkeypatch):
    monkeypatch.setenv("NETLOGIC_DATABASE_URL", "postgresql://u:p@localhost:5432/x")
    assert db.is_enabled() is True


def test_provisioning_noop_when_disabled(monkeypatch):
    monkeypatch.delenv("NETLOGIC_DATABASE_URL", raising=False)
    assert provisioning.provision_user_and_org({"sub": "user_1", "org_id": "org_9"}) is None


def test_api_key_store_in_memory_without_db(monkeypatch):
    # The process singleton was built at import time (no DB) → in-memory.
    assert isinstance(api_keys.api_key_store, api_keys.ApiKeyStore)
    monkeypatch.delenv("NETLOGIC_DATABASE_URL", raising=False)
    assert isinstance(api_keys._build_api_key_store(), api_keys.ApiKeyStore)


def test_api_key_store_selects_postgres_when_enabled(monkeypatch):
    monkeypatch.setenv("NETLOGIC_DATABASE_URL", "postgresql://u:p@localhost:5432/x")
    store = api_keys._build_api_key_store()
    assert isinstance(store, api_keys.PgApiKeyStore)   # built without touching psycopg


def test_migration_sql_parses_into_statements():
    sql = (Path(__file__).parent / "db" / "migrations" / "0001_init_auth.sql").read_text(encoding="utf-8")
    stmts = db._split_sql(sql)
    assert len(stmts) >= 8
    assert all(s.upper() not in ("BEGIN", "COMMIT") for s in stmts)
    joined = " ".join(stmts).lower()
    for table in ("organizations", "users", "org_memberships", "api_keys",
                  "audit_log", "revoked_tokens"):
        assert f"create table {table}" in joined
