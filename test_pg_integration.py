"""
LIVE Postgres integration test — exercises the actual Pg queries end to end.

Skips unless a real database is configured, so it's inert in the default
(no-DB) suite. Run it against a real Postgres to validate the durable-jobs,
per-org-key, and API-key Pg paths that the offline tests can only check
structurally:

    NETLOGIC_DATABASE_URL=postgresql://user:pass@host:5432/db \
        python -m pytest test_pg_integration.py -v

It applies migrations (idempotent), round-trips each Pg store, and cleans up the
rows it creates (unique org slug + UUID job id), so it is safe to run against an
existing database.
"""
import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    not (os.environ.get("NETLOGIC_DATABASE_URL") or "").strip(),
    reason="NETLOGIC_DATABASE_URL not set — live Postgres integration test skipped",
)


@pytest.fixture(scope="module", autouse=True)
def _migrated():
    from api import db
    assert db.is_enabled()
    db.apply_migrations()           # idempotent (schema_migrations guards re-apply)
    yield


@pytest.fixture
def org_slug():
    slug = f"itest-{uuid.uuid4().hex[:12]}"
    yield slug
    # Cleanup: org rows cascade to api_keys / org_ai_settings / scan_jobs(by org).
    from api import db
    with db.connection() as conn:
        conn.execute("DELETE FROM organizations WHERE slug = %s", (slug,))


def test_durable_job_roundtrip(org_slug):
    from api.storage.pg_store import PgScanStore
    store = PgScanStore()
    jid = str(uuid.uuid4())
    rec = {"job_id": jid, "org_id": org_slug, "status": "completed",
           "created_at": 1_700_000_000.0, "config": {"target": "example.com"},
           "events": [{"type": "done"}]}
    try:
        store.save_sync(rec)
        got = store.get_sync(jid)
        assert got is not None and got["job_id"] == jid and got["status"] == "completed"
        assert got["config"]["target"] == "example.com"

        # Update (upsert) reflects new status.
        rec["status"] = "failed"
        store.save_sync(rec)
        assert store.get_sync(jid)["status"] == "failed"

        # Org-scoped listing returns it; cross-org does not.
        assert any(r["job_id"] == jid for r in store.list_sync(limit=50, org_id=org_slug))
        assert all(r["job_id"] != jid for r in store.list_sync(limit=50, org_id="someone-else"))

        assert store.delete_sync(jid) is True
        assert store.get_sync(jid) is None
    finally:
        store.delete_sync(jid)


def test_api_key_store_roundtrip(org_slug):
    from api.auth.api_keys import PgApiKeyStore
    store = PgApiKeyStore()
    key = store.create(org_slug)
    assert store.lookup(key) == org_slug
    assert store.revoke(key) is True
    assert store.lookup(key) is None        # revoked → no longer resolves


def test_org_settings_sealed_roundtrip(org_slug, monkeypatch):
    # Real at-rest encryption: needs a master key; set a throwaway one for the test.
    from cryptography.fernet import Fernet
    monkeypatch.setenv("NETLOGIC_SECRETS_KEY", Fernet.generate_key().decode())
    from api import crypto
    crypto.reset_for_tests()

    from api.settings_store import PgOrgSettingsStore
    store = PgOrgSettingsStore()
    store.put(org_slug, "ai", provider="openai", model="gpt-4o-mini", api_key="sk-live-itest-XYZ")
    rec = store.get(org_slug, "ai")
    assert rec["provider"] == "openai" and rec["api_key"] == "sk-live-itest-XYZ"

    # Verify the key is encrypted AT REST (ciphertext column != plaintext).
    from api import db
    with db.connection() as conn:
        row = conn.execute(
            "SELECT key_ciphertext FROM org_ai_settings s JOIN organizations o ON o.id=s.org_id "
            "WHERE o.slug=%s AND s.role='ai'", (org_slug,)
        ).fetchone()
    assert row and row[0] and b"sk-live-itest-XYZ" not in bytes(row[0])
