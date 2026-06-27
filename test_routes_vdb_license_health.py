"""
Offline tests for the VDB / license / health route section.

These exercise auth, rate limiting, response-shape contracts, error handling,
and the concurrent-sync guard WITHOUT performing any real NVD sync or network
I/O — the expensive sync/engine/connectivity helpers are monkeypatched.
"""

from __future__ import annotations

import threading

import pytest
from fastapi.testclient import TestClient

from api.main import create_app
from api.auth.jwt_handler import create_token
from api.auth import rate_limit


@pytest.fixture()
def client() -> TestClient:
    return TestClient(create_app())


@pytest.fixture()
def token() -> str:
    return create_token(org_id="org-test", sub="api-key-test")


@pytest.fixture()
def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def _reset_state(monkeypatch):
    """Reset the per-org/IP rate-limit buckets and the VDB sync flag each test."""
    from api.routes import vdb as vdb_route

    rate_limit.vdb_query_limiter.reset("org-test")
    rate_limit.vdb_query_limiter.reset("org-other")
    rate_limit.license_activate_limiter.reset("testclient")
    with vdb_route._sync_lock:
        vdb_route._sync_state.update(running=False, last_result=None, last_error=None)
    yield
    with vdb_route._sync_lock:
        vdb_route._sync_state.update(running=False, last_result=None, last_error=None)


# ──────────────────────────────── HEALTH ────────────────────────────────


def test_health_public_no_auth(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] in ("ok", "degraded")
    assert "uptime_s" in body and "checks" in body


def test_health_leaks_nothing_sensitive(client):
    """Public health must not expose secrets, paths, or config posture detail."""
    text = client.get("/health").text
    lowered = text.lower()
    # No secret material or default-secret hint.
    assert "change-me" not in lowered
    assert "jwt" not in lowered and "secret" not in lowered
    # No absolute filesystem paths leaked via storage-check exception text.
    assert ":\\" not in text  # Windows drive path
    assert "/home/" not in text and "/users/" not in lowered
    # Check values are coarse ok/error only.
    for v in client.get("/health").json()["checks"].values():
        assert v in ("ok", "error")


# ──────────────────────────────── VDB AUTH ──────────────────────────────


def test_vdb_status_requires_auth(client):
    assert client.get("/v1/vdb/status").status_code == 401


def test_vdb_sync_requires_auth(client):
    assert client.post("/v1/vdb/sync").status_code == 401


def test_vdb_status_flat_shape_for_dashboard(client, auth, monkeypatch):
    """Dashboard VdbStatus reads entries/size_kb/cache_dir/nvd_available/synced flat."""
    import src.nvd_lookup as nvd
    import src.vdb_engine as engine

    monkeypatch.setattr(
        nvd, "cache_stats",
        lambda: {"entries": 42, "size_kb": 12.5, "cache_dir": "/tmp/cache"},
    )
    monkeypatch.setattr(nvd, "nvd_is_available", lambda: True)
    monkeypatch.setattr(engine.vdb_engine, "get_stats", lambda: {"vulnerabilities": 9})

    r = client.get("/v1/vdb/status", headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert body["entries"] == 42
    assert body["size_kb"] == 12.5
    assert body["cache_dir"] == "/tmp/cache"
    assert body["nvd_available"] is True
    assert body["synced"] is True
    # Richer detail still attached.
    assert body["offline_vdb"] == {"vulnerabilities": 9}


def test_vdb_status_handles_cache_failure_cleanly(client, auth, monkeypatch):
    """A None/partial cache_stats must not 500; flat defaults fill in."""
    import src.nvd_lookup as nvd
    import src.vdb_engine as engine

    monkeypatch.setattr(nvd, "cache_stats", lambda: None)
    monkeypatch.setattr(nvd, "nvd_is_available", lambda: False)
    monkeypatch.setattr(engine.vdb_engine, "get_stats", lambda: {})

    r = client.get("/v1/vdb/status", headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert body["entries"] == 0
    assert body["size_kb"] == 0.0
    assert body["cache_dir"] == ""


# ─────────────────────────────── VDB SYNC ───────────────────────────────


def test_vdb_sync_starts_in_background(client, auth, monkeypatch):
    import src.nvd_lookup as nvd
    import src.vdb_syncer as syncer

    monkeypatch.setattr(nvd, "clear_cache", lambda: None)
    # Block the worker so we can observe the running state deterministically.
    started = threading.Event()
    release = threading.Event()

    def fake_sync(limit=0):
        started.set()
        release.wait(timeout=5)
        return {"synced": True}

    monkeypatch.setattr(syncer, "run_vdb_sync", fake_sync)

    r = client.post("/v1/vdb/sync", headers=auth)
    assert r.status_code == 200
    assert r.json()["status"] == "sync_started"
    assert started.wait(timeout=5)

    # Concurrent guard: a second call while running must report already_running,
    # NOT kick off a second crawl.
    r2 = client.post("/v1/vdb/sync", headers=auth)
    assert r2.json()["status"] == "already_running"

    release.set()


def test_vdb_sync_failure_to_start_is_clean_not_500(client, auth, monkeypatch):
    """clear_cache blowing up must return a clean 503 AND release the flag."""
    import src.nvd_lookup as nvd
    from api.routes import vdb as vdb_route

    def boom():
        raise RuntimeError("disk gone")

    monkeypatch.setattr(nvd, "clear_cache", boom)

    r = client.post("/v1/vdb/sync", headers=auth)
    assert r.status_code == 503
    assert "stack" not in r.text.lower() and "traceback" not in r.text.lower()
    # Flag must be released so future syncs aren't permanently blocked.
    with vdb_route._sync_lock:
        assert vdb_route._sync_state["running"] is False


def test_vdb_sync_rejects_bad_limit(client, auth, monkeypatch):
    import src.nvd_lookup as nvd
    monkeypatch.setattr(nvd, "clear_cache", lambda: None)
    assert client.post("/v1/vdb/sync?limit=-5", headers=auth).status_code == 422
    assert client.post("/v1/vdb/sync?limit=999999999", headers=auth).status_code == 422


def test_vdb_endpoints_are_rate_limited(client, auth, monkeypatch):
    import src.nvd_lookup as nvd
    import src.vdb_engine as engine

    monkeypatch.setattr(nvd, "cache_stats", lambda: {"entries": 0, "size_kb": 0.0, "cache_dir": ""})
    monkeypatch.setattr(nvd, "nvd_is_available", lambda: False)
    monkeypatch.setattr(engine.vdb_engine, "get_stats", lambda: {})

    # vdb_query_limiter allows 30/min per org; the 31st should 429.
    statuses = [client.get("/v1/vdb/status", headers=auth).status_code for _ in range(31)]
    assert statuses.count(200) == 30
    assert statuses[-1] == 429


def test_vdb_rate_limit_is_per_org(client, monkeypatch):
    """Exhausting one org's bucket must not affect another org."""
    import src.nvd_lookup as nvd
    import src.vdb_engine as engine

    monkeypatch.setattr(nvd, "cache_stats", lambda: {"entries": 0, "size_kb": 0.0, "cache_dir": ""})
    monkeypatch.setattr(nvd, "nvd_is_available", lambda: False)
    monkeypatch.setattr(engine.vdb_engine, "get_stats", lambda: {})

    auth_a = {"Authorization": f"Bearer {create_token(org_id='org-test', sub='a')}"}
    auth_b = {"Authorization": f"Bearer {create_token(org_id='org-other', sub='b')}"}

    for _ in range(30):
        client.get("/v1/vdb/status", headers=auth_a)
    assert client.get("/v1/vdb/status", headers=auth_a).status_code == 429
    # Different org still served.
    assert client.get("/v1/vdb/status", headers=auth_b).status_code == 200


# ──────────────────────────────── LICENSE ───────────────────────────────


def test_license_status_shape(client):
    r = client.get("/v1/license")
    assert r.status_code == 200
    body = r.json()
    assert "licensed" in body and "plan" in body


def test_license_activate_valid_key(client, monkeypatch):
    monkeypatch.setenv("NETLOGIC_VALID_LICENSES", "")
    r = client.post("/v1/license/activate", json={"key": "NL-VALIDKEY12345"})
    assert r.status_code == 200
    body = r.json()
    assert body["licensed"] is True
    assert body["plan"] == "pro"


def test_license_activate_invalid_key_returns_402(client):
    r = client.post("/v1/license/activate", json={"key": "garbage-not-valid"})
    assert r.status_code == 402
    assert "traceback" not in r.text.lower()


def test_license_activate_empty_key_rejected(client):
    # Pydantic min_length rejects "" at validation → 422.
    assert client.post("/v1/license/activate", json={"key": ""}).status_code == 422
    # Whitespace-only passes min_length but is rejected after strip → 422.
    assert client.post("/v1/license/activate", json={"key": "   "}).status_code == 422


def test_license_activate_oversized_key_rejected(client):
    huge = "NL-" + "A" * 10_000
    assert client.post("/v1/license/activate", json={"key": huge}).status_code == 422


def test_license_activate_rate_limited(client):
    # license_activate_limiter allows 3/hour per IP; 4th attempt → 429.
    codes = [
        client.post("/v1/license/activate", json={"key": "garbage"}).status_code
        for _ in range(4)
    ]
    assert codes[-1] == 429
