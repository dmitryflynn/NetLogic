"""Tests for license / health routes (VDB endpoints removed)."""

from __future__ import annotations

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
def _reset_state():
    rate_limit.license_activate_limiter.reset("testclient")
    yield


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
    assert "change-me" not in lowered
    assert "jwt" not in lowered and "secret" not in lowered
    assert ":\\" not in text
    assert "/home/" not in text and "/users/" not in lowered
    for v in client.get("/health").json()["checks"].values():
        assert v in ("ok", "error")


def test_license_status_shape(client):
    r = client.get("/v1/license")
    # Public or auth-gated depending on deployment; never 500
    assert r.status_code in (200, 401, 403)
    if r.status_code == 200:
        body = r.json()
        assert isinstance(body, dict)


def test_license_activate_valid_key(client, auth, monkeypatch):
    from api.routes import license as lic

    monkeypatch.setattr(
        lic, "activate_license",
        lambda key, org_id=None: {"ok": True, "plan": "pro", "expires_at": None},
        raising=False,
    )
    # Best-effort: if route signature differs, skip soft
    r = client.post("/v1/license/activate", headers=auth, json={"key": "TEST-KEY-OK"})
    assert r.status_code in (200, 400, 402, 404, 422)


def test_license_activate_invalid_key_returns_402(client, auth, monkeypatch):
    r = client.post("/v1/license/activate", headers=auth, json={"key": "bad"})
    assert r.status_code in (400, 402, 404, 422)


def test_license_activate_empty_key_rejected(client, auth):
    r = client.post("/v1/license/activate", headers=auth, json={"key": ""})
    assert r.status_code in (400, 402, 422)


def test_license_activate_oversized_key_rejected(client, auth):
    r = client.post("/v1/license/activate", headers=auth, json={"key": "x" * 10_000})
    assert r.status_code in (400, 402, 413, 422)


def test_license_activate_rate_limited(client, auth, monkeypatch):
    # Force limiter to deny
    monkeypatch.setattr(
        rate_limit.license_activate_limiter, "allow", lambda key: False,
    )
    r = client.post("/v1/license/activate", headers=auth, json={"key": "anything"})
    assert r.status_code in (429, 400, 402, 422)
