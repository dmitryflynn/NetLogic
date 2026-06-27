"""
NetLogic — Middleware & hardening tests (offline).

Covers:
  • RateLimiter: allow up to limit then block, window reset, thread-safety,
    bounded memory (eviction of stale keys), ban-list eviction.
  • Audit sanitizer: strips injected newlines/control chars, caps length,
    sanitizes the inbound X-Request-ID header.
  • Security headers present on responses.
  • CORS: never reflects arbitrary origins with credentials; fails safe.
  • CSP: API responses get strict default-src 'none' (no unsafe-eval); HTML
    dashboard gets the looser policy.
  • Production secret validation: raises on weak secrets when
    NETLOGIC_ENV=production, no-op in dev.
"""

import importlib
import json
import logging
import os
import threading
import time

import pytest
from starlette.testclient import TestClient

from api.auth.rate_limit import RateLimiter, RateLimitBanList
from api.middleware.audit import audit_log, _sanitize


# ───────────────────────── Rate limiter ──────────────────────────────────────

def test_allows_up_to_limit_then_blocks():
    rl = RateLimiter(max_calls=3, window_seconds=60)
    assert [rl.allow("k") for _ in range(3)] == [True, True, True]
    assert rl.allow("k") is False
    # Still blocked on subsequent calls within the window.
    assert rl.allow("k") is False


def test_window_reset(monkeypatch):
    t = {"now": 1000.0}
    monkeypatch.setattr("api.auth.rate_limit.time.monotonic", lambda: t["now"])
    rl = RateLimiter(max_calls=2, window_seconds=10)
    assert rl.allow("k") and rl.allow("k")
    assert rl.allow("k") is False
    # Advance past the window — old timestamps age out.
    t["now"] += 11
    assert rl.allow("k") is True


def test_per_key_isolation():
    rl = RateLimiter(max_calls=1, window_seconds=60)
    assert rl.allow("a") is True
    assert rl.allow("b") is True   # different key not affected
    assert rl.allow("a") is False


def test_thread_safety_no_overcount():
    # With max_calls=N and many threads, exactly N must be admitted.
    rl = RateLimiter(max_calls=50, window_seconds=60)
    results = []
    lock = threading.Lock()

    def worker():
        r = rl.allow("shared")
        with lock:
            results.append(r)

    threads = [threading.Thread(target=worker) for _ in range(500)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert sum(1 for r in results if r) == 50


def test_memory_bounded_evicts_stale_keys(monkeypatch):
    t = {"now": 0.0}
    monkeypatch.setattr("api.auth.rate_limit.time.monotonic", lambda: t["now"])
    rl = RateLimiter(max_calls=1, window_seconds=10)
    # Touch many distinct keys; each is exhausted immediately.
    for i in range(1000):
        rl.allow(f"key-{i}")
    # Fast-path deletes the just-touched key once its bucket is empty, but a
    # key at limit keeps one timestamp. Advance time and trigger a sweep.
    t["now"] += 1000  # well past sweep interval and window
    rl.allow("trigger")
    # After the sweep, only live keys remain — must not be unbounded.
    assert len(rl._buckets) <= 1


def test_fast_path_does_not_leak_empty_keys():
    rl = RateLimiter(max_calls=5, window_seconds=60)
    # A single allowed call leaves a non-empty bucket (1 timestamp).
    rl.allow("x")
    assert "x" in rl._buckets
    # reset removes it
    rl.reset("x")
    assert "x" not in rl._buckets


def test_ban_list_evicts_expired(monkeypatch):
    t = {"now": 0.0}
    monkeypatch.setattr("api.auth.rate_limit.time.monotonic", lambda: t["now"])
    bl = RateLimitBanList()
    for i in range(100):
        bl.add_ban(f"ip-{i}", duration_hours=1)
    assert len(bl._banned_ips) == 100
    # Advance past expiry, add one more — expired entries get swept.
    t["now"] += 2 * 3600
    bl.add_ban("ip-new", duration_hours=1)
    assert len(bl._banned_ips) == 1
    assert bl.check_ban("ip-0") is False


# ───────────────────────── Audit sanitizer ───────────────────────────────────

def test_sanitize_strips_newlines_and_control_chars():
    dirty = "ok\nFORGED event=auth_success\r\x00\x07tail"
    clean = _sanitize(dirty)
    assert "\n" not in clean and "\r" not in clean
    assert "\x00" not in clean and "\x07" not in clean
    assert "FORGED" in clean  # text kept, only control chars removed


def test_sanitize_keeps_tab_and_nests():
    assert _sanitize("a\tb") == "a\tb"
    assert _sanitize({"k\n": ["v\r1", "v2"]}) == {"k": ["v1", "v2"]}


def test_sanitize_truncates_long_values():
    out = _sanitize("A" * 5000)
    assert len(out) < 5000 and out.endswith("...[truncated]")


def test_audit_log_emits_single_line_no_injection(caplog):
    with caplog.at_level(logging.INFO, logger="netlogic.audit"):
        audit_log("job_created", target="evil\ninjected=1", org_id="o1")
    rec = [r for r in caplog.records if r.name == "netlogic.audit"]
    assert rec, "expected an audit record"
    msg = rec[-1].getMessage()
    assert "\n" not in msg          # exactly one log line
    parsed = json.loads(msg)        # valid single JSON object
    assert parsed["event"] == "job_created"
    assert "\n" not in parsed["target"]


# ───────────────────────── App-level (TestClient) ────────────────────────────

@pytest.fixture(scope="module")
def client():
    # Ensure dev mode so lifespan secret validation is a no-op.
    os.environ.pop("NETLOGIC_ENV", None)
    import api.main as main
    importlib.reload(main)
    app = main.create_app()
    with TestClient(app) as c:
        yield c


def test_security_headers_present(client):
    r = client.get("/health")
    h = r.headers
    assert h.get("X-Content-Type-Options") == "nosniff"
    assert h.get("X-Frame-Options") == "DENY"
    assert "Referrer-Policy" in h
    assert "Content-Security-Policy" in h
    assert "X-Request-ID" in h
    # HSTS forces HTTPS for enterprise deployments.
    assert "max-age=" in h.get("Strict-Transport-Security", "")


def test_api_csp_is_strict_no_unsafe_eval(client):
    r = client.get("/health")
    csp = r.headers.get("Content-Security-Policy", "")
    # JSON API response: locked down, must NOT permit script execution.
    assert csp == "default-src 'none'"
    assert "unsafe-eval" not in csp


def test_request_id_header_injection_sanitized(client):
    r = client.get("/health", headers={"X-Request-ID": "abc\r\nSet-Cookie: x=1"})
    rid = r.headers.get("X-Request-ID", "")
    assert "\r" not in rid and "\n" not in rid


def test_cors_does_not_reflect_arbitrary_origin_without_config(client):
    # No NETLOGIC_CORS_ORIGINS set in this fixture -> CORS disabled, must not
    # echo the attacker origin nor allow credentials.
    r = client.get("/health", headers={"Origin": "https://evil.example"})
    acao = r.headers.get("access-control-allow-origin")
    assert acao != "https://evil.example"
    assert acao != "*"
    assert r.headers.get("access-control-allow-credentials") != "true"


def test_cors_never_wildcard_with_credentials(monkeypatch):
    monkeypatch.setenv("NETLOGIC_CORS_ORIGINS", "https://app.example.com")
    monkeypatch.delenv("NETLOGIC_ENV", raising=False)
    import api.main as main
    importlib.reload(main)
    app = main.create_app()
    with TestClient(app) as c:
        r = c.get(
            "/health",
            headers={"Origin": "https://app.example.com"},
        )
        acao = r.headers.get("access-control-allow-origin")
        # Allowed origin is reflected specifically, never "*".
        assert acao == "https://app.example.com"
        assert acao != "*"
        # An un-listed origin must not be reflected.
        r2 = c.get("/health", headers={"Origin": "https://evil.example"})
        assert r2.headers.get("access-control-allow-origin") not in (
            "https://evil.example", "*",
        )
    importlib.reload(main)


# ───────────────────────── Production secret validation ──────────────────────

def test_prod_secret_validation_raises_on_weak(monkeypatch):
    monkeypatch.setenv("NETLOGIC_ENV", "production")
    # Force weak/default secrets.
    monkeypatch.setenv("NETLOGIC_JWT_SECRET", "")
    monkeypatch.setenv("NETLOGIC_ADMIN_KEY", "")
    import api.main as main
    importlib.reload(main)
    app = main.create_app()
    with pytest.raises(RuntimeError):
        with TestClient(app):
            pass
    monkeypatch.delenv("NETLOGIC_ENV", raising=False)
    importlib.reload(main)


def test_dev_mode_no_secret_validation(monkeypatch):
    monkeypatch.delenv("NETLOGIC_ENV", raising=False)
    monkeypatch.setenv("NETLOGIC_JWT_SECRET", "")
    monkeypatch.setenv("NETLOGIC_ADMIN_KEY", "")
    import api.main as main
    importlib.reload(main)
    app = main.create_app()
    # Must boot fine in dev despite weak secrets.
    with TestClient(app) as c:
        assert c.get("/health").status_code == 200
    importlib.reload(main)
