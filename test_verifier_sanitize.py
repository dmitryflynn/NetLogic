"""Verifier / re-probe HTTP plans share ToolRuntime sanitizer rails."""
from __future__ import annotations

from src.directors.reprobe import _parse_probe_plans
from src.reasoning.agent.sanitize import sanitize_http_plan
from src.verifier.planner import generate_plans_for_cves
from src.verifier.runner import run_test


def test_sanitize_http_plan_allows_get():
    clean, reason = sanitize_http_plan({
        "method": "GET", "path": "/.env", "port": 8080, "tls": True,
        "headers": {"Accept": "text/plain"},
    })
    assert reason == ""
    assert clean is not None
    assert clean["method"] == "GET"
    assert clean["path"] == "/.env"
    assert clean["port"] == 8080
    assert clean["tls"] is True
    assert "Host" not in (clean["headers"] or {})


def test_sanitize_http_plan_blocks_smuggling_headers():
    for hdr in ("Transfer-Encoding", "Content-Length", "Host"):
        clean, reason = sanitize_http_plan({
            "method": "GET", "path": "/", "headers": {hdr: "chunked"},
        })
        assert clean is None, hdr
        assert "blocked" in reason.lower() or "smuggling" in reason.lower() or "hop" in reason.lower()


def test_sanitize_http_plan_blocks_crlf_path_and_put():
    clean, _ = sanitize_http_plan({
        "method": "GET", "path": "/ HTTP/1.1\r\nHost: evil\r\n\r\nGET /",
    })
    assert clean is None
    clean, reason = sanitize_http_plan({"method": "DELETE", "path": "/users/1"})
    assert clean is None
    assert "method" in reason.lower()


def test_sanitize_http_plan_blocks_destructive_body():
    clean, reason = sanitize_http_plan({
        "method": "POST", "path": "/search", "body": "DROP TABLE users",
    })
    assert clean is None
    assert "destructive" in reason.lower()


def test_sanitize_http_plan_allows_post_on_graphql():
    clean, reason = sanitize_http_plan({
        "method": "POST", "path": "/graphql",
        "body": '{"query":"{ __typename }"}',
        "headers": {"Content-Type": "application/json"},
    })
    assert reason == ""
    assert clean is not None
    assert clean["method"] == "POST"
    assert clean["body"]


def test_run_test_does_not_send_blocked_plan(monkeypatch):
    sent = []

    def boom(*_a, **_k):
        sent.append(1)
        raise AssertionError("must not send")

    monkeypatch.setattr("src.verifier.runner._tcp_send_recv", boom)
    result = run_test({
        "cve_id": "CVE-TEST",
        "method": "GET",
        "path": "/",
        "headers": {"Transfer-Encoding": "chunked", "Content-Length": "5"},
        "port": 80,
    }, "scanme.example")
    assert sent == []
    assert result.success is False
    assert "sanitize failed" in result.error
    assert "not sent" in result.evidence.lower() or "blocked" in result.error.lower()


def test_run_test_sends_sanitized_get(monkeypatch):
    sent = []

    def fake_send(host, port, payload, timeout=5.0, use_tls=False):
        sent.append(payload)
        return b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok", 1.0, ""

    monkeypatch.setattr("src.verifier.runner._tcp_send_recv", fake_send)
    result = run_test({
        "cve_id": "CVE-TEST",
        "method": "GET",
        "path": "/server-status",
        "expected_status": [200],
        "port": 80,
    }, "scanme.example")
    assert len(sent) == 1
    assert b"GET /server-status HTTP/1.0" in sent[0]
    assert b"Transfer-Encoding" not in sent[0]
    assert result.success is True


def test_builtin_smuggling_plans_are_dropped():
    plans = generate_plans_for_cves(
        [{"id": "CVE-2022-22720", "cvss_score": 9.8, "description": "smuggle"}],
        service="http", product="Apache", version="2.4", port=80,
    )
    assert plans == []


def test_builtin_safe_get_plan_survives():
    plans = generate_plans_for_cves(
        [{"id": "CVE-2019-0211", "cvss_score": 8.0, "description": "status"}],
        service="http", product="Apache", version="2.4", port=8080, use_tls=True,
    )
    assert len(plans) == 1
    assert plans[0]["path"] == "/server-status"
    assert plans[0]["method"] == "GET"
    assert plans[0]["port"] == 8080
    assert plans[0]["tls"] is True


def test_reprobe_parser_drops_put_and_keeps_get():
    text = """[
      {"finding_index": 0, "skip": false, "method": "PUT", "path": "/x", "port": 80},
      {"finding_index": 1, "skip": false, "method": "GET", "path": "/login", "port": 443, "tls": true}
    ]"""
    plans = _parse_probe_plans(text)
    assert len(plans) == 1
    assert plans[0]["method"] == "GET"
    assert plans[0]["path"] == "/login"
