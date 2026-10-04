"""Verifier / re-probe HTTP plans share ToolRuntime sanitizer rails."""
from __future__ import annotations

import json

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


def test_cve_2024_38476_not_confirmed_from_apache_htaccess_403(monkeypatch):
    """CVE-2024-38476 is substitution encoding, not a forbidden .htaccess.

    The old builtin sent GET /.htaccess and treated HTTP 403 plus the
    substring 'htaccess' as confirmation. Apache 2.4.6 / 2.4.29 default
    403 pages echo the URI ('access /.htaccess on this server'). Shared
    hosts also emit 'unable to read htaccess file'. Fusion then pinned
    the CRITICAL.
    """
    classic_403 = (
        b"HTTP/1.0 403 Forbidden\r\nContent-Type: text/html\r\n\r\n"
        b"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
        b"<html><head>\n<title>403 Forbidden</title>\n</head><body>\n"
        b"<h1>Forbidden</h1>\n"
        b"<p>You don't have permission to access /.htaccess\n"
        b"on this server.</p>\n"
        b"</body></html>\n"
    )
    hosting_403 = (
        b"HTTP/1.0 403 Forbidden\r\nContent-Type: text/html\r\n\r\n"
        b"<h1>Forbidden</h1>"
        b"<p>You don't have permission to access this resource."
        b"Server unable to read htaccess file, denying access to be safe</p>"
    )

    def reinvent(_system, _user):
        return json.dumps({
            "cve_id": "CVE-2024-38476",
            "testable": True,
            "method": "GET",
            "path": "/.htaccess",
            "expected_status": [200, 403],
            "expected_body_patterns": ["htaccess"],
            "port": 80,
            "tls": False,
        })

    plans = generate_plans_for_cves(
        [{"id": "CVE-2024-38476", "cvss_score": 8.1,
          "description": "Apache HTTP Server substitution encoding issue"}],
        service="http", product="Apache", version="2.4.29", port=80,
        complete=reinvent,
    )
    assert plans == []

    from src.verifier.planner import reverify_with_context
    assert reverify_with_context(
        ["CVE-2024-38476"], [],
        complete=lambda _s, _u: json.dumps([{
            "cve_id": "CVE-2024-38476", "method": "GET",
            "path": "/.htaccess",
            "expected_status": [403],
            "expected_body_patterns": ["htaccess"], "port": 80,
        }]),
    ) == []

    def fake_classic(host, port, payload, timeout=5.0, use_tls=False):
        return classic_403, 1.0, ""

    monkeypatch.setattr("src.verifier.runner._tcp_send_recv", fake_classic)
    leaked = run_test({
        "cve_id": "CVE-2024-38476",
        "method": "GET",
        "path": "/.htaccess",
        "expected_status": [200, 403],
        "expected_body_patterns": ["htaccess"],
        "port": 80,
    }, "scanme.example")
    assert leaked.success is True
    assert leaked.status_code == 403

    def fake_hosting(host, port, payload, timeout=5.0, use_tls=False):
        return hosting_403, 1.0, ""

    monkeypatch.setattr("src.verifier.runner._tcp_send_recv", fake_hosting)
    leaked_hosting = run_test({
        "cve_id": "CVE-2024-38476",
        "method": "GET",
        "path": "/.htaccess",
        "expected_status": [200, 403],
        "expected_body_patterns": ["htaccess"],
        "port": 80,
    }, "scanme.example")
    assert leaked_hosting.success is True


def test_cve_2024_38477_not_confirmed_from_apache_htpasswd_403(monkeypatch):
    """CVE-2024-38477 is a mod_proxy NULL deref, not a forbidden .htpasswd."""
    classic_403 = (
        b"HTTP/1.0 403 Forbidden\r\nContent-Type: text/html\r\n\r\n"
        b"<h1>Forbidden</h1>\n"
        b"<p>You don't have permission to access /.htpasswd\n"
        b"on this server.</p>\n"
    )

    def reinvent(_system, _user):
        return json.dumps({
            "cve_id": "CVE-2024-38477",
            "testable": True,
            "method": "GET",
            "path": "/.htpasswd",
            "expected_status": [200, 403],
            "expected_body_patterns": ["htpasswd"],
            "port": 80,
        })

    plans = generate_plans_for_cves(
        [{"id": "CVE-2024-38477", "cvss_score": 7.5,
          "description": "Apache HTTP Server crash in mod_proxy"}],
        service="http", product="Apache", version="2.4.29", port=80,
        complete=reinvent,
    )
    assert plans == []

    from src.verifier.planner import reverify_with_context
    assert reverify_with_context(
        ["CVE-2024-38477"], [],
        complete=lambda _s, _u: json.dumps([{
            "cve_id": "CVE-2024-38477", "method": "GET",
            "path": "/.htpasswd",
            "expected_status": [403],
            "expected_body_patterns": ["htpasswd"], "port": 80,
        }]),
    ) == []

    def fake_send(host, port, payload, timeout=5.0, use_tls=False):
        return classic_403, 1.0, ""

    monkeypatch.setattr("src.verifier.runner._tcp_send_recv", fake_send)
    leaked = run_test({
        "cve_id": "CVE-2024-38477",
        "method": "GET",
        "path": "/.htpasswd",
        "expected_status": [200, 403],
        "expected_body_patterns": ["htpasswd"],
        "port": 80,
    }, "scanme.example")
    assert leaked.success is True
    assert leaked.status_code == 403


def test_parse_http_response_accepts_lf_only():
    from src.verifier.runner import _parse_http_response

    status, headers, body = _parse_http_response(
        b"HTTP/1.0 200 OK\nServer: nginx\nContent-Type: text/plain\n\nhello"
    )
    assert status == 200
    assert headers.get("server") == "nginx"
    assert body == "hello"


def test_build_http_request_strips_crlf_from_host():
    from src.verifier.runner import _build_http_request

    payload = _build_http_request("GET", "/", "ex.com\r\nX-Injected: 1", {"Accept": "text/plain"})
    assert b"X-Injected" not in payload
    assert b"Host: ex.com" in payload
    assert b"\r\nHost:" in payload


def test_reverify_drops_smuggling_plans():
    from src.verifier.planner import reverify_with_context

    plans = reverify_with_context(
        ["CVE-TEST"],
        [],
        complete=lambda _s, _u: json.dumps([{
            "cve_id": "CVE-TEST",
            "method": "GET",
            "path": "/",
            "headers": {"Transfer-Encoding": "chunked"},
            "port": 80,
        }]),
    )
    assert plans == []


def test_builtin_mod_lua_post_root_is_dropped():
    """POST / is not on the proof allowlist; sanitizer must fail closed."""
    plans = generate_plans_for_cves(
        [{"id": "CVE-2021-44790", "cvss_score": 9.8, "description": "mod_lua"}],
        service="http", product="Apache", version="2.4", port=80,
    )
    assert plans == []


def test_reprobe_parser_drops_put_and_keeps_get():
    text = """[
      {"finding_index": 0, "skip": false, "method": "PUT", "path": "/x", "port": 80},
      {"finding_index": 1, "skip": false, "method": "GET", "path": "/login", "port": 443, "tls": true}
    ]"""
    plans = _parse_probe_plans(text)
    assert len(plans) == 1
    assert plans[0]["method"] == "GET"
    assert plans[0]["path"] == "/login"


def test_run_test_empty_expected_status_does_not_confirm(monkeypatch):
    def fake_send(host, port, payload, timeout=5.0, use_tls=False):
        return b"HTTP/1.0 200 OK\r\n\r\nok", 1.0, ""

    monkeypatch.setattr("src.verifier.runner._tcp_send_recv", fake_send)
    result = run_test({
        "cve_id": "CVE-TEST",
        "method": "GET",
        "path": "/",
        "expected_status": [],
        "port": 80,
    }, "scanme.example")
    assert result.success is False
    assert "not confirmed" in result.evidence.lower() or "expected_status" in result.evidence.lower()


def test_run_test_ignores_generic_body_patterns(monkeypatch):
    def fake_send(host, port, payload, timeout=5.0, use_tls=False):
        return b"HTTP/1.0 403 Forbidden\r\n\r\nerror forbidden", 1.0, ""

    monkeypatch.setattr("src.verifier.runner._tcp_send_recv", fake_send)
    result = run_test({
        "cve_id": "CVE-TEST",
        "method": "GET",
        "path": "/.htaccess",
        "expected_status": [403],
        "expected_body_patterns": ["error", "forbidden", "htaccess"],
        "port": 80,
    }, "scanme.example")
    assert result.success is False


def test_run_test_coerces_status_and_patterns(monkeypatch):
    def fake_send(host, port, payload, timeout=5.0, use_tls=False):
        return b"HTTP/1.0 200 OK\r\n\r\napache server-status", 1.0, ""

    monkeypatch.setattr("src.verifier.runner._tcp_send_recv", fake_send)
    result = run_test({
        "cve_id": "CVE-TEST",
        "method": "GET",
        "path": "/server-status",
        "expected_status": ["200"],
        "expected_body_patterns": "not-a-list",
        "port": 80,
    }, "scanme.example")
    assert result.success is True


def test_ssh_builtin_plan_is_not_emitted():
    plans = generate_plans_for_cves(
        [{"id": "CVE-2023-38408", "cvss_score": 9.8, "description": "openssh agent"}],
        service="ssh", product="OpenSSH", version="9.3", port=22,
    )
    assert plans == []
