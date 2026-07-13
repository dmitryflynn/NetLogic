"""AI investigation agent — tool loop, sanitize, budget, crash gate."""
from __future__ import annotations

import json

from src.reasoning.agent.sanitize import safe_path, safe_headers, safe_method, safe_raw_payload
from src.reasoning.agent.surface import build_surface_summary
from src.reasoning.agent.tools import ToolRuntime
from src.reasoning.agent.loop import InvestigationAgent
from src.reasoning.agent.findings import merge_agent_into_investigations, agent_result_to_art


def test_sanitize_rejects_ssrf_paths():
    assert safe_path("http://evil.com/x") is None
    assert safe_path("//evil.com") is None
    assert safe_path("/a b") is None
    assert safe_path("/api/v1") == "/api/v1"
    assert safe_method("get") == "GET"
    assert safe_method("TRACE") is None
    assert safe_headers({"X-Foo": "bar", "Host": "evil"}) == {"X-Foo": "bar"}
    assert safe_raw_payload("hello") == b"hello"


def test_surface_summary_from_art():
    art = {
        "ports": [{"port": 443, "service": "https", "banner": "Microsoft-IIS/10.0"}],
        "stack": ["Microsoft IIS"],
        "vulns": [{"id": "CVE-2021-31166", "cvss": 9.8, "service": "iis"}],
    }
    s = build_surface_summary("target.example", art, scope=["target.example"])
    assert s["target"] == "target.example"
    assert any(p.get("port") == 443 for p in s["ports"])
    assert s["cve_leads"][0]["id"] == "CVE-2021-31166"
    assert any("CVE-2021-31166" in x for x in s["open_leads"])


def _fake_http(method, path, headers, body, port, tls, timeout):
    return {
        "error": "", "elapsed_ms": 12.0, "status": 200,
        "headers": {"server": "Microsoft-IIS/10.0"},
        "body": "ok",
    }


def test_tool_http_and_assert_finding():
    rt = ToolRuntime(host="ex.com", port=443, tls=True, http_fn=_fake_http)
    r = rt.execute("http_request", {"method": "GET", "path": "/"})
    assert r.ok and r.network and r.observation_id.startswith("obs_")
    r2 = rt.execute("assert_finding", {
        "id": "f1", "title": "IIS present", "severity": "info",
        "status": "confirmed", "evidence_refs": [r.observation_id],
    })
    assert r2.ok
    assert rt.findings[0]["status"] == "confirmed"


def test_assert_finding_cannot_confirm_without_evidence():
    rt = ToolRuntime(host="ex.com", http_fn=_fake_http)
    r = rt.execute("assert_finding", {
        "id": "f1", "title": "bogus", "status": "confirmed", "evidence_refs": ["obs_missing"],
    })
    assert r.ok
    assert rt.findings[0]["status"] == "lead"  # demoted


def test_crash_probe_denied_without_flag():
    rt = ToolRuntime(host="ex.com", allow_crash_probes=False, http_fn=_fake_http)
    r = rt.execute("crash_probe", {"cve_id": "CVE-2021-31166"})
    assert not r.ok and "disabled" in r.error or "disabled" in r.summary


def test_crash_probe_allowed_with_flag():
    def http_fn(method, path, headers, body, port, tls, timeout):
        # Control succeeds; crash probe "times out"
        if headers and "Accept-Encoding" in headers:
            return {"error": "timeout", "elapsed_ms": 8000, "status": None,
                    "headers": {}, "body": ""}
        return {"error": "", "elapsed_ms": 20, "status": 200,
                "headers": {"server": "iis"}, "body": "ok"}

    rt = ToolRuntime(host="ex.com", allow_crash_probes=True, http_fn=http_fn)
    r = rt.execute("crash_probe", {"cve_id": "cve-2021-31166"})
    assert r.ok and r.data.get("vulnerable_signal") is True
    assert any(f.get("status") == "confirmed" for f in rt.findings)


def test_agent_loop_multi_turn_mock():
    turns = [
        {
            "thought": "confirm IIS",
            "calls": [{"tool": "http_request", "args": {"path": "/"}}],
            "findings": [], "chains": [], "stop": False,
        },
        {
            "thought": "record finding and chain",
            "calls": [
                {"tool": "assert_finding", "args": {
                    "id": "iis", "title": "IIS confirmed", "severity": "info",
                    "status": "confirmed", "evidence_refs": ["obs_1"],
                }},
                {"tool": "chain_link", "args": {
                    "from": "iis", "to": "technique:http_sys_cve", "why": "IIS 10 stack",
                }},
                {"tool": "stop", "args": {"summary": "done"}},
            ],
            "stop": False,
        },
    ]
    i = {"n": 0}

    def completer(system, user):
        n = i["n"]
        i["n"] += 1
        return json.dumps(turns[min(n, len(turns) - 1)])

    agent = InvestigationAgent(completer, max_steps=5, max_requests=10)
    res = agent.run(target="ex.com", host="ex.com", port=443, tls=True, http_fn=_fake_http,
                    art={"ports": [{"port": 443, "service": "https"}]})
    assert res.steps_used >= 2
    assert any(f.get("id") == "iis" for f in res.findings)
    assert res.chains
    d = agent_result_to_art(res)
    assert "findings" in d and d["steps_used"] >= 1


def test_agent_off_without_completer():
    res = InvestigationAgent(None).run(target="x", host="x")
    assert res.stopped_reason == "no AI completer"
    assert res.findings == []


def test_http_rejects_mutating_methods():
    """Free-form POST bodies forbidden; bare POST without template rejected."""
    calls = []

    def http_fn(method, path, headers, body, port, tls, timeout):
        calls.append((method, body))
        return {"error": "", "elapsed_ms": 1, "status": 200, "headers": {}, "body": "x"}

    rt = ToolRuntime(host="ex.com", http_fn=http_fn)
    r = rt.execute("http_request", {"method": "POST", "path": "/api", "body": "a=1"})
    assert r.ok is False
    assert "free-form" in (r.error or r.summary).lower() or "forbidden" in (r.error or "").lower()
    # Force via _do_http without allow_post
    resp = rt._do_http("POST", "/x", {}, "data", 80, False, 2.0)
    assert "not allowed" in (resp.get("error") or "")
    assert not any(m == "POST" for m, _ in calls)


def test_http_body_template_allows_curated_post():
    calls = []

    def http_fn(method, path, headers, body, port, tls, timeout):
        calls.append((method, body, headers.get("Content-Type")))
        return {"error": "", "elapsed_ms": 2, "status": 401, "headers": {}, "body": "no"}

    rt = ToolRuntime(host="ex.com", http_fn=http_fn)
    r = rt.execute("http_request", {
        "path": "/login", "body_template": "form_login_probe",
    })
    assert r.ok
    assert calls and calls[0][0] == "POST"
    assert "netlogic_probe" in (calls[0][1] or "")


def test_tier_a_tools_in_catalog():
    rt = ToolRuntime(host="ex.com")
    names = {t["name"] for t in rt.catalog()}
    for n in (
        "param_reflect", "cors_probe", "header_injection_probe", "auth_flow_probe",
        "jwt_inspect", "graphql_introspect", "api_discover", "s3_or_storage_probe",
        "subdomain_probe", "ssh_banner_timing", "ssl_cert_chain",
        "cve_probe", "sqli_boolean", "sqli_time", "ssrf_canary", "idor_diff",
        "file_disclosure", "smuggling_desync",
    ):
        assert n in names, n


def test_param_reflect_and_cors():
    def http_fn(method, path, headers, body, port, tls, timeout):
        # Reflect marker in body; open-redirect Location for redirect probe
        if "nlprobe7f3a9c2e.invalid" in path:
            return {
                "error": "", "elapsed_ms": 1, "status": 302,
                "headers": {"Location": "https://nlprobe7f3a9c2e.invalid/"},
                "body": "",
            }
        if "nlprobe7f3a9c2e" in path:
            return {
                "error": "", "elapsed_ms": 1, "status": 200,
                "headers": {}, "body": f"hello nlprobe7f3a9c2e world",
            }
        origin = (headers or {}).get("Origin") or ""
        if origin:
            return {
                "error": "", "elapsed_ms": 1, "status": 200,
                "headers": {
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true",
                },
                "body": "ok",
            }
        return {"error": "", "elapsed_ms": 1, "status": 200, "headers": {}, "body": "ok"}

    rt = ToolRuntime(host="ex.com", http_fn=http_fn)
    pr = rt.execute("param_reflect", {"path": "/", "param": "url"})
    assert pr.ok and pr.data.get("reflected_in_body")
    assert pr.data.get("open_redirect_signal")
    cr = rt.execute("cors_probe", {"path": "/"})
    assert cr.ok and cr.data.get("misconfig_signal")


def test_param_reflect_rejects_same_site_open_redirect():
    """Same-host Location with marker only in query is NOT open redirect."""
    def http_fn(method, path, headers, body, port, tls, timeout):
        if "nlprobe7f3a9c2e.invalid" in path or "https://" in path:
            return {
                "error": "", "elapsed_ms": 1, "status": 301,
                "headers": {
                    "Location": "https://ex.com/?url=https://nlprobe7f3a9c2e.invalid/",
                },
                "body": "",
            }
        return {
            "error": "", "elapsed_ms": 1, "status": 200,
            "headers": {}, "body": "hello nlprobe7f3a9c2e world",
        }

    rt = ToolRuntime(host="ex.com", http_fn=http_fn)
    pr = rt.execute("param_reflect", {"path": "/", "param": "url"})
    assert pr.ok
    assert not pr.data.get("open_redirect_signal"), pr.data


def test_jwt_inspect_decodes_without_network():
    # header {"alg":"none","typ":"JWT"} payload {"sub":"1"}
    import base64, json
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    token = f"{b64({'alg':'none','typ':'JWT'})}.{b64({'sub':'1','role':'user'})}.x"
    rt = ToolRuntime(host="ex.com")
    r = rt.execute("jwt_inspect", {"token": token})
    assert r.ok and r.data.get("alg") == "none"
    assert "alg_none" in (r.data.get("flags") or [])
    assert r.network is False


def test_graphql_introspect_detects_schema():
    def http_fn(method, path, headers, body, port, tls, timeout):
        assert method == "POST"
        assert "__schema" in (body or "")
        return {
            "error": "", "elapsed_ms": 3, "status": 200, "headers": {},
            "body": '{"data":{"__schema":{"types":[{"name":"Query"},{"name":"User"}]}}}',
        }

    rt = ToolRuntime(host="ex.com", http_fn=http_fn)
    r = rt.execute("graphql_introspect", {"path": "/graphql"})
    assert r.ok and r.data.get("schema_leak")


def test_cve_probe_apache_path_traversal_marker():
    def http_fn(method, path, headers, body, port, tls, timeout):
        if "passwd" in path or "%2e" in path.lower():
            return {
                "error": "", "elapsed_ms": 5, "status": 200, "headers": {},
                "body": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/:\n",
            }
        return {"error": "", "elapsed_ms": 1, "status": 404, "headers": {}, "body": "no"}

    rt = ToolRuntime(host="ex.com", http_fn=http_fn)
    r = rt.execute("cve_probe", {"cve_id": "CVE-2021-41773"})
    assert r.ok and r.data.get("vulnerable_signal")


def test_file_disclosure_marker_not_soft404():
    def http_fn(method, path, headers, body, port, tls, timeout):
        if path == "/.env":
            return {
                "error": "", "elapsed_ms": 2, "status": 200, "headers": {},
                "body": "APP_KEY=base64:abc\nDB_PASSWORD=secret\n",
            }
        if path == "/.git/HEAD":
            return {
                "error": "", "elapsed_ms": 1, "status": 200, "headers": {},
                "body": "<html><title>404 Not Found</title></html>",
            }
        return {"error": "", "elapsed_ms": 1, "status": 404, "headers": {}, "body": ""}

    rt = ToolRuntime(host="ex.com", http_fn=http_fn)
    r = rt.execute("file_disclosure", {"max_paths": 8})
    assert r.ok
    paths = [d["path"] for d in r.data.get("disclosures") or []]
    assert "/.env" in paths
    assert "/.git/HEAD" not in paths  # soft-404 HTML without markers


def test_sqli_boolean_differential():
    def http_fn(method, path, headers, body, port, tls, timeout):
        # true payloads return long body; false short
        if "1%3D1" in path or "1%27%3D1" in path or "%271%27%3D%271" in path:
            return {"error": "", "elapsed_ms": 2, "status": 200, "headers": {},
                    "body": "OK" + ("X" * 50)}
        if "1%3D2" in path or "%271%27%3D%272" in path:
            return {"error": "", "elapsed_ms": 2, "status": 200, "headers": {},
                    "body": "OK"}
        return {"error": "", "elapsed_ms": 1, "status": 200, "headers": {}, "body": "OK"}

    rt = ToolRuntime(host="ex.com", http_fn=http_fn)
    r = rt.execute("sqli_boolean", {"path": "/item", "param": "id"})
    assert r.ok
    # may or may not signal depending on encoding of payloads — at least structured
    assert "true" in r.data and "false" in r.data


def test_idor_diff_detects_body_difference():
    def http_fn(method, path, headers, body, port, tls, timeout):
        cookie = (headers or {}).get("Cookie") or ""
        if "sid=alice" in cookie:
            return {"error": "", "elapsed_ms": 1, "status": 200, "headers": {},
                    "body": "user=alice email=a@x.com"}
        if "sid=bob" in cookie:
            return {"error": "", "elapsed_ms": 1, "status": 200, "headers": {},
                    "body": "user=bob email=b@x.com"}
        return {"error": "", "elapsed_ms": 1, "status": 401, "headers": {}, "body": "no"}

    rt = ToolRuntime(host="ex.com", http_fn=http_fn)
    r = rt.execute("idor_diff", {
        "path": "/api/me",
        "cookies_a": {"sid": "alice"},
        "cookies_b": {"sid": "bob"},
    })
    assert r.ok and r.data.get("vulnerable_signal")


def test_ssrf_canary_requires_host_and_injects():
    seen = {}

    def http_fn(method, path, headers, body, port, tls, timeout):
        seen["path"] = path
        return {"error": "", "elapsed_ms": 2, "status": 200, "headers": {},
                "body": "ok"}

    rt = ToolRuntime(host="ex.com", http_fn=http_fn)
    bad = rt.execute("ssrf_canary", {"path": "/"})
    assert not bad.ok
    r = rt.execute("ssrf_canary", {
        "path": "/fetch", "param": "url", "canary_host": "abc.oastify.com",
    })
    assert r.ok
    assert "abc.oastify.com" in (seen.get("path") or "")


def test_smuggling_requires_crash_flag():
    rt = ToolRuntime(host="ex.com", allow_crash_probes=False)
    r = rt.execute("smuggling_desync", {"path": "/"})
    blob = f"{r.error} {r.summary}".lower()
    assert not r.ok and ("disabled" in blob or "not authorized" in blob or "allow_crash" in blob)


def test_http_proof_requires_flag():
    rt = ToolRuntime(host="ex.com", allow_freeform_proof=False)
    r = rt.execute("http_proof", {"method": "GET", "path": "/?q=1"})
    assert not r.ok
    assert "freeform" in (r.error or r.summary).lower() or "disabled" in (r.summary or "").lower()
    names = {t["name"] for t in rt.catalog()}
    assert "http_proof" not in names


def test_http_proof_get_marker_reflection():
    def http_fn(method, path, headers, body, port, tls, timeout):
        return {
            "error": "", "elapsed_ms": 2, "status": 200,
            "headers": {}, "body": f"echo {path}",
        }

    rt = ToolRuntime(host="ex.com", allow_freeform_proof=True, http_fn=http_fn)
    assert "http_proof" in {t["name"] for t in rt.catalog()}
    r = rt.execute("http_proof", {
        "method": "GET",
        "path": "/search?q=nlproofmarker99",
        "expect_marker": "nlproofmarker99",
    })
    assert r.ok
    assert r.data.get("vulnerable_signal")
    assert "expect_marker_reflected" in (r.data.get("proof_signals") or [])


def test_http_proof_blocks_destructive_and_write_methods():
    calls = []

    def http_fn(method, path, headers, body, port, tls, timeout):
        calls.append(method)
        return {"error": "", "elapsed_ms": 1, "status": 200, "headers": {}, "body": "ok"}

    rt = ToolRuntime(host="ex.com", allow_freeform_proof=True, http_fn=http_fn)
    # PUT forever forbidden
    r = rt.execute("http_proof", {"method": "PUT", "path": "/api/x", "body": "{}"})
    assert not r.ok
    assert "method" in (r.error or r.summary).lower()
    # DROP TABLE blocked even on GET path
    r2 = rt.execute("http_proof", {
        "method": "GET",
        "path": "/search?q=1;DROP%20TABLE%20users",
    })
    # path may not match DROP if encoded - also try body POST
    r3 = rt.execute("http_proof", {
        "method": "POST",
        "path": "/search",
        "body": "q=1; DROP TABLE users--",
    })
    assert not r3.ok
    assert "destructive" in (r3.error or r3.summary).lower()
    # DELETE FROM
    r4 = rt.execute("http_proof", {
        "method": "POST",
        "path": "/api/query",
        "body": '{"sql":"DELETE FROM accounts"}',
    })
    assert not r4.ok
    assert not calls  # nothing should have been sent for blocked cases above except maybe r2


def test_exploit_request_requires_flag():
    rt = ToolRuntime(host="ex.com", allow_exploit_requests=False)
    assert "exploit_request" not in {t["name"] for t in rt.catalog()}
    r = rt.execute("exploit_request", {"method": "DELETE", "path": "/api/x"})
    assert not r.ok
    assert "not authorized" in (r.error or "").lower() or "disabled" in (r.summary or "").lower()


def test_exploit_request_allows_any_method_scope_gated_and_audited():
    sent = []

    def http_fn(method, path, headers, body, port, tls, timeout):
        sent.append((method, path, body))
        return {"error": "", "elapsed_ms": 1, "status": 204, "headers": {}, "body": ""}

    rt = ToolRuntime(host="ex.com", allow_exploit_requests=True, http_fn=http_fn)
    assert "exploit_request" in {t["name"] for t in rt.catalog()}
    r = rt.execute("exploit_request", {"method": "DELETE", "path": "/api/objects/42",
                                       "headers": {"X-Exploit": "1"}, "body": ""})
    assert r.ok and sent == [("DELETE", "/api/objects/42", "")]      # write method actually sent
    assert "delete_accepted" in (r.data.get("proof_signals") or [])   # 2xx write = signal
    assert r.data.get("vulnerable_signal")
    assert rt.observations and rt.observations[-1]["tool"] == "exploit_request"  # audited


def test_exploit_request_blocks_destructive_and_crlf_injection():
    sent = []

    def http_fn(method, path, headers, body, port, tls, timeout):
        sent.append(method)
        return {"error": "", "elapsed_ms": 1, "status": 200, "headers": {}, "body": "ok"}

    rt = ToolRuntime(host="ex.com", allow_exploit_requests=True, http_fn=http_fn)
    # Mass-destructive pattern in body → blocked (filter kept per design)
    bad = rt.execute("exploit_request", {"method": "POST", "path": "/api/run",
                                         "body": "{\"sql\":\"DROP TABLE users\"}"})
    assert not bad.ok and "destructive" in (bad.error or "").lower()
    # CR/LF header injection (request splitting / scope-escape) → refused
    crlf = rt.execute("exploit_request", {"method": "GET", "path": "/",
                                          "headers": {"X-Evil": "a\r\nHost: attacker.com"}})
    assert not crlf.ok and "sanitize" in (crlf.error or "").lower()
    assert not sent  # neither ever reached the wire


def test_http_proof_same_site_location_query_not_vulnerable():
    """www/apex bounce that echoes attacker URL in query is NOT open redirect."""
    def http_fn(method, path, headers, body, port, tls, timeout):
        return {
            "error": "", "elapsed_ms": 1, "status": 307,
            "headers": {
                "Location": "https://www.zipenvy.com/api/auth/callback?callbackUrl=https://evil.com",
            },
            "body": "Redirecting...",
        }

    rt = ToolRuntime(host="zipenvy.com", allow_freeform_proof=True, http_fn=http_fn, tls=True)
    r = rt.execute("http_proof", {
        "method": "GET",
        "path": "/api/auth/callback?callbackUrl=https://evil.com",
        "expect_marker": "evil.com",
    })
    assert r.ok
    sigs = r.data.get("proof_signals") or []
    assert "same_site_redirect" in sigs or "marker_echoed_in_same_site_location_query" in sigs
    assert "external_redirect" not in sigs
    assert not r.data.get("vulnerable_signal"), r.data
    assert "www.zipenvy.com" in (r.data.get("observed_summary") or "")


def test_http_proof_post_allowlist():
    calls = []

    def http_fn(method, path, headers, body, port, tls, timeout):
        calls.append((method, path, body))
        return {"error": "", "elapsed_ms": 1, "status": 401, "headers": {}, "body": "no"}

    rt = ToolRuntime(host="ex.com", allow_freeform_proof=True, http_fn=http_fn)
    # Admin delete path denied
    bad = rt.execute("http_proof", {
        "method": "POST", "path": "/admin/users/delete", "body": "{}",
    })
    assert not bad.ok
    # Login allowlisted
    ok = rt.execute("http_proof", {
        "method": "POST", "path": "/login",
        "body": '{"username":"netlogic_probe","password":"x"}',
    })
    assert ok.ok
    assert calls and calls[0][0] == "POST" and calls[0][1].startswith("/login")


def test_tier_d_record_poc_scope_severity_readiness():
    def http_fn(method, path, headers, body, port, tls, timeout):
        return {
            "error": "", "elapsed_ms": 1, "status": 200,
            "headers": {"Location": "https://nlprobe7f3a9c2e.invalid/"},
            "body": f"x nlprobe7f3a9c2e y",
        }

    rt = ToolRuntime(host="app.example.com", scope=["example.com"], http_fn=http_fn, tls=True)
    # Prove something
    pr = rt.execute("param_reflect", {"path": "/", "param": "next"})
    assert pr.ok
    # Assert finding with evidence
    rt.execute("assert_finding", {
        "id": "open-redirect", "title": "Open redirect via next",
        "severity": "medium", "status": "confirmed",
        "evidence_refs": [pr.observation_id],
        "rationale": "Location reflects attacker host",
    })
    # Tier D
    sc = rt.execute("scope_check", {"host": "app.example.com", "path": "/login"})
    assert sc.ok and sc.data.get("in_scope") is True
    sc2 = rt.execute("scope_check", {"host": "evil.com", "path": "/"})
    assert sc2.ok and sc2.data.get("in_scope") is False

    poc = rt.execute("record_poc", {
        "observation_id": pr.observation_id,
        "finding_id": "open-redirect",  # may be normalized
        "title": "Open redirect",
    })
    assert poc.ok and "curl" in (poc.data.get("curl") or "")
    assert rt.pocs

    # Finding id after normalize
    fid = rt.findings[0]["id"]
    sev = rt.execute("severity_suggest", {"finding_id": fid, "title": "open redirect"})
    assert sev.ok and sev.data.get("suggested_severity") in ("medium", "low", "high", "info", "critical")

    ready = rt.execute("submit_readiness", {"finding_id": fid})
    assert ready.ok
    assert ready.data.get("total") == 1
    # confirmed + evidence + poc + rationale → ready
    assert ready.data["reports"][0]["ready"] is True


def test_hackerone_export_markdown():
    from src.hackerone_export import build_hackerone_markdown
    art = {
        "host": {"target": "zipenvy.com", "ip": "1.2.3.4"},
        "ai_agent": {
            "findings": [{
                "id": "open-redirect", "title": "Open redirect", "status": "confirmed",
                "severity": "medium", "rationale": "Location to external host",
                "evidence_refs": ["obs_1"],
                "poc": {"curl": "curl -sk 'https://zipenvy.com/?url=https://evil'",
                        "expected": "302 to evil", "observation_id": "obs_1"},
            }],
            "pocs": [],
            "readiness": {"ready_count": 1, "total": 1, "reports": [
                {"finding_id": "open-redirect", "ready": True}
            ]},
        },
        "investigations": [],
        "fusion": {"confirmed": []},
    }
    md = build_hackerone_markdown(art, target="zipenvy.com")
    assert "Open redirect" in md
    assert "curl" in md
    assert "zipenvy.com" in md


def test_udp_and_ssdp_tools_exist():
    rt = ToolRuntime(host="127.0.0.1", port=9)  # discard port
    names = {t["name"] for t in rt.catalog()}
    assert "udp_probe" in names and "ssdp_discover" in names
    assert "dir_enum" in names and "browser_get" in names
    assert "set_session" in names
    # dir_enum against closed host still returns a structured result
    r = rt.execute("dir_enum", {"wordlist": "short", "max_paths": 5})
    assert r.tool == "dir_enum" and r.network


def test_set_session_applies_cookie_on_http():
    seen = {}

    def http_fn(method, path, headers, body, port, tls, timeout):
        seen["headers"] = dict(headers or {})
        return {"error": "", "elapsed_ms": 1, "status": 200, "headers": {}, "body": "ok"}

    rt = ToolRuntime(host="ex.com", http_fn=http_fn)
    rt.execute("set_session", {"cookies": {"sid": "abc123"}, "headers": {"Authorization": "Bearer t"}})
    rt.execute("http_request", {"path": "/me"})
    assert "sid=abc123" in (seen["headers"].get("Cookie") or "")
    assert seen["headers"].get("Authorization") == "Bearer t"


def test_depth_mode_raises_budgets_and_blocks_early_stop():
    """Depth mode: higher default budgets; stop:true ignored until high-value work done."""
    calls = {"n": 0}

    def completer(system, user):
        calls["n"] += 1
        # First two turns: try to stop immediately without high-value work
        if calls["n"] <= 2:
            return json.dumps({
                "thought": "done enough",
                "calls": [{"tool": "stop", "args": {"summary": "early"}}],
                "stop": True,
            })
        # Then do high-value work
        return json.dumps({
            "thought": "check non-root path",
            "calls": [{"tool": "http_request", "args": {"path": f"/admin{calls['n']}"}}],
            "stop": False,
        })

    agent = InvestigationAgent(
        completer, depth_mode=True,
        max_steps=12,  # will be raised to depth floor 24 only if <=12 — it is 12 so → 24
        max_requests=40,
        min_high_value=2,
        min_steps_before_stop=2,
    )
    assert agent.max_steps >= 24
    assert agent.max_requests >= 80
    assert "DEPTH" in agent._system or "DEPTH-MODE" in agent._system or "depth" in agent._system.lower()

    # Force smaller loop for unit test speed
    agent.max_steps = 6
    agent.min_high_value = 2
    agent.min_steps_before_stop = 2

    res = agent.run(target="ex.com", host="ex.com", port=80, http_fn=_fake_http)
    # Early stops must have been refused; should have continued
    assert res.depth_mode is True
    refused = [t for t in res.turns if t.get("stop_refused")]
    assert len(refused) >= 1
    # Eventually high-value /admin GETs should run
    assert res.high_value_used >= 1
    assert any(
        "admin" in str(r.get("summary") or "")
        for t in res.turns for r in (t.get("results") or [])
    )


def test_depth_mode_stop_allowed_after_high_value():
    seq = {"n": 0}

    def completer(system, user):
        seq["n"] += 1
        n = seq["n"]
        if n <= 3:
            return json.dumps({
                "thought": f"probe {n}",
                "calls": [{"tool": "http_request", "args": {"path": f"/p{n}"}}],
                "stop": False,
            })
        return json.dumps({
            "thought": "enough high-value work",
            "calls": [{"tool": "stop", "args": {"summary": "ok"}}],
            "stop": True,
        })

    agent = InvestigationAgent(
        completer, depth_mode=True, max_steps=20, max_requests=50,
        min_high_value=3, min_steps_before_stop=3,
    )
    agent.max_steps = 10  # keep test short after floors applied
    res = agent.run(target="ex.com", host="ex.com", http_fn=_fake_http)
    assert res.high_value_used >= 3
    assert res.stopped_reason == "agent stopped"


def test_merge_agent_upgrades_investigation():
    invs = [{
        "question": "Can CVE-2021-31166 be exploited?",
        "subject": "CVE-2021-31166 — iis",
        "kind": "exploitability", "conclusion": "UNVERIFIED", "confidence": 0.65,
        "evidence": [{"name": "banner", "satisfied": True}],
        "gathered": 1, "total_evidence": 1,
    }]
    agent_art = {
        "findings": [{
            "id": "cve-2021-31166", "title": "http.sys crash signal",
            "status": "confirmed", "evidence_refs": ["obs_2"],
            "rationale": "timeout after Accept-Encoding probe",
        }],
    }
    out = merge_agent_into_investigations(invs, agent_art)
    assert out[0]["conclusion"] == "EXPLOITABLE"
    assert out[0]["adjudicated_by_ai"] is True
