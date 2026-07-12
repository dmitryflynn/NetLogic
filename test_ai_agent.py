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
    """Agent probes are read-only — POST/PUT/DELETE must not run."""
    calls = []

    def http_fn(method, path, headers, body, port, tls, timeout):
        calls.append(method)
        return {"error": "", "elapsed_ms": 1, "status": 200, "headers": {}, "body": "x"}

    rt = ToolRuntime(host="ex.com", http_fn=http_fn)
    r = rt.execute("http_request", {"method": "POST", "path": "/api", "body": "a=1"})
    # sanitize rejects POST → no network call with POST
    assert r.ok is False or (calls and calls[0] != "POST")
    # explicit path: safe_method returns None → defaults? Actually method POST fails safe_method
    # and code does: method = san.safe_method(...) or "GET"  — so POST becomes GET!
    # Force via _do_http
    resp = rt._do_http("POST", "/x", {}, "data", 80, False, 2.0)
    assert "not allowed" in (resp.get("error") or "")
    assert calls == [] or "POST" not in calls


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
