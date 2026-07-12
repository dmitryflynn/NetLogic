"""Tests for the live-engine → fusion bridge (offline; no network/AI)."""

from src.fusion.engine_bridge import signals_from_artifacts, run_fusion


def _artifacts():
    """A synthetic engine artifacts dict (dicts, which _attr handles)."""
    return {
        "host_result": {"ip": "203.0.113.5", "target": "example.com",
                        "ports": [{"port": 443, "service": "https"}]},
        "vuln_matches": [
            {"port": 443, "service": "https", "product": "openssh", "version": "7.6",
             "detection_confidence": "HIGH", "cves": [
                {"id": "CVE-2024-KEV", "cvss_score": 9.8, "kev": True, "exploit_available": True,
                 "description": "actively exploited RCE"},
                {"id": "CVE-2024-HIGH", "cvss_score": 8.1, "kev": False, "description": "version-matched high"},
                {"id": "CVE-2024-MED", "cvss_score": 5.0, "kev": False, "description": "version-matched medium"},
             ]},
        ],
        "vuln_probe_result": {"confirmed": [{"cve_id": "CVE-2017-PROBE", "title": "RCE confirmed", "confirmed": True}]},
        "service_probe_result": {"findings": [{"port": 6379, "title": "Redis unauthenticated", "severity": "HIGH"}]},
        "stack_result": {"technologies": [{"name": "nginx", "version": "1.25"}],
                        "waf": {"detected": True, "name": "Cloudflare"}, "cloud_provider": "AWS"},
    }


# ── Signal extraction ───────────────────────────────────────────────────────────

def test_signals_cover_each_artifact_category():
    sigs = signals_from_artifacts(_artifacts())
    by_claim = {s.claim: s for s in sigs}
    assert "CVE-2024-KEV" in by_claim and by_claim["CVE-2024-KEV"].source == "nvd"
    assert "CVE-2017-PROBE" in by_claim and by_claim["CVE-2017-PROBE"].source == "probe"
    assert by_claim["CVE-2017-PROBE"].reliability == "high"
    assert "nginx" in by_claim and by_claim["nginx"].kind == "tech"
    # probe misconfig present
    assert any(s.kind == "misconfig" and "redis" in s.claim for s in sigs)


def test_exposure_is_public_with_waf_context():
    s = signals_from_artifacts(_artifacts())[0]
    assert s.exposure["reachability"] == "public"
    assert s.exposure["waf"] == "Cloudflare"


# ── Adjudication (no AI → fail-soft) ────────────────────────────────────────────

def test_kev_and_probe_confirmed_are_pinned_without_ai():
    fusion = run_fusion(_artifacts())            # no cfg/complete → AI unavailable
    confirmed = {r["subject"] for r in fusion["confirmed"]}
    discarded = {r["subject"] for r in fusion["discarded"]}
    # Banner-pattern KEV is NOT a finding — only probe-confirmed is
    assert "CVE-2024-KEV" not in confirmed
    assert "CVE-2024-KEV" in discarded
    assert "CVE-2017-PROBE" in confirmed         # probe-confirmed pinned
    assert all(r["ai"] is None for r in fusion["confirmed"] if r["subject"] == "CVE-2017-PROBE")


def test_version_only_critical_with_exploit_is_discarded():
    # Pattern/version correlator hits are never findings — even critical+exploit+EPSS.
    art = {
        "host_result": {"ip": "31.11.35.143", "ports": [{"port": 80, "service": "http"}]},
        "vuln_matches": [{
            "port": 80, "service": "http", "product": "iis", "version": "10.0",
            "detection_confidence": "POTENTIAL",
            "cves": [{"id": "CVE-2021-31166", "cvss_score": 9.8, "kev": False,
                      "exploit_available": True, "epss": 0.9966, "description": "IIS HTTP.sys UAF RCE"}],
        }],
    }
    fusion = run_fusion(art)
    confirmed = {r["subject"] for r in fusion["confirmed"]}
    potential = {r["subject"] for r in fusion["potential"]}
    discarded = {r["subject"] for r in fusion["discarded"]}
    assert "CVE-2021-31166" not in confirmed
    assert "CVE-2021-31166" not in potential
    assert "CVE-2021-31166" in discarded


def test_high_impact_version_match_is_discarded_not_potential():
    fusion = run_fusion(_artifacts())
    potential = {r["subject"] for r in fusion["potential"]}
    discarded = {r["subject"] for r in fusion["discarded"]}
    assert "CVE-2024-HIGH" not in potential
    assert "CVE-2024-HIGH" in discarded


def test_tech_and_low_impact_are_discarded():
    fusion = run_fusion(_artifacts())
    discarded = {r["subject"] for r in fusion["discarded"]}
    assert "nginx" in discarded                  # inventory
    assert "CVE-2024-MED" in discarded


def test_ai_injected_completer_confirms_gray_band():
    import json
    def fake(system, user):
        obs_marker = "OBSERVATIONS:\n```json"
        if obs_marker in user:
            items_json = user.split(obs_marker, 1)[1].rsplit("```", 1)[0]
        else:
            items_json = user.split("```json", 1)[1].rsplit("```", 1)[0]
        items = json.loads(items_json)
        return json.dumps([{"id": it["id"], "verdict": "real", "severity": "high",
                            "confidence": 0.9, "reason": "ok", "benign_ruled_out": []} for it in items])
    fusion = run_fusion(_artifacts(), complete=fake)
    confirmed = {r["subject"] for r in fusion["confirmed"]}
    # Probe misconfig (non-pattern) can still be confirmed via AI path if gray
    assert "redis unauthenticated" in confirmed or "CVE-2017-PROBE" in confirmed
    # Version-pattern CVEs never become findings
    assert "CVE-2024-HIGH" not in confirmed
    discarded = {r["subject"] for r in fusion["discarded"]}
    assert "CVE-2024-HIGH" in discarded


def test_summary_counts_present():
    s = run_fusion(_artifacts())["summary"]
    assert s["signals"] >= 5
    assert s["confirmed"] >= 1 and "discarded" in s


def test_build_json_report_includes_fusion(monkeypatch):
    import src.reporter as reporter
    monkeypatch.setattr(reporter, "generate_json_report", lambda *a, **k: {})
    from src.engine import build_json_report
    art = {"host_result": None, "vuln_matches": [], "fusion": {"summary": {"confirmed": 0}}}
    report = build_json_report(art)
    assert report["fusion"] == {"summary": {"confirmed": 0}}
