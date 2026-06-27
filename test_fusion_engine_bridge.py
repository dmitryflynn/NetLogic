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
    assert "CVE-2024-KEV" in confirmed           # KEV pinned
    assert "CVE-2017-PROBE" in confirmed         # probe-confirmed pinned
    # and they were settled deterministically — not via the AI
    assert all(r["ai"] is None for r in fusion["confirmed"] if r["subject"] in ("CVE-2024-KEV", "CVE-2017-PROBE"))


def test_version_only_critical_with_exploit_does_not_falsely_confirm():
    # Regression (bibliotecapleyades IIS 10.0): a coarse version/banner correlator hit
    # for a critical CVE with a public exploit + near-1.0 EPSS but NOT in KEV and NOT
    # probe-confirmed must NOT pin as "confirmed" — it's a version guess, not patch-level
    # truth. It belongs in potential (verify). Pinning it was the cardinal-precision bug.
    art = {
        "host_result": {"ip": "31.11.35.143", "ports": [{"port": 80, "service": "http"}]},
        "vuln_matches": [{
            "port": 80, "service": "http", "product": "iis", "version": "10.0",
            "detection_confidence": "POTENTIAL",
            "cves": [{"id": "CVE-2021-31166", "cvss_score": 9.8, "kev": False,
                      "exploit_available": True, "epss": 0.9966, "description": "IIS HTTP.sys UAF RCE"}],
        }],
    }
    fusion = run_fusion(art)                          # no AI → gray degrades to potential
    confirmed = {r["subject"] for r in fusion["confirmed"]}
    potential = {r["subject"] for r in fusion["potential"]}
    assert "CVE-2021-31166" not in confirmed         # the bug: must never auto-confirm
    assert "CVE-2021-31166" in potential             # surfaced for verification, never dropped


def test_high_impact_gray_item_degrades_to_potential_without_ai():
    fusion = run_fusion(_artifacts())
    potential = {r["subject"] for r in fusion["potential"]}
    # the lone high-impact, non-KEV version match goes gray → no AI → potential (never dropped)
    assert "CVE-2024-HIGH" in potential


def test_tech_and_low_impact_are_discarded():
    fusion = run_fusion(_artifacts())
    discarded = {r["subject"] for r in fusion["discarded"]}
    assert "nginx" in discarded                  # inventory
    # CVE-2024-MED: lone medium-impact version match; version_only caps
    # false confirmation but doesn't prevent legitimate discard of noise.
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
    potential = {r["subject"] for r in fusion["potential"]}
    # The AI promotion path works: a genuine (non-version) gray item judged "real" is confirmed.
    assert "redis unauthenticated" in confirmed
    # But a version-only finding is capped at "potential" even when the AI says "real" —
    # patch level is unverifiable from a banner, so the AI cannot manufacture a confirmed
    # critical out of a version guess. This is the precision guarantee.
    assert "CVE-2024-HIGH" in potential
    assert "CVE-2024-HIGH" not in confirmed


def test_summary_counts_present():
    s = run_fusion(_artifacts())["summary"]
    assert s["signals"] >= 5
    assert s["confirmed"] >= 2 and "discarded" in s


def test_build_json_report_includes_fusion(monkeypatch):
    import src.reporter as reporter
    monkeypatch.setattr(reporter, "generate_json_report", lambda *a, **k: {})
    from src.engine import build_json_report
    art = {"host_result": None, "vuln_matches": [], "fusion": {"summary": {"confirmed": 0}}}
    report = build_json_report(art)
    assert report["fusion"] == {"summary": {"confirmed": 0}}
