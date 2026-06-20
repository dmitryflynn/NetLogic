"""Tests for the fusion layer (signal schema + deterministic agreement gate).

These encode the architectural invariants from the design:
  • ai_view strips the sensor name and self-declared severity (anti trigger-word bias),
  • independent corroboration auto-confirms (no AI token),
  • a lone low-reliability low-impact signal is auto-discarded,
  • KEV / probe-confirmed criticals are PINNED and can never be discarded/gray
    (zero-false-negative-on-criticals as an architectural guarantee, not prompt tuning),
  • impact is deterministic and exposure-aware (private demotes; unknown never does).
"""

from src.fusion import Signal, adjudicate
from src.fusion.gate import gray_band, confirmed


def _sig(source, claim, **kw):
    return Signal(source=source, kind=kw.pop("kind", "vuln"), claim=claim,
                  host=kw.pop("host", "10.0.0.5"), port=kw.pop("port", 8080), **kw)


# ── Signal schema / AI view ─────────────────────────────────────────────────────

def test_ai_view_strips_source_and_severity():
    s = _sig("nuclei", "jenkins", kind="exposure", evidence="<title>Dashboard [Jenkins]</title>",
             cvss=9.8, kev=True, exploit_available=True,
             exposure={"reachability": "public", "waf": None})
    view = s.ai_view()
    blob = repr(view)
    # The tool name and every numeric/severity score must be absent…
    assert "nuclei" not in blob
    assert "9.8" not in blob and "cvss" not in blob.lower()
    assert "kev" not in blob.lower()
    # …but the observable evidence + exposure remain.
    assert view["evidence"] == "<title>Dashboard [Jenkins]</title>"
    assert view["exposure"]["reachability"] == "public"


def test_evidence_is_capped():
    s = _sig("probe", "x", evidence="A" * 5000)
    assert len(s.evidence) < 1000 and s.evidence.endswith("…[truncated]")


# ── Agreement gate: auto-confirm ────────────────────────────────────────────────

def test_independent_corroboration_auto_confirms_without_ai():
    # banner + nuclei + probe all assert the same subject → 3 independent sources.
    sigs = [
        _sig("banner", "jenkins", reliability="medium", kind="tech"),
        _sig("nuclei", "jenkins", reliability="medium", kind="exposure"),
        _sig("probe", "jenkins", reliability="high", kind="exposure",
             evidence="HTTP 200 /login Jenkins crumb issuer"),
    ]
    [v] = adjudicate(sigs)
    assert v.decision == "confirmed"
    assert v.agreement == 3
    assert gray_band([v]) == []          # never reaches the AI


def test_two_sources_but_no_high_reliability_is_gray_not_confirmed():
    sigs = [
        _sig("banner", "acme-cms", reliability="medium", kind="tech", cvss=7.5),
        _sig("wappalyzer", "acme-cms", reliability="medium", kind="tech", cvss=7.5),
    ]
    [v] = adjudicate(sigs)
    # 2 sources but neither high-reliability and impact is high → don't auto-confirm,
    # send to AI.
    assert v.decision == "gray"


# ── Agreement gate: auto-discard ────────────────────────────────────────────────

def test_lone_low_reliability_low_impact_is_discarded():
    [v] = adjudicate([_sig("banner", "maybe-nginx", reliability="low", kind="tech", cvss=0.0)])
    assert v.decision == "discarded"
    assert confirmed([v]) == []


def test_lone_low_reliability_HIGH_impact_is_never_discarded():
    # Even a single weak signal, if high-impact, must go to the AI — never silently dropped.
    [v] = adjudicate([_sig("nuclei", "CVE-2021-44228", reliability="low", cvss=10.0)])
    assert v.decision != "discarded"
    assert v.decision in ("gray", "confirmed")


# ── PINNED: zero-false-negative-on-criticals (architectural) ────────────────────

def test_kev_is_pinned_confirmed_even_when_lone():
    [v] = adjudicate([_sig("nuclei", "CVE-2021-44228", reliability="low", cvss=10.0, kev=True)])
    assert v.pinned is True
    assert v.decision == "confirmed"
    assert gray_band([v]) == []          # the AI can't even see it, let alone drop it


def test_probe_confirmed_is_pinned():
    [v] = adjudicate([_sig("probe", "redis-unauth", reliability="high", kind="misconfig",
                           evidence="INFO reply: redis_version:7.0.0, no auth required")])
    assert v.pinned is True and v.decision == "confirmed"


def test_exploitable_critical_is_pinned():
    [v] = adjudicate([_sig("nvd", "CVE-2099-0001", reliability="medium",
                           cvss=9.8, exploit_available=True)])
    assert v.pinned is True and v.decision == "confirmed"


# ── Deterministic, exposure-aware impact ────────────────────────────────────────

def test_impact_kev_is_critical():
    [v] = adjudicate([_sig("nvd", "c", kev=True, cvss=5.0)])
    assert v.impact == "critical"


def test_private_exposure_demotes_impact():
    pub = adjudicate([_sig("nvd", "c", cvss=9.5, exposure={"reachability": "public"})])[0]
    prv = adjudicate([_sig("nvd", "c", cvss=9.5, exposure={"reachability": "private"})])[0]
    assert pub.impact == "critical"
    assert prv.impact == "high"          # demoted one band


def test_unknown_exposure_never_demotes():
    # Absence of reachability evidence is NOT evidence of safety.
    [v] = adjudicate([_sig("nvd", "c", cvss=9.5, exposure={"reachability": "unknown"})])
    assert v.impact == "critical"
