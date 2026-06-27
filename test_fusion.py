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


def test_version_matched_exploitable_critical_is_not_pinned():
    """Version-matched signals (e.g. Nuclei content matches) must not be pinned by
    EPSS/exploit alone — they remain candidate for patch-level verification."""
    [v] = adjudicate([_sig("nuclei", "CVE-2099-0001", reliability="medium",
                           cvss=9.8, epss=0.95, version_matched=True)])
    assert v.pinned is False
    # Lone + high-impact → gray (AI adjudication), never auto-confirmed
    assert v.decision == "gray"


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


# ══════════════════════════════════════════════════════════════════════════════
#  Further testing — grouping, anti-self-corroboration, boundaries, mixed
#  exposure, leak checks, and an invariant sweep across the input space.
# ══════════════════════════════════════════════════════════════════════════════

import itertools


# ── Grouping / subject identity ─────────────────────────────────────────────────

def test_empty_input_returns_no_verdicts():
    assert adjudicate([]) == []


def test_distinct_subjects_produce_separate_verdicts():
    sigs = [
        _sig("nuclei", "jenkins", port=8080),
        _sig("nuclei", "gitlab", port=443),
        _sig("nuclei", "jenkins", port=8443),   # same claim, different port = different subject
    ]
    verdicts = adjudicate(sigs)
    keys = {(v.claim, v.port) for v in verdicts}
    assert keys == {("jenkins", 8080), ("gitlab", 443), ("jenkins", 8443)}


def test_same_claim_different_port_does_not_corroborate():
    sigs = [
        _sig("banner", "jenkins", port=8080, reliability="high"),
        _sig("nuclei", "jenkins", port=8443),
    ]
    verdicts = adjudicate(sigs)
    assert all(v.agreement == 1 for v in verdicts)   # not fused across ports


def test_claim_is_normalized_for_grouping():
    # "Jenkins" / " jenkins " on the same host:port are the same subject → corroborate.
    sigs = [
        _sig("banner", "Jenkins", reliability="high"),
        _sig("nuclei", " jenkins "),
    ]
    [v] = adjudicate(sigs)
    assert v.agreement == 2


# ── Anti-self-corroboration (the critical anti-abuse invariant) ─────────────────

def test_one_noisy_tool_cannot_manufacture_consensus():
    # Five Nuclei matches for the same subject must count as ONE source of
    # agreement — a single tool can't auto-confirm itself into the report.
    sigs = [_sig("nuclei", "acme-panel", reliability="medium", cvss=8.0) for _ in range(5)]
    [v] = adjudicate(sigs)
    assert v.agreement == 1
    assert v.decision != "confirmed"        # high-impact + no corroboration → gray, not auto-confirm
    assert v.decision == "gray"


def test_two_low_reliability_sources_low_impact_go_to_ai_not_discarded():
    # Corroboration (2 sources) lifts it out of auto-discard even at low impact.
    sigs = [
        _sig("banner", "thing", reliability="low", cvss=0.0),
        _sig("wappalyzer", "thing", reliability="low", cvss=0.0),
    ]
    [v] = adjudicate(sigs)
    assert v.agreement == 2 and v.decision == "gray"


# ── Schema normalization & leak checks ──────────────────────────────────────────

def test_invalid_reliability_defaults_to_medium():
    assert Signal(source="x", kind="vuln", claim="c", host="h", reliability="bogus").reliability == "medium"


def test_confidence_is_clamped():
    assert _sig("probe", "c", confidence=5.0).confidence == 1.0
    assert _sig("probe", "c", confidence=-3.0).confidence == 0.0


def test_gray_to_ai_bundle_does_not_leak_source_or_scores():
    [v] = adjudicate([
        _sig("nuclei", "acme", reliability="medium", cvss=8.8, epss=0.4,
             evidence="weird banner", exposure={"reachability": "public"}),
        _sig("wappalyzer", "acme", reliability="medium", cvss=8.8),
    ])
    assert v.decision == "gray"
    blob = repr(v.to_ai())
    assert "nuclei" not in blob and "wappalyzer" not in blob
    assert "8.8" not in blob and "cvss" not in blob.lower()
    # but the deterministic impact band + evidence ARE present for the model
    assert v.to_ai()["deterministic_impact"] in ("high", "critical")
    assert any(e.get("evidence") == "weird banner" for e in v.to_ai()["evidence"])


# ── CVSS / EPSS boundaries ──────────────────────────────────────────────────────

def test_impact_boundaries():
    def imp(cvss=0.0, **kw):
        return adjudicate([_sig("nvd", "c", cvss=cvss, **kw)])[0].impact
    assert imp(cvss=9.0) == "critical"
    assert imp(cvss=8.99) == "high"
    assert imp(cvss=7.0) == "high"
    assert imp(cvss=6.99) == "medium"
    assert imp(cvss=4.0) == "medium"
    assert imp(cvss=3.99) == "low"
    assert imp(cvss=0.0, epss=0.30) == "high"     # high EPSS lifts to high
    assert imp(cvss=0.0, exploit_available=True) == "high"


# ── Mixed exposure ──────────────────────────────────────────────────────────────

def test_mixed_public_and_private_exposure_does_not_demote():
    [v] = adjudicate([
        _sig("nvd", "c", cvss=9.5, exposure={"reachability": "public"}),
        _sig("probe", "c", reliability="medium", cvss=9.5, exposure={"reachability": "private"}),
    ])
    assert v.impact == "critical"            # not every signal says private → no demote


def test_private_plus_missing_exposure_does_not_demote():
    # One signal private, one with no exposure info → can't conclude private-only.
    [v] = adjudicate([
        _sig("nvd", "c", cvss=9.5, exposure={"reachability": "private"}),
        _sig("banner", "c", reliability="medium", cvss=9.5),   # exposure=None
    ])
    assert v.impact == "critical"


# ── Invariant sweep — the safety guarantees must hold across the input space ─────

def test_safety_invariants_hold_across_input_space():
    sources    = ["probe", "banner", "nuclei", "nvd"]
    rels       = ["high", "medium", "low"]
    cvsses     = [0.0, 3.9, 4.0, 6.9, 7.0, 9.0, 9.8]
    kevs       = [False, True]
    exploits   = [False, True]
    epsss      = [0.0, 0.3, 0.5, 0.9]
    reaches    = [None, "public", "private", "unknown"]
    versioned  = [False, True]

    checked = 0
    for src, rel, cvss, kev, expl, epss, reach, vm in itertools.product(
        sources, rels, cvsses, kevs, exploits, epsss, reaches, versioned
    ):
        exposure = {"reachability": reach} if reach else None
        s = Signal(source=src, kind="vuln", claim="x", host="h", port=1,
                   reliability=rel, cvss=cvss, kev=kev,
                   exploit_available=expl, epss=epss, exposure=exposure,
                   version_matched=vm)
        [v] = adjudicate([s])
        checked += 1

        # 1. KEV is ALWAYS pinned+confirmed → zero false negatives on KEV.
        if kev:
            assert v.pinned and v.decision == "confirmed", (src, rel, cvss, kev)

        # 2. A high-reliability probe is always pinned+confirmed (ground truth).
        if src == "probe" and rel == "high":
            assert v.pinned and v.decision == "confirmed"

        # 3. PINNED ⇒ confirmed AND never visible to the AI (can't be suppressed).
        if v.pinned:
            assert v.decision == "confirmed"
            assert gray_band([v]) == []

        # 4. High/critical impact is NEVER silently discarded.
        if v.impact in ("high", "critical"):
            assert v.decision != "discarded", (src, rel, cvss, v.impact)

        # 5. A discard only happens for lone, low-reliability, low/medium-impact noise.
        if v.decision == "discarded":
            assert v.agreement <= 1
            assert v.impact in ("low", "medium")
            assert not any(sig.reliability == "high" for sig in v.signals)
            assert not v.pinned

        # 6. Decisions are always one of the three legal values.
        assert v.decision in ("confirmed", "discarded", "gray")

    assert checked == 4 * 3 * 7 * 2 * 2 * 4 * 4 * 2  # full cartesian product exercised
