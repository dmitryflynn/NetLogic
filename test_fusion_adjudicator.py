"""Tests for the AI adjudication pass (gray band only), with NO network.

The LLM call is injected via `complete`, so these are deterministic. They assert:
  • the prompt is label-stripped (no sensor names / severity scores leak),
  • the AI maps verdicts correctly (real→confirmed, fp→discarded),
  • the CODE-level safety floor: the AI can never discard a high/critical item,
  • fail-soft: AI errors / omissions → "potential", never dropped,
  • end-to-end: sensors → gate → gray band → AI → final decisions.
"""

import json

from src.fusion import Signal, adjudicate, run_adjudication
from src.fusion.adjudicator import build_user, parse_ai_response, apply_ai_verdicts, AIVerdict
from src.fusion.gate import gray_band


def _vuln(claim, **kw):
    # produce a gray verdict: a lone, non-high-reliability, high-impact signal goes gray
    s = Signal(source="nuclei", kind="vuln", claim=claim, host="h", port=80,
               reliability="medium", **kw)
    [v] = adjudicate([s])
    assert v.decision == "gray", (claim, v.decision, v.impact)
    return v


def _fake_complete(mapping):
    """Return a complete() that emits a JSON array from {id: (verdict, severity)}."""
    def complete(system, user):
        items = json.loads(user.split("```json", 1)[1].rsplit("```", 1)[0])
        out = []
        for it in items:
            verdict, severity = mapping.get(it["id"], ("uncertain", "low"))
            out.append({"id": it["id"], "verdict": verdict, "severity": severity,
                        "confidence": 0.9, "reason": "test", "benign_ruled_out": ["x"]})
        return "```json\n" + json.dumps(out) + "\n```"
    return complete


# ── Prompt hygiene ──────────────────────────────────────────────────────────────

def test_user_prompt_is_label_stripped():
    v = _vuln("acme-thing", cvss=8.0)
    v.signals[0].raw_metadata = {"source_secret": "nuclei-template-xyz"}
    user = build_user([v])
    assert "nuclei" not in user           # no sensor name
    assert "8.0" not in user and "cvss" not in user.lower()   # no severity scores
    # but the deterministic impact band + subject ARE present
    assert "deterministic_impact" in user and "acme-thing" in user


# ── Verdict mapping ─────────────────────────────────────────────────────────────

def test_real_becomes_confirmed():
    gray = [_vuln("a", cvss=8.0)]
    apply_ai_verdicts(gray, {0: AIVerdict("real", "high", 0.9, "demonstrated")})
    assert gray[0].decision == "confirmed"
    assert gray[0].ai.verdict == "real"


def test_false_positive_low_impact_is_discarded():
    # A lone medium-impact signal is auto-discarded by the GATE (never reaches the AI),
    # so to reach the gray band at medium impact it must be corroborated by 2 sources.
    sigs = [
        Signal(source="nuclei", kind="vuln", claim="a", host="h", port=80, cvss=5.0, reliability="medium"),
        Signal(source="banner", kind="vuln", claim="a", host="h", port=80, cvss=5.0, reliability="medium"),
    ]
    [v] = adjudicate(sigs)
    assert v.decision == "gray" and v.impact == "medium"
    apply_ai_verdicts([v], {0: AIVerdict("false_positive", "low", 0.9, "default page")})
    assert v.decision == "discarded"


def test_ai_cannot_discard_high_impact_item():
    # SAFETY: even if the AI says false_positive, a high/critical item is demoted to
    # "potential" (report + verify), never discarded.
    gray = [_vuln("a", cvss=9.8)]
    assert gray[0].impact == "critical"
    apply_ai_verdicts(gray, {0: AIVerdict("false_positive", "low", 0.99, "looks fake")})
    assert gray[0].decision == "potential"
    assert gray[0].ai_safety_override is True


def test_uncertain_becomes_potential():
    gray = [_vuln("a", cvss=8.0)]
    apply_ai_verdicts(gray, {0: AIVerdict("uncertain", "high", 0.4, "insufficient")})
    assert gray[0].decision == "potential"


def test_unjudged_item_defaults_to_potential_never_dropped():
    gray = [_vuln("a", cvss=8.0)]
    apply_ai_verdicts(gray, {})            # AI omitted it
    assert gray[0].decision == "potential"
    assert gray[0].ai is None


# ── Parsing robustness ──────────────────────────────────────────────────────────

def test_parse_tolerates_prose_and_fences():
    gray = [_vuln("a", cvss=8.0)]
    text = ("Sure! Here is my analysis:\n```json\n"
            '[{"id":0,"verdict":"real","severity":"high","confidence":0.8,'
            '"reason":"r","benign_ruled_out":[]}]\n```\nDone.')
    parsed = parse_ai_response(text, gray)
    assert parsed[0].verdict == "real"


def test_parse_ignores_out_of_range_and_bad_verdicts():
    gray = [_vuln("a", cvss=8.0)]
    text = '[{"id":5,"verdict":"real"},{"id":0,"verdict":"nonsense"}]'
    parsed = parse_ai_response(text, gray)
    assert 5 not in parsed                  # out of range dropped
    assert parsed[0].verdict == "uncertain" # unknown verdict normalized


# ── Fail-soft ───────────────────────────────────────────────────────────────────

def test_ai_exception_is_failsoft_to_potential():
    def boom(system, user):
        raise RuntimeError("provider 504")
    gray = [_vuln("a", cvss=9.0)]
    run_adjudication(gray, complete=boom)
    assert gray[0].decision == "potential"  # never crashes, never dropped


def test_no_gray_band_is_noop():
    # A KEV signal is pinned/confirmed → never gray → run_adjudication does nothing.
    [v] = adjudicate([Signal(source="nvd", kind="vuln", claim="CVE-x", host="h", port=1,
                             cvss=9.8, kev=True)])
    assert v.decision == "confirmed"
    out = run_adjudication([v], complete=lambda s, u: (_ for _ in ()).throw(AssertionError("called")))
    assert out[0].decision == "confirmed"   # complete() never invoked


# ── End to end ──────────────────────────────────────────────────────────────────

def test_end_to_end_sensor_gate_ai():
    # Two corroborating medium-reliability sensors on a high-impact subject → gray →
    # AI says real → confirmed. A separate KEV vuln stays pinned without the AI.
    sigs = [
        Signal(source="nuclei", kind="vuln", claim="CVE-A", host="h", port=80, cvss=8.1, reliability="medium"),
        Signal(source="banner", kind="vuln", claim="CVE-A", host="h", port=80, cvss=8.1, reliability="medium"),
        Signal(source="nvd", kind="vuln", claim="CVE-B", host="h", port=80, cvss=9.9, kev=True),
    ]
    verdicts = adjudicate(sigs)
    by = {v.claim: v for v in verdicts}
    assert by["CVE-A"].decision == "gray" and by["CVE-B"].decision == "confirmed"

    gray = gray_band(verdicts)
    ids = {v.claim: i for i, v in enumerate(gray)}
    run_adjudication(verdicts, complete=_fake_complete({ids["CVE-A"]: ("real", "high")}))
    assert by["CVE-A"].decision == "confirmed"
    assert by["CVE-B"].decision == "confirmed"   # untouched, still pinned
