"""ConfidenceEngine: derived, recomputable confidence with the centralized version cap + decay."""
from src.fusion.signals import Signal
from src.reasoning.confidence import ConfidenceEngine, apply_decay

ENGINE = ConfidenceEngine()


def _sig(source, *, version_matched=False, probe_confirmed=False, kev=False, confidence=0.7,
         claim="cve-2024-1", cvss=9.0):
    return Signal(source=source, kind="vuln", claim=claim, host="h", port=80, service="http",
                  evidence="x", confidence=confidence, cvss=cvss,
                  version_matched=version_matched, probe_confirmed=probe_confirmed, kev=kev)


def test_corroboration_raises_above_single_source():
    one = ENGINE.belief_for("c", "cve:c", [_sig("nvd", confidence=0.7)])
    two = ENGINE.belief_for("c", "cve:c", [_sig("nvd", confidence=0.7), _sig("nuclei", confidence=0.7)])
    assert two.confidence > one.confidence
    assert two.rule_applied == "corroborated"


def test_version_only_caps_below_confirmed():
    b = ENGINE.belief_for("c", "cve:c", [_sig("nvd", version_matched=True, confidence=0.95),
                                         _sig("nuclei", version_matched=True, confidence=0.95)])
    assert b.rule_applied == "version_matched_cap"
    assert b.confidence <= 0.60          # cannot reach "confirmed" from banners alone
    assert b.version_only is True


def test_probe_confirmed_pins_high():
    b = ENGINE.belief_for("c", "cve:c", [_sig("probe", probe_confirmed=True, confidence=0.6)])
    assert b.rule_applied == "probe_confirmed"
    assert b.confidence >= 0.95


def test_kev_pins_high_even_if_version_matched():
    b = ENGINE.belief_for("c", "cve:c", [_sig("nvd", version_matched=True, kev=True, confidence=0.5)])
    assert b.rule_applied == "kev_pin"
    assert b.confidence >= 0.95
    assert b.version_only is False


def test_decay_reduces_an_aged_belief():
    fresh = apply_decay(0.8, age_seconds=0)
    aged = apply_decay(0.8, age_seconds=7 * 24 * 3600)   # one half-life
    assert fresh == 0.8
    assert abs(aged - 0.4) < 1e-6


def test_beliefs_from_signals_groups_by_subject():
    sigs = [_sig("nvd", claim="cve-a"), _sig("nuclei", claim="cve-a"), _sig("nvd", claim="cve-b")]
    beliefs = {b.claim: b for b in ENGINE.beliefs_from_signals(sigs)}
    assert set(beliefs) == {"cve-a", "cve-b"}
    assert beliefs["cve-a"].rule_applied == "corroborated"
