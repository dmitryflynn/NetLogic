"""Version-only CVEs must not be promoted to 'confirmed' by the AI.

A banner/version match cannot establish patch level (distros backport fixes without
bumping the version), so even when the AI says "real" the verdict is capped at
"potential" — unless an independent probe/KEV signal pins it.
"""
from src.fusion.adjudicator import AIVerdict, apply_ai_verdicts
from src.fusion.gate import Verdict
from src.fusion.signals import Signal


def _verdict(*, version_matched, probe_confirmed=False, kev=False, pinned=False):
    sig = Signal(
        source="nvd", kind="vuln", claim="cve-2021-40438", host="h", port=80,
        service="http", evidence="apache 2.4.7", cvss=9.8,
        version_matched=version_matched, probe_confirmed=probe_confirmed, kev=kev,
    )
    return Verdict(host="h", port=80, claim="cve-2021-40438", decision="gray",
                   impact="critical", pinned=pinned, agreement=1, signals=[sig])


def test_version_only_real_is_capped_at_potential():
    v = _verdict(version_matched=True)
    apply_ai_verdicts([v], {0: AIVerdict(verdict="real", confidence=0.9)})
    assert v.decision == "potential"
    assert v.ai_safety_override is True


def test_probe_confirmed_real_stays_confirmed():
    v = _verdict(version_matched=True, probe_confirmed=True)
    apply_ai_verdicts([v], {0: AIVerdict(verdict="real", confidence=0.9)})
    assert v.decision == "confirmed"


def test_non_version_real_stays_confirmed():
    v = _verdict(version_matched=False)
    apply_ai_verdicts([v], {0: AIVerdict(verdict="real", confidence=0.9)})
    assert v.decision == "confirmed"


def test_version_only_false_positive_still_demotes_not_confirms():
    v = _verdict(version_matched=True)
    apply_ai_verdicts([v], {0: AIVerdict(verdict="false_positive")})
    # high/critical false positives are kept as 'potential' (never silently dropped)
    assert v.decision == "potential"
