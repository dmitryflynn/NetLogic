"""Version/pattern-matched CVEs are never findings.

A banner→NVD (or version-only) match cannot establish patch level. Distros
backport fixes without bumping the version string. Those signals are discarded
as findings — they may seed active validation elsewhere, but must not surface
as confirmed/potential in the report. Probe-confirmed evidence still promotes.
"""
from src.fusion.adjudicator import AIVerdict, apply_ai_verdicts
from src.fusion.gate import Verdict, adjudicate
from src.fusion.signals import Signal


def _nvd_sig(**kw):
    defaults = dict(
        source="nvd", kind="vuln", claim="cve-2021-40438", host="h", port=80,
        service="http", evidence="apache 2.4.7", cvss=9.8, version_matched=True,
    )
    defaults.update(kw)
    return Signal(**defaults)


def test_version_only_is_discarded_at_gate():
    [v] = adjudicate([_nvd_sig(kev=True, cvss=9.8)])
    assert v.decision == "discarded"
    assert "pattern" in v.rationale.lower() or "version" in v.rationale.lower()


def test_version_only_ai_real_is_discarded():
    v = Verdict(host="h", port=80, claim="cve-2021-40438", decision="gray",
                impact="critical", pinned=False, agreement=1,
                signals=[_nvd_sig()])
    apply_ai_verdicts([v], {0: AIVerdict(verdict="real", confidence=0.9)})
    assert v.decision == "discarded"
    assert v.ai_safety_override is True


def test_probe_confirmed_real_stays_confirmed():
    v = Verdict(host="h", port=80, claim="cve-2021-40438", decision="gray",
                impact="critical", pinned=False, agreement=1,
                signals=[_nvd_sig(probe_confirmed=True)])
    apply_ai_verdicts([v], {0: AIVerdict(verdict="real", confidence=0.9)})
    assert v.decision == "confirmed"


def test_non_version_real_stays_confirmed():
    v = Verdict(host="h", port=80, claim="exposed-admin", decision="gray",
                impact="high", pinned=False, agreement=1,
                signals=[Signal(source="probe", kind="misconfig", claim="exposed-admin",
                                host="h", port=80, reliability="medium",
                                version_matched=False, cvss=8.0)])
    apply_ai_verdicts([v], {0: AIVerdict(verdict="real", confidence=0.9)})
    assert v.decision == "confirmed"


def test_probe_signal_confirms_at_gate():
    [v] = adjudicate([
        Signal(source="probe", kind="vuln", claim="cve-2021-40438", host="h",
               port=80, reliability="high", cvss=9.8, exploit_available=True,
               version_matched=False),
    ])
    assert v.decision == "confirmed"
