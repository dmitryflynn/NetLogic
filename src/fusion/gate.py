"""
Fusion layer — the deterministic agreement gate.

This is the funnel that keeps AI cost proportional to *ambiguity*, not asset count,
and that makes the zero-false-negative-on-criticals guarantee ARCHITECTURAL rather
than a matter of prompt tuning. Given the Signals for a subject (host, port, claim),
it returns a Verdict with one of:

  • "confirmed"  — certain enough to report without spending an AI token, because
                   either it's PINNED (KEV / probe-confirmed → un-droppable) or
                   enough INDEPENDENT sensors corroborate it.
  • "discarded"  — a lone, low-reliability, low-impact signal with no corroboration.
  • "gray"       — everything in between → this (and only this) is handed to the AI.

Key invariants:
  • Independence is counted across distinct sensor *sources* (a banner + a nuclei +
    a probe = 3; two nuclei templates = 1 source of agreement).
  • PINNED verdicts can NEVER be "discarded" or "gray" — the AI is structurally
    incapable of suppressing a KEV/probe-confirmed critical.
  • `impact` is computed deterministically from KEV/CVSS/EPSS/exploit + exposure,
    never from a sensor's self-declared severity.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from src.fusion.signals import Signal

# Independent corroborating sources needed to auto-confirm without the AI.
_AGREE_CONFIRM = 2
# EPSS at/above this is treated as "actively exploitable" for pinning.
_EPSS_PIN = 0.50

_IMPACT_ORDER = ("low", "medium", "high", "critical")


def _demote(impact: str, steps: int = 1) -> str:
    i = _IMPACT_ORDER.index(impact)
    return _IMPACT_ORDER[max(0, i - steps)]


@dataclass
class Verdict:
    host: str
    port: Optional[int]
    claim: str
    decision: str                  # "confirmed" | "discarded" | "gray"
    impact: str                    # "critical" | "high" | "medium" | "low"
    pinned: bool = False           # un-droppable (KEV / probe-confirmed)
    agreement: int = 0             # count of independent corroborating sources
    rationale: str = ""            # deterministic, human-readable why
    signals: list[Signal] = field(default_factory=list)

    def to_ai(self) -> dict:
        """Evidence bundle for the AI — only used when decision == 'gray'. Carries
        the label-stripped signal views plus the deterministic impact band (so the
        model knows the stakes) but never the sensor names or self-declared severities."""
        return {
            "host": self.host,
            "port": self.port,
            "subject": self.claim,
            "deterministic_impact": self.impact,
            "independent_corroboration": self.agreement,
            "evidence": [s.ai_view() for s in self.signals],
        }


def _impact_of(signals: list[Signal]) -> str:
    """Deterministic impact band from exploitation signals + exposure context."""
    if any(s.kev for s in signals) or any(s.cvss >= 9.0 for s in signals):
        base = "critical"
    elif any(s.cvss >= 7.0 or s.exploit_available or s.epss >= 0.30 for s in signals):
        base = "high"
    elif any(s.cvss >= 4.0 for s in signals):
        base = "medium"
    else:
        base = "low"

    # Exposure context: a private/internal-only reachability demotes one band
    # (still real, but lower real-world blast radius). "unknown" never demotes —
    # absence of reachability evidence is not evidence of safety.
    reach = {(s.exposure if isinstance(s.exposure, dict) else {}).get("reachability") for s in signals}
    if reach and reach <= {"private"}:  # every signal that has exposure says private
        base = _demote(base, 1)
    return base


def _is_version_only(signals: list[Signal]) -> bool:
    """True when every signal is a banner/version/pattern match and none is probe-confirmed.

    Pattern matches are investigation *leads*, never findings — the AI cannot
    confirm or deny patch level from a version string (distros backport fixes).
    """
    if not signals:
        return False
    return (
        all(s.version_matched for s in signals)
        and not any(s.is_probe_confirmed for s in signals)
    )


def _is_pinned(signals: list[Signal], impact: str) -> bool:
    """Un-droppable only on non-pattern evidence: probe confirmation, or KEV/exploit
    that is NOT pure version-match. Banner-only KEV never pins."""
    if any(s.is_probe_confirmed for s in signals):
        return True
    if _is_version_only(signals):
        return False
    # KEV / exploitable-critical with at least one non-version signal
    if any(s.kev for s in signals):
        return True
    if impact == "critical" and any(s.exploit_available or s.epss >= _EPSS_PIN for s in signals):
        return True
    return False


def _adjudicate_group(signals: list[Signal]) -> Verdict:
    host = signals[0].host
    port = signals[0].port
    claim = signals[0].claim
    impact = _impact_of(signals)
    sources = {s.source for s in signals}
    agreement = len(sources)
    has_high = any(s.reliability == "high" for s in signals)
    version_only = _is_version_only(signals)
    pinned = _is_pinned(signals, impact)

    # Pattern/version matches are NEVER findings. They may seed active validation
    # elsewhere, but must not enter confirmed/potential/gray report surfaces.
    if version_only:
        decision = "discarded"
        rationale = (
            "version/banner pattern match only — not a finding until actively verified "
            "(patch level unverifiable from a version string)"
        )
    elif pinned:
        decision, rationale = "confirmed", "pinned (probe-confirmed / non-pattern KEV) — un-droppable"
    elif agreement >= _AGREE_CONFIRM and has_high:
        decision = "confirmed"
        rationale = f"{agreement} independent sources corroborate, ≥1 high-reliability"
    elif agreement <= 1 and not has_high and impact in ("low", "medium") and not pinned:
        # Lone, low/medium-impact, no high-reliability sensor, no corroboration → noise.
        # Note: anything high/critical is never auto-discarded — it goes to the AI.
        decision = "discarded"
        rationale = "single low-reliability signal, no corroboration, low impact"
    else:
        decision = "gray"
        rationale = "ambiguous — corroboration/impact in the gray band → AI adjudication"

    return Verdict(
        host=host, port=port, claim=claim, decision=decision, impact=impact,
        pinned=pinned, agreement=agreement, rationale=rationale, signals=list(signals),
    )


def adjudicate(signals: list[Signal]) -> list[Verdict]:
    """Group signals by subject and return one Verdict per subject.

    This is pure, deterministic, and offline. Only verdicts with decision == 'gray'
    should ever reach the AI; 'confirmed'/'discarded' are decided here for free.
    """
    groups: dict[tuple, list[Signal]] = defaultdict(list)
    for s in signals:
        groups[s.subject_key()].append(s)
    return [_adjudicate_group(group) for group in groups.values()]


def gray_band(verdicts: list[Verdict]) -> list[Verdict]:
    """The only verdicts the AI should spend tokens on."""
    return [v for v in verdicts if v.decision == "gray"]


def confirmed(verdicts: list[Verdict]) -> list[Verdict]:
    """Everything that reaches the report (auto-confirmed + later AI-promoted)."""
    return [v for v in verdicts if v.decision == "confirmed"]
