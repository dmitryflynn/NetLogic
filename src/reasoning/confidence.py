"""
ConfidenceEngine — derives beliefs and confidence from observations/signals.

See the Phase 1 plan. This is the truth model's single writer of confidence: it reads the
evidence (as `fusion.Signal`s, the interpreted observations) and computes a posterior per
claim. It never mutates node identity or observations.

Confidence is computed, never hand-set:
  • independent corroborating sources raise it (noisy-OR over distinct sources),
  • `probe_confirmed` / `kev` pin it high,
  • `version_matched` with no probe/KEV CAPS it below "confirmed" — patch level is
    unverifiable from a banner. This is the permanent, single home of the version-only rule
    (Phase 0 added stop-gaps in gate.py / adjudicator.py; those remain until the Phase 2 loop
    consumes this engine, at which point they collapse into this one).
  • confidence decays with age / on conflicting evidence.

Reuses `fusion/gate.py::_impact_of` for the deterministic impact band and the `Signal`
impact inputs (kev/epss/cvss/exploit/version_matched/probe_confirmed).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from src.fusion.gate import _impact_of
from src.fusion.signals import Signal

# Version-only findings can be "likely" but never "confirmed" from a banner alone.
_VERSION_ONLY_CAP = 0.60
_PIN_CONFIDENCE = 0.97
# Default decay half-life (seconds). At the moment of a scan, age≈0 → no effect, so this is
# inert for a single scan and only matters for long-lived / re-scanned state (design §10.1).
_DEFAULT_HALF_LIFE = 7 * 24 * 3600.0


@dataclass
class Belief:
    """A derived interpretation of evidence about a claim, with computed confidence."""
    claim: str
    node_id: str
    confidence: float
    impact: str
    rule_applied: str
    supporting: list = field(default_factory=list)   # source names that corroborate
    version_only: bool = False

    def to_dict(self) -> dict:
        return {"claim": self.claim, "node_id": self.node_id, "confidence": self.confidence,
                "impact": self.impact, "rule_applied": self.rule_applied,
                "supporting": list(self.supporting), "version_only": self.version_only}


def _noisy_or(confidences: list[float]) -> float:
    """Combine independent positive evidence: 1 - Π(1 - c_i). Corroboration raises."""
    prod = 1.0
    for c in confidences:
        prod *= (1.0 - max(0.0, min(1.0, c)))
    return 1.0 - prod


def apply_decay(confidence: float, age_seconds: float,
                half_life: float = _DEFAULT_HALF_LIFE) -> float:
    """Exponential decay toward 0 with age. age=0 → unchanged."""
    if age_seconds <= 0 or half_life <= 0:
        return confidence
    return confidence * (0.5 ** (age_seconds / half_life))


class ConfidenceEngine:
    """Computes `Belief`s from `Signal`s. Pure and deterministic."""

    def belief_for(self, claim: str, node_id: str, signals: list[Signal]) -> Belief:
        """Compute the belief for one claim from its signals (all about the same subject)."""
        impact = _impact_of(signals)
        sources = {s.source for s in signals}
        # One representative confidence per independent source (max within a source).
        per_source: dict[str, float] = {}
        for s in signals:
            per_source[s.source] = max(per_source.get(s.source, 0.0), float(s.confidence))
        base = _noisy_or(list(per_source.values()))

        kev = any(s.kev for s in signals)
        probe = any(s.is_probe_confirmed for s in signals)
        version_only = (not kev and not probe and bool(signals)
                        and all(s.version_matched for s in signals))

        if kev:
            confidence, rule = max(base, _PIN_CONFIDENCE), "kev_pin"
        elif probe:
            confidence, rule = max(base, _PIN_CONFIDENCE), "probe_confirmed"
        elif version_only:
            confidence, rule = min(base, _VERSION_ONLY_CAP), "version_matched_cap"
        elif len(sources) >= 2:
            confidence, rule = base, "corroborated"
        else:
            confidence, rule = base, "single_source"

        return Belief(
            claim=claim, node_id=node_id, confidence=round(max(0.0, min(1.0, confidence)), 4),
            impact=impact, rule_applied=rule, supporting=sorted(sources),
            version_only=version_only,
        )

    def beliefs_from_signals(self, signals: list[Signal]) -> list[Belief]:
        """Group signals by subject and return one Belief each."""
        groups: dict[tuple, list[Signal]] = {}
        for s in signals:
            groups.setdefault(s.subject_key(), []).append(s)
        out: list[Belief] = []
        for group in groups.values():
            claim = group[0].claim
            # Node id for a vuln claim is cve:<id>; otherwise tech/service-ish.
            nid = _node_id_for(group[0])
            out.append(self.belief_for(claim, nid, group))
        return out


def _node_id_for(sig: Signal) -> str:
    """Best-effort EvidenceGraph node id for a signal's subject (mirrors evidence_graph.node_id)."""
    claim = (sig.claim or "").strip().lower()
    if claim.startswith("cve-"):
        return f"cve:{claim}"
    if sig.kind == "tech":
        return f"technology:{claim}"
    if sig.port is not None:
        return f"service:{sig.host}:{sig.port}".lower()
    return f"claim:{claim}"
