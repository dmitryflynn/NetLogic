"""
Learned patterns — cross-scan priors, completely isolated (Phase 5 revised, §6).

History informs *ordering*, never truth. This module reads the provenance graph (the
irreproducible Observation→Inference→Hypothesis core) to distil which evidence rules have
historically led to resolution, then emits `PriorityHint`s that nudge the DecisionPolicy's
candidate ordering.

Hard isolation invariant (enforced by tests):
  • Output is ONLY `PriorityHint`. The pipeline never writes confidence, hypotheses, evidence,
    beliefs, or objectives. Evidence owns beliefs; history owns priority — nothing crosses.
  • Raw `successes`/`attempts` counts are stored (not a derived rate) so the schema survives
    future changes. Persistence is deferred this phase (memory-only) to avoid churn while the
    surrounding abstractions settle.

Flow:  Provenance → PatternExtractor → CandidatePattern → PatternValidator → LearnedPattern
                                                                              ↓
                                                          PatternRecall → PriorityHint
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PriorityHint:
    """The ONLY thing history is allowed to produce. A pure ordering nudge."""
    tag: str                 # matched (case-insensitive substring) against candidate kind/rationale
    boost: float             # additive priority boost
    reason: str = ""


@dataclass(frozen=True)
class CandidatePattern:
    """A proposed pattern before validation."""
    rule: str                # the evidence rule that fired (e.g. "wordpress")
    confirmed: bool          # did it accompany a confirmed inference?


@dataclass
class LearnedPattern:
    """A validated cross-scan prior. Stores raw counts, derives the rate on demand."""
    rule: str
    successes: int = 0
    attempts: int = 0

    def success_rate(self) -> float:
        return self.successes / self.attempts if self.attempts else 0.0

    def to_dict(self) -> dict:
        return {"rule": self.rule, "successes": self.successes, "attempts": self.attempts}

    @classmethod
    def from_dict(cls, data: dict) -> "LearnedPattern":
        return cls(rule=data["rule"], successes=int(data.get("successes", 0)),
                   attempts=int(data.get("attempts", 0)))


class PatternExtractor:
    """Distils CandidatePatterns from a provenance graph. Read-only over provenance + state."""

    def extract(self, provenance: dict) -> list[CandidatePattern]:
        """Walk Observation→Inference→Hypothesis edges; a rule that fed a 'confirmed' inference
        is a successful pattern, otherwise an attempt. Pure function of the provenance dict."""
        confirmed_inferences = {
            e["inference_id"] for e in provenance.get("inference_hypothesis", [])
            if e.get("decision") == "confirmed"
        }
        seen_inference = {
            e["inference_id"] for e in provenance.get("inference_hypothesis", [])
        }
        out: list[CandidatePattern] = []
        for edge in provenance.get("obs_inference", []):
            rule = edge.get("rule", "")
            iid = edge.get("inference_id", "")
            if not rule or iid not in seen_inference:
                continue
            out.append(CandidatePattern(rule=rule, confirmed=iid in confirmed_inferences))
        return out


class PatternValidator:
    """Aggregates candidates into LearnedPatterns and keeps only those with enough support."""

    def __init__(self, min_attempts: int = 1, min_success_rate: float = 0.5) -> None:
        self.min_attempts = min_attempts
        self.min_success_rate = min_success_rate

    def validate(self, candidates: list[CandidatePattern],
                 existing: dict[str, LearnedPattern] | None = None) -> dict[str, LearnedPattern]:
        """Fold candidates into (a copy of) existing patterns, then filter by support.

        Each candidate is one attempt; a confirmed candidate is also one success. Returns the
        patterns that meet the support thresholds.
        """
        patterns: dict[str, LearnedPattern] = {
            r: LearnedPattern(rule=p.rule, successes=p.successes, attempts=p.attempts)
            for r, p in (existing or {}).items()
        }
        for c in candidates:
            lp = patterns.setdefault(c.rule, LearnedPattern(rule=c.rule))
            lp.attempts += 1
            if c.confirmed:
                lp.successes += 1
        return {r: lp for r, lp in patterns.items()
                if lp.attempts >= self.min_attempts and lp.success_rate() >= self.min_success_rate}


class PatternRecall:
    """Turns validated patterns into PriorityHints for the current cycle. Emits hints only."""

    def __init__(self, boost_scale: float = 1.0) -> None:
        self.boost_scale = boost_scale

    def hints(self, patterns: dict[str, LearnedPattern]) -> list[PriorityHint]:
        """One hint per validated pattern; boost proportional to historical success rate.

        This is the entire output surface of the learned-pattern subsystem — a list of ordering
        nudges. It reads no reasoning state and writes none.
        """
        hints: list[PriorityHint] = []
        for lp in patterns.values():
            if lp.attempts <= 0:
                continue
            hints.append(PriorityHint(
                tag=lp.rule,
                boost=self.boost_scale * lp.success_rate(),
                reason=f"history: {lp.successes}/{lp.attempts} confirmations for {lp.rule}"))
        return hints
