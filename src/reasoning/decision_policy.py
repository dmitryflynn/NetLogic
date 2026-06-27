"""
Decision Policy — formalized scheduling heuristics.

Instead of ad-hoc scheduler rules, DecisionPolicy abstracts the logic for ranking actions/
capabilities by combining entropy reduction, expected information gain, budget constraints,
and historical priors.

Design: Phase 5 §6. The Scheduler delegates to a pluggable DecisionPolicy (default is
DefaultDecisionPolicy). Different policies can be tested against the benchmark corpus.

Available policies:
- DefaultDecisionPolicy: combines entropy + info_gain + budget + history (Phase 5 default)
- GreedyPolicy: maximize info_gain only (future)
- EntropyPolicy: minimize entropy only (future)
- BudgetPolicy: minimize cost/probe (future)
- StealthPolicy: minimize observable traces (future)
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from src.reasoning.registry import SensorStep, StepContext
from src.reasoning.state import ReasoningState

log = logging.getLogger("netlogic.reasoning.decision_policy")

_HIGH_IMPACT = {"high", "critical"}
_CONTESTED_BELOW = 0.60  # Beliefs below this confidence are contested (worth resolving)


@dataclass
class RankedAction:
    """Result of policy ranking: a step with its score and explanation."""
    step: SensorStep
    priority: float
    rationale: str


class DecisionPolicy(ABC):
    """Abstract base for scheduling policies.

    Two ranking surfaces:
      • `rank_actions` — the Phase 2 SensorStep loop (direct probes).
      • `rank_candidates` — the Phase 3/5 unified `Candidate` pool (Intent-producing sources:
        generator / playbook / capability / history). Policies differ by `_score_candidate`,
        so genuinely different optimization objectives produce genuinely different orderings.
    """

    @abstractmethod
    def rank_actions(self, steps: list[SensorStep], ctx: StepContext,
                     seen: Optional[set] = None) -> list[RankedAction]:
        """Rank SensorSteps by priority (highest first), excluding `seen`."""
        pass

    @abstractmethod
    def _score_candidate(self, candidate) -> float:
        """Policy-specific scalar score for a Candidate. Higher = preferred.

        This is the single point where policies diverge: GreedyPolicy ignores cost,
        BudgetPolicy maximizes gain-per-cost, FastPolicy minimizes latency, etc.
        """
        pass

    def rank_candidates(self, candidates: list, *, exclude_unmet_prereqs: bool = True,
                        satisfied: Optional[set] = None) -> list:
        """Rank a heterogeneous `Candidate` pool. Source-agnostic.

        Returns a list of RankedCandidate, highest priority first. Candidates whose
        prerequisites are not in `satisfied` are dropped when `exclude_unmet_prereqs` is set.
        """
        from src.reasoning.candidate import RankedCandidate  # noqa: PLC0415
        satisfied = satisfied or set()
        ranked = []
        for c in candidates:
            if exclude_unmet_prereqs and c.prerequisites:
                if not set(c.prerequisites) <= satisfied:
                    continue
            score = self._score_candidate(c)
            ranked.append(RankedCandidate(
                candidate=c, priority=round(score, 4),
                rationale=f"policy={self.__class__.__name__} source={c.source} "
                          f"gain={c.expected_information_gain:.2f} cost={c.cost_factor():.1f}"))
        # Stable tie-break: by source then kind, so equal scores order deterministically.
        ranked.sort(key=lambda r: (-r.priority, r.candidate.source, r.candidate.kind))
        return ranked

    @abstractmethod
    def explain(self) -> str:
        """Human-readable explanation of this policy's logic."""
        pass

    def simulate(self, steps: list[SensorStep], ctx: StepContext) -> dict:
        """Simulate the policy without committing. For testing / analysis."""
        ranked = self.rank_actions(steps, ctx)
        return {
            "policy": self.__class__.__name__,
            "ranked_count": len(ranked),
            "top_choice": ranked[0].step.name if ranked else None,
            "top_priority": ranked[0].priority if ranked else None,
        }


class DefaultDecisionPolicy(DecisionPolicy):
    """Phase 5 default: combines entropy reduction, expected gain, cost, history."""

    def __init__(self, info_gain_weight: float = 1.0, entropy_weight: float = 0.5,
                 budget_weight: float = 1.0, history_weight: float = 0.25) -> None:
        """Initialize policy weights. All weights are > 0."""
        self.info_gain_weight = max(0.01, info_gain_weight)
        self.entropy_weight = max(0.01, entropy_weight)
        self.budget_weight = max(0.01, budget_weight)
        self.history_weight = max(0.01, history_weight)

    def rank_actions(self, steps: list[SensorStep], ctx: StepContext,
                     seen: Optional[set] = None) -> list[RankedAction]:
        """Rank steps by: info_gain × entropy_reduction ÷ (budget_cost × (1 - history_success))."""
        seen = seen or set()
        ranked = []

        for step in steps:
            if step.name in seen or not self._applies(step, ctx):
                continue

            score = self._score_step(step, ctx)
            if score is not None:
                ranked.append(score)

        ranked.sort(key=lambda a: a.priority, reverse=True)
        return ranked

    def _score_step(self, step: SensorStep, ctx: StepContext) -> Optional[RankedAction]:
        """Score a single step using the policy formula."""
        state = ctx.state

        # Information gain: base, doubled if step matches active persona
        info_gain = step.base_gain * (2.0 if step.persona == state.investigation.persona else 1.0)

        # Entropy reduction: how many contested beliefs this step could resolve
        contested = self._contested_beliefs(state)
        entropy_reduction = self._entropy_reduction(step, contested, state)

        # Budget cost factor (normalized to 1..N range)
        cost_factor = self._cost_factor(step.cost)

        # History factor: discount steps that have failed repeatedly
        history_discount = self._history_discount(step, ctx)

        # Final priority formula
        numerator = info_gain * entropy_reduction * self.info_gain_weight * self.entropy_weight
        denominator = cost_factor * history_discount * self.budget_weight * self.history_weight
        priority = numerator / max(0.01, denominator)

        rationale = (
            f"policy=default persona={state.investigation.persona} "
            f"gain={info_gain:.1f} entropy_red={entropy_reduction:.1f} "
            f"cost={cost_factor:.1f} history_discount={history_discount:.2f}"
        )

        return RankedAction(step=step, priority=round(priority, 4), rationale=rationale)

    def _contested_beliefs(self, state: ReasoningState) -> list[dict]:
        """High/critical beliefs whose confidence is still low."""
        return [
            b for b in state.world.belief_records
            if b.get("impact") in _HIGH_IMPACT
            and float(b.get("confidence", 1.0)) < _CONTESTED_BELOW
        ]

    def _entropy_reduction(self, step: SensorStep, contested: list[dict],
                          state: ReasoningState) -> float:
        """How many contested beliefs could this step resolve?"""
        if not step.resolves:
            return 1.0

        version_only = any(b.get("version_only") for b in contested)
        resolvable = sum(
            1 for b in contested
            if ("version_only" in step.resolves and b.get("version_only"))
            or ("cve" in step.resolves and str(b.get("claim", "")).lower().startswith("cve"))
        )

        return float(max(1, resolvable)) if (resolvable or version_only) else 0.5

    def _cost_factor(self, cost: dict) -> float:
        """Normalized cost: 1.0 is baseline, higher = more expensive."""
        return max(1.0, cost.get("time_ms", 0) / 1000.0
                       + cost.get("tokens", 0) / 1000.0
                       + cost.get("probes", 0))

    def _history_discount(self, step: SensorStep, ctx: StepContext) -> float:
        """Discount factor based on historical success. Default 1.0 (no discount)."""
        # TODO(Phase 5): Track step success rates in execution_history; discount failures
        return 1.0

    def _applies(self, step: SensorStep, ctx: StepContext) -> bool:
        """Check if step's guard applies to current state."""
        try:
            return bool(step.applies(ctx))
        except Exception:  # noqa: BLE001
            return False

    def _score_candidate(self, candidate) -> float:
        """Weighted *additive* blend of gain and cost.

        Additive (not ratio) so the weights genuinely change ordering — a global multiplicative
        weight would cancel and leave ordering invariant (that pure gain/cost ratio is BudgetPolicy).
        score = w_gain · gain − w_budget · cost_factor.
        """
        gain = self.info_gain_weight * candidate.expected_information_gain
        cost = self.budget_weight * candidate.cost_factor()
        return gain - cost

    def explain(self) -> str:
        """Human-readable explanation of this policy."""
        return (
            f"DefaultDecisionPolicy(info_gain={self.info_gain_weight}, "
            f"entropy={self.entropy_weight}, budget={self.budget_weight}, "
            f"history={self.history_weight}): "
            "Combines information gain × entropy reduction ÷ (cost × history discount)"
        )


# ── Alternative policies: genuinely different objectives (review point #2) ──
#
# Each overrides only `_score_candidate`, so the same candidate pool yields a different ordering
# per policy. They share the SensorStep path via DefaultDecisionPolicy so the live Phase 2 loop is
# unaffected unless a policy is explicitly injected.


class GreedyPolicy(DefaultDecisionPolicy):
    """Maximize expected information gain, ignoring cost. 'Learn the most, whatever it takes.'"""

    def _score_candidate(self, candidate) -> float:
        return candidate.expected_information_gain

    def explain(self) -> str:
        return "GreedyPolicy: rank by expected_information_gain only (cost ignored)."


class BudgetPolicy(DefaultDecisionPolicy):
    """Maximize information gain *per unit cost*. 'Best bang for the probe.'"""

    def _score_candidate(self, candidate) -> float:
        return candidate.expected_information_gain / max(0.01, candidate.cost_factor())

    def explain(self) -> str:
        return "BudgetPolicy: rank by expected_information_gain / cost_factor."


class FastPolicy(DefaultDecisionPolicy):
    """Minimize latency. 'Cheapest/fastest first', gain as tie-breaker via the stable sort."""

    def _score_candidate(self, candidate) -> float:
        # Higher score = lower latency. Invert estimated time.
        time_ms = max(1.0, float(candidate.estimated_cost.time_ms))
        return 1000.0 / time_ms

    def explain(self) -> str:
        return "FastPolicy: rank by inverse latency (fastest first)."
