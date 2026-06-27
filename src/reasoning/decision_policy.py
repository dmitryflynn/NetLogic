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
    """Abstract base for scheduling policies."""

    @abstractmethod
    def rank_actions(self, steps: list[SensorStep], ctx: StepContext,
                     seen: Optional[set] = None) -> list[RankedAction]:
        """Rank a list of SensorSteps by priority. Higher priority = better.

        Args:
            steps: Available SensorSteps to rank
            ctx: StepContext with current state + artifacts
            seen: Set of step names already tried (to skip)

        Returns:
            Sorted list of RankedActions (highest priority first), excluding seen
        """
        pass

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

    def explain(self) -> str:
        """Human-readable explanation of this policy."""
        return (
            f"DefaultDecisionPolicy(info_gain={self.info_gain_weight}, "
            f"entropy={self.entropy_weight}, budget={self.budget_weight}, "
            f"history={self.history_weight}): "
            "Combines information gain × entropy reduction ÷ (cost × history discount)"
        )
