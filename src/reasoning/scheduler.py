"""
Scheduler — information-gain action selection with pluggable decision policies.

See the Phase 2 plan §2 and design §5. Scores every candidate action and returns the best,
subject to the StrategyManager's explore/exploit policy. In Phase 2 ExpectedInformationGain is a
deterministic heuristic over the current beliefs (the hypothesis-entropy version is Phase 3).

Phase 5: DecisionPolicy abstraction separates heuristics from scheduling logic. Policies can be
swapped, tested, and A/B'd against the benchmark corpus without changing Scheduler.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Optional

from src.reasoning.registry import SensorStep, StepContext

_HIGH_IMPACT = {"high", "critical"}
# A belief is "contested" (worth resolving) below this confidence.
_CONTESTED_BELOW = 0.60


@dataclass
class ScoredAction:
    step: SensorStep
    priority: float
    rationale: str


class Scheduler:
    """Deterministic Priority ranking + explore/exploit selection with pluggable DecisionPolicy."""

    def __init__(self, explore_reserve: float = 0.10, rng: Optional[random.Random] = None,
                 policy = None) -> None:
        """Initialize Scheduler with a DecisionPolicy (default: DefaultDecisionPolicy)."""
        self.explore_reserve = explore_reserve
        self._rng = rng or random.Random(1337)   # seeded → deterministic tests

        # Phase 5: Lazy-import to avoid circular dependency
        if policy is None:
            from src.reasoning.decision_policy import DefaultDecisionPolicy  # noqa: PLC0415
            policy = DefaultDecisionPolicy()
        self.policy = policy

    def score(self, step: SensorStep, ctx: StepContext) -> ScoredAction:
        """Score a single step using the policy. (Kept for backward compatibility.)"""
        # Delegate to policy, convert RankedAction to ScoredAction
        from src.reasoning.decision_policy import RankedAction  # noqa: PLC0415
        ranked_list = self.policy.rank_actions([step], ctx)
        if ranked_list:
            r = ranked_list[0]
            return ScoredAction(step=r.step, priority=r.priority, rationale=r.rationale)
        return ScoredAction(step=step, priority=0.0, rationale="no score")

    def select(self, steps: list[SensorStep], ctx: StepContext,
               seen: Optional[set] = None) -> Optional[ScoredAction]:
        """Pick the highest-Priority applicable, unseen step. Reserve a fraction of the time
        for an exploratory (non-top) choice so the loop doesn't tunnel on one branch."""
        seen = seen or set()

        # Rank all steps using the policy
        ranked = self.policy.rank_actions(steps, ctx, seen)

        if not ranked:
            return None

        # Explore/exploit: pick explore_reserve % of the time from candidates[1:]
        if len(ranked) > 1 and self._rng.random() < self.explore_reserve:
            choice_idx = self._rng.randint(1, len(ranked) - 1)
            choice = ranked[choice_idx]
            # Convert RankedAction to ScoredAction
            scored = ScoredAction(step=choice.step, priority=choice.priority,
                                 rationale=choice.rationale + " [explore]")
            return scored

        # Pick the top choice
        top = ranked[0]
        return ScoredAction(step=top.step, priority=top.priority, rationale=top.rationale)
