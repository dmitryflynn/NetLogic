"""
Scheduler — information-gain action selection.

See the Phase 2 plan §2 and design §5. Scores every candidate action and returns the best,
subject to the StrategyManager's explore/exploit policy. In Phase 2 ExpectedInformationGain is a
deterministic heuristic over the current beliefs (the hypothesis-entropy version is Phase 3).

    Priority(action) = (ExpectedInfoGain × ConfidenceReduction) ÷ (Cost × Time × Tokens × ProbeRisk)

The math is deterministic Python; the model never sets a priority.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Optional

from src.reasoning.registry import SensorStep, StepContext
from src.reasoning.state import ReasoningState

_HIGH_IMPACT = {"high", "critical"}
# A belief is "contested" (worth resolving) below this confidence.
_CONTESTED_BELOW = 0.60


@dataclass
class ScoredAction:
    step: SensorStep
    priority: float
    rationale: str


def _contested_beliefs(state: ReasoningState) -> list[dict]:
    """High/critical beliefs whose confidence is still low — the loop's targets."""
    out = []
    for b in state.world.belief_records:
        if b.get("impact") in _HIGH_IMPACT and float(b.get("confidence", 1.0)) < _CONTESTED_BELOW:
            out.append(b)
    return out


def _cost_factor(cost: dict) -> float:
    return max(1.0, cost.get("time_ms", 0) / 1000.0
              + cost.get("tokens", 0) / 1000.0
              + cost.get("probes", 0))


class Scheduler:
    """Deterministic Priority ranking + explore/exploit selection."""

    def __init__(self, explore_reserve: float = 0.10, rng: Optional[random.Random] = None) -> None:
        self.explore_reserve = explore_reserve
        self._rng = rng or random.Random(1337)   # seeded → deterministic tests

    def score(self, step: SensorStep, ctx: StepContext) -> ScoredAction:
        state = ctx.state
        contested = _contested_beliefs(state)
        # ExpectedInfoGain: base, doubled if the step matches the active persona.
        gain = step.base_gain * (2.0 if step.persona == state.investigation.persona else 1.0)
        # ConfidenceReduction: how many contested beliefs this step could resolve.
        if step.resolves:
            version_only = any(b.get("version_only") for b in contested)
            resolvable = sum(
                1 for b in contested
                if ("version_only" in step.resolves and b.get("version_only"))
                or ("cve" in step.resolves and str(b.get("claim", "")).lower().startswith("cve"))
            )
            reduction = max(1, resolvable) if (resolvable or version_only) else 0.5
        else:
            reduction = 1.0
        priority = (gain * reduction) / _cost_factor(step.cost)
        rationale = (f"persona={state.investigation.persona} gain={gain:.1f} "
                     f"reduction={reduction} cost={_cost_factor(step.cost):.1f}")
        return ScoredAction(step=step, priority=round(priority, 4), rationale=rationale)

    def select(self, steps: list[SensorStep], ctx: StepContext,
               seen: Optional[set] = None) -> Optional[ScoredAction]:
        """Pick the highest-Priority applicable, unseen step. Reserve a fraction of the time
        for an exploratory (non-top) choice so the loop doesn't tunnel on one branch."""
        seen = seen or set()
        candidates = [
            self.score(s, ctx) for s in steps
            if s.name not in seen and _applies(s, ctx)
        ]
        if not candidates:
            return None
        candidates.sort(key=lambda a: a.priority, reverse=True)
        if len(candidates) > 1 and self._rng.random() < self.explore_reserve:
            choice = self._rng.choice(candidates[1:])
            choice.rationale += " [explore]"
            return choice
        return candidates[0]


def _applies(step: SensorStep, ctx: StepContext) -> bool:
    try:
        return bool(step.applies(ctx))
    except Exception:  # noqa: BLE001 — a bad guard must not crash scheduling
        return False
