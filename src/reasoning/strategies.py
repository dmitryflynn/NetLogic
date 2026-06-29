"""
Strategy + Investigation Template layer (Phase 8) — the planner's scaling abstraction.

The planner does NOT search hundreds of raw actions. It searches a handful of **strategies** within
the current **stage** of an **investigation template**:

    Objective (goal predicate)
        ↓
    InvestigationTemplate   ordered STAGES for a goal class  (light in 8a: a default single stage)
        ↓
    Strategy                an APPROACH: generate_plan(world) → conditional actions
        ↓
    Action                  descriptor + semantics

A Strategy is **declarative-but-adaptive**: it does not hold a static action list, it yields actions
*conditional on the current world facts* (try headers; if nothing, body; then JS; then TLS). That
keeps strategies branching without the planner hard-coding sequences, and keeps the search branching
factor tiny as knowledge packs grow.

Templates + strategies are authored as DATA (in knowledge/technology packs) and compiled once.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from src.reasoning.actions import Action, RiskTier


# A plan generator: given the current world facts, return the actions this strategy would attempt
# next. Pure and deterministic — it reads facts, it never executes.
PlanGen = Callable[[dict], list[Action]]


@dataclass
class Strategy:
    """A named approach to a class of goals. `generate_plan(world)` yields conditional actions."""
    id: str
    goal_class: str                      # which predicate class this addresses, e.g. "framework_known"
    stage: str = "default"               # which template stage this strategy belongs to
    applicability: tuple = ()            # Predicates that must hold for the strategy to apply at all
    cost: str = "low"
    expected_information_gain: float = 1.0
    _plan_gen: PlanGen | None = field(default=None, repr=False, compare=False)
    _actions: tuple[Action, ...] = ()    # fallback static actions if no generator given

    @property
    def max_risk_tier(self) -> RiskTier:
        acts = self._actions
        return max((a.risk_tier for a in acts), default=RiskTier.READ_ONLY)

    def applies(self, facts: dict) -> bool:
        from src.reasoning.actions import satisfied  # noqa: PLC0415
        return satisfied(self.applicability, facts)

    def generate_plan(self, facts: dict) -> list[Action]:
        """Conditional/adaptive: yield the CANDIDATE actions toward progress given the world —
        those whose effects aren't yet established. The planner decides applicability and records
        unmet preconditions, so an inapplicable-but-useful action surfaces what evidence is missing.
        Deterministic, reads facts only."""
        if self._plan_gen is not None:
            return list(self._plan_gen(facts) or [])
        return [a for a in self._actions if not _effects_hold(a, facts)]

    @classmethod
    def of_actions(cls, id: str, goal_class: str, actions: list[Action], **kw) -> "Strategy":
        return cls(id=id, goal_class=goal_class, _actions=tuple(actions), **kw)

    @classmethod
    def deferred(cls, id: str, goal_class: str, plan_gen: PlanGen, **kw) -> "Strategy":
        return cls(id=id, goal_class=goal_class, _plan_gen=plan_gen, **kw)


def _effects_hold(action: Action, facts: dict) -> bool:
    return all(e.evaluate(facts) for e in action.semantics.effects) if action.semantics.effects else False


@dataclass(frozen=True)
class InvestigationTemplate:
    """Ordered stages for a goal class. Light in 8a: most goals use a single default stage.

    Staged planning means the planner only enumerates the *current* stage's strategies, then advances
    when the stage's exit predicate holds — turning a complex goal into a structured workflow instead
    of one flat search. Richer multi-stage templating deepens in Phase 9; the seam exists now.
    """
    id: str
    goal_class: str
    stages: tuple[str, ...] = ("default",)   # ordered stage names

    def first_stage(self) -> str:
        return self.stages[0] if self.stages else "default"

    def next_stage(self, current: str) -> str | None:
        try:
            i = self.stages.index(current)
        except ValueError:
            return None
        return self.stages[i + 1] if i + 1 < len(self.stages) else None


class StrategyRegistry:
    """Catalog of strategies + templates, keyed by goal_class. Compiled once from pack data."""

    def __init__(self) -> None:
        self._by_class: dict[str, list[Strategy]] = {}
        self._templates: dict[str, InvestigationTemplate] = {}

    def register_strategy(self, strategy: Strategy) -> None:
        self._by_class.setdefault(strategy.goal_class, []).append(strategy)

    def register_template(self, template: InvestigationTemplate) -> None:
        self._templates[template.goal_class] = template

    def strategies_for(self, goal_class: str, stage: str | None = None) -> list[Strategy]:
        out = self._by_class.get(goal_class, [])
        if stage is not None:
            out = [s for s in out if s.stage == stage]
        return list(out)

    def template_for(self, goal_class: str) -> InvestigationTemplate:
        return self._templates.get(goal_class) or InvestigationTemplate(
            id=f"default:{goal_class}", goal_class=goal_class)
