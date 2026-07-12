"""
GoalPlanner (Phase 8a) — goal-directed investigation planning. ANALYSIS ONLY: executes nothing.

Given an `Objective` (a goal predicate) and the world's facts, it searches **strategies within the
current template stage** to build a plan whose actions chain (precondition satisfied, or satisfied by
an earlier action's effect) until the goal predicate holds. Attack-chain construction is just one
goal predicate; the planner does not special-case any goal.

Responsibilities are split (avoid a god object — a field/method tripwire test guards it):
  • `GoalPlanner`   — searches the strategy space (immutable plan states).
  • `PlanEvaluator` — scores a plan (impact ÷ cost ÷ risk).
  • `PlanExplainer` — human rationale.
  • `PlanCompiler`  — emits the immutable `InvestigationPlan`.

Search uses immutable states (`PartialPlan` → extended `PartialPlan` → `InvestigationPlan`) so it is
deterministic and replayable. The planner reads `facts`; it never probes or acts.
"""
from __future__ import annotations

from dataclasses import dataclass

from src.reasoning.actions import Action, Predicate, RiskTier, satisfied
from src.reasoning.objective import Objective
from src.reasoning.strategies import StrategyRegistry


# ── Immutable plan states ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PlannedStep:
    """One step of a plan: the action, what satisfied it, what it would establish."""
    action_id: str
    risk_tier: str
    satisfied_by: tuple[str, ...]        # precondition keys that held
    establishes: tuple[str, ...]         # effect keys it would set
    strategy_id: str = ""
    rationale: str = ""

    def to_dict(self) -> dict:
        return {"action_id": self.action_id, "risk_tier": self.risk_tier,
                "satisfied_by": list(self.satisfied_by), "establishes": list(self.establishes),
                "strategy_id": self.strategy_id, "rationale": self.rationale}


@dataclass(frozen=True)
class PartialPlan:
    """An immutable search state: steps so far + the (hypothetical) facts after them."""
    steps: tuple[PlannedStep, ...] = ()
    facts: tuple = ()                    # frozenset-able items of the facts dict

    @classmethod
    def start(cls, facts: dict) -> "PartialPlan":
        return cls(steps=(), facts=tuple(sorted(facts.items(), key=lambda kv: str(kv[0]))))

    def facts_dict(self) -> dict:
        return dict(self.facts)

    def extend(self, step: PlannedStep, new_facts: dict) -> "PartialPlan":
        return PartialPlan(steps=self.steps + (step,),
                           facts=tuple(sorted(new_facts.items(), key=lambda kv: str(kv[0]))))


@dataclass(frozen=True)
class InvestigationPlan:
    """The compiled, immutable output. Pure analysis — nothing here was executed."""
    objective: str
    goal_reachable: bool
    steps: tuple[PlannedStep, ...] = ()
    unmet_preconditions: tuple[str, ...] = ()    # → objective seeds (read-only evidence to gather)
    max_risk_tier: str = "read_only"
    score: float = 0.0
    rationale: str = ""

    @property
    def is_empty(self) -> bool:
        return not self.steps

    def to_dict(self) -> dict:
        return {"objective": self.objective, "goal_reachable": self.goal_reachable,
                "steps": [s.to_dict() for s in self.steps],
                "unmet_preconditions": list(self.unmet_preconditions),
                "max_risk_tier": self.max_risk_tier, "score": self.score, "rationale": self.rationale}


def _goal_class(objective: Objective) -> str:
    """The predicate class to plan for: the goal predicate's key, else the objective name prefix."""
    if objective.goal_predicate:
        first = objective.goal_predicate[0]
        if isinstance(first, dict):
            return str(first.get("key", "")).split(":", 1)[0]
        return str(first).split("=", 1)[0].split(":", 1)[0]
    return objective.name.split(":", 1)[0]


# ── Evaluator / Explainer / Compiler (separate concerns) ─────────────────────────────

class PlanEvaluator:
    """Scores a plan: more goal progress + lower cost + lower risk = higher score."""
    _RISK_PENALTY = {"read_only": 1.0, "safe_active": 1.3, "intrusive": 2.0, "exploit": 3.0}

    def score(self, steps: tuple[PlannedStep, ...], reachable: bool) -> float:
        if not steps:
            return 0.0
        risk = max(self._RISK_PENALTY.get(s.risk_tier, 1.0) for s in steps)
        base = (2.0 if reachable else 1.0) * len({k for s in steps for k in s.establishes})
        return round(base / (len(steps) * risk), 4)


class PlanExplainer:
    """Human rationale for a plan."""

    def explain(self, objective: Objective, steps: tuple[PlannedStep, ...], reachable: bool) -> str:
        if not steps:
            return f"No plan found for {objective.name}."
        verb = "would satisfy" if reachable else "would make progress toward"
        chain = " → ".join(s.action_id for s in steps)
        return f"{len(steps)}-step plan {verb} {objective.name}: {chain}."


class PlanCompiler:
    """Emits the immutable InvestigationPlan from a finished search."""

    def __init__(self, evaluator: PlanEvaluator | None = None,
                 explainer: PlanExplainer | None = None) -> None:
        self._eval = evaluator or PlanEvaluator()
        self._explain = explainer or PlanExplainer()

    def compile(self, objective: Objective, plan: PartialPlan, reachable: bool,
                unmet: list[str]) -> InvestigationPlan:
        steps = plan.steps
        max_risk = max((s.risk_tier for s in steps), default="read_only",
                       key=lambda t: RiskTier.parse(t))
        return InvestigationPlan(
            objective=objective.name, goal_reachable=reachable, steps=steps,
            unmet_preconditions=tuple(sorted(set(unmet))),
            max_risk_tier=max_risk if steps else "read_only",
            score=self._eval.score(steps, reachable),
            rationale=self._explain.explain(objective, steps, reachable))


# ── GoalPlanner (search only) ────────────────────────────────────────────────────────

class GoalPlanner:
    """Searches strategy space to satisfy an objective's goal predicate. Executes nothing."""

    def __init__(self, registry: StrategyRegistry, compiler: PlanCompiler | None = None) -> None:
        self._registry = registry
        self._compiler = compiler or PlanCompiler()

    def plan(self, objective: Objective, facts: dict, memory=None) -> InvestigationPlan:
        """Build a plan reaching the objective's goal predicate from `facts`. Pure analysis.

        If `memory` (InvestigationMemory) is given, strategies that already FAILED for this goal
        while the world is unchanged are skipped (re-eligible once the world's fingerprint moves).
        """
        goal_preds = [Predicate.from_spec(p) for p in objective.goal_predicate]
        goal_class = _goal_class(objective)
        template = self._registry.template_for(goal_class)
        stage = template.first_stage()
        risk_ceiling = RiskTier.parse(objective.risk_budget)
        max_steps = int(objective.constraints.get("max_steps", 8))

        state = PartialPlan.start(facts)
        unmet: list[str] = []

        def goal_met(f: dict) -> bool:
            return satisfied(goal_preds, f) if goal_preds else False

        while not goal_met(state.facts_dict()) and len(state.steps) < max_steps:
            progressed = False
            for strat in sorted(self._registry.strategies_for(goal_class, stage), key=lambda s: s.id):
                facts = state.facts_dict()
                if memory is not None and memory.should_skip(objective.name, strat.id, facts):
                    continue                          # already failed here; world unchanged
                if not strat.applies(facts):
                    continue
                for action in strat.generate_plan(facts):
                    if action.risk_tier > risk_ceiling:
                        continue                      # respect the objective's risk budget
                    if action.applicable(facts):
                        new_facts = action.apply(facts)
                        if new_facts != facts:
                            state = state.extend(self._step(action, facts, strat.id), new_facts)
                            progressed = True
                            break
                    else:
                        unmet.extend(p.key for p in action.semantics.preconditions
                                     if not p.evaluate(facts))
                if progressed:
                    break
            if not progressed:
                nxt = template.next_stage(stage)
                if nxt is not None:
                    stage = nxt
                    continue
                break

        reachable = goal_met(state.facts_dict())
        return self._compiler.compile(objective, state, reachable, unmet)

    @staticmethod
    def _step(action: Action, facts: dict, strategy_id: str) -> PlannedStep:
        return PlannedStep(
            action_id=action.id, risk_tier=action.risk_tier.name.lower(),
            satisfied_by=tuple(p.key for p in action.semantics.preconditions if p.evaluate(facts)),
            establishes=tuple(e.key for e in action.semantics.effects),
            strategy_id=strategy_id,
            rationale=f"{strategy_id}:{action.id}")
