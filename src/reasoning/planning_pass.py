"""
Phase 8 live wiring — run the GoalPlanner over the engine's objectives after reasoning completes.

ANALYSIS ONLY. This pass produces `InvestigationPlan`s made of **read-only** action descriptors; it
executes nothing. The Phase-8b `ActionGate` plus an (absent-by-default) external executor remain the
only path to anything above `read_only`, so nothing here can probe, mutate, or attack.

The deterministic engine already generates objectives (`verify:<cve>`, `identify_framework:<node>`,
`identify_service:<node>`). Those objectives carry an empty goal predicate, so on their own the
planner has nothing to reach. This pass maps each objective's goal *class* to a concrete goal fact,
derives the starting facts from the world's evidence graph, and asks the GoalPlanner for the
read-only investigation plan that would satisfy it. A small built-in `StrategyRegistry` seeds the
planner until knowledge packs ship their own strategies.

It is purely additive: it reads `state` and returns plan dicts; it never mutates beliefs, evidence,
hypotheses, or confidence. With reasoning off it is never called, so the byte-identical baseline holds.
"""
from __future__ import annotations

from src.reasoning.actions import (
    Action, ActionDescriptor, ActionSemantics, Predicate, RiskTier,
)
from src.reasoning.investigation_planner import GoalPlanner
from src.reasoning.objective import Objective
from src.reasoning.strategies import Strategy, StrategyRegistry

# The fact that means "this goal class is achieved" — the planner's target predicate.
_GOAL_FACT = {
    "identify_framework": "framework_known",
    "identify_service": "service_known",
    "verify": "cve_evidence_gathered",
}


def _act(aid: str, effect: str, *, pre: tuple = (), risk: RiskTier = RiskTier.READ_ONLY,
         refs: tuple = ()) -> Action:
    """A read-only action descriptor: preconditions → effect. Descriptors only — no payloads."""
    return Action(
        descriptor=ActionDescriptor(id=aid, risk_tier=risk, references=tuple(refs)),
        semantics=ActionSemantics(
            preconditions=tuple(Predicate.from_spec(p) for p in pre),
            effects=(Predicate.from_spec(effect),)))


def default_strategy_registry() -> StrategyRegistry:
    """Starter strategies for the goal classes the generator emits. All read-only.

    Each strategy is adaptive: `generate_plan(facts)` yields the next read-only step given what is
    already known, so the produced plan is the shortest evidence-gathering ladder to the goal fact.
    """
    reg = StrategyRegistry()
    # NOTE: the planner derives a goal's class from its goal-predicate KEY (see
    # investigation_planner._goal_class), so strategies are registered under the goal *fact*
    # (e.g. "framework_known"), not the objective-name prefix ("identify_framework").

    # framework_known — an HTTP fingerprint ladder: server header → headers → body.
    def _framework(facts: dict) -> list[Action]:
        if not facts.get("server_header_seen"):
            return [_act("read_server_header", "server_header_seen=true")]
        if not facts.get("http_headers_seen"):
            return [_act("read_http_headers", "http_headers_seen=true",
                         pre=("server_header_seen=true",))]
        return [_act("analyze_http_body", "framework_known=true",
                     pre=("http_headers_seen=true",))]
    reg.register_strategy(Strategy.deferred(
        "framework_fingerprint", "framework_known", _framework,
        expected_information_gain=1.5))

    # service_known — a single read-only banner grab.
    reg.register_strategy(Strategy.of_actions(
        "service_banner", "service_known",
        [_act("grab_banner", "service_known=true")]))

    # cve_evidence_gathered — match the version range, then assemble the read-only evidence bundle.
    def _cve(facts: dict) -> list[Action]:
        if not facts.get("version_known"):
            return [_act("match_version_range", "version_known=true")]
        return [_act("gather_cve_evidence", "cve_evidence_gathered=true",
                     pre=("version_known=true",))]
    reg.register_strategy(Strategy.deferred(
        "cve_evidence", "cve_evidence_gathered", _cve, expected_information_gain=2.0))

    return reg


def facts_from_world(state) -> dict:
    """Derive a flat facts dict from the evidence graph — what the engine already knows.

    Pure read of `state.world.graph`. The richer the evidence, the shorter the resulting plans
    (already-known goals yield 0-step reachable plans)."""
    # Facts use the string "true" to match the action-effect convention: an effect spec like
    # "framework_known=true" coerces its value to the string "true", and Action.apply writes that
    # string. Seeding booleans here would silently fail the `eq` predicate comparison.
    facts: dict = {}
    graph = getattr(getattr(state, "world", None), "graph", None)
    nodes = graph.nodes() if graph is not None and hasattr(graph, "nodes") else []
    for node in nodes:
        kind = getattr(node, "kind", "")
        attrs = getattr(node, "attrs", {}) or {}
        if kind == "technology":
            facts["framework_known"] = "true"
            facts["server_header_seen"] = "true"
            facts["http_headers_seen"] = "true"
        if kind == "service":
            if attrs.get("version") or attrs.get("product"):
                facts["version_known"] = "true"
        # A CVE node implies we already matched a version to raise it.
        if kind == "cve":
            facts["version_known"] = "true"
    return facts


def plan_investigations(state, *, max_plans: int = 12) -> list[dict]:
    """Run the GoalPlanner over the engine's objectives. Returns read-only InvestigationPlan dicts.

    Additive + analysis-only: reads objectives + world facts, returns plans. Mutates nothing."""
    registry = default_strategy_registry()
    planner = GoalPlanner(registry)
    facts = facts_from_world(state)
    plans: list[dict] = []
    for obj in state.investigation.objectives.all():
        goal_class = obj.name.split(":", 1)[0]
        goal_fact = _GOAL_FACT.get(goal_class)
        if goal_fact is None:
            continue
        planning_obj = Objective(
            name=obj.name,
            priority=obj.priority,
            goal_predicate=[f"{goal_fact}=true"],
            risk_budget="read_only",                 # surfaced plans never exceed read-only
            constraints={"max_steps": 6})
        plan = planner.plan(planning_obj, facts)
        if plan.steps or plan.unmet_preconditions:
            plans.append(plan.to_dict())
        if len(plans) >= max_plans:
            break
    return plans
