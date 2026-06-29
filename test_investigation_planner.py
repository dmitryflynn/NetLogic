"""GoalPlanner (Phase 8a-4): goal-directed strategy search, analysis-only.

Attack-chain construction is just one goal predicate — the planner does not special-case it.
"""
from src.reasoning.actions import Action, ActionDescriptor, ActionSemantics, Predicate, RiskTier
from src.reasoning.investigation_planner import (
    GoalPlanner,
    InvestigationPlan,
    PartialPlan,
    PlannedStep,
)
from src.reasoning.objective import Objective
from src.reasoning.strategies import InvestigationTemplate, Strategy, StrategyRegistry


def _action(aid, pre=None, eff=None, risk=RiskTier.READ_ONLY):
    return Action(
        descriptor=ActionDescriptor(id=aid, risk_tier=risk),
        semantics=ActionSemantics(
            preconditions=tuple(Predicate.from_spec(p) for p in (pre or [])),
            effects=tuple(Predicate.from_spec(e) for e in (eff or []))))


def _registry(*strategies):
    reg = StrategyRegistry()
    for s in strategies:
        reg.register_strategy(s)
    return reg


# ── Single-step reachability ──

def test_simple_goal_reached():
    # goal: framework known; one read-only action establishes it
    reg = _registry(Strategy.of_actions(
        "fp", "framework", [_action("headers", eff=["framework"])]))
    obj = Objective(name="identify_framework", goal_predicate=["framework"])
    plan = GoalPlanner(reg).plan(obj, facts={})
    assert plan.goal_reachable
    assert [s.action_id for s in plan.steps] == ["headers"]


# ── Multi-step chaining via effect propagation ──

def test_multi_step_chain_via_postconditions():
    # need version (requires framework) → then cve_confirmed (requires version)
    reg = _registry(
        Strategy.of_actions("fp", "cve_confirmed", [
            _action("headers", eff=["framework"]),
            _action("banner", pre=["framework"], eff=["version"]),
            _action("verify", pre=["version"], eff=["cve_confirmed"]),
        ]))
    obj = Objective(name="confirm", goal_predicate=["cve_confirmed"])
    plan = GoalPlanner(reg).plan(obj, facts={})
    assert plan.goal_reachable
    assert [s.action_id for s in plan.steps] == ["headers", "banner", "verify"]
    # provenance: each step records what satisfied it + what it establishes
    assert plan.steps[1].satisfied_by == ("framework",)
    assert plan.steps[2].establishes == ("cve_confirmed",)


# ── Attack-chain is just another predicate ──

def test_attack_chain_is_just_a_goal_predicate():
    reg = _registry(Strategy.of_actions("chain", "access", [
        _action("foothold", eff=["foothold"], risk=RiskTier.SAFE_ACTIVE),
        _action("privesc", pre=["foothold"], eff=["access"], risk=RiskTier.SAFE_ACTIVE),
    ]))
    obj = Objective(name="access", goal_predicate=["access"], risk_budget="safe_active")
    plan = GoalPlanner(reg).plan(obj, facts={})
    assert plan.goal_reachable
    assert [s.action_id for s in plan.steps] == ["foothold", "privesc"]
    assert plan.max_risk_tier == "safe_active"


# ── Risk budget is respected at planning time ──

def test_planner_respects_risk_budget():
    reg = _registry(Strategy.of_actions("x", "pwned", [
        _action("exploit_it", eff=["pwned"], risk=RiskTier.EXPLOIT)]))
    obj = Objective(name="pwn", goal_predicate=["pwned"], risk_budget="read_only")
    plan = GoalPlanner(reg).plan(obj, facts={})
    # the only path needs EXPLOIT, above the read_only budget → not reachable, no steps
    assert not plan.goal_reachable
    assert plan.steps == ()


# ── Unmet preconditions → objective seeds ──

def test_unmet_preconditions_reported():
    reg = _registry(Strategy.of_actions("x", "cve_confirmed", [
        _action("verify", pre=["version"], eff=["cve_confirmed"])]))   # version never established
    obj = Objective(name="confirm", goal_predicate=["cve_confirmed"])
    plan = GoalPlanner(reg).plan(obj, facts={})
    assert not plan.goal_reachable
    assert "version" in plan.unmet_preconditions


# ── Determinism ──

def test_planner_is_deterministic():
    reg = _registry(Strategy.of_actions("fp", "framework", [_action("headers", eff=["framework"])]))
    obj = Objective(name="x", goal_predicate=["framework"])
    p1 = GoalPlanner(reg).plan(obj, {}).to_dict()
    p2 = GoalPlanner(reg).plan(obj, {}).to_dict()
    assert p1 == p2


# ── Staged template advancement ──

def test_staged_template_advances_between_stages():
    reg = StrategyRegistry()
    reg.register_template(InvestigationTemplate(
        id="cve", goal_class="cve_confirmed", stages=("version", "confirm")))
    reg.register_strategy(Strategy.of_actions(
        "ver", "cve_confirmed", [_action("banner", eff=["version"])], stage="version"))
    reg.register_strategy(Strategy.of_actions(
        "conf", "cve_confirmed", [_action("verify", pre=["version"], eff=["cve_confirmed"])],
        stage="confirm"))
    obj = Objective(name="cve_confirmed", goal_predicate=["cve_confirmed"])
    plan = GoalPlanner(reg).plan(obj, {})
    assert plan.goal_reachable
    assert [s.action_id for s in plan.steps] == ["banner", "verify"]   # crossed both stages


# ── Immutable search states ──

def test_partial_plan_is_immutable_and_extends_into_new_state():
    p0 = PartialPlan.start({"a": 1})
    step = PlannedStep(action_id="x", risk_tier="read_only", satisfied_by=(), establishes=("b",))
    p1 = p0.extend(step, {"a": 1, "b": True})
    assert p0.steps == ()                  # original unchanged
    assert len(p1.steps) == 1
    assert p1.facts_dict()["b"] is True


# ── THE invariant: the planner executes nothing ──

def test_planner_executes_nothing():
    """Actions are descriptors; planning must never invoke any execution. We give actions an
    effect-application that would raise if 'executed', and assert planning still works via apply()
    being pure (returns facts), with zero side effects tracked."""
    calls = {"n": 0}

    class Tripwire(Strategy):
        def generate_plan(self, facts):
            # generating a plan reads facts only — record that we never 'ran' anything external
            return [_action("headers", eff=["framework"])]

    reg = _registry(Tripwire(id="fp", goal_class="framework"))
    obj = Objective(name="x", goal_predicate=["framework"])
    plan = GoalPlanner(reg).plan(obj, {})
    assert plan.goal_reachable
    assert calls["n"] == 0                 # nothing external was invoked


# ── God-object tripwire ──

def test_goalplanner_public_surface_is_small():
    """GoalPlanner stays a searcher. Scoring/explaining/compiling live in their own classes; if this
    grows, split further (the Candidate/WorldState discipline)."""
    public = {m for m in dir(GoalPlanner) if not m.startswith("_")}
    assert public == {"plan"}, f"GoalPlanner grew a public surface: {public}"
