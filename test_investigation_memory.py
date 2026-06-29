"""InvestigationMemory (Phase 8a-5): skip failed strategies until the world changes; isolation."""
from src.reasoning.actions import Action, ActionDescriptor, ActionSemantics, Predicate, RiskTier
from src.reasoning.investigation_memory import (
    InvestigationMemory,
    StrategyAttempt,
    world_fingerprint,
)
from src.reasoning.investigation_planner import GoalPlanner
from src.reasoning.objective import Objective
from src.reasoning.state import ReasoningState
from src.reasoning.strategies import Strategy, StrategyRegistry


def _action(aid, eff=None, risk=RiskTier.READ_ONLY):
    return Action(descriptor=ActionDescriptor(id=aid, risk_tier=risk),
                  semantics=ActionSemantics(
                      effects=tuple(Predicate.from_spec(e) for e in (eff or []))))


# ── Fingerprint ──

def test_world_fingerprint_stable_and_sensitive():
    assert world_fingerprint({"a": 1, "b": 2}) == world_fingerprint({"b": 2, "a": 1})  # order-insensitive
    assert world_fingerprint({"a": 1}) != world_fingerprint({"a": 2})                  # value-sensitive


# ── Skip-while-unchanged, re-eligible after change ──

def test_failed_strategy_skipped_until_world_changes():
    mem = InvestigationMemory()
    facts = {"http_ok": True}
    mem.record("identify_framework", "passive_fp", "failed", facts=facts)

    assert mem.should_skip("identify_framework", "passive_fp", facts)          # same world → skip
    changed = {"http_ok": True, "new_header": "x-powered-by"}                  # world moved (Phase-7 delta)
    assert not mem.should_skip("identify_framework", "passive_fp", changed)    # re-eligible


def test_succeeded_attempt_does_not_cause_skip():
    mem = InvestigationMemory()
    facts = {"http_ok": True}
    mem.record("g", "s", "succeeded", facts=facts)
    assert not mem.should_skip("g", "s", facts)        # only FAILED attempts skip


def test_different_strategy_not_skipped():
    mem = InvestigationMemory()
    facts = {"http_ok": True}
    mem.record("g", "s1", "failed", facts=facts)
    assert mem.should_skip("g", "s1", facts)
    assert not mem.should_skip("g", "s2", facts)


# ── Planner integration ──

def test_planner_skips_failed_strategy_then_re_attempts_after_change():
    reg = StrategyRegistry()
    reg.register_strategy(Strategy.of_actions("fp", "framework", [_action("headers", eff=["framework"])]))
    obj = Objective(name="framework", goal_predicate=["framework"])
    mem = InvestigationMemory()

    # Record that 'fp' failed in the starting world.
    mem.record("framework", "fp", "failed", facts={})
    plan_blocked = GoalPlanner(reg).plan(obj, facts={}, memory=mem)
    assert not plan_blocked.goal_reachable           # the only strategy is skipped → no plan

    # World changes → strategy eligible again → plan found.
    plan_ok = GoalPlanner(reg).plan(obj, facts={"world_moved": True}, memory=mem)
    assert plan_ok.goal_reachable


# ── Round-trip ──

def test_memory_round_trip():
    mem = InvestigationMemory()
    mem.record("g", "s", "failed", facts={"a": 1}, confidence_gained=0.0, cost=2.0)
    restored = InvestigationMemory.from_dict(mem.to_dict())
    assert restored.attempts_for("g")[0].strategy_id == "s"
    assert restored.attempts_for("g")[0].outcome == "failed"


# ── Isolation invariant ──

def test_memory_mutates_no_reasoning_state():
    s = ReasoningState(target="ex.com:80", scope=["ex.com"])
    s.world.beliefs = {"x": 0.5}
    hid = s.investigation.hypotheses.add_hypothesis(label="h", likelihoods={"a": 0.5, "b": 0.5})
    before_beliefs = dict(s.world.beliefs)
    before_hyp = {h.id: (h.status, dict(h.likelihoods)) for h in s.investigation.hypotheses.all()}

    mem = InvestigationMemory()
    mem.record("g", "strat", "failed", facts={"a": 1})
    mem.should_skip("g", "strat", {"a": 1})

    assert s.world.beliefs == before_beliefs
    assert {h.id: (h.status, dict(h.likelihoods)) for h in s.investigation.hypotheses.all()} == before_hyp
