"""Architectural invariant guards (Phase 5 consolidation).

These protect *design properties*, not functions — tripwires that fail when a future change
quietly erodes an architectural boundary. Each maps to a specific review concern:

  • Candidate must stay a tiny, frozen contract (God-Object tripwire).
  • DecisionPolicy ranking must be pure: f(candidates) -> ordering, no side effects.
  • Playbook YAML is parsed once, never re-parsed at ranking time.
  • CapabilityRegistry must do something single-playbook metadata cannot (multi-implementation
    selection by applicability) — i.e. it has to earn its existence.
"""
import dataclasses as dc

import pytest

from src.reasoning.candidate import Candidate
from src.reasoning.capability_registry import Capability, CapabilityRegistry
from src.reasoning.decision_policy import DefaultDecisionPolicy, GreedyPolicy
from src.reasoning.intent import Intent, ProbeCost, StopCondition
from src.reasoning.playbooks import Playbook, PlaybookRegistry
from src.reasoning.probe_plan import Condition, ConditionOp
from src.reasoning.state import ReasoningState


# ── 1. Candidate stays a tiny, frozen contract ──

def test_candidate_is_frozen():
    assert Candidate.__dataclass_params__.frozen, "Candidate must be immutable"


def test_candidate_field_set_is_locked():
    """Tripwire: adding a field to Candidate must be a conscious decision, not accretion.
    If this fails, ask whether the new responsibility truly belongs on the contract or elsewhere
    (metadata, registries, provenance) — Candidate must not become a God Object."""
    fields = {f.name for f in dc.fields(Candidate)}
    assert fields == {
        "source", "kind", "expected_information_gain", "estimated_cost",
        "risk", "prerequisites", "rationale", "_factory",
    }, f"Candidate grew/shrank unexpectedly: {fields}"


# ── 2. DecisionPolicy ranking is pure ──

def _cand(kind, gain):
    return Candidate.deferred(source="s", kind=kind, factory=lambda: [Intent(goal=kind)], gain=gain)


def test_rank_candidates_does_not_mutate_inputs():
    pool = [_cand("a", 1.0), _cand("b", 3.0), _cand("c", 2.0)]
    snapshot = list(pool)
    GreedyPolicy().rank_candidates(pool)
    assert pool == snapshot, "ranking must not reorder/mutate the input list"
    # candidates are frozen, but assert identity preserved too
    assert all(p is s for p, s in zip(pool, snapshot))


def test_rank_actions_does_not_mutate_state():
    from src.reasoning.registry import SensorStep, StepContext
    state = ReasoningState(target="ex.com:443", scope=["ex.com:443"])
    state.world.belief_records = [{"claim": "cve-1", "kind": "cve", "impact": "high",
                                   "confidence": 0.3}]
    before = state.to_dict()
    ctx = StepContext(state=state, target="ex.com:443", art={}, emit=lambda *a, **k: None)
    steps = [SensorStep(name="s1", persona="service_discovery", run=lambda c: None,
                        base_gain=1.0, resolves=("cve",))]
    DefaultDecisionPolicy().rank_actions(steps, ctx)
    assert state.to_dict() == before, "ranking SensorSteps must not mutate reasoning state"


def test_ranking_is_idempotent():
    pool = [_cand("a", 1.0), _cand("b", 2.0)]
    p = GreedyPolicy()
    r1 = [r.candidate.kind for r in p.rank_candidates(pool)]
    r2 = [r.candidate.kind for r in p.rank_candidates(pool)]
    assert r1 == r2


# ── 3. Playbook YAML is parsed once, not at ranking time ──

def test_to_candidates_does_not_parse_yaml(monkeypatch):
    import src.reasoning.playbooks as pb_mod
    calls = {"n": 0}
    real = pb_mod.yaml.safe_load

    def counting_safe_load(*a, **k):
        calls["n"] += 1
        return real(*a, **k)
    monkeypatch.setattr(pb_mod.yaml, "safe_load", counting_safe_load)

    reg = PlaybookRegistry()
    reg.register(Playbook(id="p", name="P", trigger_rule=Condition(op=ConditionOp.TRUST),
                          intent_template=Intent(goal="g"),
                          default_stopping_condition=StopCondition()))
    state = ReasoningState(target="ex.com:80", scope=["ex.com:80"])

    # Ranking-time candidate emission must not touch the YAML parser.
    reg.to_candidates(state)
    reg.to_candidates(state)
    assert calls["n"] == 0, "to_candidates must not parse YAML — playbooks are loaded once"


# ── 4. CapabilityRegistry earns its existence (multi-implementation selection) ──

def test_capability_selects_among_multiple_implementations():
    """The differentiator vs. single-playbook metadata: one capability, TWO implementing
    playbooks, and the registry picks the APPLICABLE one. A lone playbook's metadata cannot
    express 'choose the right implementation for this state'."""
    state = ReasoningState(target="ex.com:80", scope=["ex.com:80"])
    state.investigation.objectives.add(
        __import__("src.reasoning.objective", fromlist=["Objective"]).Objective(
            name="identify_framework:ex.com:80"))

    # Two playbooks implement the same capability; only the second matches this state.
    pb_inactive = Playbook(
        id="impl_a", name="Impl A",
        trigger_rule=Condition(op=ConditionOp.CONTAINS, field="technologies", value="never"),
        intent_template=Intent(goal="A"), default_stopping_condition=StopCondition())
    pb_active = Playbook(
        id="impl_b", name="Impl B", trigger_rule=Condition(op=ConditionOp.TRUST),
        intent_template=Intent(goal="B"), default_stopping_condition=StopCondition())

    pb_reg = PlaybookRegistry()
    pb_reg.register(pb_inactive)
    pb_reg.register(pb_active)

    cap_reg = CapabilityRegistry()
    cap_reg.register(Capability(
        id="resolve_cms", name="Resolve CMS", produces=("identify_framework",),
        expected_information_gain=4.0,
        implemented_by_playbooks=("impl_a", "impl_b")))

    candidates = cap_reg.to_candidates(state, pb_reg)
    assert len(candidates) == 1
    # It chose the applicable implementation (impl_b), proving the registry's unique value.
    assert "impl_b" in candidates[0].rationale
    assert candidates[0].instantiate()[0].goal == "B"
