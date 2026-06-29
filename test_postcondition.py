"""Postcondition feedback (Phase 8c): effects become real ONLY under authorized successful execution."""
from src.reasoning.actions import Action, ActionDescriptor, ActionSemantics, Predicate, RiskTier
from src.reasoning.postcondition import ExecutionOutcome, assert_effects, proof_observation
from src.reasoning.state import ReasoningState


def _action(aid="verify", eff=("cve_confirmed",), risk=RiskTier.SAFE_ACTIVE):
    return Action(
        descriptor=ActionDescriptor(id=aid, risk_tier=risk, references=("CVE-2024-1",)),
        semantics=ActionSemantics(effects=tuple(Predicate.from_spec(e) for e in eff)))


# ── Effects are hypothetical by default ──

def test_effects_not_asserted_without_authorized_execution():
    a = _action()
    facts = {"version": "1.0"}
    # planning-only: not authorized → effects stay hypothetical
    out = assert_effects(a, facts, ExecutionOutcome(action_id="verify", authorized=False, succeeded=True))
    assert "cve_confirmed" not in out
    assert out == facts


def test_effects_not_asserted_on_authorized_failure():
    a = _action()
    out = assert_effects(a, {}, ExecutionOutcome(action_id="verify", authorized=True, succeeded=False))
    assert "cve_confirmed" not in out


# ── Effects asserted only under authorized success ──

def test_effects_asserted_under_authorized_success():
    a = _action()
    out = assert_effects(a, {}, ExecutionOutcome(action_id="verify", authorized=True, succeeded=True))
    assert out["cve_confirmed"] is True


def test_outcome_for_different_action_is_ignored():
    a = _action(aid="verify")
    out = assert_effects(a, {}, ExecutionOutcome(action_id="other", authorized=True, succeeded=True))
    assert out == {}


def test_returns_new_dict_never_mutates_input():
    a = _action()
    facts = {"x": 1}
    out = assert_effects(a, facts, ExecutionOutcome(action_id="verify", authorized=True, succeeded=True))
    assert facts == {"x": 1}          # input untouched
    assert out is not facts


# ── PoC is an Observation(kind="proof"), not a new hierarchy ──

def test_proof_observation_lands_in_evidence_graph():
    s = ReasoningState(target="ex.com:80", scope=["ex.com"])
    n = s.world.graph.upsert_node("service", "ex.com:80")
    kwargs = proof_observation(_action(), evidence="reflected boolean confirmed")
    obs = s.world.graph.observe(n, **kwargs)
    assert obs.kind == "proof"
    assert "CVE-2024-1" in obs.data["references"]
    # it's a normal observation — participates in snapshots/change-detection like any evidence
    snap = s.world.graph.snapshot()
    assert any(o.obs_kind == "proof" for o in snap.observations.values())
