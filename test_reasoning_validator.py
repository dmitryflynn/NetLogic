"""ReasoningValidator.audit: each integrity invariant + a clean state + EvidenceRequest contract."""
import dataclasses

import pytest

from src.reasoning import ReasoningState
from src.reasoning.objective import Objective
from src.reasoning.reasoning_validator import ReasoningValidator


def _errors(state):
    return {i.code for i in ReasoningValidator().audit(state) if i.severity in ("error", "fatal")}


def test_clean_state_has_no_errors():
    assert _errors(ReasoningState(target="ex.com")) == set()


def test_orphan_objective_dependency_is_error():
    s = ReasoningState()
    s.investigation.objectives.add(Objective(name="a", dependencies=["missing"]))
    assert "orphan-objective-dependency" in _errors(s)


def test_confirmed_hypothesis_without_evidence_is_error():
    s = ReasoningState()
    hid = s.investigation.hypotheses.add_hypothesis("h", likelihoods={"a": 0.5, "b": 0.5})
    s.investigation.hypotheses.resolve(hid, "confirmed")
    assert "confirmed-without-evidence" in _errors(s)


def test_confirmed_with_evidence_is_clean():
    s = ReasoningState()
    hid = s.investigation.hypotheses.add_hypothesis("h", likelihoods={"a": 0.5, "b": 0.5})
    s.investigation.hypotheses.resolve(hid, "confirmed", evidence_refs=["wp-content"])
    assert "confirmed-without-evidence" not in _errors(s)


def test_missing_belief_ref_is_only_a_warning():
    s = ReasoningState()
    s.investigation.hypotheses.add_hypothesis("h", belief_ref="nope")
    issues = ReasoningValidator().audit(s)
    refs = [i for i in issues if i.code == "missing-belief-ref"]
    assert refs and refs[0].severity == "warning"
    assert "missing-belief-ref" not in _errors(s)            # warnings don't fail


def test_dangling_explanation_evidence_id_is_warning():
    s = ReasoningState()
    s.execution.explanations.append({"evidence_ids": ["cve:does-not-exist"], "rule_applied": "x"})
    assert any(i.code == "dangling-evidence-id" for i in ReasoningValidator().audit(s))


def test_plan_graph_cycle_is_fatal():
    from src.reasoning.probe_plan import ProbePlan, ProbePlanGraph, ProbeSpec
    g = ProbePlanGraph()
    g.add(ProbePlan(spec=ProbeSpec(id="a"), depends_on=["b"]))
    g.add(ProbePlan(spec=ProbeSpec(id="b"), depends_on=["a"]))
    issues = ReasoningValidator.audit_plan_graph(g)
    assert any(i.code == "plan-graph-cycle" and i.severity == "fatal" for i in issues)


# ── §0: EvidenceRequest is a frozen public contract ──
def test_evidence_request_is_frozen_and_roundtrips():
    from src.reasoning.investigation_graph import EvidenceRequest
    req = EvidenceRequest(evidence_type="http_headers", target_ref="ex.com")
    assert req.id                                            # auto-id assigned despite frozen
    with pytest.raises(dataclasses.FrozenInstanceError):
        req.target_ref = "evil.com"
    assert EvidenceRequest.from_dict(req.to_dict()).evidence_type == "http_headers"
