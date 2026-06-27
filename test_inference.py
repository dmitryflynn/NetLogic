"""InferenceEngine: rule-pack-driven confirm/refute/contradiction from evidence content,
objective satisfaction, and the confidence single-owner invariant."""
from src.reasoning import ReasoningState
from src.reasoning.inference import InferenceEngine
from src.reasoning.objective import Objective

_OBJ = "identify_framework:ex.com:80"


def _state():
    s = ReasoningState(target="ex.com", scope=["ex.com"])
    s.investigation.objectives.add(Objective(name=_OBJ))
    hid = s.investigation.hypotheses.add_hypothesis(
        label="fw", likelihoods={"wordpress": 0.5, "spring_boot": 0.5}, reason=_OBJ)
    return s, hid


def _observe(s, evidence):
    n = s.world.graph.upsert_node("service", "ex.com:80")
    s.world.graph.observe(n, kind="http_headers", evidence=evidence, source="phase3")


def test_confirms_framework_and_satisfies_objective():
    s, hid = _state()
    _observe(s, "X-Powered-By: WordPress; wp-content/themes/x")
    steps = InferenceEngine().infer(s)
    assert any(st.decision == "confirmed" for st in steps)
    assert s.investigation.hypotheses.get(hid).status == "confirmed"
    assert s.investigation.objectives.get(_OBJ).satisfied
    assert s.investigation.hypotheses.get(hid).evidence_refs   # evidence attributed


def test_contradiction_when_two_frameworks_match():
    s, hid = _state()
    _observe(s, "wp-content here and x-application-context and /actuator there")
    steps = InferenceEngine().infer(s)
    assert any(st.decision == "contradiction" for st in steps)
    assert s.investigation.contradictions
    assert s.investigation.hypotheses.get(hid).status == "active"   # unresolved on conflict


def test_noop_without_matching_evidence():
    s, hid = _state()
    _observe(s, "nothing of interest in this response body")
    assert InferenceEngine().infer(s) == []
    assert s.investigation.hypotheses.get(hid).status == "active"


def test_inference_never_writes_confidence():
    s, hid = _state()
    s.world.beliefs = {"existing": 0.4}
    _observe(s, "wp-content")
    InferenceEngine().infer(s)
    # confidence remains owned by the ConfidenceEngine — inference must not touch beliefs
    assert s.world.beliefs == {"existing": 0.4}


def test_rules_are_loaded_declaratively():
    from src.reasoning.inference import RuleLoader
    rules = RuleLoader.load()
    assert "wordpress" in rules and "spring_boot" in rules
    assert "wp-content" in rules["wordpress"].confirm       # data-driven, no Python matcher
