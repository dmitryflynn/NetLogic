"""Novel-vulnerability inference — deterministically REFUTE / mark LIKELY C1's novel hypotheses from
passive evidence. Never CONFIRMS (that needs active validation). No AI."""
from src.reasoning.novel_inference import NovelInferenceEngine, NovelRule
from src.reasoning.state import ReasoningState


def _state_with_novel(vuln_type, evidence):
    s = ReasoningState(target="ex.com:80", scope=["ex.com"])
    n = s.world.graph.upsert_node("service", "ex.com:80", label="ex.com:80")
    s.world.graph.observe(n, kind="http_headers", evidence=evidence, source="phase3")
    s.investigation.hypotheses.add_hypothesis(
        label=f"ai:novel:{vuln_type}", created_by="hypothesis_generator",
        likelihoods={"vulnerable": 0.4, "safe": 0.6}, reason=f"novel:{vuln_type}:ai")
    return s


def test_refutes_when_ruling_out_evidence_present():
    s = _state_with_novel("cache_poisoning", "HTTP/1.1 200 OK; Cache-Control: no-store")
    steps = NovelInferenceEngine().infer(s)
    assert any(st.decision == "refuted" for st in steps)
    h = s.investigation.hypotheses.all()[0]
    assert h.status == "refuted"


def test_marks_likely_when_suggestive_evidence_present():
    s = _state_with_novel("cache_poisoning", "HTTP/1.1 200 OK; X-Cache: HIT; Age: 42")
    steps = NovelInferenceEngine().infer(s)
    assert any(st.decision == "likely" for st in steps)
    # LIKELY never resolves — confirming exploitability needs active validation, out of scope here.
    assert s.investigation.hypotheses.all()[0].status == "active"


def test_never_confirms_from_passive_evidence():
    # Even overwhelming suggestive evidence never yields a "confirmed" status.
    s = _state_with_novel("cache_poisoning", "X-Cache: HIT; Age: 9; Vary: X-Forwarded-Host")
    steps = NovelInferenceEngine().infer(s)
    assert all(st.decision != "confirmed" for st in steps)
    assert s.investigation.hypotheses.all()[0].status != "confirmed"


def test_unknown_vuln_type_is_ignored():
    s = _state_with_novel("time_travel", "anything")
    assert NovelInferenceEngine().infer(s) == []
    assert s.investigation.hypotheses.all()[0].status == "active"


def test_no_matching_evidence_leaves_hypothesis_unresolved():
    s = _state_with_novel("cache_poisoning", "HTTP/1.1 200 OK; Content-Type: text/html")
    assert NovelInferenceEngine().infer(s) == []
    assert s.investigation.hypotheses.all()[0].status == "active"


def test_rules_are_swappable_data():
    custom = {"foo": NovelRule("foo", refute=("bar",))}
    s = _state_with_novel("foo", "here is bar in the evidence")
    steps = NovelInferenceEngine(custom).infer(s)
    assert steps and steps[0].decision == "refuted"


def test_only_touches_active_hypotheses():
    s = _state_with_novel("cache_poisoning", "Cache-Control: no-store")
    h = s.investigation.hypotheses.all()[0]
    s.investigation.hypotheses.resolve(h.id, "confirmed")   # already resolved elsewhere
    assert NovelInferenceEngine().infer(s) == []            # left alone
    assert s.investigation.hypotheses.all()[0].status == "confirmed"
