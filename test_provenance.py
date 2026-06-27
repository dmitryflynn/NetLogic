"""Observation Provenance Graph (Phase 5 §1): the irreproducible Observation→Inference→
Hypothesis core. Verifies edge accuracy, transitive queries, deterministic replay, round-trip
serialization, and the read-only invariant (building provenance mutates no reasoning state)."""
from src.reasoning import ReasoningState
from src.reasoning.inference import InferenceEngine
from src.reasoning.objective import Objective
from src.reasoning.provenance import (
    ProvenanceBuilder,
    ProvenanceGraph,
    ProvenanceTracer,
    inference_step_id,
)

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


def test_inference_step_id_is_deterministic():
    a = inference_step_id("h1", "wordpress", "confirmed", "wp-content")
    b = inference_step_id("h1", "wordpress", "confirmed", "wp-content")
    c = inference_step_id("h1", "wordpress", "confirmed", "actuator")
    assert a == b           # pure function of content
    assert a != c           # different match → different id


def test_builds_observation_to_inference_to_hypothesis_edges():
    s, hid = _state()
    _observe(s, "X-Powered-By: WordPress; wp-content/themes/x")
    steps = InferenceEngine().infer(s)
    graph = ProvenanceBuilder().build(s, steps)

    # one inference→hypothesis edge for the confirmed hypothesis
    assert any(e.hypothesis_id == hid and e.decision == "confirmed"
               for e in graph.inference_hypothesis)
    # the wp-content observation is attributed to that inference
    assert graph.obs_inference, "expected observation→inference attribution"
    assert all(e.matched == "wp-content" for e in graph.obs_inference)


def test_tracer_hypothesis_to_observations():
    s, hid = _state()
    _observe(s, "wp-content/plugins/akismet")
    steps = InferenceEngine().infer(s)
    graph = ProvenanceBuilder().build(s, steps)
    tracer = ProvenanceTracer(graph)

    obs_ids = tracer.hypothesis_to_observations(hid)
    assert obs_ids, "hypothesis should trace back to at least one observation"
    # every traced obs_id is real (exists in the graph)
    real = {o.obs_id for node in s.world.graph.nodes() for o in node.observations()}
    assert obs_ids <= real


def test_tracer_forward_observation_to_hypotheses():
    s, hid = _state()
    _observe(s, "wp-content here")
    steps = InferenceEngine().infer(s)
    graph = ProvenanceBuilder().build(s, steps)
    tracer = ProvenanceTracer(graph)

    obs_id = next(o.obs_id for node in s.world.graph.nodes() for o in node.observations())
    assert hid in tracer.observation_to_hypotheses(obs_id)


def test_replay_is_byte_stable():
    s, _ = _state()
    _observe(s, "wp-content/themes/x")
    steps = InferenceEngine().infer(s)
    g1 = ProvenanceBuilder().build(s, steps).to_dict()
    g2 = ProvenanceBuilder().build(s, steps).to_dict()
    assert g1 == g2          # deterministic: replay yields identical provenance


def test_round_trip_serialization():
    s, _ = _state()
    _observe(s, "wp-content")
    steps = InferenceEngine().infer(s)
    graph = ProvenanceBuilder().build(s, steps)
    restored = ProvenanceGraph.from_dict(graph.to_dict())
    assert restored.to_dict() == graph.to_dict()


def test_building_provenance_mutates_nothing():
    s, hid = _state()
    s.world.beliefs = {"existing": 0.4}
    _observe(s, "wp-content")
    steps = InferenceEngine().infer(s)
    before_status = s.investigation.hypotheses.get(hid).status
    before_beliefs = dict(s.world.beliefs)

    ProvenanceBuilder().build(s, steps)

    # read-only: provenance construction perturbs no reasoning state
    assert s.investigation.hypotheses.get(hid).status == before_status
    assert s.world.beliefs == before_beliefs


def test_no_match_yields_no_obs_edges():
    s, _ = _state()
    _observe(s, "nothing of interest here")
    steps = InferenceEngine().infer(s)        # [] — no inference
    graph = ProvenanceBuilder().build(s, steps)
    assert graph.obs_inference == []
    assert graph.inference_hypothesis == []
