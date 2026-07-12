"""Track C — the evaluation harness: cassette-based, deterministic, reproducible metrics
(precision, acceptance, rejection-by-stage, novelty, refutation coverage)."""
import json

from src.reasoning.ai import (
    Cassette, CounterfactualReasoner, HypothesisGenerator, VerifierContext, evaluate_agents,
    refutation_coverage,
)
from src.reasoning.objective import Objective
from src.reasoning.state import ReasoningState


def _state():
    s = ReasoningState(target="ex.com:80", scope=["ex.com"])
    s.world.graph.upsert_node("service", "ex.com:80", label="ex.com:80")
    s.investigation.objectives.add(Objective(name="identify_framework:ex.com:80"))
    s.investigation.hypotheses.add_hypothesis(label="framework_of:ex.com:80", created_by="rule",
                                              likelihoods={"wordpress": 0.7, "django": 0.3})
    return s


def _cassette():
    return Cassette({
        "hypothesis_generator": json.dumps([
            {"objective": "identify_framework:ex.com:80", "candidates": {"wordpress": 0.8, "x": 0.2},
             "novel": False, "information_gain": 2.0, "prob_correct": 0.7},
            {"objective": "novel:cache_poisoning", "candidates": {"vuln": 0.4, "safe": 0.6},
             "novel": True, "information_gain": 4.0, "prob_correct": 0.5},
            {"objective": "verify:GHOST", "candidates": {"a": 1.0}, "novel": False},   # rejected
        ]),
        "counterfactual_reasoner": json.dumps([
            {"refutes": "wordpress", "check": "no_wp_json", "information_gain": 3.0},
        ]),
    })


def test_metrics_are_computed_and_reproducible():
    cas = _cassette()
    ctx = VerifierContext(known_objectives=frozenset({"identify_framework:ex.com:80"}))
    agents = [
        HypothesisGenerator(cas.completer_for("hypothesis_generator")),
        CounterfactualReasoner(cas.completer_for("counterfactual_reasoner")),
    ]
    m1 = evaluate_agents(agents, _state(), ctx=ctx)
    m2 = evaluate_agents(agents, _state(), ctx=ctx)
    assert m1.to_dict() == m2.to_dict()   # deterministic given a cassette

    # 3 hypotheses + 1 refutation objective proposed; the fabricated verify:GHOST is rejected.
    assert m1.proposed == 4
    assert m1.rejected == 1
    assert m1.rejection_by_stage.get("semantic") == 1
    assert m1.accepted == 3
    assert 0.0 < m1.precision <= 1.0
    assert m1.novel_hypotheses == 1
    assert m1.refutation_objectives == 1


def test_precision_reflects_rejections():
    # A cassette where every hypothesis fabricates a deterministic objective -> precision 0.
    cas = Cassette({"hypothesis_generator": json.dumps([
        {"objective": "verify:FAKE1", "candidates": {"a": 1.0}},
        {"objective": "verify:FAKE2", "candidates": {"a": 1.0}},
    ])})
    ctx = VerifierContext(known_objectives=frozenset({"verify:REAL"}))
    m = evaluate_agents([HypothesisGenerator(cas.completer_for("hypothesis_generator"))],
                        _state(), ctx=ctx)
    assert m.proposed == 2 and m.accepted == 0 and m.precision == 0.0
    assert m.rejection_by_stage.get("semantic") == 2


def test_uncertainty_breakdown_marks_generated_hypotheses_possible():
    cas = Cassette({"hypothesis_generator": json.dumps([
        {"objective": "novel:x", "candidates": {"a": 1.0}, "novel": True},
    ])})
    m = evaluate_agents([HypothesisGenerator(cas.completer_for("hypothesis_generator"))],
                        _state(), ctx=VerifierContext())
    assert m.uncertainty_breakdown.get("possible") == 1


def test_refutation_coverage_metric():
    labels = ["framework_of:ex.com:80"]   # leading candidate is "wordpress"
    goals = ["refute:wordpress:no_wp_json", "refute:wordpress:no_rest_api"]
    # "wordpress" isn't literally in the label, so coverage requires matching on the candidate,
    # not the label text — this documents the current (label-substring) heuristic's limits.
    assert refutation_coverage([], goals) == 0.0
    assert 0.0 <= refutation_coverage(labels, goals) <= 1.0
    # A label that literally contains the refuted candidate is covered.
    assert refutation_coverage(["stack:wordpress:80"], goals) == 1.0


def test_empty_run_yields_zero_metrics_not_error():
    m = evaluate_agents([], _state(), ctx=VerifierContext())
    assert m.proposed == 0 and m.precision == 0.0 and m.acceptance_rate == 0.0
