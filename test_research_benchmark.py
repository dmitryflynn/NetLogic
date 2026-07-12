"""The research evaluation suite — comprehensive per-investigation metrics (investigation quality,
reasoning quality, cost, efficiency, and — with ground-truth labels — precision/recall). This is the
instrument that makes future components justify themselves with a number."""
import json

from src.reasoning.ai_benchmark import (
    ResearchReport, research_report, run_and_report, run_investigation,
)
from src.reasoning.state import ReasoningState
from src.reasoning.trace import ExecutionResult


def _stub_executor(spec):
    return ExecutionResult(success=True, data={},
                           evidence="x-powered-by: wordpress wp-content/themes; cache-control: no-store")


def _state_factory():
    s = ReasoningState(target="ex.com", scope=["ex.com"])
    s.world.belief_records = [{"claim": "cve-x", "confidence": 0.5, "impact": "critical",
                               "version_only": True}]
    s.world.beliefs = {"cve-x": 0.5}
    s.world.graph.upsert_node("service", "ex.com:80", label="ex.com:80")
    return s


class _Cassette:
    def __call__(self, system, user):
        if "DESIGN read-only" in system:
            return json.dumps({"required_evidence": ["http_headers", "http_body"], "information_gain": 3.0})
        if "REFUTATION" in system:
            return json.dumps([{"refutes": "wordpress", "check": "no_wp_json", "information_gain": 3.0}])
        return json.dumps([
            {"objective": "identify_framework:ex.com:80", "candidates": {"wordpress": 0.8, "drupal": 0.2},
             "novel": False, "information_gain": 2.5, "prob_correct": 0.7},
            {"objective": "novel:cache_poisoning", "candidates": {"vulnerable": 0.4, "safe": 0.6},
             "novel": True, "information_gain": 4.0, "prob_correct": 0.5},
        ])


def test_report_covers_all_metric_categories():
    r = run_and_report(_state_factory, completer=_Cassette(), executor=_stub_executor)
    assert isinstance(r, ResearchReport)
    d = r.to_dict()
    # every category is present
    for key in ("hypotheses", "confirmed", "refuted", "resolution_rate",       # investigation quality
                "uncertainty_reduction", "mean_entropy_remaining", "evidence_reuse",  # reasoning quality
                "probes", "runtime_s", "planner_iterations",                    # cost
                "uncertainty_reduction_per_probe", "resolved_per_probe"):       # efficiency
        assert key in d
    assert r.runtime_s > 0.0                       # real wall time was measured
    assert r.resolved >= 2                         # framework confirmed + cache_poisoning refuted
    assert r.uncertainty_reduction > 0.0           # resolving hypotheses eliminated entropy


def test_efficiency_ratios_are_consistent():
    r = run_and_report(_state_factory, completer=_Cassette(), executor=_stub_executor)
    if r.probes:
        assert abs(r.resolved_per_probe - r.resolved / r.probes) < 1e-6
        assert abs(r.uncertainty_reduction_per_probe - r.uncertainty_reduction / r.probes) < 1e-6


def test_precision_recall_with_ground_truth():
    # Truth: wordpress really present; cache poisoning really absent.
    gt = {"wordpress": True, "cache_poisoning": False}
    r = run_and_report(_state_factory, completer=_Cassette(), executor=_stub_executor, ground_truth=gt)
    # wordpress confirmed & true → TP; cache_poisoning refuted & false → correct rejection (not FN).
    assert r.true_positives == 1
    assert r.false_negatives == 0          # we did not wrongly rule out anything real
    assert r.precision == 1.0              # every confirmation we made was correct
    assert r.recall == 1.0


def test_precision_penalizes_a_wrong_confirmation():
    # Truth says wordpress is NOT present, but the engine confirmed it → a false positive.
    gt = {"wordpress": False, "cache_poisoning": False}
    r = run_and_report(_state_factory, completer=_Cassette(), executor=_stub_executor, ground_truth=gt)
    assert r.false_positives == 1
    assert r.precision == 0.0              # the one confirmation was wrong


def test_reliability_none_without_labels():
    r = run_and_report(_state_factory, completer=_Cassette(), executor=_stub_executor)
    assert r.precision is None and r.recall is None
    assert r.true_positives is None        # honestly absent — needs a labeled corpus


def test_deterministic_baseline_report_has_no_ai_gain():
    r = research_report(run_investigation(_state_factory, completer=None, executor=_stub_executor))
    assert r.est_information_gain == 0.0    # no AI ⇒ no proposal-economy gain recorded
    assert r.refuted == 0                   # deterministic baseline invents no novel vulns to refute


def test_time_to_first_confirmation_measured_when_a_hypothesis_confirms():
    from src.reasoning.state import ReasoningState
    s = ReasoningState(target="ex.com:80", scope=["ex.com"])
    hid = s.investigation.hypotheses.add_hypothesis(label="framework_of:svc", created_by="rule",
                                                    likelihoods={"express": 0.5, "nginx": 0.5})
    s.investigation.hypotheses.resolve(hid, "confirmed")     # stamps resolved_at
    r = research_report(s)
    assert r.time_to_first_confirmation_s is not None
    assert r.time_to_first_confirmation_s >= 0.0             # start → first confirmation


def test_time_to_first_confirmation_is_none_without_a_confirmation():
    from src.reasoning.state import ReasoningState
    s = ReasoningState(target="ex.com:80", scope=["ex.com"])
    s.investigation.hypotheses.add_hypothesis(label="framework_of:svc", created_by="rule",
                                              likelihoods={"express": 0.5, "nginx": 0.5})
    r = research_report(s)
    assert r.time_to_first_confirmation_s is None            # nothing confirmed ⇒ honestly None
