"""Validation infrastructure — corpus runner, aggregate stats, CSV/JSON export, and regression-vs-
baseline gating. Fixture-driven (deterministic); real authorized scans ingest the same way."""
import json

from src.reasoning.benchmark_corpus import (
    AggregateStats, BenchmarkCase, CorpusResult, load_baseline, regression_check, run_corpus,
    save_baseline,
)
from src.reasoning.state import ReasoningState
from src.reasoning.trace import ExecutionResult


def _executor(evidence):
    def _e(spec):
        return ExecutionResult(success=True, data={}, evidence=evidence)
    return _e


def _factory():
    s = ReasoningState(target="ex.com", scope=["ex.com"])
    s.world.belief_records = [{"claim": "cve-x", "confidence": 0.5, "impact": "critical",
                               "version_only": True}]
    s.world.beliefs = {"cve-x": 0.5}
    s.world.graph.upsert_node("service", "ex.com:80", label="ex.com:80")
    return s


class _WPCassette:
    def __call__(self, system, user):
        if "DESIGN read-only" in system:
            return json.dumps({"required_evidence": ["http_headers"], "information_gain": 3.0})
        if "REFUTATION" in system:
            return json.dumps([{"refutes": "wordpress", "check": "no_wp_json"}])
        return json.dumps([
            {"objective": "identify_framework:ex.com:80", "candidates": {"wordpress": 0.8, "drupal": 0.2},
             "novel": False, "information_gain": 2.5},
            {"objective": "novel:cache_poisoning", "candidates": {"vulnerable": 0.4, "safe": 0.6},
             "novel": True, "information_gain": 4.0},
        ])


def _corpus():
    return [
        BenchmarkCase("wp-1", _factory, completer=_WPCassette(),
                      executor=_executor("wordpress wp-content; cache-control: no-store"),
                      ground_truth={"wordpress": True, "cache_poisoning": False}, label="wordpress"),
        BenchmarkCase("wp-2", _factory, completer=_WPCassette(),
                      executor=_executor("wordpress wp-content; cache-control: no-store"),
                      ground_truth={"wordpress": True, "cache_poisoning": False}, label="wordpress"),
        BenchmarkCase("static-1", _factory, completer=None,
                      executor=_executor("just some html"), label="static"),   # AI-off baseline case
    ]


def test_run_corpus_produces_a_report_per_case():
    result = run_corpus(_corpus())
    assert isinstance(result, CorpusResult)
    assert len(result.results) == 3
    assert {r.name for r in result.results} == {"wp-1", "wp-2", "static-1"}


def test_aggregate_is_reproducible_and_covers_reliability():
    a1 = run_corpus(_corpus()).aggregate()
    a2 = run_corpus(_corpus()).aggregate()
    # Every metric is deterministic EXCEPT wall-clock runtime (a real measurement that varies) —
    # and regression gating deliberately never triggers on runtime for that reason.
    d1 = {k: v for k, v in a1.to_dict().items() if k != "avg_runtime_s"}
    d2 = {k: v for k, v in a2.to_dict().items() if k != "avg_runtime_s"}
    assert d1 == d2
    assert a1.n == 3
    # two labeled cases (wp-1/wp-2); each: wordpress confirmed&true (TP), cache_poisoning refuted&false.
    assert a1.labeled_cases == 2
    assert a1.true_positives == 2 and a1.false_negatives == 0
    assert a1.precision == 1.0 and a1.recall == 1.0
    assert a1.fp_rate == 0.0


def test_csv_export_has_one_row_per_case():
    csv_text = run_corpus(_corpus()).to_csv()
    lines = [ln for ln in csv_text.strip().splitlines() if ln]
    assert len(lines) == 4                         # header + 3 cases
    assert "name" in lines[0] and "precision" in lines[0] and "uncertainty_reduction" in lines[0]


def test_baseline_roundtrip(tmp_path):
    agg = run_corpus(_corpus()).aggregate()
    p = str(tmp_path / "baseline.json")
    save_baseline(agg, p)
    loaded = load_baseline(p)
    assert loaded.to_dict() == agg.to_dict()


def test_regression_passes_against_itself():
    agg = run_corpus(_corpus()).aggregate()
    r = regression_check(agg, agg)
    assert r.passed and r.failures == []


def test_regression_fails_on_false_positive_spike():
    baseline = AggregateStats(n=3, avg_probes=8.0, avg_uncertainty_reduction=5.0, fp_rate=0.01)
    worse = AggregateStats(n=3, avg_probes=8.0, avg_uncertainty_reduction=5.0, fp_rate=0.09)
    r = regression_check(worse, baseline)
    assert not r.passed
    assert any("false-positive" in f for f in r.failures)
    assert r.deltas["fp_rate"] > 0


def test_regression_fails_on_probe_cost_blowup():
    baseline = AggregateStats(n=3, avg_probes=10.0, avg_uncertainty_reduction=5.0, fp_rate=0.0)
    worse = AggregateStats(n=3, avg_probes=13.0, avg_uncertainty_reduction=5.0, fp_rate=0.0)
    r = regression_check(worse, baseline)
    assert not r.passed and any("probes" in f for f in r.failures)


def test_regression_fails_when_uncertainty_reduction_collapses():
    baseline = AggregateStats(n=3, avg_probes=8.0, avg_uncertainty_reduction=10.0, fp_rate=0.0)
    worse = AggregateStats(n=3, avg_probes=8.0, avg_uncertainty_reduction=5.0, fp_rate=0.0)
    r = regression_check(worse, baseline)
    assert not r.passed and any("uncertainty" in f for f in r.failures)


# ── Per-validator quality (the "should this validator exist?" benchmark questions) ──

def _vres(confirms, executed=True, succeeded=False):
    return {"probe": f"confirm_tech:{confirms}", "confirms": confirms, "gated_allowed": True,
            "executed": executed, "succeeded": succeeded, "denials": [], "evidence": ""}


def test_validator_quality_scores_correct_incorrect_and_no_info():
    from src.reasoning.benchmark_corpus import validator_quality
    results = [
        _vres("express", succeeded=True),    # correct (truly present)
        _vres("express", succeeded=True),    # correct again
        _vres("wordpress", succeeded=True),  # incorrect (not present) → false positive
        _vres("django", succeeded=False),    # ran, no info
    ]
    gt = {"express": True, "wordpress": False, "django": True}
    q = {v.validator: v for v in validator_quality(results, gt)}
    assert q["express"].correct_confirm == 2 and q["express"].incorrect_confirm == 0
    assert q["express"].precision == 1.0
    assert q["wordpress"].incorrect_confirm == 1 and q["wordpress"].precision == 0.0
    assert q["django"].no_info == 1 and q["django"].correct_confirm == 0


def test_validator_quality_gate_denied_probes_do_not_count():
    from src.reasoning.benchmark_corpus import validator_quality
    results = [_vres("express", executed=False, succeeded=False)]   # gate-denied → never ran
    assert validator_quality(results, {"express": True}) == []


def test_validator_quality_unlabeled_confirmations_are_separated():
    from src.reasoning.benchmark_corpus import validator_quality
    q = validator_quality([_vres("nginx", succeeded=True)], ground_truth=None)  # no labels
    assert len(q) == 1
    assert q[0].unlabeled_confirm == 1 and q[0].precision is None   # can't score without truth
