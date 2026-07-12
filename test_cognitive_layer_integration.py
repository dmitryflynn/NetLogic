"""Track C — the cognitive layer WIRED into the live director. A --reason --ai scan (simulated
with a cassette completer + stub executor) produces AI hypotheses, refutation objectives, and an
Investigation Transcript whose framework hypothesis is resolved by the deterministic InferenceEngine.
"""
import json

from src.reasoning import (BudgetManager, ReasoningState, ReconDirector, Scheduler,
                           StepContext, StrategyManager)
from src.reasoning.trace import ExecutionResult


def _stub_executor(spec):
    # Deterministic offline evidence: WordPress markers so inference can confirm the framework.
    return ExecutionResult(success=True, data={"server": "Apache"},
                           evidence="x-powered-by: wordpress wp-content/themes")


class _Cassette:
    """One completer serving both agents: C1 (hypothesis system prompt) gets framework + novel
    hypotheses; C11 (refutation system prompt) gets disconfirming checks. Distinguished by a
    keyword in the system prompt so a single object drives a full --ai cycle deterministically."""
    def __call__(self, system, user):
        if "REFUTATION" in system:
            return json.dumps([{"refutes": "wordpress", "check": "no_wp_json",
                                "information_gain": 3.0}])
        return json.dumps([
            {"objective": "identify_framework:ex.com:80",
             "candidates": {"wordpress": 0.8, "drupal": 0.2}, "novel": False,
             "rationale": "wp-content asset paths", "information_gain": 2.5, "prob_correct": 0.7},
            {"objective": "novel:cache_poisoning", "candidates": {"vulnerable": 0.4, "safe": 0.6},
             "novel": True, "rationale": "unkeyed header reflected in cache",
             "information_gain": 4.0, "prob_correct": 0.5},
        ])


def _run(completer):
    s = ReasoningState(target="ex.com", scope=["ex.com"], reasoning_enabled=True)
    s.world.belief_records = [{"claim": "cve-x", "confidence": 0.5, "impact": "critical",
                               "version_only": True}]
    s.world.beliefs = {"cve-x": 0.5}
    s.world.graph.upsert_node("service", "ex.com:80", label="ex.com:80")
    director = ReconDirector(
        Scheduler(), StrategyManager(), BudgetManager.for_tier("local"), [],
        has_ai_key=(completer is not None), ai_completer=completer,
        refresh=lambda st, a: None, executor=_stub_executor)
    director.run(StepContext("ex.com", s, {}, lambda *a, **k: None))
    return s


def test_ai_hypotheses_are_seeded_into_the_live_forest():
    s = _run(_Cassette())
    labels = {h.label for h in s.investigation.hypotheses.all()}
    # C1's framework + novel hypotheses are present, clearly namespaced.
    assert "ai:identify_framework:ex.com:80" in labels
    assert "ai:novel:cache_poisoning" in labels
    # The deterministic hypotheses are still there too (additive, never replaced).
    assert any(lbl.startswith("framework_of:") for lbl in labels)


def test_novel_hypothesis_seeds_a_new_objective():
    s = _run(_Cassette())
    names = {o.name for o in s.investigation.objectives.all()}
    assert "novel:cache_poisoning" in names   # the novel inquiry became a tracked objective


def test_refutation_objective_is_seeded_read_only():
    s = _run(_Cassette())
    names = {o.name for o in s.investigation.objectives.all()}
    assert "refute:wordpress:no_wp_json" in names
    obj = s.investigation.objectives.get("refute:wordpress:no_wp_json")
    assert obj.risk_budget == "read_only" and obj.source.generated_by == "ai_counterfactual_reasoner"


def test_transcript_records_the_reasoning_replay_with_outcomes():
    s = _run(_Cassette())
    transcript = s.execution.ai_transcript
    assert transcript and transcript["entries"]
    summary = transcript["summary"]
    assert summary["proposed"] >= 3          # 2 hypotheses + 1 refutation objective (+ any rejects)
    assert summary["accepted"] >= 3
    # The framework hypothesis, seeded then confirmed by the InferenceEngine from wp-content
    # evidence, is recorded as an outcome — the AI proposed, the deterministic engine proved.
    fw = [e for e in transcript["entries"] if e["seeded_as"] == "ai:identify_framework:ex.com:80"]
    assert fw and fw[0]["outcome"] == "confirmed"
    # A generated hypothesis is recorded at POSSIBLE uncertainty (a proposal, not a truth).
    assert fw[0]["uncertainty"] == "possible"


def test_no_ai_means_empty_transcript_and_no_ai_labels():
    s = _run(None)
    assert not s.execution.ai_transcript
    assert not any(h.label.startswith("ai:") for h in s.investigation.hypotheses.all())


def test_broken_ai_seeds_nothing():
    def _boom(system, user):
        raise RuntimeError("model down")

    s = _run(_boom)
    assert not s.execution.ai_transcript
    assert not any(h.label.startswith("ai:") for h in s.investigation.hypotheses.all())
    assert not any(o.name.startswith(("ai:", "refute:", "novel:"))
                   for o in s.investigation.objectives.all())
