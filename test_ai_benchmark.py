"""Track C Validation — the investigation-level A/B benchmark: same fixture, AI-off vs AI-on,
measuring what the cognitive layer actually changes. Deterministic given a cassette + stub executor.
"""
import json

from src.reasoning.ai_benchmark import BenchmarkComparison, compare_investigations, run_investigation
from src.reasoning.state import ReasoningState
from src.reasoning.trace import ExecutionResult


def _stub_executor(spec):
    # WordPress markers (confirm the framework) + a cache-control header that RULES OUT cache
    # poisoning — so the novel hypothesis reaches a real deterministic outcome (refuted), not limbo.
    return ExecutionResult(success=True, data={"server": "Apache"},
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
        if "DESIGN read-only" in system:          # C2 Investigation Designer
            return json.dumps({"required_evidence": ["http_headers", "http_body"],
                               "rationale": "cache headers", "information_gain": 3.0})
        if "REFUTATION" in system:                # C11
            return json.dumps([{"refutes": "wordpress", "check": "no_wp_json", "information_gain": 3.0}])
        return json.dumps([                       # C1
            {"objective": "identify_framework:ex.com:80", "candidates": {"wordpress": 0.8, "drupal": 0.2},
             "novel": False, "information_gain": 2.5, "prob_correct": 0.7},
            {"objective": "novel:cache_poisoning", "candidates": {"vulnerable": 0.4, "safe": 0.6},
             "novel": True, "information_gain": 4.0, "prob_correct": 0.5},
        ])


def test_comparison_is_deterministic():
    c1 = compare_investigations(_state_factory, completer=_Cassette(), executor=_stub_executor)
    c2 = compare_investigations(_state_factory, completer=_Cassette(), executor=_stub_executor)
    assert c1.to_dict() == c2.to_dict()
    assert isinstance(c1, BenchmarkComparison)


def test_ai_enriches_the_investigation():
    c = compare_investigations(_state_factory, completer=_Cassette(), executor=_stub_executor)
    # AI adds hypotheses (its own competing explanations) and objectives (novel + refutation).
    assert c.deltas["hypotheses"] > 0
    assert c.deltas["objectives"] > 0
    assert c.with_ai.ai_hypotheses >= 2
    assert c.with_ai.novel_hypotheses >= 1
    assert c.with_ai.refutation_objectives >= 1
    # The AI's estimated information gain is recorded (Reflection can weigh it later).
    assert c.with_ai.est_information_gain > 0.0


def test_novel_hypotheses_reach_a_real_outcome_not_limbo():
    """The outcome metric that actually matters: a novel hypothesis the AI invented reaches a
    deterministic conclusion. Here the cache-control:no-store evidence REFUTES cache poisoning —
    the AI proposed it, the engine (not the AI) ruled it out. That's a conclusion, not 'unresolved'."""
    c = compare_investigations(_state_factory, completer=_Cassette(), executor=_stub_executor)
    assert c.baseline.hypotheses_refuted == 0          # deterministic baseline invents no novel vulns
    assert c.with_ai.hypotheses_refuted >= 1           # …the AI's novel hypothesis was refuted
    assert c.deltas["hypotheses_refuted"] >= 1


def test_baseline_has_no_ai_artifacts():
    c = compare_investigations(_state_factory, completer=_Cassette(), executor=_stub_executor)
    assert c.baseline.ai_hypotheses == 0
    assert c.baseline.novel_hypotheses == 0
    assert c.baseline.refutation_objectives == 0
    assert c.baseline.proposed == 0


def test_c2_makes_ai_objectives_investigable():
    """C2's measurable effect: the AI-invented objectives (novel:/refute:) now have an
    evidence-gathering path, where before they were inert. This is the gap the earlier benchmark
    surfaced (+objectives / +0 investigable) now closed to +objectives / +investigable.

    (NOTE: 'investigable' — has an intent-producing evidence mapping — is the signal C2 owns.
    Whether an objective then becomes 'satisfied'/'confirmed' additionally needs successful probe
    execution and, for novel vulns, inference rules — separate concerns, honestly not claimed here.)
    """
    c = compare_investigations(_state_factory, completer=_Cassette(), executor=_stub_executor)
    ai_only = c.with_ai.novel_hypotheses + c.with_ai.refutation_objectives
    assert ai_only >= 2
    # Every AI objective got an investigation path from C2 → all objectives are investigable.
    assert c.with_ai.objectives_investigable == c.with_ai.objectives
    # …which is a strict improvement over baseline (C2 added investigability for the AI objectives).
    assert c.deltas["objectives_investigable"] == c.deltas["objectives"] >= 2


def test_run_investigation_without_ai_is_usable_alone():
    s = run_investigation(_state_factory, completer=None, executor=_stub_executor)
    assert not s.execution.ai_transcript
    assert not any(h.label.startswith("ai:") for h in s.investigation.hypotheses.all())
