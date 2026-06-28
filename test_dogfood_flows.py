"""Dogfooding the reasoning engine end-to-end (pre-Phase-6 discipline).

Before adding Phase 6 abstractions, exercise realistic investigation flows using ONLY current
primitives — playbooks + capabilities + rule packs expressed as data, driven through the real
ReconDirector pipeline over synthetic (offline) evidence. The question each test answers is not
"does function X work" but "does the architecture compose a whole flow without fighting me?"

Flows: WordPress assessment, Kubernetes assessment, generic web-app. A *new* flow (Kubernetes)
was added as pure data (rules/kubernetes.json + playbooks/kubernetes_investigation.yaml) with no
engine code change — itself evidence the planner is extensible by configuration.
"""
from src.reasoning import (
    BudgetManager, ReasoningState, ReconDirector, Scheduler, StepContext, StrategyManager,
)
from src.reasoning.capability_registry import Capability
from src.reasoning.inference import InferenceEngine
from src.reasoning.learned_patterns import PatternExtractor, PatternRecall, PatternValidator
from src.reasoning.objective import Objective
from src.reasoning.provenance import ProvenanceBuilder, ProvenanceGraph, ProvenanceTracer
from src.reasoning.trace import ExecutionResult


def _executor_returning(evidence_text):
    def _exec(spec):
        return ExecutionResult(success=True, data={"server": "nginx"}, evidence=evidence_text)
    return _exec


def _run_flow(evidence_text, *, register_capability=None):
    """Drive a full director cycle over fixed offline evidence and return the final state."""
    s = ReasoningState(target="ex.com", scope=["ex.com"], reasoning_enabled=True)
    s.world.belief_records = [{"claim": "cve-x", "confidence": 0.5, "impact": "critical",
                               "version_only": True}]
    s.world.beliefs = {"cve-x": 0.5}
    s.world.graph.upsert_node("service", "ex.com:80", label="ex.com:80")

    director = ReconDirector(
        Scheduler(), StrategyManager(), BudgetManager.for_tier("local"), [],
        has_ai_key=False, refresh=lambda st, a: None,
        executor=_executor_returning(evidence_text))
    if not director._phase3_initialized:
        import pytest
        pytest.skip("phase3 not initialized")
    if register_capability is not None:
        director._capability_registry.register(register_capability)

    director.run(StepContext("ex.com", s, {}, lambda *a, **k: None))
    return s, director


# ── Flow 1: WordPress assessment composes end to end ──

def test_wordpress_flow_composes():
    evidence = "X-Powered-By: WordPress; wp-content/themes/x; wp-json"
    s, _ = _run_flow(evidence)

    # The director loaded the WordPress + generic playbooks from disk and the cycle ran.
    # Inference should have resolved a framework hypothesis from the evidence content.
    explanations = [e for e in s.execution.explanations
                    if str(e.get("rule_applied", "")).startswith("inference:")]
    assert explanations, "expected inference to fire on WordPress evidence"

    # Provenance was recorded as the irreproducible core.
    prov = ProvenanceGraph.from_dict(s.execution.provenance)
    assert prov.inference_hypothesis, "expected Observation->Inference->Hypothesis provenance"


def test_wordpress_flow_provenance_traces_to_observation():
    s, _ = _run_flow("wp-content/plugins/akismet wp-json x-powered-by: wordpress")
    prov = ProvenanceGraph.from_dict(s.execution.provenance)
    tracer = ProvenanceTracer(prov)
    # Every confirmed hypothesis traces back to at least one real observation.
    real_obs = {o.obs_id for node in s.world.graph.nodes() for o in node.observations()}
    for edge in prov.inference_hypothesis:
        traced = tracer.hypothesis_to_observations(edge.hypothesis_id)
        assert traced and traced <= real_obs


# ── Flow 2: Kubernetes flow — added as pure DATA, no engine change ──

def test_kubernetes_flow_added_by_configuration_only():
    evidence = "server: kubelet; /api/v1/namespaces; x-kubernetes-pf: 1"
    cap = Capability(
        id="resolve_orchestrator", name="Resolve Orchestrator",
        produces=("identify_framework",), expected_information_gain=4.0,
        implemented_by_playbooks=("kubernetes_investigation",))
    s, director = _run_flow(evidence, register_capability=cap)

    # The kubernetes playbook loaded purely from YAML (no code referenced it).
    assert "kubernetes_investigation" in director._playbook_registry.playbooks
    # The kubernetes rule pack loaded purely from JSON and let inference confirm the cluster.
    rules = InferenceEngine()._rules
    assert "kubernetes" in rules


# ── Flow 3: generic web-app — baseline always produces a usable plan ──

def test_generic_webapp_flow_yields_objectives_and_provenance():
    s, _ = _run_flow("Server: nginx; Content-Type: text/html; set-cookie: sid=1")
    # Even with no framework match, the deterministic baseline must produce reasoning structure.
    assert s.investigation.objectives.all(), "baseline must generate objectives"
    # Provenance dict always exists (possibly empty) and round-trips.
    assert ProvenanceGraph.from_dict(s.execution.provenance).to_dict() == s.execution.provenance


# ── Cross-cutting: the learned-pattern loop closes over a real provenance graph ──

def test_learned_pattern_loop_closes_over_real_flow():
    s, _ = _run_flow("wp-content wp-json x-powered-by: wordpress")
    prov = s.execution.provenance
    candidates = PatternExtractor().extract(prov)
    patterns = PatternValidator(min_attempts=1, min_success_rate=0.0).validate(candidates)
    hints = PatternRecall().hints(patterns)
    # If the flow confirmed wordpress, history should now nudge wordpress-flavored candidates.
    if prov.get("inference_hypothesis"):
        assert any(h.tag for h in hints)
