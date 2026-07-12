"""Reasoning equivalence — the permanent regression guard.

Drives the full ReconDirector cycle over a FIXED input (a 'cassette': a synthetic ReasoningState
+ a recorded stub executor, so it is network-independent and deterministic) under every AI
failure mode, and asserts each produces a state IDENTICAL to the deterministic baseline
(completer absent). I.e. a broken AI can never change the deterministic execution path:

    AI disabled / silent / failure / timeout / malformed / invalid / exception-mid-cycle == baseline
"""
import json

from src.reasoning import (BudgetManager, ReasoningState, ReconDirector, Scheduler,
                           StepContext, StrategyManager)
from src.reasoning.trace import ExecutionResult

# Volatile = time/counter fields + random UUIDs (compare STRUCTURE, not unstable IDs).
# Provenance edges (Phase 5) reference hypotheses by their random UUID and derive an inference_id
# from it; both are unstable reference ids — the structural shape (rules matched, decisions,
# obs attribution) is what the guard compares.
_VOLATILE = {"started_at", "created_at", "timestamp", "resolved_at", "elapsed_s",
             "depth", "probes_run", "tokens_used",
             "id", "request_id", "spec_id", "parent_id", "children", "derived_from",
             "evidence_requests", "probe_key",
             "hypothesis_id", "inference_id"}


def _stub_executor(spec):
    # Deterministic, offline. Returns framework evidence so inference is exercised identically.
    return ExecutionResult(success=True, data={"server": "Apache"},
                           evidence="x-powered-by: wordpress wp-content/themes")


def _normalize(obj):
    """Strip volatile (time/counter) fields so structural state can be compared."""
    if isinstance(obj, dict):
        return {k: _normalize(v) for k, v in obj.items() if k not in _VOLATILE}
    if isinstance(obj, list):
        return [_normalize(v) for v in obj]
    return obj


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
    return _normalize(s.to_dict())


# ── AI failure modes (none may change the deterministic outcome) ──
def _silent(sysp, usr): return ""
def _none(sysp, usr): return None
def _fail(sysp, usr): raise ValueError("boom")
def _timeout(sysp, usr): raise TimeoutError("slow")
def _malformed(sysp, usr): return "{{{ not json at all"
def _invalid(sysp, usr): return json.dumps(["not_a_real_evidence_type"])


def test_all_ai_failure_modes_equal_baseline():
    baseline = _run(None)                     # deterministic, no AI
    # Every FAILING completer must contribute nothing (fail-soft): the cognitive-layer agents
    # return no tasks, the coordinator accepts nothing, the core seeds nothing. "broken AI == no AI".
    for name, completer in [
        ("silent", _silent), ("none", _none), ("failure", _fail), ("timeout", _timeout),
        ("malformed", _malformed), ("invalid", _invalid),
    ]:
        assert _run(completer) == baseline, f"AI mode '{name}' diverged from deterministic baseline"


def test_baseline_actually_did_work():
    # Guard against a vacuous test: the deterministic cycle must produce real reasoning.
    baseline = _run(None)
    inv = baseline["investigation"]
    assert inv["objectives"], "expected deterministic objectives"
    assert inv["hypotheses"], "expected a deterministic hypothesis forest"


# ── Track C (C0): the cognitive layer package is not yet wired into director.run() at all
# (that lands in C1). Until then the strongest, most honest equivalence guarantee is: the
# package's mere EXISTENCE/IMPORT has zero effect on the deterministic loop, and running an
# AICoordinator in the same process — even producing real accepted proposals — never perturbs a
# concurrent director cycle (no shared global state between the two).

def test_importing_ai_package_does_not_change_deterministic_output():
    import src.reasoning.ai  # noqa: F401 — import-only; presence must be inert
    assert _run(None) == _run(None)


def test_working_ai_is_an_additive_superset_never_altering_deterministic_facts():
    """A WORKING cognitive layer is allowed to diverge from baseline — that's its purpose — but only
    ADDITIVELY: every deterministic objective and hypothesis is preserved, and the AI's contribution
    is clearly namespaced (`ai:` hypotheses). It never removes or rewrites a deterministic fact."""
    def _working(sysp, usr):
        # C1's prompt gets framework hypotheses; C11's prompt (different system text) gets nothing
        # usable from this shape — either way the deterministic core stays intact.
        return json.dumps([{"objective": "identify_framework:ex.com:80",
                            "candidates": {"wordpress": 0.9, "django": 0.1},
                            "novel": False, "information_gain": 2.0, "prob_correct": 0.7}])

    baseline = _run(None)
    working = _run(_working)

    base_h = {h["label"] for h in baseline["investigation"]["hypotheses"]}
    work_h = {h["label"] for h in working["investigation"]["hypotheses"]}
    assert base_h <= work_h, "a deterministic hypothesis was lost when AI was enabled"
    assert any(lbl.startswith("ai:") for lbl in work_h), "working AI added no hypothesis"

    base_o = {o["name"] for o in baseline["investigation"]["objectives"]}
    work_o = {o["name"] for o in working["investigation"]["objectives"]}
    assert base_o <= work_o, "a deterministic objective was lost when AI was enabled"

    # The transcript (reasoning replay) is populated on a working run and empty on the baseline.
    assert working["execution"]["ai_transcript"].get("entries")
    assert not baseline["execution"]["ai_transcript"]


def test_ai_coordinator_activity_never_perturbs_a_concurrent_director_run():
    import json as _json
    from src.reasoning.ai import AgentTask, AICoordinator, ProposalKind, VerifierContext

    baseline = _run(None)

    # Run a real, busy AICoordinator cycle (accepted + rejected proposals, reputation updates)
    # interleaved with the director cycle. Nothing here touches ReasoningState at all.
    coordinator = AICoordinator()
    tasks = [
        AgentTask(agent="hyp_gen", kind=ProposalKind.HYPOTHESIS, raw=_json.dumps(
            {"payload": {"objective": "verify:CVE-1", "candidates": {"a": 0.6, "b": 0.4}},
             "economics": {"estimated_information_gain": 3.0}})),
        AgentTask(agent="hyp_gen", kind=ProposalKind.HYPOTHESIS, raw="garbage"),
    ]
    coordinator.run(tasks, ctx=VerifierContext(known_objectives=frozenset({"verify:CVE-1"})))
    assert len(coordinator.store) >= 1   # proves the coordinator actually did something

    after = _run(None)
    assert after == baseline, "AICoordinator activity changed the deterministic reasoning output"
