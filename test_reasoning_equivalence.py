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
_VOLATILE = {"started_at", "created_at", "timestamp", "resolved_at", "elapsed_s",
             "depth", "probes_run", "tokens_used",
             "id", "request_id", "spec_id", "parent_id", "children", "derived_from",
             "evidence_requests", "probe_key"}


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


class _ExcMidCycle:
    """First LLM call (hypotheses) returns a VALID proposal, second (intents) throws — proves
    augmentation is atomic and a mid-cycle failure applies nothing."""
    def __init__(self): self.n = 0
    def __call__(self, sysp, usr):
        self.n += 1
        if self.n >= 2:
            raise RuntimeError("died mid-cycle")
        return json.dumps([{"objective": "identify_framework:ex.com:80",
                            "candidates": {"wordpress": 0.9, "django": 0.1}}])


def test_all_ai_failure_modes_equal_baseline():
    baseline = _run(None)                     # deterministic, no AI
    for name, completer in [
        ("silent", _silent), ("none", _none), ("failure", _fail), ("timeout", _timeout),
        ("malformed", _malformed), ("invalid", _invalid), ("exception_mid", _ExcMidCycle()),
    ]:
        assert _run(completer) == baseline, f"AI mode '{name}' diverged from deterministic baseline"


def test_baseline_actually_did_work():
    # Guard against a vacuous test: the deterministic cycle must produce real reasoning.
    baseline = _run(None)
    inv = baseline["investigation"]
    assert inv["objectives"], "expected deterministic objectives"
    assert inv["hypotheses"], "expected a deterministic hypothesis forest"
