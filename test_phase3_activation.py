"""Phase 3 Activation: safety validators, deterministic generators, executor dispatch,
feedback closure, and the reasoning_enabled gate. All offline (no network)."""
from src.reasoning import (BudgetManager, MemoryStore, ReasoningState)
from src.reasoning.execution_kernel import (
    ExecutionKernel, validate_budget, validate_dedup, validate_depth,
    validate_read_only, validate_scope,
)
from src.reasoning.probe_plan import ProbePlan, ProbePlanGraph, ProbeSpec
from src.reasoning.probe_executor import ProbeExecutor
from src.reasoning.trace import ExecutionResult
from src.reasoning import generators


def _plan(host="ex.com", risk="read_only", primitive="http_head"):
    spec = ProbeSpec(protocol="HTTP", target_host=host, target_port=80,
                     request_spec={"primitive": primitive})
    return ProbePlan(spec=spec, metadata={"risk": risk, "cost": {"probes": 1},
                                          "evidence_request_id": "r1", "evidence_type": "http_headers"})


# ── Safety validators ────────────────────────────────────────────────────────────
def test_validate_read_only_rejects_non_read_only():
    assert validate_read_only(_plan(risk="invasive"), {"read_only": True})
    assert validate_read_only(_plan(risk=None), {"read_only": True})        # fail-closed
    assert not validate_read_only(_plan(risk="read_only"), {"read_only": True})


def test_validate_scope_rejects_off_scope():
    assert validate_scope(_plan(host="evil.com"), {"scope": ["ex.com"]})
    assert not validate_scope(_plan(host="ex.com"), {"scope": ["ex.com"]})
    assert not validate_scope(_plan(host="api.ex.com"), {"scope": ["ex.com"]})   # subdomain ok


def test_validate_budget_rejects_when_exhausted():
    b = BudgetManager(max_probes=0, max_tokens=1, max_wall_clock_s=1000, max_recursion=10)
    assert validate_budget(_plan(), {"budget": b})
    ok = BudgetManager.for_tier("local")
    assert not validate_budget(_plan(), {"budget": ok})


def test_validate_dedup_rejects_seen():
    mem = MemoryStore()
    p = _plan()
    assert not validate_dedup(p, {"memory": mem})
    mem.record(p.spec.to_dict(), success=True)
    assert validate_dedup(p, {"memory": mem})


def test_validate_depth_rejects_over_ceiling():
    assert validate_depth(_plan(), {"depth": 6, "max_depth": 6})
    assert not validate_depth(_plan(), {"depth": 0, "max_depth": 6})


def test_kernel_blocks_off_scope_probe():
    kernel = ExecutionKernel(executor=lambda spec: ExecutionResult(success=True, evidence="x"))
    kernel.add_validator(validate_scope)
    res = kernel.execute_plan(_plan(host="evil.com"), context={"scope": ["ex.com"]})
    assert res.success is False and "not in scope" in (res.error or "")


# ── Deterministic generators ───────────────────────────────────────────────────────
def _state_with_service():
    s = ReasoningState(target="ex.com", scope=["ex.com"], reasoning_enabled=True)
    s.world.graph.upsert_node("service", "ex.com:80", label="ex.com:80")
    s.world.belief_records = [{"claim": "cve-2021-40438", "confidence": 0.5, "impact": "critical",
                               "version_only": True}]
    return s


def test_generators_populate_objectives_deterministically():
    s = _state_with_service()
    generators.populate_objectives(s)
    names = {o.name for o in s.investigation.objectives.all()}
    assert "verify:cve-2021-40438" in names              # version-only critical → verify
    assert "identify_framework:ex.com:80" in names       # no tech yet → identify framework
    # idempotent
    n = len(s.investigation.objectives)
    generators.populate_objectives(s)
    assert len(s.investigation.objectives) == n


def test_generators_spawn_hypothesis_forest():
    s = _state_with_service()
    generators.populate(s)
    leaves = s.investigation.hypotheses.leaves()
    assert leaves                                        # a framework hypothesis exists
    assert any("spring_boot" in l.likelihoods and "wordpress" in l.likelihoods for l in leaves)
    assert s.investigation.hypotheses.forest_entropy() > 0   # competing candidates → entropy


def test_generate_intents_requests_discriminating_evidence():
    s = _state_with_service()
    generators.populate(s)
    intents = generators.generate_intents(s)
    goals = {i.goal for i in intents}
    assert "identify_framework:ex.com:80" in goals
    fw = next(i for i in intents if i.goal == "identify_framework:ex.com:80")
    ev = {e.value for e in fw.desired_evidence}
    assert {"server_header", "http_headers"} <= ev       # discriminating evidence


# ── Executor dispatch (offline) ────────────────────────────────────────────────────
def test_executor_unknown_primitive_fails_soft():
    res = ProbeExecutor()(ProbeSpec(target_host="ex.com", request_spec={"primitive": "nope"}))
    assert res.success is False and "no read-only backend" in (res.error or "")


def test_executor_no_host_fails_soft():
    res = ProbeExecutor()(ProbeSpec(target_host="", request_spec={"primitive": "http_head"}))
    assert res.success is False
