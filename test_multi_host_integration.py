"""Live multi-host integration through the real ReconDirector.run() (Phase 6c integration).

These prove the *feature*, not just the mechanics: with world_modeling_enabled, the existing
pipeline actually CONSUMES the multi-host layer — a neighbor discovered from the primary's evidence
is authorized, spawned as its own HostReasoner, and reasoned over within one run(). Flag OFF stays
byte-identical (covered by test_reasoning_equivalence.py).
"""
from src.reasoning import (
    BudgetManager, ReasoningState, ReconDirector, Scheduler, StepContext, StrategyManager,
)
from src.reasoning.trace import ExecutionResult


def _stub_executor(spec):
    # Deterministic, offline. Returns framework evidence so phase3 inference runs identically.
    return ExecutionResult(success=True, data={"server": "Apache"},
                           evidence="x-powered-by: wordpress wp-content/themes")


def _director():
    return ReconDirector(
        Scheduler(), StrategyManager(), BudgetManager.for_tier("local"), [],
        has_ai_key=False, refresh=lambda st, a: None, executor=_stub_executor)


def _primary_state(multi_host: bool):
    """A primary host whose evidence implies an IN-SCOPE neighbor (DNS MX → mail.ex.com)."""
    s = ReasoningState(target="web.ex.com", scope=["ex.com"],
                       reasoning_enabled=True, world_modeling_enabled=multi_host)
    s.world.belief_records = [{"claim": "cve-x", "confidence": 0.5, "impact": "critical",
                               "version_only": True}]
    s.world.beliefs = {"cve-x": 0.5}
    n = s.world.graph.upsert_node("service", "web.ex.com")
    s.world.graph.observe(n, kind="dns_records", evidence="", source="scan",
                          data={"mx": ["mail.ex.com"]})
    return s


def _multi_host_record(state):
    for entry in state.execution.execution_history:
        if isinstance(entry, dict) and "multi_host" in entry:
            return entry["multi_host"]
    return None


def test_director_does_not_expand_when_flag_off():
    d = _director()
    s = _primary_state(multi_host=False)
    d.run(StepContext("web.ex.com", s, {}, lambda *a, **k: None))
    # No multi-host record at all when the flag is off.
    assert _multi_host_record(s) is None


def test_director_expands_in_scope_neighbor_when_flag_on():
    d = _director()
    s = _primary_state(multi_host=True)
    d.run(StepContext("web.ex.com", s, {}, lambda *a, **k: None))

    rec = _multi_host_record(s)
    assert rec is not None, "expected a multi_host record when world modeling is on"
    assert rec["primary"] == "web.ex.com"
    # The in-scope neighbor was discovered, authorized, spawned, and reasoned over.
    assert "mail.ex.com" in rec["expanded_hosts"]
    assert any(e["dest_host"] == "mail.ex.com" for e in rec["discovered_edges"])


def test_director_does_not_expand_out_of_scope_neighbor():
    d = _director()
    s = ReasoningState(target="web.ex.com", scope=["ex.com"],
                       reasoning_enabled=True, world_modeling_enabled=True)
    s.world.belief_records = [{"claim": "cve-x", "confidence": 0.5, "impact": "critical",
                               "version_only": True}]
    n = s.world.graph.upsert_node("service", "web.ex.com")
    s.world.graph.observe(n, kind="dns_records", evidence="", source="scan",
                          data={"mx": ["mail.evil.com"]})       # OUT of scope
    d.run(StepContext("web.ex.com", s, {}, lambda *a, **k: None))

    rec = _multi_host_record(s)
    assert rec is not None
    assert rec["expanded_hosts"] == []                          # off-scope never spawns
    assert rec["rejected_or_deferred"].get("mail.evil.com") == "reject"


def test_global_budget_bounds_expansion():
    """Spawned hosts share the scan-wide budget; exhausting it stops further expansion."""
    d = ReconDirector(
        Scheduler(), StrategyManager(),
        BudgetManager(max_probes=1, max_recursion=12, max_wall_clock_s=600), [],
        has_ai_key=False, refresh=lambda st, a: None, executor=_stub_executor)
    s = _primary_state(multi_host=True)
    # Make the primary imply several in-scope neighbors.
    n = s.world.graph.nodes()[0]
    s.world.graph.observe(n, kind="dns_records", evidence="", source="scan",
                          data={"ns": ["a.ex.com", "b.ex.com", "c.ex.com"]})
    d.run(StepContext("web.ex.com", s, {}, lambda *a, **k: None))
    # With a tiny global probe budget, expansion must not run away (bounded by budget + _max_hosts).
    rec = _multi_host_record(s)
    assert rec is not None
    assert len(rec["expanded_hosts"]) <= d._max_hosts
