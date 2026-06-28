"""WorldState / HostManager / HostReasoner adapter (Phase 6a).

Adapter-first: a one-host WorldState wraps today's ReasoningState with no behavior change. These
tests pin: (a) WorldState stays a thin 3-field root (god-object tripwire), (b) the single-host
adapter is equivalent to the bare ReasoningState, (c) serialization round-trips, (d) HostManager
owns lifecycle.
"""
import dataclasses as dc

import pytest

from src.reasoning.budget import BudgetManager
from src.reasoning.objective import Objective
from src.reasoning.state import ReasoningState
from src.reasoning.world_state import (
    EnvironmentGraph,
    HostManager,
    HostReasoner,
    WorldState,
)


def _state(target="ex.com:80"):
    s = ReasoningState(target=target, scope=[target])
    s.investigation.objectives.add(Objective(name="identify_framework:ex.com:80"))
    s.investigation.hypotheses.add_hypothesis(
        label="fw", likelihoods={"wordpress": 0.5, "spring_boot": 0.5})
    n = s.world.graph.upsert_node("service", target)
    s.world.graph.observe(n, kind="http_headers", evidence="server: nginx", source="scan")
    return s


# ── Thin root: god-object tripwire ──

def test_worldstate_has_exactly_three_fields():
    """WorldState must stay a thin coordination root. Adding a field is a conscious decision:
    if this fails, the new responsibility belongs in a collaborator (environment/hosts/budget),
    not on the root."""
    fields = {f.name for f in dc.fields(WorldState)}
    assert fields == {"environment", "hosts", "global_budget"}, f"WorldState grew: {fields}"


def test_worldstate_holds_no_reasoning_fields():
    ws = WorldState()
    for forbidden in ("objectives", "hypotheses", "beliefs", "execution", "investigation"):
        assert not hasattr(ws, forbidden), f"WorldState must not own {forbidden}"


# ── Adapter equivalence ──

def test_single_host_wraps_state_unchanged():
    s = _state()
    ws = WorldState.single_host(s)
    assert ws.is_single_host
    assert len(ws.hosts) == 1
    primary = ws.primary()
    assert primary is not None
    assert primary.state is s                      # same object, no copy
    assert primary.host == "ex.com:80"


def test_single_host_environment_shares_the_evidence_graph():
    s = _state()
    ws = WorldState.single_host(s)
    # Observations are shared truth: the environment graph IS the host's graph.
    assert ws.environment.evidence_graph is s.world.graph


def test_host_reasoner_accessors_delegate_to_state():
    s = _state()
    hr = HostReasoner(host="ex.com:80", state=s)
    assert hr.objectives is s.investigation.objectives
    assert hr.hypotheses is s.investigation.hypotheses
    assert hr.execution is s.execution
    assert hr.persona == s.investigation.persona


# ── Serialization round-trip ──

def test_worldstate_round_trip_preserves_host_state():
    s = _state()
    ws = WorldState.single_host(s, global_budget=BudgetManager.for_tier("local"))
    restored = WorldState.from_dict(ws.to_dict())

    assert restored.is_single_host
    rp = restored.primary()
    assert rp is not None
    # The wrapped ReasoningState survives the round-trip structurally.
    assert rp.state.target == s.target
    assert rp.state.investigation.objectives.get("identify_framework:ex.com:80") is not None
    assert len(rp.state.investigation.hypotheses) == len(s.investigation.hypotheses)
    # Global budget tier preserved.
    assert restored.global_budget.max_probes == BudgetManager.for_tier("local").max_probes


def test_environment_graph_round_trip():
    s = _state()
    env = EnvironmentGraph(evidence_graph=s.world.graph)
    restored = EnvironmentGraph.from_dict(env.to_dict())
    assert restored.to_dict() == env.to_dict()
    assert restored.cross_host_graph.edges == []     # empty in 6a


# ── HostManager lifecycle ──

def test_host_manager_create_get_remove():
    mgr = HostManager()
    s = _state()
    hr = mgr.create("ex.com:80", s)
    assert mgr.get("ex.com:80") is hr
    assert "ex.com:80" in mgr
    assert len(mgr) == 1

    # create is idempotent for the same host
    hr2 = mgr.create("ex.com:80", _state())
    assert hr2 is hr
    assert len(mgr) == 1

    mgr.remove("ex.com:80")
    assert mgr.get("ex.com:80") is None
    assert len(mgr) == 0


def test_host_manager_all_lists_reasoners():
    mgr = HostManager()
    mgr.create("a:80", ReasoningState(target="a:80", scope=["a:80"]))
    mgr.create("b:80", ReasoningState(target="b:80", scope=["b:80"]))
    hosts = {hr.host for hr in mgr.all()}
    assert hosts == {"a:80", "b:80"}
