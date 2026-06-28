"""Multi-host expansion + dispatch (Phase 6c).

Pins: lazy HostCandidate (ranking spawns no reasoners), authorized-only expansion, loop-level
dispatch over multiple hosts ("probes on both"), per-host budget independence under a global cap,
hypothesis isolation, and the default-OFF flag (byte-identical guarantee).
"""
from src.reasoning.budget import BudgetManager
from src.reasoning.decision_policy import GreedyPolicy
from src.reasoning.cross_host import ScopeAuthorizer
from src.reasoning.multi_host import (
    dispatch,
    expand_world,
    host_expansion_candidates,
    make_host_candidate,
)
from src.reasoning.state import ReasoningState
from src.reasoning.world_state import WorldState


def _web_state_with_neighbor(neighbor="mail.ex.com", source_kind="dns", data_key="mx"):
    s = ReasoningState(target="web.ex.com:80", scope=["ex.com"])
    n = s.world.graph.upsert_node("service", "web.ex.com:80")
    if source_kind == "dns":
        s.world.graph.observe(n, kind="dns_records", evidence="", source="scan",
                              data={data_key: [neighbor]})
    elif source_kind == "http_redirect":
        s.world.graph.observe(n, kind="http_headers",
                              evidence=f"HTTP/1.1 301\r\nLocation: https://{neighbor}/", source="scan")
    return s


def _build_host_state(host):
    return ReasoningState(target=host, scope=["ex.com"])


# ── Lazy expansion ──

def test_ranking_host_candidates_spawns_no_reasoners():
    s = _web_state_with_neighbor()
    ws = WorldState.single_host(s)
    auth = ScopeAuthorizer()
    cands = host_expansion_candidates(ws, ["ex.com"], auth, _build_host_state)
    assert cands, "expected an authorized in-scope neighbor candidate"
    GreedyPolicy().rank_candidates(cands)
    # Ranking must not create the neighbor host.
    assert "mail.ex.com" not in ws.hosts
    assert len(ws.hosts) == 1


def test_instantiate_spawns_the_reasoner():
    s = _web_state_with_neighbor()
    ws = WorldState.single_host(s)
    cands = host_expansion_candidates(ws, ["ex.com"], ScopeAuthorizer(), _build_host_state)
    cands[0].instantiate()
    assert "mail.ex.com" in ws.hosts
    assert len(ws.hosts) == 2


# ── Authorized-only expansion ──

def test_expand_world_creates_in_scope_neighbor():
    s = _web_state_with_neighbor("mail.ex.com")
    ws = WorldState.single_host(s)
    created = expand_world(ws, ["ex.com"], ScopeAuthorizer(), _build_host_state, GreedyPolicy())
    assert created == ["mail.ex.com"]
    assert "mail.ex.com" in ws.hosts


def test_expand_world_skips_out_of_scope_neighbor():
    s = _web_state_with_neighbor("mail.evil.com")    # out of scope
    ws = WorldState.single_host(s)
    created = expand_world(ws, ["ex.com"], ScopeAuthorizer(), _build_host_state, GreedyPolicy())
    assert created == []
    assert "mail.evil.com" not in ws.hosts            # off-scope never spawns a host


def test_expansion_records_edges_on_environment_graph():
    s = _web_state_with_neighbor("mail.ex.com")
    ws = WorldState.single_host(s)
    expand_world(ws, ["ex.com"], ScopeAuthorizer(), _build_host_state, GreedyPolicy())
    dests = {e.dest_host for e in ws.environment.cross_host_graph.edges}
    assert "mail.ex.com" in dests                     # discovery recorded as facts


# ── Loop-level dispatch ("probes on both") ──

def test_dispatch_runs_every_host():
    s = _web_state_with_neighbor("mail.ex.com")
    ws = WorldState.single_host(s)
    expand_world(ws, ["ex.com"], ScopeAuthorizer(), _build_host_state, GreedyPolicy())

    probed = []
    dispatch(ws, run_host=lambda hr: probed.append(hr.host))
    assert set(probed) == {"web.ex.com:80", "mail.ex.com"}    # both hosts reasoned over


# ── Hierarchical budgets ──

def test_per_host_budget_independent_under_global_cap():
    global_budget = BudgetManager(max_probes=10, max_recursion=99)
    a = BudgetManager(max_probes=3, max_recursion=99, parent=global_budget)
    b = BudgetManager(max_probes=3, max_recursion=99, parent=global_budget)

    for _ in range(3):
        a.spend({"probes": 1})
    assert a.exhausted()           # host A hit its own cap
    assert not b.exhausted()       # host B is unaffected
    assert b.can_afford({"probes": 1})   # and can still proceed

    # Global aggregate tracks both hosts' spend.
    assert global_budget.probes_run == 3


def test_global_cap_stops_all_hosts():
    global_budget = BudgetManager(max_probes=4, max_recursion=99)
    a = BudgetManager(max_probes=100, max_recursion=99, parent=global_budget)
    b = BudgetManager(max_probes=100, max_recursion=99, parent=global_budget)
    for _ in range(2):
        a.spend({"probes": 1})
    for _ in range(2):
        b.spend({"probes": 1})
    # Global cap (4) reached → neither host may spend more, despite roomy per-host caps.
    assert not a.can_afford({"probes": 1})
    assert not b.can_afford({"probes": 1})


def test_per_host_depth_not_propagated_to_global():
    """Recursion depth is per-host; it must not exhaust the global aggregate across hosts."""
    global_budget = BudgetManager(max_probes=100, max_recursion=99)
    hosts = [BudgetManager(max_probes=100, max_recursion=6, parent=global_budget) for _ in range(5)]
    for h in hosts:
        for _ in range(5):
            h.spend({"probes": 1})
    # 25 spends across 5 hosts; global depth must NOT be 25-bound (depth is per-host only).
    assert not global_budget.exhausted()
    assert global_budget.probes_run == 25


# ── Isolation ──

def test_hypothesis_isolation_between_hosts():
    s = _web_state_with_neighbor("mail.ex.com")
    ws = WorldState.single_host(s)
    expand_world(ws, ["ex.com"], ScopeAuthorizer(), _build_host_state, GreedyPolicy())

    web = ws.hosts.get("web.ex.com:80")
    mail = ws.hosts.get("mail.ex.com")
    # A contradiction recorded on web must not appear on mail (separate reasoning contexts).
    web.state.investigation.contradictions.append({"signal": "x", "source": "test"})
    assert mail.state.investigation.contradictions == []


# ── Flag default OFF (byte-identical guarantee) ──

def test_world_modeling_flag_defaults_off():
    s = ReasoningState(target="ex.com:80", scope=["ex.com"])
    assert s.world_modeling_enabled is False


def test_world_modeling_flag_round_trips():
    s = ReasoningState(target="ex.com:80", scope=["ex.com"], world_modeling_enabled=True)
    assert ReasoningState.from_dict(s.to_dict()).world_modeling_enabled is True
