"""CrossHostGraph (structure) + ScopeAuthorizer (policy) — Phase 6b.

Pins the truth/policy separation: the graph holds immutable edges that carry their own observation
refs (confidence computed from them); authorization is a separate policy that reads edges + scope and
never mutates the graph.
"""
import dataclasses as dc

from src.reasoning.cross_host import (
    AuthDecision,
    CrossHostEdge,
    CrossHostGraph,
    ScopeAuthorizer,
    derive_cross_host_edges,
)
from src.reasoning.state import ReasoningState


# ── Immutable edge with intrinsic provenance ──

def test_edge_is_frozen():
    assert CrossHostEdge.__dataclass_params__.frozen


def test_confidence_computed_from_observations_and_source():
    dns1 = CrossHostEdge("a", "b", observations=("o1",), source_kind="dns")
    dns2 = CrossHostEdge("a", "b", observations=("o1", "o2", "o3"), source_kind="dns")
    banner = CrossHostEdge("a", "b", observations=("o1",), source_kind="banner")
    assert dns1.confidence == 0.9                 # base DNS weight, 1 obs
    assert dns2.confidence > dns1.confidence       # more observations → higher confidence
    assert banner.confidence < dns1.confidence     # weaker source → lower confidence


def test_edge_carries_observation_refs_as_provenance():
    e = CrossHostEdge("web.ex.com", "mail.ex.com", observations=("obsA", "obsB"), source_kind="dns")
    # The edge IS its provenance — no separate lookup needed.
    assert set(e.observations) == {"obsA", "obsB"}


# ── Derivation from evidence content only ──

def _graph_with(node_key, *, kind, evidence="", data=None):
    s = ReasoningState(target=node_key, scope=[node_key])
    n = s.world.graph.upsert_node("service", node_key)
    s.world.graph.observe(n, kind=kind, evidence=evidence, source="scan", data=data or {})
    return s.world.graph


def test_derive_dns_neighbors():
    g = _graph_with("ex.com:53", kind="dns_records", data={"mx": ["mail.ex.com"], "ns": ["ns1.ex.com"]})
    edges = derive_cross_host_edges(g)
    dests = {(e.dest_host, e.source_kind) for e in edges}
    assert ("mail.ex.com", "dns") in dests
    assert ("ns1.ex.com", "dns") in dests


def test_derive_http_redirect_neighbor():
    g = _graph_with("web.ex.com:80", kind="http_headers",
                    evidence="HTTP/1.1 301\r\nLocation: https://admin.ex.com/login")
    edges = derive_cross_host_edges(g)
    assert any(e.dest_host == "admin.ex.com" and e.source_kind == "http_redirect" for e in edges)


def test_derive_tls_san_neighbors():
    g = _graph_with("ex.com:443", kind="tls_cert", data={"san": ["ex.com", "portal.ex.com", "*.api.ex.com"]})
    edges = derive_cross_host_edges(g)
    dests = {e.dest_host for e in edges if e.source_kind == "tls_san"}
    assert "portal.ex.com" in dests
    assert "api.ex.com" in dests          # wildcard stripped
    assert "ex.com" not in dests          # self excluded


def test_derive_excludes_self_and_attaches_obs_ids():
    g = _graph_with("ex.com:53", kind="dns_records", data={"mx": ["mail.ex.com"]})
    edges = derive_cross_host_edges(g)
    assert edges and all(e.observations for e in edges)   # provenance attached


def test_derivation_is_evidence_only_no_invention():
    g = _graph_with("ex.com:80", kind="http_headers", evidence="Server: nginx")  # no neighbor signal
    assert derive_cross_host_edges(g) == []


# ── ScopeAuthorizer: policy separate from graph ──

def test_authorize_in_scope_and_confident():
    auth = ScopeAuthorizer(min_confidence=0.6)
    edge = CrossHostEdge("web.ex.com", "mail.ex.com", observations=("o1",), source_kind="dns")  # 0.9
    assert auth.evaluate(edge, scope=["ex.com"]) == AuthDecision.AUTHORIZE


def test_reject_out_of_scope_is_terminal():
    auth = ScopeAuthorizer()
    edge = CrossHostEdge("web.ex.com", "evil.com", observations=("o1",), source_kind="dns")
    assert auth.evaluate(edge, scope=["ex.com"]) == AuthDecision.REJECT
    # terminal: stays rejected even if a later (hypothetical) call would otherwise differ
    assert auth.evaluate(edge, scope=["ex.com", "evil.com"]) == AuthDecision.REJECT


def test_defer_in_scope_but_low_confidence():
    auth = ScopeAuthorizer(min_confidence=0.95)
    edge = CrossHostEdge("web.ex.com", "mail.ex.com", observations=("o1",), source_kind="banner")  # 0.5
    assert auth.evaluate(edge, scope=["ex.com"]) == AuthDecision.DEFER
    # defer is NOT terminal — raising confidence (more obs) could authorize next time
    stronger = CrossHostEdge("web.ex.com", "mail.ex.com",
                             observations=tuple(f"o{i}" for i in range(12)), source_kind="dns")
    assert auth.evaluate(stronger, scope=["ex.com"]) == AuthDecision.AUTHORIZE


def test_changing_authorizer_rules_does_not_mutate_graph():
    graph = CrossHostGraph()
    edge = CrossHostEdge("web.ex.com", "mail.ex.com", observations=("o1",), source_kind="dns")
    graph.add_edge(edge)
    before = graph.to_dict()

    # Evaluate under two different policies; neither may touch the graph.
    ScopeAuthorizer(min_confidence=0.1).evaluate(edge, scope=["ex.com"])
    ScopeAuthorizer(min_confidence=0.99).evaluate(edge, scope=["nope.com"])
    assert graph.to_dict() == before
    # The graph stores no authorization flags.
    edge_fields = {f.name for f in dc.fields(CrossHostEdge)}
    assert "authorized" not in edge_fields and "state" not in edge_fields


def test_graph_dedup_keeps_better_supported_edge():
    g = CrossHostGraph()
    g.add_edge(CrossHostEdge("a", "b", observations=("o1",), source_kind="dns"))
    g.add_edge(CrossHostEdge("a", "b", observations=("o1", "o2"), source_kind="dns"))
    assert len(g.edges) == 1
    assert len(g.edges[0].observations) == 2     # kept the better-supported one
