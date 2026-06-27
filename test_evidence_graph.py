"""EvidenceGraph: stable IDs, deduplicated entities, append-only immutable observations."""
import dataclasses

import pytest

from src.reasoning.evidence_graph import EvidenceGraph, node_id


def test_node_id_is_deterministic_per_identity():
    assert node_id("service", "1.2.3.4", 443) == "service:1.2.3.4:443"
    assert node_id("host", "Example.COM") == "host:example.com"          # normalized
    assert node_id("cve", "CVE-2024-1") == "cve:cve-2024-1"
    assert node_id("service", "1.2.3.4", 443) == node_id("service", "1.2.3.4", 443)


def test_entities_are_deduplicated_observations_append():
    g = EvidenceGraph()
    n1 = g.upsert_node("service", "h", 80)
    n2 = g.upsert_node("service", "h", 80)            # same identity → same node
    assert n1 is n2
    assert len(g) == 1

    g.observe(n1, kind="banner", evidence="Apache/2.4.7", source="scan")
    g.observe(n1, kind="banner", evidence="Apache/2.4.7", source="scan")   # identical fact → deduped
    assert len(n1.observations()) == 1
    g.observe(n1, kind="header", evidence="Server: Apache", source="headers")  # distinct fact → appends
    assert len(n1.observations()) == 2


def test_observations_are_immutable():
    g = EvidenceGraph()
    n = g.upsert_node("host", "h")
    obs = g.observe(n, kind="host", evidence="h", source="scan")
    with pytest.raises(dataclasses.FrozenInstanceError):
        obs.evidence = "tampered"


def test_node_holds_no_confidence_scalar():
    g = EvidenceGraph()
    n = g.upsert_node("cve", "CVE-2024-1")
    # the truth model forbids a stored confidence on nodes — it's derived elsewhere
    assert not hasattr(n, "confidence")


def test_edges_reference_node_ids_and_dedup():
    g = EvidenceGraph()
    a = g.upsert_node("host", "mail.example.com")
    b = g.upsert_node("host", "exchange.example.com")
    e1 = g.add_edge("infers_host", a.id, b.id, evidence="OWA → Exchange")
    e2 = g.add_edge("infers_host", a.id, b.id)                  # same relationship → merged
    assert e1 is e2
    assert len(g.edges()) == 1
    assert e1.source_id == a.id and e1.target_id == b.id        # IDs, not embedded objects


def test_graph_roundtrips_through_dict():
    g = EvidenceGraph()
    n = g.upsert_node("ip", "1.2.3.4")
    g.observe(n, kind="ip", evidence="1.2.3.4", source="scan")
    g.add_edge("same_asn", n.id, n.id, evidence="AS123")
    restored = EvidenceGraph.from_dict(g.to_dict())
    assert len(restored) == 1
    assert restored.get("ip:1.2.3.4") is not None
    assert len(restored.edges()) == 1
