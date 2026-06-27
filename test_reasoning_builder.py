"""Builder: artifacts → deduplicated graph + derived beliefs + structured explanations."""
from src.reasoning import ReasoningState, build_reasoning_state


def _artifacts():
    return {
        "host_result": {"ip": "45.33.32.156", "hostname": "scanme.nmap.org",
                        "ports": [{"port": 22, "service": "ssh"}, {"port": 80, "service": "http"}]},
        "vuln_matches": [
            {"port": 80, "service": "http", "product": "apache", "version": "2.4.7",
             "detection_confidence": "HIGH", "cves": [
                {"id": "CVE-2021-40438", "cvss_score": 9.0, "kev": False,
                 "exploit_available": True, "description": "mod_proxy SSRF"}]},
        ],
        "vuln_probe_result": {"confirmed": [{"cve_id": "CWE-601", "title": "Open redirect", "confirmed": True}]},
        "stack_result": {"technologies": [{"name": "wordpress", "version": None}]},
    }


def test_builder_creates_graph_nodes_and_host_edges():
    st = build_reasoning_state("scanme.nmap.org", ["scanme.nmap.org"], _artifacts())
    kinds = {n.kind for n in st.world.graph.nodes()}
    assert {"host", "ip", "cve", "service"} <= kinds
    # host resolves_to ip edge exists, by id
    assert any(e.type == "resolves_to" for e in st.world.graph.edges())


def test_builder_derives_beliefs_with_version_cap():
    st = build_reasoning_state("scanme.nmap.org", ["scanme.nmap.org"], _artifacts())
    # version-only Apache CVE capped; probe-confirmed finding high
    assert st.world.beliefs["CVE-2021-40438"] <= 0.60
    assert st.world.beliefs["CWE-601"] >= 0.95


def test_builder_explanations_are_structured_no_prose():
    st = build_reasoning_state("scanme.nmap.org", ["scanme.nmap.org"], _artifacts())
    assert st.execution.explanations
    for ex in st.execution.explanations:
        assert ex["rule_applied"]                 # a deterministic rule id is always set
        assert ex["ai_summary"] == ""             # no LLM/prose in Phase 1
        assert isinstance(ex["evidence_ids"], list)
    rules = {ex["rule_applied"] for ex in st.execution.explanations}
    assert "version_matched_cap" in rules and "probe_confirmed" in rules


def test_builder_output_roundtrips_with_graph():
    st = build_reasoning_state("scanme.nmap.org", ["scanme.nmap.org"], _artifacts())
    restored = ReasoningState.from_json(st.to_json())
    assert len(restored.world.graph) == len(st.world.graph)
    assert restored.world.beliefs == st.world.beliefs


def test_builder_is_deterministic():
    a = build_reasoning_state("scanme.nmap.org", ["scanme.nmap.org"], _artifacts())
    b = build_reasoning_state("scanme.nmap.org", ["scanme.nmap.org"], _artifacts())
    assert len(a.world.graph) == len(b.world.graph)
    assert a.world.beliefs == b.world.beliefs
