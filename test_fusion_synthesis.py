"""Tests for the synthesis pass — deterministic graph + grounded narration. Offline."""

from src.fusion.gate import Verdict
from src.fusion.signals import Signal
from src.fusion.synthesis import build_attack_graph, synthesize


def _finding(claim, host, port, impact="high", exposure=None):
    s = Signal(source="probe", kind="vuln", claim=claim, host=host, port=port, exposure=exposure)
    return Verdict(host=host, port=port, claim=claim, decision="confirmed", impact=impact, signals=[s])


# ── Deterministic graph: the "connect two isolated findings" proof ──────────────

def test_same_host_findings_are_connected():
    # A public RCE on A:443 and an internal admin panel on A:8080 are connected by a
    # same-host post-exploitation edge — the chain that the AI then narrates.
    v1 = _finding("CVE-RCE", "A", 443, "critical", {"reachability": "public"})
    v2 = _finding("admin-panel", "A", 8080, "high", {"reachability": "private"})
    g = build_attack_graph([v1, v2])
    assert any(e.src == 0 and e.dst == 1 for e in g.edges)
    assert any(e.reason == "same-host post-exploitation" for e in g.edges)
    assert g.entry_points == [0]            # only the public one is an entry point


def test_unreachable_different_hosts_are_isolated():
    # No edge is invented between two hosts with no reachability relationship.
    v1 = _finding("x", "A", 443, exposure={"reachability": "public"})
    v2 = _finding("y", "B", 22, exposure={"reachability": "private"})
    g = build_attack_graph([v1, v2])
    assert g.edges == []


def test_explicit_reach_creates_cross_host_edge():
    # exposure.reaches makes the public host able to pivot to an internal host.
    v1 = _finding("CVE-RCE", "A", 443, "critical", {"reachability": "public", "reaches": ["B:22"]})
    v2 = _finding("weak-ssh", "B", 22, "high", {"reachability": "private"})
    g = build_attack_graph([v1, v2])
    assert any(e.src == 0 and e.dst == 1 and e.reason == "network-reachable" for e in g.edges)


# ── Narration is grounded in the real graph ─────────────────────────────────────

def test_synthesize_feeds_real_edges_and_narrates_the_chain():
    v1 = _finding("CVE-RCE", "A", 443, "critical", {"reachability": "public"})
    v2 = _finding("admin-panel", "A", 8080, "high", {"reachability": "private"})
    captured = {}

    def fake(system, user):
        captured["system"] = system
        captured["user"] = user
        return ("## Attack Chains\n### Chain 1 — public RCE to internal panel\n"
                "- **Steps:** 1. exploit `CVE-RCE` (id 0) -> same-host post-exploitation -> "
                "reach `admin-panel` (id 1)\n- **Impact:** full host control\n"
                "- **Breaks if:** patch the RCE")

    md = synthesize([v1, v2], complete=fake)
    # The prompt carried the real edge + both findings + the entry point…
    assert "same-host post-exploitation" in captured["user"]
    assert "admin-panel" in captured["user"] and "CVE-RCE" in captured["user"]
    assert '"entry_points": [\n    0\n  ]' in captured["user"] or '"entry_points": [0]' in captured["user"]
    # …and the system prompt forbids inventing connectivity.
    assert "NEVER invent connectivity" in captured["system"]
    # …and the narrated chain connects the two isolated findings.
    assert "Chain 1" in md and "CVE-RCE" in md and "admin-panel" in md


def test_synthesize_failsoft_on_model_error():
    v1 = _finding("CVE-RCE", "A", 443, "critical", {"reachability": "public"})

    def boom(system, user):
        raise RuntimeError("HTTP 402")

    out = synthesize([v1], complete=boom)
    assert out.startswith("_Attack-chain synthesis unavailable")


def test_empty_findings_is_noop():
    assert synthesize([]) == "_No confirmed findings to synthesize._"
