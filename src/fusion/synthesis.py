"""
Fusion layer — the synthesis pass (attack-chain narration over a REAL graph).

LLMs cannot do zero-shot graph traversal — dump a flat list of findings and they
hallucinate impossible pivots (XSS on a public marketing site -> internal DB on a
different subnet). So we DETERMINISTICALLY pre-compute the reachability edges from
the findings' exposure context, hand the model an explicit graph, and ask it to
EXPLAIN paths along real edges — never to discover topology.

Edge rules (deterministic):
  • same-host: after compromising one service on a host, its other services are
    reachable (local post-exploitation) — an edge both ways.
  • explicit reach: a finding whose exposure carries `reaches: ["host:port"|"host"]`
    gets an edge to matching findings (network-reachable from there).
Entry points = findings whose exposure reachability is "public".

The model call is injected (`complete`) so this is offline-testable; the live
narration uses the configured model via src.fusion.ai.make_completer().
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable, Optional

from src.fusion.gate import Verdict


@dataclass
class GraphNode:
    id: int
    host: str
    port: Optional[int]
    claim: str
    impact: str
    exposure: dict


@dataclass
class GraphEdge:
    src: int
    dst: int
    reason: str


@dataclass
class AttackGraph:
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    entry_points: list[int] = field(default_factory=list)


def _exposure_of(v: Verdict) -> dict:
    for s in v.signals:
        if s.exposure:
            return s.exposure
    return {"reachability": "unknown"}


def _reaches(exposure: dict, host: str, port) -> bool:
    targets = exposure.get("reaches") or []
    if not isinstance(targets, list):
        return False
    want = {f"{host}:{port}", str(host)}
    return any(str(t) in want for t in targets)


def build_attack_graph(findings: list[Verdict]) -> AttackGraph:
    """Compute the deterministic reachability graph over confirmed findings."""
    nodes = [
        GraphNode(i, v.host, v.port, v.claim, v.impact, _exposure_of(v))
        for i, v in enumerate(findings)
    ]
    edges: list[GraphEdge] = []
    for a in nodes:
        for b in nodes:
            if a.id >= b.id:
                continue
            if a.host == b.host:
                edges.append(GraphEdge(a.id, b.id, "same-host post-exploitation"))
                edges.append(GraphEdge(b.id, a.id, "same-host post-exploitation"))
            else:
                if _reaches(a.exposure, b.host, b.port):
                    edges.append(GraphEdge(a.id, b.id, "network-reachable"))
                if _reaches(b.exposure, a.host, a.port):
                    edges.append(GraphEdge(b.id, a.id, "network-reachable"))
    entry = [n.id for n in nodes if (n.exposure or {}).get("reachability") == "public"]
    return AttackGraph(nodes=nodes, edges=edges, entry_points=entry)


_SYNTH_SYSTEM = (
    "You are a red-team lead writing the attack-chain narrative for a set of CONFIRMED "
    "findings. You are given: the findings, an explicit reachability GRAPH (directed "
    "edges between finding ids), and which findings are public ENTRY POINTS.\n\n"
    "Construct attack chains ONLY along the provided edges. NEVER invent connectivity "
    "between findings that the graph does not contain — if two findings are not connected "
    "by an edge, they are on separate paths. Every chain must START at a public entry "
    "point and pivot strictly along edges.\n\n"
    "Output GitHub-Flavored Markdown:\n"
    "## Attack Chains\n"
    "For each chain:\n"
    "### Chain <N> — <short title>\n"
    "- **Steps:** numbered; each step names the finding (by subject and id) it exploits "
    "and, for a pivot, the edge reason used.\n"
    "- **Impact:** what the attacker ultimately gains.\n"
    "- **Breaks if:** the single control that defeats this chain.\n"
    "If no multi-step path exists along the edges, output exactly: "
    "`_No multi-step attack chain across the confirmed findings._`"
)


def _build_user(graph: AttackGraph) -> str:
    payload = {
        "findings": [
            {"id": n.id, "subject": n.claim, "host": n.host, "port": n.port,
             "impact": n.impact, "exposure": n.exposure}
            for n in graph.nodes
        ],
        "edges": [{"from": e.src, "to": e.dst, "reason": e.reason} for e in graph.edges],
        "entry_points": graph.entry_points,
    }
    return (
        "Narrate the attack chains over this graph. Use ONLY the provided edges.\n\n"
        "```json\n" + json.dumps(payload, indent=2, default=str) + "\n```"
    )


def synthesize(findings: list[Verdict], complete: Optional[Callable[[str, str], str]] = None) -> str:
    """Build the reachability graph from confirmed findings and narrate attack chains
    over its real edges. Returns markdown. Fail-soft: returns a clear note on error."""
    if not findings:
        return "_No confirmed findings to synthesize._"
    graph = build_attack_graph(findings)

    if complete is None:
        from src.fusion.ai import make_completer  # noqa: PLC0415
        complete = make_completer()

    try:
        return complete(_SYNTH_SYSTEM, _build_user(graph)).strip()
    except Exception as exc:  # noqa: BLE001 — never break the report
        return f"_Attack-chain synthesis unavailable ({exc})._"
