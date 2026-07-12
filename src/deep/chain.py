"""Exploit chain planning and proof generation (Phase 3).

Builds multi-step attack chains from the fusion attack graph, generates
reproducible PoC scripts per step, runs them through the sandbox for
validation, and records ``validated_by`` / ``breaks_if`` on findings.
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass
from typing import Callable, Optional

from src.deep.sandbox import (
    gen_poc_connect,
    gen_poc_http,
    run_poc,
)

log = logging.getLogger("netlogic.deep.chain")

TECHNIQUE_KEYWORDS: dict[str, list[str]] = {
    "RCE":        ["rce", "remote code", "code execution", "command injection",
                    "shell", "execute", "deserialization", "unauthenticated rce"],
    "SSRF":       ["ssrf", "server-side request", "open redirect"],
    "LFI":        ["lfi", "local file", "path traversal", "directory traversal",
                    "../", "..\\"],
    "SQLi":       ["sql", "sqli", "injection", "sql injection"],
    "XSS":        ["xss", "cross-site", "cross site"],
    "PrivEsc":    ["privilege escalation", "privesc", "privilege"],
    "AuthBypass": ["authentication bypass", "auth bypass", "bypass",
                    "unauthenticated"],
    "InfoLeak":   ["information disclosure", "info leak", "directory listing",
                    "sensitive", "exposure"],
    "MitM":       ["mitm", "man-in-the-middle", "downgrade"],
    "DOS":        ["denial", "dos", "dDoS"],
}

# ── data types ─────────────────────────────────────────────────────────────


@dataclass
class ChainNode:
    """A single step in an exploit chain."""
    subject: str
    host: str
    port: int
    impact: str
    technique: str
    node_id: int
    poc_script: str = ""
    validated: bool = False
    validated_by: str = ""
    breaks_if: str = ""
    evidence: str = ""


@dataclass
class ExploitChain:
    """A multi-step attack path through the graph."""
    steps: list[ChainNode]
    entry_point_id: int
    target_subject: str
    summary: str = ""
    confidence: float = 0.0
    validated: bool = False


# ── attack graph (from fusion verdict rows) ────────────────────────────────


@dataclass
class _GraphNode:
    id: int
    host: str
    port: int
    subject: str
    impact: str
    reachability: str
    reaches: list[str]


@dataclass
class _GraphEdge:
    src: int
    dst: int
    reason: str


def _build_graph(confirmed: list[dict], host_ip: str) -> tuple[list[_GraphNode], list[_GraphEdge], list[int]]:
    """Build a reachability graph from fusion confirmed-verdict rows."""
    nodes: list[_GraphNode] = []
    for i, row in enumerate(confirmed):
        nodes.append(_GraphNode(
            id=i,
            host=host_ip,
            port=row.get("port") or 0,
            subject=row.get("subject", ""),
            impact=row.get("impact", "medium"),
            reachability="public",
            reaches=[],
        ))
    edges: list[_GraphEdge] = []
    for a in nodes:
        for b in nodes:
            if a.id >= b.id:
                continue
            edges.append(_GraphEdge(a.id, b.id, "same-host post-exploitation"))
            edges.append(_GraphEdge(b.id, a.id, "same-host post-exploitation"))
    entry = [n.id for n in nodes]
    return nodes, edges, entry


# ── path finding ───────────────────────────────────────────────────────────


def _find_paths(
    graph: list[_GraphNode],
    edges: list[_GraphEdge],
    entry_points: list[int],
) -> list[list[int]]:
    """BFS from each entry point to every other reachable node.

    Returns a list of paths (each path is a list of node IDs).
    """
    adj: dict[int, list[int]] = {n.id: [] for n in graph}
    for e in edges:
        adj[e.src].append(e.dst)

    paths: list[list[int]] = []
    for start in entry_points:
        for target_node in graph:
            if target_node.id == start:
                continue
            found = _bfs_shortest(adj, start, target_node.id)
            if found:
                paths.append(found)
    return paths


def _bfs_shortest(adj: dict[int, list[int]], start: int, end: int) -> list[int]:
    """Shortest path via BFS."""
    visited = {start}
    queue: deque = deque([(start, [start])])
    while queue:
        node, path = queue.popleft()
        for nxt in adj.get(node, []):
            if nxt == end:
                return path + [nxt]
            if nxt not in visited:
                visited.add(nxt)
                queue.append((nxt, path + [nxt]))
    return []


# ── technique classifier ───────────────────────────────────────────────────


def _classify_technique(subject: str, impact: str) -> str:
    """Map a finding to an attack technique label."""
    lower = subject.lower()
    for tech, keywords in TECHNIQUE_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            return tech
    if impact in ("critical", "high"):
        return "RCE"
    return "Exploit"


# ── PoC script generation per step ─────────────────────────────────────────


def _generate_poc(step: _GraphNode, technique: str, use_tls: bool = False) -> str:
    """Generate a standalone Python PoC script for a chain step."""
    lower = step.subject.lower()
    if technique in ("RCE", "SQLi", "LFI", "SSRF", "XSS", "AuthBypass", "InfoLeak"):
        return gen_poc_http(
            subject=step.subject,
            target=step.host,
            port=step.port,
            use_tls=use_tls,
            path="/",
            expected_pattern="",
        )
    return gen_poc_connect(
        subject=step.subject,
        target=step.host,
        port=step.port,
        use_tls=use_tls,
    )


# ── breaks_if reasoning ────────────────────────────────────────────────────


def _breaks_if(technique: str, impact: str) -> str:
    """Determine the single control that defeats this chain step."""
    mapping = {
        "RCE":        "Input sanitisation / WAF rule on the vulnerable endpoint",
        "SSRF":       "Egress network filtering / private-IP blocklist",
        "LFI":        "Path canonicalisation / chroot jail",
        "SQLi":       "Prepared statements / parameterised queries",
        "XSS":        "Content-Security-Policy / output encoding",
        "PrivEsc":    "Least-privilege OS config / kernel patch",
        "AuthBypass": "Multi-factor authentication / session validation",
        "InfoLeak":   "Response-header stripping / directory listing disabled",
        "MitM":       "HSTS / certificate pinning / TLS 1.3",
        "DOS":        "Rate limiting / upstream DDoS protection",
        "Exploit":    "Vendor security patch / input validation",
    }
    return mapping.get(technique, "Relevant security control / patch")


# ── public entry point ─────────────────────────────────────────────────────


def plan_chains(
    art: dict,
    target: str,
    host_ip: str,
    ai_complete: Optional[Callable] = None,
    emit: Optional[Callable] = None,
) -> dict:
    """Build exploit chains from fusion output and optionally validate via sandbox.

    Returns a dict suitable for storing under ``art["exploit_chains"]``:
    ::
        {
            "chains": [ExploitChain, ...],
            "chain_graph": {"nodes": [...], "edges": [...], "entry_points": [...]},
            "enabled": True,
        }
    """
    fusion = art.get("fusion")
    if not fusion:
        return _empty_result()

    confirmed = fusion.get("confirmed") or []
    if len(confirmed) < 2:
        return _empty_result()

    nodes, edges, entry_points = _build_graph(confirmed, host_ip)
    paths = _find_paths(nodes, edges, entry_points)

    if not paths:
        return _empty_result()

    chains: list[ExploitChain] = []
    for path_ids in paths:
        steps: list[ChainNode] = []
        for nid in path_ids:
            gn = nodes[nid]
            technique = _classify_technique(gn.subject, gn.impact)
            poc = _generate_poc(gn, technique, use_tls=gn.port in (443, 8443))
            steps.append(ChainNode(
                subject=gn.subject,
                host=gn.host,
                port=gn.port,
                impact=gn.impact,
                technique=technique,
                node_id=nid,
                poc_script=poc,
                breaks_if=_breaks_if(technique, gn.impact),
            ))

        entry_point = path_ids[0]
        target_subject = nodes[path_ids[-1]].subject

        chain = ExploitChain(
            steps=steps,
            entry_point_id=entry_point,
            target_subject=target_subject,
            summary=_summarize(steps, nodes),
            confidence=0.0,
        )

        # Validate via sandbox (no AI needed) + AI refinement when available
        _validate_chain(chain, target, ai_complete, emit)

        chains.append(chain)

    # Rank chains by confidence (validated > unvalidated)
    chains.sort(key=lambda c: c.confidence, reverse=True)

    graph_out = {
        "nodes": [{"id": n.id, "subject": n.subject, "host": n.host,
                    "port": n.port, "impact": n.impact}
                  for n in nodes],
        "edges": [{"from": e.src, "to": e.dst, "reason": e.reason}
                  for e in edges],
        "entry_points": entry_points,
    }

    return {
        "chains": [_chain_to_dict(c) for c in chains],
        "chain_graph": graph_out,
        "enabled": True,
    }


def _validate_chain(
    chain: ExploitChain,
    target: str,
    ai_complete: Optional[Callable],
    emit: Optional[Callable],
) -> None:
    """Run each step's PoC through the sandbox and record results."""
    all_validated = True
    for step in chain.steps:
        if not step.poc_script:
            continue
        if emit:
            emit("log", {"text": f"Chain PoC: {step.subject} on {step.host}:{step.port}",
                         "level": "info"})
        result = run_poc(step.poc_script, target, timeout=15)
        step.validated = result.success
        step.validated_by = "sandbox" if result.success else ""
        step.evidence = result.stdout[:500] or result.error
        if not result.success:
            all_validated = False

    if all_validated and chain.steps:
        chain.validated = True
        chain.confidence = 1.0
    elif chain.steps:
        validated_count = sum(1 for s in chain.steps if s.validated)
        chain.confidence = validated_count / len(chain.steps)

    # Use AI to refine summary if available
    if ai_complete and chain.steps:
        try:
            _ai_refine_chain(chain, ai_complete)
        except Exception as exc:
            log.warning("Chain AI refinement: %s", exc)


def _ai_refine_chain(chain: ExploitChain, ai_complete: Callable) -> None:
    """Ask the AI to generate a human-readable chain summary."""
    steps_text = "\n".join(
        f"  {i+1}. {s.subject} ({s.technique}) on {s.host}:{s.port} "
        f"— impact: {s.impact}"
        for i, s in enumerate(chain.steps)
    )
    prompt = (
        "You are a red-team lead summarizing an attack chain.\n"
        f"Chain steps:\n{steps_text}\n\n"
        "Write a 1-2 sentence summary of what this chain achieves "
        "from the attacker's perspective. Be specific about the entry point "
        "and the ultimate impact.\n"
    )
    reply = ai_complete(prompt)
    if reply:
        cleaned = reply.strip().strip('"').strip("'")
        if cleaned:
            chain.summary = cleaned


def _summarize(steps: list[ChainNode], nodes: list[_GraphNode]) -> str:
    """Generate a basic deterministic summary without AI."""
    if not steps:
        return ""
    entry = nodes[steps[0].node_id]
    target = nodes[steps[-1].node_id]
    return (
        f"Compromise {entry.subject} on {entry.host}:{entry.port} "
        f"({entry.impact}) → pivot to {target.subject} on {target.host}:{target.port} "
        f"({target.impact})"
    )


def _chain_to_dict(chain: ExploitChain) -> dict:
    return {
        "steps": [
            {
                "subject": s.subject,
                "host": s.host,
                "port": s.port,
                "impact": s.impact,
                "technique": s.technique,
                "node_id": s.node_id,
                "poc_script": s.poc_script,
                "validated": s.validated,
                "validated_by": s.validated_by,
                "breaks_if": s.breaks_if,
                "evidence": s.evidence,
            }
            for s in chain.steps
        ],
        "entry_point_id": chain.entry_point_id,
        "target_subject": chain.target_subject,
        "summary": chain.summary,
        "confidence": chain.confidence,
        "validated": chain.validated,
    }


def _empty_result() -> dict:
    return {"chains": [], "chain_graph": None, "enabled": False}
