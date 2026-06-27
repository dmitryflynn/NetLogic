"""
Builder — passively populates a ReasoningState from already-collected scan artifacts.

See the Phase 1 plan. This runs AFTER the deterministic pipeline has produced its artifacts;
it reads them (no new network activity) and fills the truth model:

  • creates deduplicated EvidenceGraph nodes + immutable observations (Builder owns these),
  • asks the ConfidenceEngine for derived beliefs (ConfidenceEngine owns confidence),
  • emits structured Explanation records.

It must never change scan behavior: it emits nothing, returns a ReasoningState, and is called
fail-soft by the engine. Reuses `fusion/engine_bridge.signals_from_artifacts` so signal
extraction is not duplicated.
"""
from __future__ import annotations

import logging
from typing import Optional

from src.fusion.signals import Signal
from src.reasoning.confidence import Belief, ConfidenceEngine, _node_id_for
from src.reasoning.evidence_graph import EvidenceGraph, node_id
from src.reasoning.explanation import Explanation
from src.reasoning.state import ReasoningState

log = logging.getLogger("netlogic.reasoning.builder")

# Confidence thresholds that map a continuous posterior to a reportable decision band.
_CONFIRM_AT = 0.85
_DISCARD_BELOW = 0.20


def _decision_for(belief: Belief) -> str:
    if belief.rule_applied in ("kev_pin", "probe_confirmed") or belief.confidence >= _CONFIRM_AT:
        return "confirmed"
    if belief.confidence < _DISCARD_BELOW and belief.impact in ("low", "medium"):
        return "discarded"
    return "potential"


def build_reasoning_state(target: str, scope: list[str], artifacts: dict,
                          signals: Optional[list[Signal]] = None) -> ReasoningState:
    """Build a ReasoningState from engine artifacts. Pure, offline, deterministic."""
    if signals is None:
        from src.fusion.engine_bridge import signals_from_artifacts  # noqa: PLC0415
        signals = signals_from_artifacts(artifacts) or []

    state = ReasoningState(target=target, scope=list(scope or []))
    graph: EvidenceGraph = state.world.graph

    # ── Host / IP node from the host result ───────────────────────────────────────
    host = (artifacts.get("host_result") or {})
    ip = host.get("ip") if isinstance(host, dict) else None
    hostname = (host.get("hostname") or host.get("target")) if isinstance(host, dict) else None
    host_node = None
    if hostname:
        host_node = graph.upsert_node("host", hostname, label=str(hostname))
        graph.observe(host_node, kind="host", evidence=str(hostname), source="scan")
    if ip:
        ip_node = graph.upsert_node("ip", ip, label=str(ip))
        graph.observe(ip_node, kind="ip", evidence=str(ip), source="scan")
        if host_node is not None:
            graph.add_edge("resolves_to", host_node.id, ip_node.id, evidence=str(ip))

    # ── Builder owns nodes + observations: one per signal ─────────────────────────
    for s in signals:
        nid = _node_id_for(s)
        kind = {"vuln": "cve", "tech": "technology", "misconfig": "misconfiguration",
                "exposure": "exposure", "service": "service"}.get(s.kind, s.kind or "claim")
        node = graph.upsert_node(kind, s.claim, label=s.claim)
        # the stable id from upsert may differ from _node_id_for's heuristic; align on upsert's
        graph.observe(node, kind=s.kind or "claim", evidence=s.evidence or s.claim,
                      source=s.source, reliability=s.reliability,
                      data={"port": s.port, "service": s.service})
        if s.port is not None:
            svc = graph.upsert_node("service", s.host, s.port, label=f"{s.host}:{s.port}")
            graph.add_edge("affects", node.id, svc.id, evidence=s.evidence[:120], source_probe=s.source)

    # ── ConfidenceEngine owns confidence/beliefs ──────────────────────────────────
    beliefs = ConfidenceEngine().beliefs_from_signals(signals)
    state.world.beliefs = {b.claim: b.confidence for b in beliefs}
    state.world.belief_records = [b.to_dict() for b in beliefs]

    # ── Structured explanations (JSON only; no prose/LLM in Phase 1) ──────────────
    explanations = []
    for b in beliefs:
        explanations.append(Explanation(
            decision=_decision_for(b),
            evidence_ids=[b.node_id],
            supporting_obs=list(b.supporting),
            confidence_delta=b.confidence,
            rule_applied=b.rule_applied,
            ai_summary="",
        ).to_dict())
    state.execution.explanations = explanations

    # convenience projections (do not change behavior; just summaries)
    state.world.technology = [n.label for n in graph.technologies()]
    state.world.interesting_hosts = [n.label for n in graph.hosts()]
    return state


def refresh_beliefs(state: ReasoningState, artifacts: dict,
                    signals: Optional[list[Signal]] = None) -> None:
    """Recompute beliefs/confidence from the current artifacts, in place.

    Called by the ReconDirector after each loop action so confidence reflects newly gathered
    evidence (e.g. verifier signals). Owned by the ConfidenceEngine; never touches node identity.
    """
    if signals is None:
        from src.fusion.engine_bridge import signals_from_artifacts  # noqa: PLC0415
        try:
            signals = signals_from_artifacts(artifacts) or []
        except Exception:  # noqa: BLE001
            return
    beliefs = ConfidenceEngine().beliefs_from_signals(signals)
    state.world.beliefs = {b.claim: b.confidence for b in beliefs}
    state.world.belief_records = [b.to_dict() for b in beliefs]


def safe_build_reasoning_state(target: str, scope: list[str], artifacts: dict,
                               signals: Optional[list[Signal]] = None) -> Optional[ReasoningState]:
    """Fail-soft wrapper for the engine: never raise into a scan."""
    try:
        return build_reasoning_state(target, scope, artifacts, signals)
    except Exception as exc:  # noqa: BLE001
        log.warning("reasoning build skipped (%s)", exc)
        return None
