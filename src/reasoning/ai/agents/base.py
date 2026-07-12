"""
Cognitive agents (Track C, C1+) — the thin LLM-facing layer.

An agent's ONLY job is to turn a `ReasoningState` into raw `AgentTask`s. It builds a fenced,
minimal context, calls the injected completer, and shapes the completion into proposal-envelope
dicts. Everything after that — normalization, ranking, meta-pruning, verification, provenance,
reputation — belongs to the `AICoordinator`, not the agent.

Design rules every agent follows (enforced by tests):
  • Fail-soft: an absent completer, a raised exception, or unparseable output ⇒ `[]` (no tasks).
    Combined with the coordinator's atomicity this is the "broken AI == no AI" guarantee.
  • Read-only: agents read `state`; they never mutate it.
  • Target-fenced: any target-derived text is wrapped as untrusted DATA, never instructions.
"""
from __future__ import annotations

import json
import logging
from typing import Callable, Protocol

from src.reasoning.ai.coordinator import AgentTask, fence
from src.reasoning.state import ReasoningState

log = logging.getLogger("netlogic.reasoning.ai.agents")

# The same completer contract the Phase-3 `AIProposer` uses: (system, user) -> text.
Completer = Callable[[str, str], str]


class CognitiveAgent(Protocol):
    name: str

    def generate(self, state: ReasoningState) -> list[AgentTask]:  # pragma: no cover - protocol
        ...


def world_context(state: ReasoningState, *, max_items: int = 20) -> str:
    """A compact, label-free snapshot of what the engine currently knows — the shared context
    every agent fences and hands to its completer. Mirrors `AIProposer._context` but richer:
    it also surfaces contradictions and dead-ends, which are exactly the signals that provoke
    the creative leaps deterministic generation can't make."""
    graph = state.world.graph
    services = [n.key for n in graph.nodes("service")][:max_items]
    techs = [str(t) for t in (state.world.technology or [])][:max_items]
    cves = [n.key for n in graph.nodes("cve")][:max_items]
    objectives = [o.name for o in state.investigation.objectives.unsatisfied()][:max_items]
    contradictions = [c.get("subject", "") for c in state.investigation.contradictions][:max_items]
    dead_ends = [d.get("step", d.get("reason", "")) for d in state.investigation.dead_ends][:max_items]
    return json.dumps({
        "target": state.target,
        "services": services,
        "technologies": techs,
        "cves": cves,
        "open_objectives": objectives,
        "contradictions": contradictions,
        "dead_ends": dead_ends,
    }, default=str)


def observation_ids(state: ReasoningState, *, limit: int = 64) -> list[str]:
    """Every real obs_id currently in the evidence graph — the set an agent may legitimately cite
    as supporting evidence. Anything a proposal cites outside this set is rejected by the
    EvidenceVerifier, so passing this list to the agent keeps honest proposals honest."""
    ids: list[str] = []
    for node in state.world.graph.nodes():
        for obs in node.observations():
            ids.append(obs.obs_id)
            if len(ids) >= limit:
                return ids
    return ids


def call_completer(completer: Completer, system: str, payload: str) -> str | None:
    """Fence the payload, call the completer, and return the raw text — or None on ANY failure.
    Centralizes the fail-soft boundary so every agent inherits identical broken-AI behavior."""
    try:
        return completer(system, fence(payload))
    except Exception as exc:  # noqa: BLE001 — any completer failure ⇒ contribute nothing
        log.warning("completer failed (%s) — agent contributes nothing", exc)
        return None
