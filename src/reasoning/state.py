"""
Hierarchical reasoning state — the single persistent object for an entire scan.

See docs/REASONING_ENGINE_DESIGN.md §3. The state is split into four layers that evolve
at different rates so the system stays reasoned-about as it grows:

    ReasoningState
    ├── WorldModel          what EXISTS across the environment (slow-changing facts)
    ├── InvestigationState  what we're trying to learn (fast-changing goals/hypotheses)
    ├── ExecutionState      what we've done and what's left (monotonic)
    └── LearnedPatterns     cross-scan heuristics + playbooks (unused in Phase 0)

Everything here is a plain, JSON-serializable dataclass. There is no behavior beyond
construction and (de)serialization in Phase 0 — the EvidenceGraph, ConfidenceEngine, and
the loop that mutate this state arrive in later phases. Persisting the state to the
Postgres job store (design §11.4) consumes `to_dict()` / `from_dict()`.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from src.reasoning.evidence_graph import EvidenceGraph
from src.reasoning.hypothesis import HypothesisEngine
from src.reasoning.objective import ObjectiveDAG


@dataclass
class WorldModel:
    """What we believe EXISTS across the whole authorized environment (multi-host).

    `graph` is the deduplicated, append-only EvidenceGraph (owned by the Builder). `beliefs`
    and `belief_records` are the derived confidence (owned by the ConfidenceEngine). The flat
    containers carry summary projections for convenience.
    """
    graph: EvidenceGraph = field(default_factory=EvidenceGraph)
    hosts: dict[str, dict] = field(default_factory=dict)          # host -> fact bag
    observations: list[dict] = field(default_factory=list)        # raw facts (summary projection)
    beliefs: dict[str, float] = field(default_factory=dict)       # claim_key -> confidence 0..1
    belief_records: list[dict] = field(default_factory=list)      # structured Belief dicts
    technology: list[dict] = field(default_factory=list)
    reachability: dict[str, Any] = field(default_factory=dict)
    potential_pivots: list[dict] = field(default_factory=list)
    interesting_services: list[dict] = field(default_factory=list)
    interesting_hosts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "graph": self.graph.to_dict(),
            "hosts": self.hosts,
            "observations": self.observations,
            "beliefs": self.beliefs,
            "belief_records": self.belief_records,
            "technology": self.technology,
            "reachability": self.reachability,
            "potential_pivots": self.potential_pivots,
            "interesting_services": self.interesting_services,
            "interesting_hosts": self.interesting_hosts,
        }

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "WorldModel":
        data = data or {}
        return cls(
            graph=EvidenceGraph.from_dict(data.get("graph")),
            hosts=dict(data.get("hosts", {})),
            observations=list(data.get("observations", [])),
            beliefs=dict(data.get("beliefs", {})),
            belief_records=list(data.get("belief_records", [])),
            technology=list(data.get("technology", [])),
            reachability=dict(data.get("reachability", {})),
            potential_pivots=list(data.get("potential_pivots", [])),
            interesting_services=list(data.get("interesting_services", [])),
            interesting_hosts=list(data.get("interesting_hosts", [])),
        )


@dataclass
class InvestigationState:
    """What we're currently trying to learn — fast-changing.

    `objectives` is a first-class ObjectiveDAG (Phase 3) that the Scheduler optimises;
    `hypotheses` is a forest (nested dicts) per design §6; `persona` is the active
    investigation mode per §7.
    """
    persona: str = "service_discovery"
    objectives: ObjectiveDAG = field(default_factory=ObjectiveDAG)
    goals: list[dict] = field(default_factory=list)
    hypotheses: HypothesisEngine = field(default_factory=HypothesisEngine)
    unknowns: list[dict] = field(default_factory=list)
    contradictions: list[dict] = field(default_factory=list)
    dead_ends: list[dict] = field(default_factory=list)


@dataclass
class ExecutionState:
    """What we've done and what budget remains — monotonic (only grows)."""
    budget: dict[str, Any] = field(default_factory=dict)         # remaining time/tokens/probes/recursion
    tokens_used: int = 0
    probe_history: list[dict] = field(default_factory=list)
    failed_probes: list[dict] = field(default_factory=list)
    execution_history: list[dict] = field(default_factory=list)
    explanations: list[dict] = field(default_factory=list)       # design §10.2
    provenance: dict = field(default_factory=dict)               # Phase 5 §1: Obs→Inference→Hypothesis


@dataclass
class LearnedPatterns:
    """Cross-scan heuristics + discovered playbooks. Designed now, unused in Phase 0."""
    heuristics: list[dict] = field(default_factory=list)
    playbooks: list[dict] = field(default_factory=list)


# Bump whenever the persisted shape of ReasoningState changes in a way that needs a
# migration (new layers, renamed/removed fields). `from_dict` reads the stored value so a
# future loader can upgrade older rows; unknown/missing fields already degrade gracefully.
SCHEMA_VERSION = 1


@dataclass
class ReasoningState:
    """The persistent reasoning state for a single scan.

    `scope` is the authorized target set; in later phases the ExecutionKernel enforces
    that every probe target falls within it (the CFAA boundary, design §12).
    """
    schema_version: int = SCHEMA_VERSION
    target: str = ""
    scope: list[str] = field(default_factory=list)
    # Opt-in switch for the adaptive reasoning loop (Phase 3 Activation). Default off → the
    # loop never engages → scan output is byte-identical. AI presence augments but does not
    # activate; activation is governed by this flag alone.
    reasoning_enabled: bool = False
    started_at: float = field(default_factory=time.time)
    world: WorldModel = field(default_factory=WorldModel)
    investigation: InvestigationState = field(default_factory=InvestigationState)
    execution: ExecutionState = field(default_factory=ExecutionState)
    learned: LearnedPatterns = field(default_factory=LearnedPatterns)

    # ── Serialization (for Postgres persistence + UI replay) ──────────────────────
    def to_dict(self) -> dict:
        # WorldModel and InvestigationState hold non-dataclass objects and are
        # serialized explicitly; execution and learned are plain dataclasses.
        inv = self.investigation
        return {
            "schema_version": self.schema_version,
            "target": self.target,
            "scope": list(self.scope),
            "reasoning_enabled": self.reasoning_enabled,
            "started_at": self.started_at,
            "world": self.world.to_dict(),
            "investigation": {
                "persona": inv.persona,
                "objectives": inv.objectives.to_dict(),
                "goals": inv.goals,
                "hypotheses": inv.hypotheses.to_dict(),
                "unknowns": inv.unknowns,
                "contradictions": inv.contradictions,
                "dead_ends": inv.dead_ends,
            },
            "execution": asdict(self.execution),
            "learned": asdict(self.learned),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "ReasoningState":
        """Reconstruct a ReasoningState (and its nested layers) from a plain dict.
        Unknown keys are ignored and missing keys fall back to defaults, so the format
        can evolve across phases without breaking older persisted rows."""
        data = data or {}
        inv_data = data.get("investigation", {}) or {}
        from src.reasoning.hypothesis import HypothesisEngine  # noqa: PLC0415
        from src.reasoning.objective import ObjectiveDAG  # noqa: PLC0415
        investigation = InvestigationState(
            persona=inv_data.get("persona", "service_discovery"),
            objectives=ObjectiveDAG.from_dict(inv_data.get("objectives", []) or []),
            goals=list(inv_data.get("goals", []) or []),
            hypotheses=HypothesisEngine.from_dict(inv_data.get("hypotheses", []) or []),
            unknowns=list(inv_data.get("unknowns", []) or []),
            contradictions=list(inv_data.get("contradictions", []) or []),
            dead_ends=list(inv_data.get("dead_ends", []) or []),
        )
        return cls(
            schema_version=int(data.get("schema_version", SCHEMA_VERSION)),
            target=data.get("target", ""),
            scope=list(data.get("scope", []) or []),
            reasoning_enabled=bool(data.get("reasoning_enabled", False)),
            started_at=float(data.get("started_at", time.time())),
            world=WorldModel.from_dict(data.get("world")),
            investigation=investigation,
            execution=_build(ExecutionState, data.get("execution")),
            learned=_build(LearnedPatterns, data.get("learned")),
        )

    @classmethod
    def from_json(cls, text: str) -> "ReasoningState":
        return cls.from_dict(json.loads(text))


def _build(cls, data: Optional[dict]):
    """Construct a flat dataclass from a dict, keeping only its declared fields."""
    data = data or {}
    allowed = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
    return cls(**{k: v for k, v in data.items() if k in allowed})
