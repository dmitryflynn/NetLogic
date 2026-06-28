"""
World model (Phase 6) — the multi-host coordination layer.

`WorldState` is a **thin coordination root** composing exactly three collaborators
(`environment`, `hosts`, `global_budget`) — frozen by a field-set tripwire test so future features
land in the right collaborator instead of bloating one god object:

    WorldState
    ├── environment : EnvironmentGraph   shared environment TRUTH (evidence + cross-host structure)
    ├── hosts       : HostManager        HostReasoner lifecycle (create / lookup / remove)
    └── global_budget : BudgetManager    scan-wide ceiling

`HostReasoner` is a COMPLETE per-host reasoning context. **Phase 6a is adapter-first**: a HostReasoner
wraps today's `ReasoningState` unchanged, and `WorldState.single_host(...)` builds a one-host world
that is byte-identical to the single-host reasoner — so the entire existing suite passes untouched.
Per-host graph splitting and multi-host dispatch arrive in 6b/6c behind a default-OFF flag.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from src.reasoning.budget import BudgetManager
from src.reasoning.cross_host import CrossHostGraph
from src.reasoning.evidence_graph import EvidenceGraph
from src.reasoning.state import ReasoningState


@dataclass
class HostReasoner:
    """A complete per-host reasoning context. In 6a it adapts an existing ReasoningState."""
    host: str
    state: ReasoningState

    # Convenience accessors delegate to the wrapped state, so call sites can migrate gradually
    # from `state.investigation.X` to `host_reasoner.X` without behavior change.
    @property
    def objectives(self):
        return self.state.investigation.objectives

    @property
    def hypotheses(self):
        return self.state.investigation.hypotheses

    @property
    def execution(self):
        return self.state.execution

    @property
    def persona(self) -> str:
        return self.state.investigation.persona

    def to_dict(self) -> dict:
        return {"host": self.host, "state": self.state.to_dict()}

    @classmethod
    def from_dict(cls, data: dict) -> "HostReasoner":
        return cls(host=data["host"], state=ReasoningState.from_dict(data.get("state")))


class HostManager:
    """Owns HostReasoner lifecycle. Nothing else may create or destroy a HostReasoner."""

    def __init__(self) -> None:
        self._hosts: dict[str, HostReasoner] = {}

    def create(self, host: str, state: ReasoningState) -> HostReasoner:
        """Create (or return existing) HostReasoner for `host`."""
        existing = self._hosts.get(host)
        if existing is not None:
            return existing
        hr = HostReasoner(host=host, state=state)
        self._hosts[host] = hr
        return hr

    def get(self, host: str) -> HostReasoner | None:
        return self._hosts.get(host)

    def remove(self, host: str) -> None:
        self._hosts.pop(host, None)

    def all(self) -> list[HostReasoner]:
        return list(self._hosts.values())

    def __len__(self) -> int:
        return len(self._hosts)

    def __contains__(self, host: str) -> bool:
        return host in self._hosts

    def to_dict(self) -> dict:
        return {"host_reasoners": [hr.to_dict() for hr in self._hosts.values()]}

    @classmethod
    def from_dict(cls, data: dict | None) -> "HostManager":
        data = data or {}
        mgr = cls()
        for hr_data in data.get("host_reasoners", []):
            hr = HostReasoner.from_dict(hr_data)
            mgr._hosts[hr.host] = hr
        return mgr


@dataclass
class EnvironmentGraph:
    """Shared environment truth: the evidence graph + the cross-host structure.

    Introduced now as the SEAM for the documented end state (per-host HostEvidenceGraphs linked by
    the environment graph); Phase 6 keeps a single shared `evidence_graph` so the expensive,
    well-tested graph is untouched.
    """
    evidence_graph: EvidenceGraph = field(default_factory=EvidenceGraph)
    cross_host_graph: CrossHostGraph = field(default_factory=CrossHostGraph)

    def to_dict(self) -> dict:
        return {"evidence_graph": self.evidence_graph.to_dict(),
                "cross_host_graph": self.cross_host_graph.to_dict()}

    @classmethod
    def from_dict(cls, data: dict | None) -> "EnvironmentGraph":
        data = data or {}
        return cls(
            evidence_graph=EvidenceGraph.from_dict(data.get("evidence_graph")),
            cross_host_graph=CrossHostGraph.from_dict(data.get("cross_host_graph")),
        )


# The thin root's allowed fields — enforced by test_world_state.py's god-object tripwire.
_WORLDSTATE_FIELDS = {"environment", "hosts", "global_budget"}


@dataclass
class WorldState:
    """Thin coordination root: exactly three collaborators, no reasoning fields of its own."""
    environment: EnvironmentGraph = field(default_factory=EnvironmentGraph)
    hosts: HostManager = field(default_factory=HostManager)
    global_budget: BudgetManager = field(default_factory=BudgetManager)

    @classmethod
    def single_host(cls, state: ReasoningState,
                    global_budget: BudgetManager | None = None) -> "WorldState":
        """Adapter-first constructor: wrap one ReasoningState as a one-host world.

        The environment's evidence graph IS the host's graph (observations are shared truth), so a
        single-host world is behaviorally identical to the bare ReasoningState.
        """
        ws = cls(
            environment=EnvironmentGraph(evidence_graph=state.world.graph),
            hosts=HostManager(),
            global_budget=global_budget or BudgetManager(),
        )
        ws.hosts.create(state.target or "", state)
        return ws

    @property
    def is_single_host(self) -> bool:
        return len(self.hosts) <= 1

    def primary(self) -> HostReasoner | None:
        """The sole/first HostReasoner — the single-host fast path."""
        all_hosts = self.hosts.all()
        return all_hosts[0] if all_hosts else None

    def to_dict(self) -> dict:
        return {
            "environment": self.environment.to_dict(),
            "hosts": self.hosts.to_dict(),
            "global_budget": self.global_budget.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict | None) -> "WorldState":
        data = data or {}
        gb = data.get("global_budget") or {}
        budget = BudgetManager(
            max_wall_clock_s=float(gb.get("max_wall_clock_s", 120.0)),
            max_tokens=int(gb.get("max_tokens", 40_000)),
            max_probes=int(gb.get("max_probes", 40)),
            max_recursion=int(gb.get("max_recursion", 6)),
        )
        return cls(
            environment=EnvironmentGraph.from_dict(data.get("environment")),
            hosts=HostManager.from_dict(data.get("hosts")),
            global_budget=budget,
        )
