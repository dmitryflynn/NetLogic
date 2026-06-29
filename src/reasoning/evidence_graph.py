"""
EvidenceGraph — the deduplicated, temporal, multi-host truth model.

See the Phase 1 plan. Two distinct concerns, both enforced here:

  • Entity nodes are DEDUPLICATED by a stable, deterministic id (`node_id(kind, *identity)`),
    so one host / service / cve is exactly one node no matter how many times it is observed.
  • Observations are APPEND-ONLY and immutable: each node holds the chain of facts that were
    observed about it. A node stores no confidence scalar — confidence is derived from the
    observation chain by the ConfidenceEngine (the truth model's one writer of confidence).

Edges reference nodes by id (never embedded objects) and carry provenance (evidence,
timestamp, source_probe, dependencies), which is what makes graph merging, persistence,
cross-host reasoning, incremental rescans, and "what changed?" tractable.

Ownership (Phase 1): the Builder creates nodes + observations and adds edges; the
ConfidenceEngine reads the graph and writes confidence/beliefs elsewhere. Nothing else
mutates the graph.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from src.reasoning.observation import Observation


def node_id(kind: str, *identity: object) -> str:
    """Deterministic node id from an entity's identity, e.g.
    node_id("service", "1.2.3.4", 443) -> "service:1.2.3.4:443"."""
    parts = ":".join(str(p).strip().lower() for p in identity if p is not None and str(p) != "")
    return f"{kind}:{parts}" if parts else f"{kind}:"


@dataclass
class EntityNode:
    """A deduplicated entity. Holds an append-only, content-deduplicated observation chain.

    `attrs` accumulates structured fields from observations (provenance), but the node never
    holds a confidence value — that is derived from `observations` by the ConfidenceEngine.
    """
    id: str
    kind: str
    key: str
    label: str = ""
    attrs: dict = field(default_factory=dict)
    _observations: dict = field(default_factory=dict)   # obs_id -> Observation (append-only, deduped)

    def observe(self, obs: Observation) -> Observation:
        """Append an observation. Idempotent: an identical fact (same obs_id) is a no-op, so
        re-scanning never grows the chain with duplicates."""
        self._observations.setdefault(obs.obs_id, obs)
        for k, v in (obs.data or {}).items():
            self.attrs.setdefault(k, v)
        return obs

    def observations(self) -> list[Observation]:
        """The observation chain, in chronological order."""
        return sorted(self._observations.values(), key=lambda o: o.timestamp)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "kind": self.kind, "key": self.key, "label": self.label,
            "attrs": self.attrs,
            "observations": [o.to_dict() for o in self.observations()],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EntityNode":
        node = cls(id=data["id"], kind=data.get("kind", ""), key=data.get("key", ""),
                   label=data.get("label", ""), attrs=dict(data.get("attrs", {})))
        for od in data.get("observations", []):
            o = Observation.from_dict(od)
            node._observations[o.obs_id] = o
        return node


@dataclass
class Edge:
    """A typed, temporal relationship between two nodes, referenced by id.

    `confidence` is written by the ConfidenceEngine, not the Builder (truth-model ownership).
    """
    type: str
    source_id: str
    target_id: str
    evidence: str = ""
    source_probe: str = "passive"
    dependencies: list = field(default_factory=list)   # edge keys this was derived from
    confidence: Optional[float] = None
    timestamp: float = 0.0

    def key(self) -> str:
        return f"{self.type}|{self.source_id}|{self.target_id}"

    def to_dict(self) -> dict:
        return {"type": self.type, "source_id": self.source_id, "target_id": self.target_id,
                "evidence": self.evidence, "source_probe": self.source_probe,
                "dependencies": list(self.dependencies), "confidence": self.confidence,
                "timestamp": self.timestamp}

    @classmethod
    def from_dict(cls, data: dict) -> "Edge":
        allowed = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in allowed})


class EvidenceGraph:
    """Deduplicated entity nodes + provenance edges. The Builder writes; everyone else reads."""

    def __init__(self) -> None:
        self._nodes: dict[str, EntityNode] = {}
        self._edges: dict[str, Edge] = {}

    # ── Nodes (deduplicated by id) ────────────────────────────────────────────────
    def upsert_node(self, kind: str, *identity: object, label: str = "") -> EntityNode:
        """Return the node for this identity, creating it once. Never duplicates."""
        nid = node_id(kind, *identity)
        node = self._nodes.get(nid)
        if node is None:
            key = ":".join(str(p).strip().lower() for p in identity if p is not None and str(p) != "")
            node = EntityNode(id=nid, kind=kind, key=key, label=label or key)
            self._nodes[nid] = node
        elif label and not node.label:
            node.label = label
        return node

    def observe(self, node: EntityNode, *, kind: str, evidence: str = "", source: str = "",
                reliability: str = "medium", data: Optional[dict] = None) -> Observation:
        """Attach an immutable observation to a node (idempotent on identical facts)."""
        return node.observe(Observation(
            node_id=node.id, kind=kind, evidence=evidence, source=source,
            reliability=reliability, data=dict(data or {}),
        ))

    def get(self, nid: str) -> Optional[EntityNode]:
        return self._nodes.get(nid)

    def nodes(self, kind: Optional[str] = None) -> list[EntityNode]:
        if kind is None:
            return list(self._nodes.values())
        return [n for n in self._nodes.values() if n.kind == kind]

    def snapshot(self):
        """The immutable observation set of this graph (Phase 7 change detection). The graph owns
        its own traversal; callers diff snapshots rather than walking nodes themselves."""
        from src.reasoning.change_detection import ObservationSnapshot  # noqa: PLC0415 — avoid cycle
        return ObservationSnapshot.from_graph(self)

    # ── Edges (deduplicated by (type, source, target)) ────────────────────────────
    def add_edge(self, type: str, source_id: str, target_id: str, *, evidence: str = "",
                 source_probe: str = "passive", dependencies: Optional[Iterable] = None,
                 timestamp: float = 0.0) -> Edge:
        e = Edge(type=type, source_id=source_id, target_id=target_id, evidence=evidence,
                 source_probe=source_probe, dependencies=list(dependencies or []),
                 timestamp=timestamp)
        existing = self._edges.get(e.key())
        if existing is None:
            self._edges[e.key()] = e
            return e
        # merge provenance into the existing edge rather than duplicating
        if evidence and not existing.evidence:
            existing.evidence = evidence
        return existing

    def edges(self) -> list[Edge]:
        return list(self._edges.values())

    # ── Views (computed, never stored) ────────────────────────────────────────────
    def technologies(self) -> list[EntityNode]:
        return self.nodes("technology")

    def hosts(self) -> list[EntityNode]:
        return self.nodes("host") + self.nodes("ip")

    def __len__(self) -> int:
        return len(self._nodes)

    # ── Serialization ─────────────────────────────────────────────────────────────
    def to_dict(self) -> dict:
        return {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges.values()],
        }

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "EvidenceGraph":
        g = cls()
        for nd in (data or {}).get("nodes", []):
            node = EntityNode.from_dict(nd)
            g._nodes[node.id] = node
        for ed in (data or {}).get("edges", []):
            edge = Edge.from_dict(ed)
            g._edges[edge.key()] = edge
        return g
