"""
Cross-host structure (Phase 6) — facts only, no policy.

`CrossHostGraph` records *which host points at which* and *why*, derived solely from evidence already
in the EvidenceGraph. It is pure structure: an edge carries its supporting observation ids and a
source kind, and its confidence is **computed** from those — so the edge *is* its own provenance and
there is no separate Observation→edge lookup.

Authorization (may this edge spawn a host?) is a **policy** decision and lives in `ScopeAuthorizer`
(added in Phase 6b), never as graph state. The graph stores no `authorized/rejected/...` flags.

In Phase 6a this module ships the immutable edge + graph container (empty by default) so
`EnvironmentGraph` can compose it; edge derivation from evidence and the authorizer arrive in 6b.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Confidence weight by the kind of evidence that implied a host→host edge. DNS is the most
# trustworthy structural signal; a banner-inferred neighbor is the least. AI is excluded entirely.
_SOURCE_WEIGHT = {
    "dns": 0.9,          # MX / NS / A records
    "tls_san": 0.8,      # certificate Subject Alternative Name
    "http_redirect": 0.7,  # Location header / meta refresh
    "smtp_helo": 0.6,    # SMTP HELO/EHLO banner hostname
    "banner": 0.5,       # generic banner inference
}


@dataclass(frozen=True)
class CrossHostEdge:
    """An immutable host→host link. Confidence is derived from its observations, not stored."""
    source_host: str
    dest_host: str
    observations: tuple[str, ...] = ()     # obs_ids that imply this edge (intrinsic provenance)
    source_kind: str = "banner"

    @property
    def confidence(self) -> float:
        """Computed from the supporting observations + source kind. Deterministic, monotone in count."""
        base = _SOURCE_WEIGHT.get(self.source_kind, 0.4)
        n = max(1, len(self.observations))
        return round(min(1.0, base + 0.05 * (n - 1)), 4)

    def to_dict(self) -> dict:
        return {"source_host": self.source_host, "dest_host": self.dest_host,
                "observations": list(self.observations), "source_kind": self.source_kind,
                "confidence": self.confidence}

    @classmethod
    def from_dict(cls, data: dict) -> "CrossHostEdge":
        return cls(source_host=data["source_host"], dest_host=data["dest_host"],
                   observations=tuple(data.get("observations", [])),
                   source_kind=data.get("source_kind", "banner"))


@dataclass
class CrossHostGraph:
    """A directed graph of immutable CrossHostEdges. Pure structure — no authorization state."""
    edges: list[CrossHostEdge] = field(default_factory=list)

    def add_edge(self, edge: CrossHostEdge) -> None:
        # Dedup on (source, dest, source_kind) keeping the better-supported edge.
        key = (edge.source_host, edge.dest_host, edge.source_kind)
        for i, e in enumerate(self.edges):
            if (e.source_host, e.dest_host, e.source_kind) == key:
                if len(edge.observations) > len(e.observations):
                    self.edges[i] = edge
                return
        self.edges.append(edge)

    def neighbors(self, host: str) -> list[CrossHostEdge]:
        return [e for e in self.edges if e.source_host == host]

    def to_dict(self) -> dict:
        return {"edges": [e.to_dict() for e in self.edges]}

    @classmethod
    def from_dict(cls, data: dict | None) -> "CrossHostGraph":
        data = data or {}
        return cls(edges=[CrossHostEdge.from_dict(d) for d in data.get("edges", [])])
