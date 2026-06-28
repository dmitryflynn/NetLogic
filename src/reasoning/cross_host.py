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

import re
from dataclasses import dataclass, field
from enum import Enum

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


# ── Edge derivation (Phase 6b): facts only, from evidence already in the EvidenceGraph ──

_HOSTNAME = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+"
_LOCATION_RE = re.compile(r"location:\s*https?://(" + _HOSTNAME + r")", re.I)
_SMTP_RE = re.compile(r"220[ -]+(" + _HOSTNAME + r")", re.I)


def _host_only(host_port: str) -> str:
    """Strip a :port suffix, leaving the bare hostname (IPv6-naive, sufficient here)."""
    h = (host_port or "").strip().lower()
    if h.count(":") == 1:                # host:port (not IPv6)
        h = h.split(":", 1)[0]
    return h


def _neighbors_from_observation(obs) -> list[tuple[str, str]]:
    """Return (source_kind, dest_host) pairs implied by ONE observation. Deterministic, no IO."""
    out: list[tuple[str, str]] = []
    ev = (obs.evidence or "")
    data = obs.data or {}
    kind = (obs.kind or "").lower()

    # DNS MX/NS/A records → structural neighbors (highest trust)
    if "dns" in kind or any(k in data for k in ("mx", "ns", "records")):
        for k in ("mx", "ns", "records"):
            for rec in (data.get(k) or []):
                host = _host_only(str(rec))
                if host:
                    out.append(("dns", host))

    # TLS certificate SAN → co-located hosts on the same cert
    if "tls" in kind or "cert" in kind or "san" in data or "subject_alt_names" in data:
        for k in ("san", "subject_alt_names"):
            for name in (data.get(k) or []):
                host = _host_only(str(name).lstrip("*."))
                if host:
                    out.append(("tls_san", host))

    # HTTP redirect Location header → pointed-at origin/proxy
    for m in _LOCATION_RE.finditer(ev):
        out.append(("http_redirect", _host_only(m.group(1))))

    # SMTP HELO/EHLO banner hostname
    if "smtp" in kind or ev.strip().startswith("220"):
        for m in _SMTP_RE.finditer(ev):
            out.append(("smtp_helo", _host_only(m.group(1))))

    return out


def derive_cross_host_edges(graph) -> list[CrossHostEdge]:
    """Walk an EvidenceGraph and emit immutable CrossHostEdges from evidence content only.

    Pure: never proposes a host the evidence didn't imply; AI/user paths cannot inject edges.
    """
    edges: dict[tuple[str, str, str], list[str]] = {}
    try:
        nodes = graph.nodes()
    except Exception:  # noqa: BLE001
        return []
    for node in nodes:
        src = _host_only(node.key)
        if not src:
            continue
        for obs in node.observations():
            for source_kind, dest in _neighbors_from_observation(obs):
                if not dest or dest == src:
                    continue
                edges.setdefault((src, dest, source_kind), []).append(obs.obs_id)
    return [CrossHostEdge(source_host=s, dest_host=d, observations=tuple(sorted(set(obs))),
                          source_kind=k)
            for (s, d, k), obs in edges.items()]


# ── Authorization (Phase 6b): POLICY, separate from the graph ──

class AuthDecision(Enum):
    AUTHORIZE = "authorize"   # in scope + confident enough → may spawn a HostReasoner
    REJECT = "reject"         # out of scope (terminal — never reconsidered this scan)
    DEFER = "defer"           # in scope but not yet confident enough (may upgrade with more evidence)


@dataclass
class ScopeAuthorizer:
    """Decides whether a discovered edge may become an investigated host. Reads edges + scope;
    never mutates the graph. Terminal outcomes (reject/expire) are remembered so a rejected or
    budget-expired neighbor is not reconsidered within the scan."""
    min_confidence: float = 0.6

    def __post_init__(self) -> None:
        self._terminal: dict[str, AuthDecision] = {}   # dest_host -> terminal decision

    def evaluate(self, edge: CrossHostEdge, scope: list[str]) -> AuthDecision:
        prior = self._terminal.get(edge.dest_host)
        if prior is not None:
            return prior
        if not _in_scope(edge.dest_host, scope):
            self._terminal[edge.dest_host] = AuthDecision.REJECT   # out of scope is terminal
            return AuthDecision.REJECT
        if edge.confidence < self.min_confidence:
            return AuthDecision.DEFER                              # not terminal: more evidence may help
        return AuthDecision.AUTHORIZE

    def mark_expired(self, dest_host: str) -> None:
        """Record a host whose investigation is done/over-budget; treated as terminal hereafter."""
        self._terminal[dest_host] = AuthDecision.REJECT

    def terminal_hosts(self) -> dict[str, str]:
        return {h: d.value for h, d in self._terminal.items()}


def _in_scope(dest_host: str, scope: list[str]) -> bool:
    """Mirror execution_kernel.validate_scope semantics at the host level (the CFAA boundary
    remains the kernel; this is an additional gate above it)."""
    host = _host_only(dest_host)
    if not scope:
        return False
    for s in scope:
        s = _host_only(s)
        if host == s or host.endswith("." + s):
            return True
    return False
