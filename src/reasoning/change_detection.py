"""
Change detection (Phase 7) — "how did the world change?"

A single scan is a snapshot; the security signal is in *what changed*. NetLogic already has the
right primitive: the immutable, content-addressed `Observation` (`obs_id` = hash of node/kind/
evidence/source/data). Two scans that observe the same fact share an `obs_id`; a changed fact gets a
new one — so change detection is a deterministic **set-diff over obs_ids**, no graph diff or
heuristics needed.

Central rule (agreed across phases): **diff immutable observations, NOT `ReasoningState`.**
Observations are ground truth; beliefs/hypotheses are interpretation. A re-scan that merely reasons
*better* over identical evidence must produce an EMPTY delta.

Separation of concerns:
  • `ObservationSnapshot` — the tiny immutable set extracted from the EvidenceGraph (the graph owns
    its own traversal via `EvidenceGraph.snapshot()`).
  • `ObservationDiffer` → `ScanDelta` — **purely factual** added/removed/changed `DeltaEvent`s, each
    carrying its originating `before_obs_id`/`after_obs_id` (delta provenance).
  • `DeltaTyper` — an extensible registry mapping (node_kind, obs_kind, direction) → event type.
  • `DeltaAnalyzer` — the INTERPRETATION layer (severity/impact), kept out of the factual delta.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional


# ── Snapshot ───────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SnapObs:
    """One immutable observation as it appears in a snapshot. `obs_id` is its identity."""
    obs_id: str
    host: str
    node_id: str
    node_kind: str
    obs_kind: str
    evidence: str = ""
    data_json: str = "{}"

    def to_dict(self) -> dict:
        return {"obs_id": self.obs_id, "host": self.host, "node_id": self.node_id,
                "node_kind": self.node_kind, "obs_kind": self.obs_kind,
                "evidence": self.evidence, "data_json": self.data_json}

    @classmethod
    def from_dict(cls, d: dict) -> "SnapObs":
        return cls(obs_id=d["obs_id"], host=d.get("host", ""), node_id=d.get("node_id", ""),
                   node_kind=d.get("node_kind", ""), obs_kind=d.get("obs_kind", ""),
                   evidence=d.get("evidence", ""), data_json=d.get("data_json", "{}"))


def _host_of(node) -> str:
    """Best-effort host for grouping: host:port → host; host node → key; else environment ("")."""
    key = (getattr(node, "key", "") or "").strip().lower()
    kind = getattr(node, "kind", "")
    if kind == "host":
        return key
    if ":" in key and key.count(":") == 1:        # host:port (not IPv6)
        return key.rsplit(":", 1)[0]
    return ""


@dataclass
class ObservationSnapshot:
    """The immutable observation set of one scan, keyed by obs_id. Tiny and decoupled from the engine."""
    observations: dict[str, SnapObs] = field(default_factory=dict)

    @classmethod
    def from_graph(cls, graph) -> "ObservationSnapshot":
        snap = cls()
        try:
            nodes = graph.nodes()
        except Exception:  # noqa: BLE001
            return snap
        for node in nodes:
            host = _host_of(node)
            for o in node.observations():
                snap.observations[o.obs_id] = SnapObs(
                    obs_id=o.obs_id, host=host, node_id=node.id, node_kind=node.kind,
                    obs_kind=o.kind, evidence=(o.evidence or "")[:300],
                    data_json=json.dumps(o.data or {}, sort_keys=True, default=str))
        return snap

    @classmethod
    def from_state(cls, state) -> "ObservationSnapshot":
        return cls.from_graph(state.world.graph)

    def hosts(self) -> set[str]:
        return {o.host for o in self.observations.values()}

    def to_dict(self) -> dict:
        return {"observations": [o.to_dict() for o in self.observations.values()]}

    @classmethod
    def from_dict(cls, d: dict | None) -> "ObservationSnapshot":
        d = d or {}
        snap = cls()
        for od in d.get("observations", []):
            so = SnapObs.from_dict(od)
            snap.observations[so.obs_id] = so
        return snap


# ── Delta event typing (extensible registry, not if/else) ────────────────────────────

class DeltaTyper:
    """Maps (node_kind, obs_kind, direction) → event type via a registered table.

    Resolution is most-specific-first: exact → node-only → obs-only → fallback. New event types
    (certificate_changed, cdn_changed, dns_changed, …) register without touching the differ.
    """
    _FALLBACK = {"added": "observation_added", "removed": "observation_removed",
                 "changed": "observation_changed"}

    def __init__(self) -> None:
        self._rules: dict[tuple[str, str, str], str] = {}
        self._register_defaults()

    def register(self, *, node_kind: str = "*", obs_kind: str = "*", direction: str, event_type: str) -> None:
        self._rules[(node_kind, obs_kind, direction)] = event_type

    def type_for(self, node_kind: str, obs_kind: str, direction: str) -> str:
        nk, ok = (node_kind or "").lower(), (obs_kind or "").lower()
        for key in ((nk, ok, direction), (nk, "*", direction), ("*", ok, direction)):
            if key in self._rules:
                return self._rules[key]
        return self._FALLBACK.get(direction, "observation_changed")

    def _register_defaults(self) -> None:
        r = self.register
        # ports / services
        r(node_kind="service", direction="added", event_type="new_port")
        r(node_kind="service", direction="removed", event_type="port_closed")
        r(obs_kind="open_port", direction="added", event_type="new_port")
        r(obs_kind="open_port", direction="removed", event_type="port_closed")
        # CVEs
        for ok in ("cve", "cve_match", "vuln"):
            r(obs_kind=ok, direction="added", event_type="new_cve")
            r(obs_kind=ok, direction="removed", event_type="cve_resolved")
        r(node_kind="cve", direction="added", event_type="new_cve")
        r(node_kind="cve", direction="removed", event_type="cve_resolved")
        # technologies
        for ok in ("technology", "tech", "framework"):
            r(obs_kind=ok, direction="added", event_type="tech_added")
            r(obs_kind=ok, direction="removed", event_type="tech_removed")
        r(node_kind="technology", direction="added", event_type="tech_added")
        r(node_kind="technology", direction="removed", event_type="tech_removed")
        # hosts
        r(node_kind="host", direction="added", event_type="new_host")
        r(node_kind="host", direction="removed", event_type="host_removed")
        # versions (the canonical "changed" case)
        for ok in ("version", "banner", "service"):
            r(obs_kind=ok, direction="changed", event_type="version_changed")


_DEFAULT_TYPER = DeltaTyper()


# ── Factual delta ────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class DeltaEvent:
    """A single factual change. Carries provenance (before/after obs_id). NO severity here."""
    type: str
    host: str
    node_id: str
    before_obs_id: Optional[str] = None
    after_obs_id: Optional[str] = None
    detail: str = ""

    def to_dict(self) -> dict:
        return {"type": self.type, "host": self.host, "node_id": self.node_id,
                "before_obs_id": self.before_obs_id, "after_obs_id": self.after_obs_id,
                "detail": self.detail}


@dataclass
class ScanDelta:
    """Purely factual change set. Severity/priority live in DeltaAnalyzer, never here."""
    added: list[DeltaEvent] = field(default_factory=list)
    removed: list[DeltaEvent] = field(default_factory=list)
    changed: list[DeltaEvent] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed)

    def all_events(self) -> list[DeltaEvent]:
        return list(self.added) + list(self.removed) + list(self.changed)

    def to_dict(self) -> dict:
        return {"added": [e.to_dict() for e in self.added],
                "removed": [e.to_dict() for e in self.removed],
                "changed": [e.to_dict() for e in self.changed],
                "has_changes": self.has_changes}


class ObservationDiffer:
    """Pure, deterministic set-diff over obs_ids. Reads ONLY observations (never beliefs/hypotheses)."""

    def __init__(self, typer: DeltaTyper | None = None) -> None:
        self._typer = typer or _DEFAULT_TYPER

    def diff(self, before: ObservationSnapshot, after: ObservationSnapshot) -> ScanDelta:
        b, a = before.observations, after.observations
        added_ids = set(a) - set(b)
        removed_ids = set(b) - set(a)

        # Pair value-changes: same (node_id, obs_kind) with exactly one removed + one added.
        delta = ScanDelta()
        paired_added: set[str] = set()
        paired_removed: set[str] = set()
        groups: dict[tuple[str, str], dict[str, list[str]]] = {}
        for oid in added_ids:
            o = a[oid]
            groups.setdefault((o.node_id, o.obs_kind), {"add": [], "rm": []})["add"].append(oid)
        for oid in removed_ids:
            o = b[oid]
            groups.setdefault((o.node_id, o.obs_kind), {"add": [], "rm": []})["rm"].append(oid)
        for (node_id, obs_kind), g in groups.items():
            if len(g["add"]) == 1 and len(g["rm"]) == 1:
                aid, rid = g["add"][0], g["rm"][0]
                ao, bo = a[aid], b[rid]
                delta.changed.append(DeltaEvent(
                    type=self._typer.type_for(ao.node_kind, obs_kind, "changed"),
                    host=ao.host, node_id=node_id, before_obs_id=rid, after_obs_id=aid,
                    detail=f"{bo.evidence} → {ao.evidence}".strip(" →")))
                paired_added.add(aid)
                paired_removed.add(rid)

        for oid in sorted(added_ids - paired_added):
            o = a[oid]
            delta.added.append(DeltaEvent(
                type=self._typer.type_for(o.node_kind, o.obs_kind, "added"),
                host=o.host, node_id=o.node_id, after_obs_id=oid, detail=o.evidence))
        for oid in sorted(removed_ids - paired_removed):
            o = b[oid]
            delta.removed.append(DeltaEvent(
                type=self._typer.type_for(o.node_kind, o.obs_kind, "removed"),
                host=o.host, node_id=o.node_id, before_obs_id=oid, detail=o.evidence))
        # Deterministic ordering.
        delta.added.sort(key=lambda e: (e.host, e.type, e.after_obs_id or ""))
        delta.removed.sort(key=lambda e: (e.host, e.type, e.before_obs_id or ""))
        delta.changed.sort(key=lambda e: (e.host, e.type, e.node_id))
        return delta


def diff_states(before_state, after_state, typer: DeltaTyper | None = None) -> ScanDelta:
    """Convenience: snapshot both states and diff. `before_state` may be a dict (persisted state)."""
    before = (ObservationSnapshot.from_dict(_graph_dict(before_state))
              if isinstance(before_state, dict) else ObservationSnapshot.from_state(before_state))
    after = ObservationSnapshot.from_state(after_state)
    return ObservationDiffer(typer).diff(before, after)


def _graph_dict(state_dict: dict) -> dict:
    """Rebuild an ObservationSnapshot dict from a persisted ReasoningState dict's EvidenceGraph."""
    from src.reasoning.evidence_graph import EvidenceGraph  # noqa: PLC0415
    graph = EvidenceGraph.from_dict(((state_dict or {}).get("world") or {}).get("graph"))
    return ObservationSnapshot.from_graph(graph).to_dict()


# ── Interpretation (separate from the factual delta) ────────────────────────────────

_IMPACT = {
    "new_cve": "critical", "new_host": "high", "tech_added": "medium", "new_port": "medium",
    "version_changed": "low", "port_closed": "low", "cve_resolved": "info", "tech_removed": "info",
    "host_removed": "low",
}


@dataclass
class DeltaAssessment:
    severity_counts: dict[str, int]
    top_severity: str

    def to_dict(self) -> dict:
        return {"severity_counts": dict(self.severity_counts), "top_severity": self.top_severity}


class DeltaAnalyzer:
    """Interpretation layer: assigns severity to a factual ScanDelta. Swappable; the delta stays facts."""

    _ORDER = ["critical", "high", "medium", "low", "info", "none"]

    def __init__(self, impact: dict[str, str] | None = None) -> None:
        self._impact = impact or _IMPACT

    def severity_of(self, event: DeltaEvent) -> str:
        return self._impact.get(event.type, "info")

    def analyze(self, delta: ScanDelta) -> DeltaAssessment:
        counts: dict[str, int] = {}
        for e in delta.all_events():
            sev = self.severity_of(e)
            counts[sev] = counts.get(sev, 0) + 1
        top = next((s for s in self._ORDER if counts.get(s)), "none")
        return DeltaAssessment(severity_counts=counts, top_severity=top)


# ── Re-investigation seeding (Phase 7b) — deltas warm-start the next scan ────────────
#
# Isolation invariant (Phase 5 carried forward): seeding influences ORDERING + objective selection
# ONLY. It writes no confidence, beliefs, hypotheses, or evidence — it is a pure function from a
# factual delta to ordering hints + objective-name seeds. History/deltas own priority; Evidence
# owns beliefs.

import re as _re

_SEV_BOOST = {"critical": 1.0, "high": 0.7, "medium": 0.5, "low": 0.3, "info": 0.1, "none": 0.0}
_CVE_RE = _re.compile(r"cve-\d{4}-\d{1,7}", _re.I)


def _tag_for(event: DeltaEvent) -> str:
    """A matching tag for the next scan's candidate ranking (host / cve id / product token)."""
    if event.type in ("new_host",) and event.host:
        return event.host
    if event.type in ("new_cve", "cve_resolved"):
        m = _CVE_RE.search(event.detail or "")
        if m:
            return m.group(0).lower()
    if event.type in ("tech_added", "tech_removed", "version_changed"):
        tok = _re.sub(r"[^a-z0-9 ]", " ", (event.detail or "").lower()).split()
        if tok:
            return tok[0]
    return event.host or ""


def _objective_for(event: DeltaEvent) -> Optional[str]:
    if event.type == "new_host" and event.host:
        return f"identify_framework:{event.host}"
    if event.type == "new_cve":
        m = _CVE_RE.search(event.detail or "")
        if m:
            return f"verify_cve:{m.group(0).lower()}"
    if event.type == "new_port" and event.host:
        return f"investigate_service:{event.host}"
    if event.type == "tech_added" and event.host:
        return f"assess_tech:{event.host}"
    return None


@dataclass
class ReinvestigationSeed:
    """Pure data the next scan consumes: ordering hints + objective-name seeds. Mutates nothing."""
    hints: list = field(default_factory=list)            # list[PriorityHint]
    objectives: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"hints": [{"tag": h.tag, "boost": h.boost, "reason": h.reason} for h in self.hints],
                "objectives": list(self.objectives)}


def seed_from_delta(delta: ScanDelta, analyzer: DeltaAnalyzer | None = None) -> ReinvestigationSeed:
    """Turn a factual delta into re-investigation priors: a new CVE/host is high-impact and should
    be looked at first next time. Output is ONLY PriorityHints + objective names — never state."""
    from src.reasoning.learned_patterns import PriorityHint  # noqa: PLC0415
    analyzer = analyzer or DeltaAnalyzer()
    hints, objectives, seen_obj = [], [], set()
    for e in delta.all_events():
        boost = _SEV_BOOST.get(analyzer.severity_of(e), 0.1)
        tag = _tag_for(e)
        if tag and boost > 0:
            hints.append(PriorityHint(tag=tag, boost=round(boost, 3), reason=f"change:{e.type}"))
        obj = _objective_for(e)
        if obj and obj not in seen_obj:
            seen_obj.add(obj)
            objectives.append(obj)
    return ReinvestigationSeed(hints=hints, objectives=objectives)


# ── Reporting ────────────────────────────────────────────────────────────────────────

def delta_report(delta: ScanDelta, analyzer: DeltaAnalyzer | None = None) -> str:
    """Human 'what changed since last scan' markdown (mirrors scan_diff.py's reporter shape)."""
    if not delta.has_changes:
        return "## Change Detection\n\nNo environmental changes since the last scan."
    analyzer = analyzer or DeltaAnalyzer()
    lines = ["## Change Detection", ""]
    assess = analyzer.analyze(delta)
    lines.append(f"**Top severity:** {assess.top_severity}  "
                 f"({', '.join(f'{k}:{v}' for k, v in sorted(assess.severity_counts.items()))})")
    lines.append("")
    for title, events in (("Added", delta.added), ("Removed", delta.removed), ("Changed", delta.changed)):
        if not events:
            continue
        lines.append(f"### {title}")
        for e in events:
            host = f"`{e.host}` " if e.host else ""
            lines.append(f"- {host}**{e.type}** — {e.detail}".rstrip(" —"))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
