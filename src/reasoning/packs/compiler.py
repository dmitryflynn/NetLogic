"""
PackCompiler (Phase 6.5) — YAML → CompiledPack, once at startup.

Mirrors the Phase 4 rule compiler: parse + validate + resolve everything up front into immutable
`CompiledPack`s, so the runtime consumes compiled knowledge only (deterministic, no per-cycle YAML
parsing — guarded by the parse-once performance invariant).

Resolves three authoring conveniences so thousands of fingerprints don't duplicate each other:
  • **inheritance** (`extends: wordpress`) — a child additively merges its parent's fingerprints,
    endpoints, capabilities, etc., overriding scalars.
  • **aliases** (`aliases: [wp, wp6]`) — lookups resolve id OR alias.
  • **composition** (`compose([apache, php, wordpress, cloudflare])`) — merge independent packs into
    one detection view, avoiding the exponential "WordPress-on-Apache-behind-Cloudflare" blow-up.

Confidence is **calibrated by source**: a fingerprint's effective confidence is its base confidence
times the reliability of the `KnowledgeSource` it came from, so imported rules aren't all trusted equally.
"""
from __future__ import annotations

import logging
from pathlib import Path

import yaml

from src.reasoning.inference import Rule
from src.reasoning.packs.schema import (
    MANUAL_SOURCE,
    CompiledPack,
    Fingerprints,
    KnowledgeSource,
    PackCapability,
    StoppingSpec,
)

log = logging.getLogger("netlogic.reasoning.packs")


def _tuple(x) -> tuple:
    if x is None:
        return ()
    if isinstance(x, (list, tuple)):
        return tuple(str(i) for i in x)
    return (str(x),)


def _lower_tuple(x) -> tuple:
    return tuple(s.lower() for s in _tuple(x))


class PackLibrary:
    """The compiled catalog: id/alias lookup + adapters into the engine's existing systems."""

    def __init__(self, packs: dict[str, CompiledPack], sources: dict[str, KnowledgeSource],
                 calibration=None) -> None:
        from src.reasoning.packs.calibration import MultiplicativeCalibration  # noqa: PLC0415
        self._packs = packs
        self._sources = sources
        self._calibration = calibration or MultiplicativeCalibration()
        self._by_alias: dict[str, str] = {}
        for pid, pack in packs.items():
            for name in pack.names():
                self._by_alias[name.lower()] = pid

    # ── lookup ──
    def get(self, id_or_alias: str) -> CompiledPack | None:
        pid = self._by_alias.get((id_or_alias or "").lower())
        return self._packs.get(pid) if pid else None

    def all(self) -> list[CompiledPack]:
        return list(self._packs.values())

    def __len__(self) -> int:
        return len(self._packs)

    def __contains__(self, id_or_alias: str) -> bool:
        return (id_or_alias or "").lower() in self._by_alias

    # ── calibration ──
    def source_of(self, pack: CompiledPack) -> KnowledgeSource:
        return self._sources.get(pack.source, MANUAL_SOURCE)

    def effective_confidence(self, pack: CompiledPack, base_confidence: float = 1.0) -> float:
        """Calibrate a fingerprint's confidence by source reliability via the swappable
        CalibrationPolicy — so imported rules aren't trusted equally and the formula isn't
        hard-coded into callers."""
        return self._calibration.calibrate(base_confidence, self.source_of(pack))

    # ── adapters into existing engine systems (additive; nothing is rewired by force) ──
    def to_inference_rules(self) -> dict[str, Rule]:
        """Every pack's rule, keyed by pack id — drop-in for InferenceEngine(rules=...)."""
        return {p.id: p.rule for p in self._packs.values() if p.rule and p.rule.name}

    def to_capabilities(self):
        """Emit CapabilityRegistry entries from pack capabilities (lazy import to avoid cycles)."""
        from src.reasoning.capability_registry import Capability, CapabilityRegistry  # noqa: PLC0415
        reg = CapabilityRegistry()
        for p in self._packs.values():
            for cap in p.capabilities:
                # `requires` (knowledge) drives the capability's evidence needs — NOT preferred_order
                # (which is an advisory scheduling hint and flows through priority_hints()).
                reg.register(Capability(
                    id=cap.id, name=cap.id.replace("_", " ").title(),
                    produces=tuple(cap.produces) or ("identify_framework",),
                    required_evidence_types=tuple(cap.requires),
                    expected_information_gain=cap.expected_information_gain,
                    implemented_by_playbooks=()))
        return reg

    def priority_hints(self):
        """Bootstrap Phase 5 PriorityHints from packs' investigation order (warm-start ranking)."""
        from src.reasoning.learned_patterns import PriorityHint  # noqa: PLC0415
        hints = []
        for p in self._packs.values():
            for i, marker in enumerate(p.priority_hints):
                # earlier in the order → larger boost
                hints.append(PriorityHint(tag=marker, boost=round(1.0 - i * 0.1, 3),
                                          reason=f"pack:{p.id} preferred order"))
        return hints

    # ── composition ──
    def compose(self, ids: list[str], composed_id: str | None = None) -> CompiledPack:
        """Merge independent packs (e.g. apache + php + wordpress + cloudflare) into one detection
        view for a co-present stack. Explicit semantics:
          • fingerprints + confirm markers + endpoints: UNION (deduped, order-preserving).
          • refute markers: a member may NOT refute a technology that is also in the stack, so any
            refute that matches another member's confirm marker is DROPPED (resolves the
            "nginx refutes apache" vs "apache present" conflict).
          • confidence_priors / explanation_templates: later member wins on key clash (left→right).
        """
        members = [self.get(i) for i in ids]
        missing = [i for i, m in zip(ids, members) if m is None]
        if missing:
            raise KeyError(f"compose: unknown pack(s) {missing}")
        return _merge_packs(members, result_id=composed_id or "+".join(ids), source="composed",
                            resolve_refute_conflicts=True)


class PackCompiler:
    """Compiles a directory of *.pack.yaml (+ sources.yaml) into an immutable PackLibrary."""

    def compile_dir(self, directory: str | Path = "src/reasoning/packs/library") -> PackLibrary:
        directory = Path(directory)
        sources = self._load_sources(directory / "sources.yaml")
        raw: dict[str, dict] = {}
        if directory.exists():
            for f in sorted(directory.glob("*.pack.yaml")):
                try:
                    data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
                    if data.get("id"):
                        raw[data["id"]] = data
                except Exception as exc:  # noqa: BLE001 — a bad pack is skipped, not fatal
                    log.warning("skipping pack %s (%s)", f.name, exc)

        compiled: dict[str, CompiledPack] = {}
        # Resolve in dependency order so a child compiles after its parent.
        for pid in self._topo_order(raw):
            try:
                compiled[pid] = self._compile_one(raw[pid], compiled)
            except Exception as exc:  # noqa: BLE001
                log.warning("failed to compile pack %s (%s)", pid, exc)
        log.info("compiled %d technology packs from %s", len(compiled), directory)
        return PackLibrary(compiled, sources)

    # ── internals ──
    @staticmethod
    def _load_sources(path: Path) -> dict[str, KnowledgeSource]:
        sources = {"manual": MANUAL_SOURCE}
        if path.exists():
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
                for sid, sdata in (data.get("sources") or {}).items():
                    sources[sid] = KnowledgeSource.from_dict(sid, sdata)
            except Exception as exc:  # noqa: BLE001
                log.warning("failed to load sources.yaml (%s)", exc)
        return sources

    @staticmethod
    def _topo_order(raw: dict[str, dict]) -> list[str]:
        """Parents before children; cycles/missing parents degrade gracefully."""
        order, seen = [], set()

        def visit(pid, stack):
            if pid in seen or pid not in raw or pid in stack:
                return
            stack.add(pid)
            for parent in _tuple(raw[pid].get("extends")):
                visit(parent, stack)
            stack.discard(pid)
            seen.add(pid)
            order.append(pid)

        for pid in raw:
            visit(pid, set())
        return order

    def _compile_one(self, data: dict, compiled: dict[str, CompiledPack]) -> CompiledPack:
        pid = data["id"]
        parents = [compiled[p] for p in _tuple(data.get("extends")) if p in compiled]

        # Start from merged parents (inheritance), then layer this pack's own fields on top.
        base = _merge_packs(parents, result_id=pid, source=data.get("source", "manual")) \
            if parents else CompiledPack(id=pid, source=data.get("source", "manual"))

        fp = data.get("fingerprints") or {}
        own_fp = Fingerprints(
            headers=_lower_tuple(fp.get("headers")), cookies=_lower_tuple(fp.get("cookies")),
            body=_lower_tuple(fp.get("body")), favicon=_tuple(fp.get("favicon")))

        rule_data = data.get("rule") or {}
        own_rule = Rule(
            name=pid,
            confirm=tuple(base.rule.confirm) + _lower_tuple(rule_data.get("confirm")),
            refute=tuple(base.rule.refute) + _lower_tuple(rule_data.get("refute")),
            contradiction=tuple(base.rule.contradiction) + _lower_tuple(rule_data.get("contradiction")))

        caps = list(base.capabilities) + [
            PackCapability(id=c["id"],
                           expected_information_gain=float(c.get("expected_information_gain", 1.0)),
                           requires=_tuple(c.get("requires")),
                           produces=_tuple(c.get("produces")),
                           cost=c.get("cost", "medium"),
                           preferred_order=_tuple(c.get("preferred_order")),
                           fallback=_tuple(c.get("fallback")))
            for c in (data.get("capabilities") or [])]

        stop = data.get("stopping_condition") or {}
        lineage = tuple(p.id for p in parents) + tuple(
            x for p in parents for x in p.lineage)

        return CompiledPack(
            id=pid,
            source=data.get("source", base.source),
            aliases=_tuple(data.get("aliases")),
            lineage=lineage,
            fingerprints=base.fingerprints.merge(own_fp),
            rule=own_rule,
            capabilities=tuple(caps),
            endpoints=_dedup(tuple(base.endpoints) + _tuple(data.get("endpoints"))),
            admin_paths=_dedup(tuple(base.admin_paths) + _tuple(data.get("admin_paths"))),
            confidence_priors={**base.confidence_priors, **(data.get("confidence_priors") or {})},
            priority_hints=_tuple(data.get("priority_hints")) or base.priority_hints,
            stopping=StoppingSpec(confidence_goal=float(stop.get("confidence_goal", base.stopping.confidence_goal)),
                                  max_probes=int(stop.get("max_probes", base.stopping.max_probes))),
            known_false_positives=_dedup(tuple(base.known_false_positives) + _tuple(data.get("known_false_positives"))),
            explanation_templates={**base.explanation_templates, **(data.get("explanation_templates") or {})},
            benchmark_fixtures=_dedup(tuple(base.benchmark_fixtures) + _tuple(data.get("benchmark_fixtures"))),
        )


def _dedup(items: tuple) -> tuple:
    seen, out = set(), []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return tuple(out)


def _merge_packs(packs: list[CompiledPack], *, result_id: str, source: str,
                 resolve_refute_conflicts: bool = False) -> CompiledPack:
    """Additive merge of several compiled packs (inheritance base or composition).

    When `resolve_refute_conflicts` (composition), drop any refute marker that matches a co-present
    member's confirm marker — a technology in the stack must not refute another technology in it.
    """
    if not packs:
        return CompiledPack(id=result_id, source=source)
    fp = Fingerprints()
    confirm, refute, contra = (), (), ()
    caps, endpoints, admin, hints, fps_neg, fixtures = (), (), (), (), (), ()
    priors, expl = {}, {}
    for p in packs:
        fp = fp.merge(p.fingerprints)
        confirm += tuple(p.rule.confirm)
        refute += tuple(p.rule.refute)
        contra += tuple(p.rule.contradiction)
        caps += tuple(p.capabilities)
        endpoints += tuple(p.endpoints)
        admin += tuple(p.admin_paths)
        hints += tuple(p.priority_hints)
        fps_neg += tuple(p.known_false_positives)
        fixtures += tuple(p.benchmark_fixtures)
        priors.update(p.confidence_priors)
        expl.update(p.explanation_templates)

    confirm = _dedup(confirm)
    refute = _dedup(refute)
    if resolve_refute_conflicts:
        # A refute marker conflicts if it substring-matches (either direction) a present confirm.
        def _conflicts(r: str) -> bool:
            return any(r in c or c in r for c in confirm)
        refute = tuple(r for r in refute if not _conflicts(r))

    return CompiledPack(
        id=result_id, source=source,
        lineage=tuple(p.id for p in packs),
        fingerprints=fp,
        rule=Rule(name=result_id, confirm=confirm, refute=refute, contradiction=_dedup(contra)),
        capabilities=_dedup(caps), endpoints=_dedup(endpoints), admin_paths=_dedup(admin),
        confidence_priors=priors, priority_hints=_dedup(hints),
        known_false_positives=_dedup(fps_neg), explanation_templates=expl,
        benchmark_fixtures=_dedup(fixtures))
