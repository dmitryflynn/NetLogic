"""
Technology Pack schema (Phase 6.5) — the knowledge module, compiled and immutable.

A Technology Pack unifies everything NetLogic knows about one technology — fingerprints,
inference rules, capabilities (with investigation *order*), endpoints, confidence priors, priority
hints, benchmark fixtures, explanations — into a single plug-and-play unit. Adding a technology is
adding one pack; the reasoning engine never changes.

These are the **compiled** (post-`PackCompiler`) immutable forms. Authoring is YAML; the compiler
resolves inheritance/aliases/composition and parses once at startup so the runtime stays
deterministic (no per-cycle YAML parsing).

Every pack records the `KnowledgeSource` it came from, so a finding can be traced to its origin
("which source caused this?", "disable this source", "regenerate this pack") and confidence can be
*calibrated* by source reliability — see `compiler.PackLibrary.effective_confidence`.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from src.reasoning.inference import Rule   # packs emit the SAME Rule the InferenceEngine consumes


@dataclass(frozen=True)
class KnowledgeSource:
    """Provenance + calibration for an import origin (Wappalyzer, WhatWeb, VulnClaw, manual, ...)."""
    id: str
    confidence: float = 0.8          # how much we trust this source's fingerprints (0..1)
    false_positive_rate: float = 0.0
    coverage: str = "unknown"        # "high" | "medium" | "low" | "unknown"

    def to_dict(self) -> dict:
        return {"id": self.id, "confidence": self.confidence,
                "false_positive_rate": self.false_positive_rate, "coverage": self.coverage}

    @classmethod
    def from_dict(cls, sid: str, data: dict) -> "KnowledgeSource":
        data = data or {}
        return cls(id=sid, confidence=float(data.get("confidence", 0.8)),
                   false_positive_rate=float(data.get("false_positive_rate", 0.0)),
                   coverage=data.get("coverage", "unknown"))


# Manual is the implicit, highest-trust source for hand-written packs.
MANUAL_SOURCE = KnowledgeSource(id="manual", confidence=0.95, coverage="high")


@dataclass(frozen=True)
class Fingerprints:
    """Detection markers grouped by where they appear. Lower-cased substrings / hashes."""
    headers: tuple[str, ...] = ()
    cookies: tuple[str, ...] = ()
    body: tuple[str, ...] = ()
    favicon: tuple[str, ...] = ()    # favicon hashes (e.g. mmh3/md5)

    def all_markers(self) -> tuple[str, ...]:
        return tuple(self.headers) + tuple(self.cookies) + tuple(self.body) + tuple(self.favicon)

    def merge(self, other: "Fingerprints") -> "Fingerprints":
        """Additive merge (used by inheritance + composition). Order-preserving, deduped."""
        def _u(a, b):
            seen, out = set(), []
            for x in tuple(a) + tuple(b):
                if x not in seen:
                    seen.add(x)
                    out.append(x)
            return tuple(out)
        return Fingerprints(headers=_u(self.headers, other.headers),
                            cookies=_u(self.cookies, other.cookies),
                            body=_u(self.body, other.body),
                            favicon=_u(self.favicon, other.favicon))

    def to_dict(self) -> dict:
        return {"headers": list(self.headers), "cookies": list(self.cookies),
                "body": list(self.body), "favicon": list(self.favicon)}


@dataclass(frozen=True)
class PackCapability:
    """A capability with an investigation *sequence* — the most valuable knowledge, not just signatures."""
    id: str
    expected_information_gain: float = 1.0
    preferred_order: tuple[str, ...] = ()   # e.g. (headers, cookies, favicon, body, actuator)
    fallback: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {"id": self.id, "expected_information_gain": self.expected_information_gain,
                "preferred_order": list(self.preferred_order), "fallback": list(self.fallback)}


@dataclass(frozen=True)
class StoppingSpec:
    confidence_goal: float = 0.85
    max_probes: int = 15


@dataclass(frozen=True)
class CompiledPack:
    """An immutable, fully-resolved technology knowledge module."""
    id: str
    source: str = "manual"
    aliases: tuple[str, ...] = ()
    lineage: tuple[str, ...] = ()         # resolved ancestor ids (extends chain), nearest-first
    fingerprints: Fingerprints = field(default_factory=Fingerprints)
    rule: Rule = field(default_factory=lambda: Rule(name=""))
    capabilities: tuple[PackCapability, ...] = ()
    endpoints: tuple[str, ...] = ()
    admin_paths: tuple[str, ...] = ()
    confidence_priors: dict = field(default_factory=dict)   # marker-kind -> prior weight
    priority_hints: tuple[str, ...] = ()
    stopping: StoppingSpec = field(default_factory=StoppingSpec)
    known_false_positives: tuple[str, ...] = ()
    explanation_templates: dict = field(default_factory=dict)
    benchmark_fixtures: tuple[str, ...] = ()

    def names(self) -> tuple[str, ...]:
        """All identifiers this pack answers to: its id plus aliases."""
        return (self.id,) + tuple(self.aliases)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "source": self.source, "aliases": list(self.aliases),
            "lineage": list(self.lineage),
            "fingerprints": self.fingerprints.to_dict(),
            "rule": {"name": self.rule.name, "confirm": list(self.rule.confirm),
                     "refute": list(self.rule.refute), "contradiction": list(self.rule.contradiction)},
            "capabilities": [c.to_dict() for c in self.capabilities],
            "endpoints": list(self.endpoints), "admin_paths": list(self.admin_paths),
            "confidence_priors": dict(self.confidence_priors),
            "priority_hints": list(self.priority_hints),
            "stopping": {"confidence_goal": self.stopping.confidence_goal,
                         "max_probes": self.stopping.max_probes},
            "known_false_positives": list(self.known_false_positives),
            "explanation_templates": dict(self.explanation_templates),
            "benchmark_fixtures": list(self.benchmark_fixtures),
        }
