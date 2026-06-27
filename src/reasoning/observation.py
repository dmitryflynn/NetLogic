"""
Observations — the immutable atoms of the truth model.

See docs/REASONING_ENGINE_DESIGN.md and the Phase 1 plan. An Observation is a single fact
that was *observed* about an entity (a banner string, a header, a CVE match, a cert). It is
frozen and content-addressed: two observations carrying the same fact about the same node
share an `obs_id`, so re-running a scan never duplicates a fact. Observations never change;
beliefs and confidence are *derived* from them (and are recomputable), never the reverse.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Observation:
    """One immutable observed fact attached to an EvidenceGraph node."""
    node_id: str                       # the entity this fact is about
    kind: str                          # "banner" | "header" | "cve_match" | "tls_cert" | "dns" | "probe" | ...
    evidence: str = ""                 # the raw observed fact
    source: str = ""                   # the sensor that produced it ("nvd","probe","headers","tls","stack","dns",...)
    reliability: str = "medium"        # inherent reliability of that sensor
    data: dict = field(default_factory=dict)   # structured extras (parsed fields)
    timestamp: float = field(default_factory=time.time)

    @property
    def obs_id(self) -> str:
        """Deterministic content id — identical facts about the same node collapse to one."""
        ident = json.dumps(
            {"node_id": self.node_id, "kind": self.kind, "evidence": self.evidence,
             "source": self.source, "data": self.data},
            sort_keys=True, separators=(",", ":"), default=str,
        )
        return hashlib.sha256(ident.encode("utf-8")).hexdigest()[:24]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["obs_id"] = self.obs_id
        return d

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "Observation":
        data = data or {}
        allowed = {f for f in cls.__dataclass_fields__}  # obs_id is a property, excluded
        return cls(**{k: v for k, v in data.items() if k in allowed})
