"""
Explanation — structured, deterministic provenance for a decision.

See the Phase 1 plan. Explanations are pure structured data, never free-form AI text: a
human-readable summary is *regenerated* from the typed fields on demand, so the reasoning
state stays deterministic. Phase 1 leaves `ai_summary` empty (no LLM in the truth model).
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Optional


@dataclass
class Explanation:
    """Why a decision was reached, in terms the system can recompute and audit."""
    decision: str                                   # "confirmed" | "potential" | "discarded"
    evidence_ids: list = field(default_factory=list)    # EvidenceGraph node ids
    supporting_obs: list = field(default_factory=list)  # observation ids / source names
    confidence_delta: float = 0.0                       # contribution to the posterior
    rule_applied: str = ""                              # deterministic rule id
    ai_summary: str = ""                                # OPTIONAL, derived; empty in Phase 1
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "Explanation":
        data = data or {}
        allowed = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in allowed})
