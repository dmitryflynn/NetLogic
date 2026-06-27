from __future__ import annotations

import math
import time
import uuid
from dataclasses import dataclass, field
from typing import Literal


@dataclass
class Hypothesis:
    id: str
    label: str
    parent_id: str | None = None
    belief_ref: str | None = None
    likelihoods: dict[str, float] = field(default_factory=dict)
    entropy: float = 0.0
    information_gain: float = 0.0
    status: Literal["active", "confirmed", "refuted", "superseded"] = "active"
    children: list[str] = field(default_factory=list)
    derived_from: list[str] = field(default_factory=list)
    created_by: Literal["planner", "rule", "ai", "imported"] = "ai"
    reason: str | None = None
    created_at: float = field(default_factory=time.time)
    resolved_at: float | None = None
    evidence_refs: list[str] = field(default_factory=list)
    evidence_requests: list[str] = field(default_factory=list)

    def normalized_posterior(self) -> dict[str, float]:
        """Likelihoods normalized to a proper distribution (sums to 1).

        A hypothesis with multiple `likelihoods` keys IS the competing-candidate set (e.g.
        {"wordpress": .5, "spring_boot": .5}), so the grouping a separate `Question` object would
        provide already lives here — see test_posterior_stopping.py for the design decision.
        """
        total = sum(v for v in self.likelihoods.values() if v > 0)
        if total <= 0:
            return {}
        return {k: v / total for k, v in self.likelihoods.items() if v > 0}

    def leading_posterior(self) -> float:
        """The joint posterior mass of the leading candidate (0..1). 0 if no candidates."""
        post = self.normalized_posterior()
        return max(post.values()) if post else 0.0

    def posterior_resolved(self, threshold: float = 0.95) -> bool:
        """True when the competing set has concentrated past `threshold` on one candidate.

        This is the joint-posterior stopping rule over a competing hypothesis — something an
        Objective's boolean `satisfied` cannot express, and the only capability a `Question`
        object would have added. Implemented here because the competing set already lives on the
        Hypothesis, so no new layer is warranted.
        """
        return len(self.likelihoods) >= 2 and self.leading_posterior() >= threshold

    def to_dict(self) -> dict:
        return {"id": self.id, "label": self.label, "parent_id": self.parent_id,
                "belief_ref": self.belief_ref, "likelihoods": dict(self.likelihoods),
                "entropy": self.entropy, "information_gain": self.information_gain,
                "status": self.status, "children": list(self.children),
                "derived_from": list(self.derived_from), "created_by": self.created_by,
                "reason": self.reason, "created_at": self.created_at,
                "resolved_at": self.resolved_at, "evidence_refs": list(self.evidence_refs),
                "evidence_requests": list(self.evidence_requests)}

    @classmethod
    def from_dict(cls, data: dict) -> Hypothesis:
        return cls(id=data["id"], label=data["label"],
                   parent_id=data.get("parent_id"),
                   belief_ref=data.get("belief_ref"),
                   likelihoods=dict(data.get("likelihoods", {})),
                   entropy=float(data.get("entropy", 0.0)),
                   information_gain=float(data.get("information_gain", 0.0)),
                   status=data.get("status", "active"),
                   children=list(data.get("children", [])),
                   derived_from=list(data.get("derived_from", [])),
                   created_by=data.get("created_by", "ai"),
                   reason=data.get("reason"),
                   created_at=float(data.get("created_at", time.time())),
                   resolved_at=data.get("resolved_at"),
                   evidence_refs=list(data.get("evidence_refs", [])),
                   evidence_requests=list(data.get("evidence_requests", [])))


class HypothesisEngine:
    def __init__(self) -> None:
        self._hypotheses: dict[str, Hypothesis] = {}

    def add_hypothesis(self, label: str, parent_id: str | None = None,
                       likelihoods: dict[str, float] | None = None,
                       belief_ref: str | None = None,
                       created_by: Literal["planner", "rule", "ai", "imported"] = "ai",
                       reason: str | None = None,
                       derived_from: list[str] | None = None) -> str:
        hid = uuid.uuid4().hex[:12]
        likelihoods = likelihoods or {}
        entropy = self._compute_entropy_from_likelihoods(likelihoods)
        hyp = Hypothesis(id=hid, label=label, parent_id=parent_id,
                         likelihoods=likelihoods, entropy=entropy,
                         belief_ref=belief_ref, created_by=created_by,
                         reason=reason, derived_from=derived_from or [])
        self._hypotheses[hid] = hyp
        if parent_id and parent_id in self._hypotheses:
            self._hypotheses[parent_id].children.append(hid)
        self._recompute_gains()
        return hid

    def spawn_children(self, parent_id: str, outcomes: dict[str, float],
                       created_by: Literal["planner", "rule", "ai", "imported"] = "ai",
                       reason: str | None = None) -> list[str]:
        if parent_id not in self._hypotheses:
            return []
        ids: list[str] = []
        for label, likelihood in outcomes.items():
            hid = self.add_hypothesis(label=label, parent_id=parent_id,
                                      likelihoods={label: likelihood},
                                      created_by=created_by, reason=reason)
            ids.append(hid)
        return ids

    def get(self, hypothesis_id: str) -> Hypothesis | None:
        return self._hypotheses.get(hypothesis_id)

    def all(self) -> list[Hypothesis]:
        return list(self._hypotheses.values())

    def active(self) -> list[Hypothesis]:
        return [h for h in self._hypotheses.values() if h.status == "active"]

    def leaves(self) -> list[Hypothesis]:
        return [h for h in self._hypotheses.values()
                if h.status == "active" and not h.children]

    def resolve(self, hypothesis_id: str,
                status: Literal["confirmed", "refuted", "superseded"],
                evidence_refs: list[str] | None = None) -> None:
        hyp = self._hypotheses.get(hypothesis_id)
        if hyp is None:
            return
        hyp.status = status
        hyp.resolved_at = time.time()
        if evidence_refs:
            hyp.evidence_refs.extend(evidence_refs)
        self._recompute_gains()

    def compute_entropy(self, hypothesis_id: str) -> float:
        return self._hypotheses.get(hypothesis_id, Hypothesis(id="", label="")).entropy

    def compute_information_gain(self, hypothesis_id: str) -> float:
        return self._hypotheses.get(hypothesis_id, Hypothesis(id="", label="")).information_gain

    def forest_entropy(self) -> float:
        return sum(h.entropy for h in self.leaves())

    def _compute_entropy_from_likelihoods(self, likelihoods: dict[str, float]) -> float:
        total = sum(likelihoods.values())
        if total <= 0:
            return 0.0
        return -sum((p / total) * math.log2(p / total)
                    for p in likelihoods.values() if p > 0)

    def _recompute_gains(self) -> None:
        for hyp in self._hypotheses.values():
            if hyp.parent_id and hyp.parent_id in self._hypotheses:
                parent = self._hypotheses[hyp.parent_id]
                hyp.information_gain = parent.entropy - hyp.entropy
            else:
                hyp.information_gain = hyp.entropy

    def to_dict(self) -> list[dict]:
        return [h.to_dict() for h in self._hypotheses.values()]

    @classmethod
    def from_dict(cls, data: list[dict]) -> HypothesisEngine:
        engine = cls()
        for item in data:
            h = Hypothesis.from_dict(item)
            engine._hypotheses[h.id] = h
        return engine

    def __len__(self) -> int:
        return len(self._hypotheses)

    def __contains__(self, hid: str) -> bool:
        return hid in self._hypotheses
