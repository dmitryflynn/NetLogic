from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from src.reasoning.intent import EvidenceType
from src.reasoning.investigation_graph import InvestigationGraph


@dataclass
class PlannerFeedback:
    prioritize_evidence: list[str] = field(default_factory=list)
    deprioritize_evidence: list[str] = field(default_factory=list)
    new_hypotheses: list[dict] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    dead_ends: list[str] = field(default_factory=list)
    confidence_gaps: list[dict] = field(default_factory=list)
    suggest_reprobe: list[str] = field(default_factory=list)
    switch_objective: str | None = None
    rationale: str = ""

    def to_dict(self) -> dict:
        return {"prioritize_evidence": list(self.prioritize_evidence),
                "deprioritize_evidence": list(self.deprioritize_evidence),
                "new_hypotheses": list(self.new_hypotheses),
                "contradictions": list(self.contradictions),
                "dead_ends": list(self.dead_ends),
                "confidence_gaps": list(self.confidence_gaps),
                "suggest_reprobe": list(self.suggest_reprobe),
                "switch_objective": self.switch_objective,
                "rationale": self.rationale}

    @classmethod
    def from_dict(cls, data: dict) -> PlannerFeedback:
        return cls(prioritize_evidence=list(data.get("prioritize_evidence", [])),
                   deprioritize_evidence=list(data.get("deprioritize_evidence", [])),
                   new_hypotheses=list(data.get("new_hypotheses", [])),
                   contradictions=list(data.get("contradictions", [])),
                   dead_ends=list(data.get("dead_ends", [])),
                   confidence_gaps=list(data.get("confidence_gaps", [])),
                   suggest_reprobe=list(data.get("suggest_reprobe", [])),
                   switch_objective=data.get("switch_objective"),
                   rationale=data.get("rationale", ""))


class Reflect:
    """Examines ExecutionKernel results and feeds back to the Planner.
    Evidence-centric — recommends what evidence to seek, not which primitives to use."""

    def reflect(self, graph: InvestigationGraph,
                results: dict[str, Any],
                beliefs: dict[str, float] | None = None) -> PlannerFeedback:
        feedback = PlannerFeedback()
        for req in graph.all():
            result = results.get(req.id)
            if result is None:
                continue
            success = result.get("success", False) if isinstance(result, dict) else getattr(result, "success", False)
            if not success:
                feedback.dead_ends.append(req.id)
                continue
            evidence = result.get("evidence", "") if isinstance(result, dict) else getattr(result, "evidence", "")
            if evidence:
                feedback.confidence_gaps.append(
                    {"request_id": req.id, "evidence": str(evidence)[:200]})
        confidence_gaps = self._find_confidence_gaps(beliefs)
        for gap in confidence_gaps:
            if gap not in feedback.prioritize_evidence:
                feedback.prioritize_evidence.append(gap)
        return feedback

    def _find_confidence_gaps(self, beliefs: dict[str, float] | None) -> list[str]:
        gaps: list[str] = []
        if not beliefs:
            return gaps
        for key, conf in beliefs.items():
            if conf < 0.6:
                gaps.append(key)
        return gaps

    def reprioritize(self, feedback: PlannerFeedback,
                     graph: InvestigationGraph) -> InvestigationGraph:
        for ev_type_str in feedback.prioritize_evidence:
            for req in graph.all():
                if req.evidence_type == ev_type_str:
                    pass
        for dead_id in feedback.dead_ends:
            graph.requests.pop(dead_id, None)
        return graph
