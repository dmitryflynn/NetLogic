"""
Observation Provenance Graph — the irreproducible source of truth.

See the Phase 5 (revised) plan §1. This persists ONLY the relationships that cannot be
regenerated from rules + state:

    Observation ──▶ InferenceStep ──▶ Hypothesis

Everything downstream (Objective derivation, scheduler decisions, playbook selection) is a pure
function of the persisted core plus the rule packs and policies, so it is *replayed* on demand
rather than stored. This keeps the graph compact while remaining fully explainable.

Boundaries (kept clean):
  • Provenance is ADDITIVE and READ-ONLY over reasoning state. It never mutates observations,
    hypotheses, confidence, or objectives — so building it cannot perturb the byte-identical
    invariant established in Phase 4.
  • `InferenceStep` is left untouched; its stable id is derived here as a pure function of its
    content, so the InferenceEngine has no new responsibilities.
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Iterable

log = logging.getLogger("netlogic.reasoning.provenance")


def inference_step_id(hypothesis_id: str, rule: str, decision: str, matched: str) -> str:
    """Deterministic id for an InferenceStep — a pure function of its content.

    Computed in the provenance layer (not on InferenceStep itself) so the InferenceEngine
    contract is unchanged and replay is byte-stable.
    """
    ident = json.dumps(
        {"h": hypothesis_id, "r": rule, "d": decision, "m": matched},
        sort_keys=True, separators=(",", ":"), default=str,
    )
    return hashlib.sha256(ident.encode("utf-8")).hexdigest()[:24]


@dataclass(frozen=True)
class ObservationInferenceEdge:
    """Observation ──▶ InferenceStep: this observed fact triggered this rule match."""
    obs_id: str
    inference_id: str
    rule: str
    matched: str

    def to_dict(self) -> dict:
        return {"obs_id": self.obs_id, "inference_id": self.inference_id,
                "rule": self.rule, "matched": self.matched}

    @classmethod
    def from_dict(cls, data: dict) -> "ObservationInferenceEdge":
        return cls(obs_id=data["obs_id"], inference_id=data["inference_id"],
                   rule=data.get("rule", ""), matched=data.get("matched", ""))


@dataclass(frozen=True)
class InferenceHypothesisEdge:
    """InferenceStep ──▶ Hypothesis: this inference changed this hypothesis."""
    inference_id: str
    hypothesis_id: str
    decision: str            # "confirmed" | "refuted" | "contradiction"
    objective_satisfied: str = ""

    def to_dict(self) -> dict:
        return {"inference_id": self.inference_id, "hypothesis_id": self.hypothesis_id,
                "decision": self.decision, "objective_satisfied": self.objective_satisfied}

    @classmethod
    def from_dict(cls, data: dict) -> "InferenceHypothesisEdge":
        return cls(inference_id=data["inference_id"], hypothesis_id=data["hypothesis_id"],
                   decision=data.get("decision", ""),
                   objective_satisfied=data.get("objective_satisfied", ""))


@dataclass
class ProvenanceGraph:
    """The two irreproducible edge sets. JSON-serializable for Postgres JSONB persistence."""
    obs_inference: list[ObservationInferenceEdge] = field(default_factory=list)
    inference_hypothesis: list[InferenceHypothesisEdge] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"obs_inference": [e.to_dict() for e in self.obs_inference],
                "inference_hypothesis": [e.to_dict() for e in self.inference_hypothesis]}

    @classmethod
    def from_dict(cls, data: dict | None) -> "ProvenanceGraph":
        data = data or {}
        return cls(
            obs_inference=[ObservationInferenceEdge.from_dict(d)
                           for d in data.get("obs_inference", [])],
            inference_hypothesis=[InferenceHypothesisEdge.from_dict(d)
                                  for d in data.get("inference_hypothesis", [])],
        )


class ProvenanceBuilder:
    """Builds a ProvenanceGraph from inference steps + reasoning state.

    Pure and deterministic: the same (state, steps) always yields identical edges, so a replayed
    run produces an identical provenance graph. Attribution maps a matched substring back to the
    observation(s) whose evidence/data contained it — restoring the observation→inference link the
    InferenceEngine's evidence-blob concatenation would otherwise lose.
    """

    def build(self, state, inference_steps: Iterable) -> ProvenanceGraph:
        graph = ProvenanceGraph()
        obs_index = self._index_observations(state)

        for step in inference_steps:
            iid = inference_step_id(step.hypothesis_id, step.rule, step.decision, step.matched)

            # InferenceStep ──▶ Hypothesis (always present)
            graph.inference_hypothesis.append(InferenceHypothesisEdge(
                inference_id=iid,
                hypothesis_id=step.hypothesis_id,
                decision=step.decision,
                objective_satisfied=getattr(step, "objective_satisfied", "") or "",
            ))

            # Observation ──▶ InferenceStep (attribute the matched substring to observations)
            matched = (step.matched or "").lower()
            if not matched:
                continue
            for obs_id, blob in obs_index:
                if matched in blob:
                    graph.obs_inference.append(ObservationInferenceEdge(
                        obs_id=obs_id, inference_id=iid, rule=step.rule, matched=step.matched))

        return graph

    @staticmethod
    def _index_observations(state) -> list[tuple[str, str]]:
        """(obs_id, lowercased evidence+data blob) for every observation in the graph."""
        index: list[tuple[str, str]] = []
        try:
            nodes = state.world.graph.nodes()
        except Exception:  # noqa: BLE001
            return index
        for node in nodes:
            for o in node.observations():
                parts = []
                if o.evidence:
                    parts.append(str(o.evidence))
                if o.data:
                    parts.append(json.dumps(o.data, default=str))
                index.append((o.obs_id, " ".join(parts).lower()))
        return index


class ProvenanceTracer:
    """Read-only queries over a ProvenanceGraph."""

    def __init__(self, graph: ProvenanceGraph) -> None:
        self._g = graph

    def hypothesis_to_observations(self, hypothesis_id: str) -> set[str]:
        """All observation ids that contributed to a hypothesis (transitive over inferences)."""
        inference_ids = {e.inference_id for e in self._g.inference_hypothesis
                         if e.hypothesis_id == hypothesis_id}
        return {e.obs_id for e in self._g.obs_inference if e.inference_id in inference_ids}

    def observation_to_hypotheses(self, obs_id: str) -> set[str]:
        """All hypotheses an observation influenced (forward trace)."""
        inference_ids = {e.inference_id for e in self._g.obs_inference if e.obs_id == obs_id}
        return {e.hypothesis_id for e in self._g.inference_hypothesis
                if e.inference_id in inference_ids}

    def inferences_for_hypothesis(self, hypothesis_id: str) -> list[InferenceHypothesisEdge]:
        """The inference edges that resolved a hypothesis (for Reflect / Explanation)."""
        return [e for e in self._g.inference_hypothesis if e.hypothesis_id == hypothesis_id]
