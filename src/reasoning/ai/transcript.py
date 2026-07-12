"""
InvestigationTranscript (Track C) — the "reasoning replay" of an AI-augmented investigation.

For every proposal the cognitive layer produced this scan, it records the causal chain:

    trigger (what was observed)
        → hypothesis / objective proposed
        → why (agent, rationale, economics)
        → disposition (accepted at uncertainty X, or rejected at stage Y)
        → seeded as (what the deterministic core actually added to the world)
        → outcome (confirmed / refuted / unresolved, filled in after inference)

It is an inert RECORDER: it holds references to already-computed values and never mutates the world,
the evidence graph, or any proposal. It reuses pieces that already exist (proposals carry their own
provenance/economics/uncertainty; the store carries dispositions) — the transcript is mostly about
recording how they connect during one investigation, which is invaluable for debugging, demos, and
as structured training/eval data.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from src.reasoning.ai.proposals import Proposal
from src.reasoning.ai.verifier import VerifyDecision


@dataclass
class TranscriptEntry:
    """One proposal's full lifecycle within an investigation. Mutable in exactly one dimension:
    `outcome` is filled in after the deterministic InferenceEngine resolves the seeded item."""
    proposal_id: str
    agent: str
    kind: str
    summary: str                       # human-readable "what was proposed"
    rationale: str = ""
    trigger: str = ""                  # what observation/context prompted it
    accepted: bool = False
    uncertainty: str = "unknown"       # at proposal time
    stage_failed: str = ""             # if rejected
    seeded_as: str = ""                # hypothesis label / objective name the core added, if any
    economics: dict = field(default_factory=dict)
    outcome: str = "unresolved"        # confirmed | refuted | unresolved (post-inference)
    timestamp: float = field(default_factory=time.time)

    @property
    def value(self) -> float:
        """Estimated worth of this proposal: information gain per probe. This is what lets a later
        Reflection agent ask "was investigating this hypothesis worth its cost?" — high-gain /
        low-probe proposals are the ones the engine should have chased first."""
        gain = float(self.economics.get("estimated_information_gain", 0.0))
        probes = max(int(self.economics.get("estimated_probe_count", 1) or 1), 1)
        return round(gain / probes, 4)

    def to_dict(self) -> dict:
        return {"proposal_id": self.proposal_id, "agent": self.agent, "kind": self.kind,
                "summary": self.summary, "rationale": self.rationale, "trigger": self.trigger,
                "accepted": self.accepted, "uncertainty": self.uncertainty,
                "stage_failed": self.stage_failed, "seeded_as": self.seeded_as,
                "economics": dict(self.economics), "value": self.value,
                "outcome": self.outcome, "timestamp": self.timestamp}


def _summarize(p: Proposal) -> str:
    payload = p.payload
    if hasattr(payload, "objective") and hasattr(payload, "candidates"):
        lead = max(payload.candidates.items(), key=lambda kv: kv[1])[0] if payload.candidates else "?"
        novel = " (novel)" if getattr(payload, "novel", False) else ""
        return f"{payload.objective} → leading: {lead}{novel}"
    if hasattr(payload, "goal_name"):
        return payload.goal_name
    return p.kind.value


class InvestigationTranscript:
    """Accumulates entries across a scan. One per ReasoningState (attached to execution state)."""

    def __init__(self) -> None:
        self._entries: list[TranscriptEntry] = []
        self._by_id: dict[str, TranscriptEntry] = {}

    def record(self, decision: VerifyDecision, *, trigger: str = "", seeded_as: str = "") -> TranscriptEntry:
        p = decision.proposal
        entry = TranscriptEntry(
            proposal_id=p.id, agent=p.agent, kind=p.kind.value, summary=_summarize(p),
            rationale=getattr(p.payload, "rationale", ""), trigger=trigger,
            accepted=decision.accepted, uncertainty=p.uncertainty.value,
            stage_failed=decision.stage_failed, seeded_as=seeded_as,
            economics=p.economics.to_dict())
        self._entries.append(entry)
        self._by_id[p.id] = entry
        return entry

    def record_note(self, *, agent: str, summary: str, rationale: str = "",
                    outcome: str = "unresolved") -> TranscriptEntry:
        """Record an AI DECISION that didn't come through the proposal pipeline (e.g. the
        FindingAdjudicator resolving a stuck CVE). It has no Proposal, so we synthesize a minimal
        accepted entry — the replay should show the AI's judgement calls, not just its proposals."""
        entry = TranscriptEntry(
            proposal_id=f"note:{agent}:{len(self._entries)}", agent=agent, kind="adjudication",
            summary=summary, rationale=rationale, trigger=agent, accepted=True,
            uncertainty="unknown", seeded_as="", outcome=outcome)
        self._entries.append(entry)
        self._by_id[entry.proposal_id] = entry
        return entry

    def set_outcome(self, proposal_id: str, outcome: str) -> None:
        entry = self._by_id.get(proposal_id)
        if entry is not None:
            entry.outcome = outcome

    def resolve_outcomes(self, resolved_labels: dict[str, str]) -> None:
        """Post-inference pass: `resolved_labels` maps a seeded hypothesis/objective name to its
        deterministic outcome ('confirmed'/'refuted'). Only entries whose seeded item the engine
        actually resolved get an outcome; everything else stays 'unresolved' (honest)."""
        for entry in self._entries:
            if entry.seeded_as and entry.seeded_as in resolved_labels:
                entry.outcome = resolved_labels[entry.seeded_as]

    def entries(self) -> list[TranscriptEntry]:
        return list(self._entries)

    def accepted(self) -> list[TranscriptEntry]:
        return [e for e in self._entries if e.accepted]

    def to_dict(self) -> dict:
        acc = self.accepted()
        # Cost rollup over ACCEPTED proposals — the investigation the AI actually caused. Estimated
        # (from proposal economics); the A/B benchmark measures the real, engine-level probe cost.
        est_gain = round(sum(float(e.economics.get("estimated_information_gain", 0.0)) for e in acc), 4)
        est_probes = sum(int(e.economics.get("estimated_probe_count", 0) or 0) for e in acc)
        est_runtime = round(sum(float(e.economics.get("estimated_runtime", 0.0)) for e in acc), 4)
        return {
            "entries": [e.to_dict() for e in self._entries],
            "summary": {
                "proposed": len(self._entries),
                "accepted": len(acc),
                "confirmed": sum(1 for e in acc if e.outcome == "confirmed"),
                "refuted": sum(1 for e in acc if e.outcome == "refuted"),
                "unresolved": sum(1 for e in acc if e.outcome == "unresolved"),
                "est_information_gain": est_gain,
                "est_probe_cost": est_probes,
                "est_runtime": est_runtime,
            },
        }

    def __len__(self) -> int:
        return len(self._entries)
