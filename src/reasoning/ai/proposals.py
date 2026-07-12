"""
Proposal types (Track C / Phase 9, C0) — the typed envelope every cognitive-layer agent emits.

"AI proposes, NetLogic proves." A `Proposal` is the ONLY thing an agent may produce: it carries a
kind-specific typed payload, full provenance (model/prompt/confidence/supporting evidence),
economics (what it would cost to verify, and what it's worth), and an uncertainty state that only
the deterministic verifier pipeline may advance. Nothing here mutates the world model — these are
inert, frozen data.

Every payload dataclass is immutable and field-bounded (short strings, tuples not lists) so a
Proposal is always safe to hash, log, and persist forever (including when rejected).
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Union


class ProposalKind(str, Enum):
    HYPOTHESIS = "hypothesis"
    OBJECTIVE = "objective"
    STRATEGY = "strategy"
    REFLECTION = "reflection"
    KNOWLEDGE = "knowledge"
    TEMPLATE = "template"
    PACK = "pack"
    EXPLANATION = "explanation"
    CONTRADICTION = "contradiction"


class UncertaintyState(str, Enum):
    """Verification outcome — NOT binary accept/reject. Only the verifier pipeline may advance a
    proposal along this order; a Proposal is born UNKNOWN and nothing else may set it higher."""
    UNKNOWN = "unknown"
    POSSIBLE = "possible"
    LIKELY = "likely"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"


_UNCERTAINTY_ORDER = {s: i for i, s in enumerate(
    (UncertaintyState.UNKNOWN, UncertaintyState.POSSIBLE, UncertaintyState.LIKELY,
     UncertaintyState.CONFIRMED))}


def uncertainty_rank(state: UncertaintyState) -> int:
    """REFUTED is terminal but not "higher" than CONFIRMED — it is its own outcome, not more
    certain. Callers comparing "how resolved" should treat REFUTED like CONFIRMED (rank 3)."""
    if state == UncertaintyState.REFUTED:
        return _UNCERTAINTY_ORDER[UncertaintyState.CONFIRMED]
    return _UNCERTAINTY_ORDER[state]


# ── Provenance + economics ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ProposalProvenance:
    """Where a proposal came from. Required on every proposal, verified or not."""
    model: str = ""
    prompt_version: str = ""
    temperature: float = 0.0
    timestamp: float = field(default_factory=time.time)
    reasoning_hash: str = ""                       # hash of the raw completion, for audit
    confidence: float = 0.0                         # the AGENT's self-reported confidence
    supporting_observation_ids: tuple[str, ...] = ()  # obs_ids the proposal claims to rest on

    def to_dict(self) -> dict:
        return {"model": self.model, "prompt_version": self.prompt_version,
                "temperature": self.temperature, "timestamp": self.timestamp,
                "reasoning_hash": self.reasoning_hash, "confidence": self.confidence,
                "supporting_observation_ids": list(self.supporting_observation_ids)}

    @classmethod
    def from_dict(cls, d: dict) -> "ProposalProvenance":
        return cls(model=str(d.get("model", "")), prompt_version=str(d.get("prompt_version", "")),
                   temperature=float(d.get("temperature", 0.0)),
                   timestamp=float(d.get("timestamp", time.time())),
                   reasoning_hash=str(d.get("reasoning_hash", "")),
                   confidence=float(d.get("confidence", 0.0)),
                   supporting_observation_ids=tuple(d.get("supporting_observation_ids", [])))


@dataclass(frozen=True)
class ProposalEconomics:
    """What verifying this proposal would cost, and what it's estimated to be worth. The Ranker
    (not this class) applies agent reputation — economics is intrinsic to the proposal alone."""
    estimated_information_gain: float = 0.0
    estimated_runtime: float = 1.0                 # seconds
    estimated_api_cost: float = 0.0                 # USD
    estimated_probe_count: int = 1
    estimated_risk: str = "read_only"                # RiskTier name, lowercase
    estimated_prob_correct: float = 0.5              # 0..1, the agent's own calibration guess

    def raw_score(self) -> float:
        """Intrinsic economy score: information gain per unit of (time x probes). Never negative;
        degenerate (non-positive/non-finite) inputs floor to 0 rather than raising or exploding."""
        gain = self.estimated_information_gain
        if not (gain == gain and gain > 0):          # NaN-safe
            return 0.0
        runtime = max(self.estimated_runtime, 0.01)
        probes = max(self.estimated_probe_count, 1)
        return round(gain / (runtime * probes), 6)

    def to_dict(self) -> dict:
        return {"estimated_information_gain": self.estimated_information_gain,
                "estimated_runtime": self.estimated_runtime,
                "estimated_api_cost": self.estimated_api_cost,
                "estimated_probe_count": self.estimated_probe_count,
                "estimated_risk": self.estimated_risk,
                "estimated_prob_correct": self.estimated_prob_correct}

    @classmethod
    def from_dict(cls, d: dict) -> "ProposalEconomics":
        return cls(estimated_information_gain=float(d.get("estimated_information_gain", 0.0)),
                   estimated_runtime=float(d.get("estimated_runtime", 1.0)),
                   estimated_api_cost=float(d.get("estimated_api_cost", 0.0)),
                   estimated_probe_count=int(d.get("estimated_probe_count", 1)),
                   estimated_risk=str(d.get("estimated_risk", "read_only")),
                   estimated_prob_correct=float(d.get("estimated_prob_correct", 0.5)))


# ── Typed payloads (one per ProposalKind) ────────────────────────────────────────────
# All immutable, all field-bounded. These are DESCRIPTORS: a StrategyPayload references existing
# ActionLibrary action ids, never a raw payload/exploit; a KnowledgePayload's `rule` is the same
# confirm/refute/contradiction marker shape the deterministic InferenceEngine already consumes.

@dataclass(frozen=True)
class HypothesisPayload:
    objective: str
    candidates: dict[str, float] = field(default_factory=dict)   # competing-explanation distribution
    novel: bool = False              # True for a novel-vulnerability hypothesis (no CVE/signature)
    rationale: str = ""

    def to_dict(self) -> dict:
        return {"objective": self.objective, "candidates": dict(self.candidates),
                "novel": self.novel, "rationale": self.rationale}


@dataclass(frozen=True)
class ObjectivePayload:
    goal_name: str
    goal_predicate: tuple[str, ...] = ()             # Predicate.from_spec()-compatible strings
    priority: float = 0.5
    risk_budget: str = "read_only"                    # AI may never propose above read_only
    # C2: the gatherable EvidenceType values this objective needs. The Normalizer filters this to a
    # fixed read-only vocabulary, so the AI can request evidence but never an arbitrary/intrusive probe.
    required_evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {"goal_name": self.goal_name, "goal_predicate": list(self.goal_predicate),
                "priority": self.priority, "risk_budget": self.risk_budget,
                "required_evidence": list(self.required_evidence)}


@dataclass(frozen=True)
class StrategyPayload:
    goal_class: str
    action_ids: tuple[str, ...] = ()                 # references into ActionLibrary, not payloads
    rationale: str = ""

    def to_dict(self) -> dict:
        return {"goal_class": self.goal_class, "action_ids": list(self.action_ids),
                "rationale": self.rationale}


@dataclass(frozen=True)
class ReflectionPayload:
    subject: str                                       # objective/strategy id being reflected on
    optimization: str = ""                              # e.g. "redundant_probe", "shorter_path"
    detail: str = ""

    def to_dict(self) -> dict:
        return {"subject": self.subject, "optimization": self.optimization, "detail": self.detail}


@dataclass(frozen=True)
class KnowledgePayload:
    tech_id: str
    rule: dict = field(default_factory=dict)            # confirm/refute/contradiction markers
    fixtures: tuple[dict, ...] = ()                       # benchmark fixtures EvidenceVerifier runs

    def to_dict(self) -> dict:
        return {"tech_id": self.tech_id, "rule": dict(self.rule), "fixtures": list(self.fixtures)}


@dataclass(frozen=True)
class TemplatePayload:
    goal_class: str
    stages: tuple[str, ...] = ("default",)

    def to_dict(self) -> dict:
        return {"goal_class": self.goal_class, "stages": list(self.stages)}


@dataclass(frozen=True)
class PackPayload:
    tech_id: str
    fingerprints: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"tech_id": self.tech_id, "fingerprints": dict(self.fingerprints)}


@dataclass(frozen=True)
class ExplanationPayload:
    subject: str
    text: str = ""

    def to_dict(self) -> dict:
        return {"subject": self.subject, "text": self.text}


@dataclass(frozen=True)
class ContradictionPayload:
    subject: str
    candidates: tuple[str, ...] = ()                     # e.g. ("reverse_proxy", "migration", "cdn")
    evidence_node_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {"subject": self.subject, "candidates": list(self.candidates),
                "evidence_node_ids": list(self.evidence_node_ids)}


Payload = Union[HypothesisPayload, ObjectivePayload, StrategyPayload, ReflectionPayload,
                KnowledgePayload, TemplatePayload, PackPayload, ExplanationPayload,
                ContradictionPayload]

_PAYLOAD_BY_KIND: dict[ProposalKind, type] = {
    ProposalKind.HYPOTHESIS: HypothesisPayload,
    ProposalKind.OBJECTIVE: ObjectivePayload,
    ProposalKind.STRATEGY: StrategyPayload,
    ProposalKind.REFLECTION: ReflectionPayload,
    ProposalKind.KNOWLEDGE: KnowledgePayload,
    ProposalKind.TEMPLATE: TemplatePayload,
    ProposalKind.PACK: PackPayload,
    ProposalKind.EXPLANATION: ExplanationPayload,
    ProposalKind.CONTRADICTION: ContradictionPayload,
}


# ── The envelope ──────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Proposal:
    """The ONLY unit an agent may emit. Frozen — advancing uncertainty produces a NEW Proposal
    (`with_uncertainty`), never a mutation, so a rejected proposal's original state is preserved
    forever in the store."""
    id: str
    kind: ProposalKind
    agent: str
    payload: Payload
    provenance: ProposalProvenance
    economics: ProposalEconomics
    uncertainty: UncertaintyState = UncertaintyState.UNKNOWN
    created_at: float = field(default_factory=time.time)

    def with_uncertainty(self, state: UncertaintyState) -> "Proposal":
        return Proposal(id=self.id, kind=self.kind, agent=self.agent, payload=self.payload,
                        provenance=self.provenance, economics=self.economics,
                        uncertainty=state, created_at=self.created_at)

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind.value, "agent": self.agent,
                "payload": self.payload.to_dict(), "provenance": self.provenance.to_dict(),
                "economics": self.economics.to_dict(), "uncertainty": self.uncertainty.value,
                "created_at": self.created_at}


def new_proposal_id() -> str:
    return uuid.uuid4().hex
