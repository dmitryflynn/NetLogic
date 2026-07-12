"""
NetLogic Cognitive Layer (Track C / Phase 9, C0) — "AI proposes, NetLogic proves."

This package is the entire AI/deterministic-core boundary: every agent emits a typed `Proposal`
through here; nothing outside this package ever accepts raw AI text as truth. The deterministic
core (Phases 1-8) does not import this package — the dependency points one way only.

Pipeline: Generate -> Normalize -> Rank -> [MetaReasoner prune] -> Verify -> Store.
Safety: SafetyVerifier + a forbidden-key scan enforce the Phase-8b boundary independently of the
Normalizer's own risk-forcing, so removing either gate alone never opens a path to elevated risk.
"""
from __future__ import annotations

from src.reasoning.ai.agents import (
    CounterfactualReasoner, HypothesisGenerator, InvestigationDesigner,
)
from src.reasoning.ai.coordinator import AgentTask, AICoordinator, fence
from src.reasoning.ai.errors import ValidationError
from src.reasoning.ai.evaluation import Cassette, EvalMetrics, evaluate_agents, refutation_coverage
from src.reasoning.ai.meta_reasoner import MetaReasoner, PruneDecision, proposal_signature
from src.reasoning.ai.normalize import NormalizeResult, ProposalNormalizer, decode_total
from src.reasoning.ai.proposals import (
    ContradictionPayload,
    ExplanationPayload,
    HypothesisPayload,
    KnowledgePayload,
    ObjectivePayload,
    PackPayload,
    Proposal,
    ProposalEconomics,
    ProposalKind,
    ProposalProvenance,
    ReflectionPayload,
    StrategyPayload,
    TemplatePayload,
    UncertaintyState,
    new_proposal_id,
    uncertainty_rank,
)
from src.reasoning.ai.rank import NEUTRAL_REPUTATION, ProposalRanker, RankedProposal, ReputationSource
from src.reasoning.ai.reputation import AgentReputation
from src.reasoning.ai.store import ProposalRecord, ProposalStatus, ProposalStore
from src.reasoning.ai.transcript import InvestigationTranscript, TranscriptEntry
from src.reasoning.ai.verifier import VerifierContext, VerifierPipeline, VerifyDecision

__all__ = [
    "AgentReputation",
    "AgentTask",
    "AICoordinator",
    "Cassette",
    "ContradictionPayload",
    "CounterfactualReasoner",
    "EvalMetrics",
    "HypothesisGenerator",
    "ExplanationPayload",
    "HypothesisPayload",
    "InvestigationDesigner",
    "InvestigationTranscript",
    "KnowledgePayload",
    "MetaReasoner",
    "NEUTRAL_REPUTATION",
    "NormalizeResult",
    "ObjectivePayload",
    "PackPayload",
    "Proposal",
    "ProposalEconomics",
    "ProposalKind",
    "ProposalNormalizer",
    "ProposalProvenance",
    "ProposalRanker",
    "ProposalRecord",
    "ProposalStatus",
    "ProposalStore",
    "PruneDecision",
    "RankedProposal",
    "ReflectionPayload",
    "ReputationSource",
    "StrategyPayload",
    "TemplatePayload",
    "TranscriptEntry",
    "UncertaintyState",
    "ValidationError",
    "VerifierContext",
    "VerifierPipeline",
    "VerifyDecision",
    "decode_total",
    "evaluate_agents",
    "fence",
    "new_proposal_id",
    "proposal_signature",
    "refutation_coverage",
    "uncertainty_rank",
]
