"""
Staged Verifier (Track C, C0) — stage 4 of the pipeline, defense in depth like the Phase-8b
`ActionGate`: SyntaxVerifier -> SemanticVerifier -> EvidenceVerifier -> SafetyVerifier -> Decision.

Any stage can independently reject; removing one stage never opens a path to acceptance the others
would have blocked. This is the ONLY place a Proposal's `uncertainty` may be advanced past UNKNOWN
— and even then only to POSSIBLE/LIKELY (evidence-backed) or CONFIRMED (benchmark-verified
knowledge). Nothing here ever mutates the world model, evidence graph, beliefs, or hypotheses;
it returns a decision the caller may act on.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from src.reasoning.actions import RiskTier
from src.reasoning.ai.proposals import (
    ContradictionPayload, HypothesisPayload, KnowledgePayload, ObjectivePayload, Proposal,
    StrategyPayload, UncertaintyState,
)

# Keys that must NEVER appear anywhere in a proposal's payload — the Phase-8b "AI never" boundary,
# re-enforced here independently of the Normalizer (which already forces estimated_risk to
# read_only) so removing either gate alone still leaves this one standing.
_FORBIDDEN_KEYS = frozenset({
    "authorized", "execution_authorized", "risk_ceiling", "kill_switch",
    "authorization", "external_executor",
})


def _scan_for_forbidden_keys(obj) -> Optional[str]:
    """Recursively scan a dict/list for any forbidden key, at any depth. Returns the key found,
    or None. Case-insensitive so `Authorized`/`AUTHORIZED` can't slip past a naive check."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in _FORBIDDEN_KEYS:
                return k
            found = _scan_for_forbidden_keys(v)
            if found:
                return found
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            found = _scan_for_forbidden_keys(item)
            if found:
                return found
    return None


@dataclass(frozen=True)
class VerifierContext:
    """Read-only facts the verifier checks a proposal against. Every field is optional — an
    absent context makes the corresponding check a no-op, so unit tests aren't forced to
    fabricate a full world just to exercise one stage. Production callers should supply all of
    them (the AICoordinator does)."""
    known_observation_ids: Optional[frozenset] = None
    known_objectives: Optional[frozenset] = None
    action_library: Optional[object] = None                      # .get(action_id) -> Action | None
    benchmark_check: Optional[Callable[[KnowledgePayload], bool]] = None


@dataclass(frozen=True)
class StageResult:
    ok: bool
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class VerifyDecision:
    accepted: bool
    proposal: Proposal
    stage_failed: str = ""
    reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {"accepted": self.accepted, "proposal": self.proposal.to_dict(),
                "stage_failed": self.stage_failed, "reasons": list(self.reasons)}


# ── Stage 1: Syntax ──────────────────────────────────────────────────────────────────

def _syntax_stage(p: Proposal, _ctx: VerifierContext) -> StageResult:
    if not p.id or not p.agent:
        return StageResult(False, ("missing id or agent",))
    payload = p.payload
    if isinstance(payload, HypothesisPayload):
        if not payload.objective or not payload.candidates:
            return StageResult(False, ("hypothesis missing objective or candidates",))
    elif isinstance(payload, ObjectivePayload):
        if not payload.goal_name:
            return StageResult(False, ("objective missing goal_name",))
    elif isinstance(payload, StrategyPayload):
        if not payload.goal_class or not payload.action_ids:
            return StageResult(False, ("strategy missing goal_class or action_ids",))
    elif isinstance(payload, KnowledgePayload):
        if not payload.tech_id or not payload.rule:
            return StageResult(False, ("knowledge missing tech_id or rule",))
    elif isinstance(payload, ContradictionPayload):
        if not payload.subject or len(payload.candidates) < 2:
            return StageResult(False, ("contradiction needs >=2 candidates",))
    return StageResult(True)


# ── Stage 2: Semantic ────────────────────────────────────────────────────────────────

# Objective namespaces OWNED by the deterministic generators. A hypothesis claiming to refine one
# of these MUST match a real open objective (anti-hallucination — the AI can't fabricate entries in
# the deterministic layer's own space). Any OTHER slug is a novel line of inquiry the AI is allowed
# to introduce (it seeds a new objective downstream) — rejecting those would kill C1's whole point.
_DETERMINISTIC_OBJECTIVE_PREFIXES = ("verify:", "identify_framework:", "identify_service:")


def _semantic_stage(p: Proposal, ctx: VerifierContext) -> StageResult:
    payload = p.payload
    if isinstance(payload, HypothesisPayload) and ctx.known_objectives is not None:
        obj = payload.objective
        if any(obj.startswith(pre) for pre in _DETERMINISTIC_OBJECTIVE_PREFIXES) \
                and obj not in ctx.known_objectives:
            return StageResult(False, (f"refines unknown deterministic objective: {obj}",))
    if isinstance(payload, StrategyPayload) and ctx.action_library is not None:
        for aid in payload.action_ids:
            action = ctx.action_library.get(aid)
            if action is None:
                return StageResult(False, (f"unknown action_id: {aid}",))
            if action.risk_tier > RiskTier.READ_ONLY:
                return StageResult(False, (f"action {aid} exceeds read_only",))
    if isinstance(payload, KnowledgePayload):
        rule = payload.rule
        if not any(rule.get(k) for k in ("confirm", "refute", "contradiction")):
            return StageResult(False, ("knowledge rule has no confirm/refute/contradiction markers",))
    return StageResult(True)


# ── Stage 3: Evidence ────────────────────────────────────────────────────────────────

def _evidence_stage(p: Proposal, ctx: VerifierContext) -> StageResult:
    # No phantom evidence: every cited observation id must be real, if we know what's real.
    if p.provenance.supporting_observation_ids and ctx.known_observation_ids is not None:
        missing = [oid for oid in p.provenance.supporting_observation_ids
                  if oid not in ctx.known_observation_ids]
        if missing:
            return StageResult(False, (f"cites unknown observation(s): {missing[:3]}",))
    if isinstance(p.payload, KnowledgePayload):
        # Knowledge is fail-closed: no configured benchmark => cannot pass, ever.
        if ctx.benchmark_check is None:
            return StageResult(False, ("no benchmark configured for knowledge verification",))
        if not ctx.benchmark_check(p.payload):
            return StageResult(False, ("failed benchmark corpus",))
    return StageResult(True)


# ── Stage 4: Safety (the Phase-8b boundary) ─────────────────────────────────────────

def _safety_stage(p: Proposal, ctx: VerifierContext) -> StageResult:
    found = _scan_for_forbidden_keys(p.payload.to_dict())
    if found:
        return StageResult(False, (f"payload smuggles gate-controlling key: {found}",))
    if p.economics.estimated_risk != "read_only":
        return StageResult(False, ("economics claims risk above read_only",))
    if isinstance(p.payload, StrategyPayload) and ctx.action_library is not None:
        for aid in p.payload.action_ids:
            action = ctx.action_library.get(aid)
            if action is not None and action.risk_tier > RiskTier.READ_ONLY:
                return StageResult(False, (f"action {aid} exceeds read_only (safety re-check)",))
    return StageResult(True)


_STAGES: tuple[tuple[str, Callable[[Proposal, VerifierContext], StageResult]], ...] = (
    ("syntax", _syntax_stage),
    ("semantic", _semantic_stage),
    ("evidence", _evidence_stage),
    ("safety", _safety_stage),
)


def _resolve_uncertainty(p: Proposal) -> UncertaintyState:
    """Only reached once every stage has passed. KNOWLEDGE reaching here already passed the
    benchmark corpus => CONFIRMED. Evidence-backed claims => LIKELY. Everything else that is
    merely structurally/semantically sound => POSSIBLE (an idea worth investigating, not a truth)."""
    if isinstance(p.payload, KnowledgePayload):
        return UncertaintyState.CONFIRMED
    if p.provenance.supporting_observation_ids:
        return UncertaintyState.LIKELY
    return UncertaintyState.POSSIBLE


class VerifierPipeline:
    """Runs the four stages in order. First failure stops the pipeline (defense in depth: a
    proposal that fails ANY stage is rejected, full stop)."""

    def verify(self, proposal: Proposal, ctx: VerifierContext | None = None) -> VerifyDecision:
        ctx = ctx or VerifierContext()
        for name, stage in _STAGES:
            result = stage(proposal, ctx)
            if not result.ok:
                return VerifyDecision(accepted=False, proposal=proposal,
                                      stage_failed=name, reasons=result.reasons)
        verified = proposal.with_uncertainty(_resolve_uncertainty(proposal))
        return VerifyDecision(accepted=True, proposal=verified)
