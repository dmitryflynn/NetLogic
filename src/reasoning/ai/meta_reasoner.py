"""
MetaReasoner (Track C, C0) — deterministic, core-side pruning of the proposal frontier.

NOT an LLM. AlphaGo-style split: agents (and the GoalPlanner) EXPLORE, the MetaReasoner PRUNES.
Three deterministic questions, in order: has this already been tried and failed while the world is
unchanged (reuses Phase 8's `InvestigationMemory`)? Have we seen this exact idea too many times
already (a loop)? Does it add anything a caller doesn't already have (no-uncertainty-reduction)?

Pure and replayable: given the same call sequence, `evaluate()` always returns the same decision —
no randomness, no AI, no wall-clock dependence beyond what the caller passes in.
"""
from __future__ import annotations

from dataclasses import dataclass

from src.reasoning.ai.proposals import (
    HypothesisPayload, ObjectivePayload, Proposal, StrategyPayload,
)
from src.reasoning.investigation_memory import InvestigationMemory

_DEFAULT_MAX_REPEATS = 3


@dataclass(frozen=True)
class PruneDecision:
    prune: bool
    reason: str = ""


def _goal_for(proposal: Proposal) -> str:
    """The InvestigationMemory goal key a proposal is "about", if it has one."""
    payload = proposal.payload
    if isinstance(payload, HypothesisPayload):
        return payload.objective
    if isinstance(payload, ObjectivePayload):
        return payload.goal_name
    if isinstance(payload, StrategyPayload):
        return payload.goal_class
    return ""


def proposal_signature(proposal: Proposal) -> str:
    """A stable signature of what a proposal is ABOUT — independent of its id/timestamp, so two
    proposals from different agents (or the same agent re-asked) that say the same thing collapse
    to one signature for loop/duplicate detection."""
    payload = proposal.payload
    if isinstance(payload, HypothesisPayload):
        cand_key = ",".join(sorted(payload.candidates))
        return f"hypothesis:{payload.objective}:{cand_key}"
    if isinstance(payload, ObjectivePayload):
        return f"objective:{payload.goal_name}"
    if isinstance(payload, StrategyPayload):
        return f"strategy:{payload.goal_class}:{','.join(sorted(payload.action_ids))}"
    return f"{payload.__class__.__name__}:{payload.to_dict()}"


class MetaReasoner:
    def __init__(self, memory: InvestigationMemory | None = None,
                 max_repeats: int = _DEFAULT_MAX_REPEATS) -> None:
        self._memory = memory
        self._max_repeats = max_repeats
        self._seen: dict[str, int] = {}

    def evaluate(self, proposal: Proposal, *, facts: dict | None = None,
                 existing_signatures: frozenset[str] | None = None) -> PruneDecision:
        """Should this proposal be pruned BEFORE it costs a probe? Checked in a fixed order so the
        reported reason is always the first one that applies."""
        sig = proposal_signature(proposal)

        if self._seen.get(sig, 0) >= self._max_repeats:
            return PruneDecision(True, f"looping: seen {self._seen[sig]}x already")

        goal = _goal_for(proposal)
        if self._memory is not None and goal:
            if self._memory.should_skip(goal, proposal.agent, facts or {}):
                return PruneDecision(True, "already tested (InvestigationMemory) — world unchanged")

        if existing_signatures is not None and sig in existing_signatures:
            return PruneDecision(True, "no uncertainty reduction: duplicate of an existing signature")

        return PruneDecision(False)

    def record(self, proposal: Proposal) -> None:
        """Call once per proposal actually considered, so repeats accumulate toward the loop cap."""
        sig = proposal_signature(proposal)
        self._seen[sig] = self._seen.get(sig, 0) + 1

    def prune_frontier(self, proposals: list[Proposal], *, facts: dict | None = None,
                       existing_signatures: frozenset[str] | None = None) -> list[Proposal]:
        """Filter a frontier in one pass: keep = not pruned, and record every proposal considered
        (so repeats within the SAME batch also count toward the loop cap)."""
        kept: list[Proposal] = []
        for p in proposals:
            decision = self.evaluate(p, facts=facts, existing_signatures=existing_signatures)
            self.record(p)
            if not decision.prune:
                kept.append(p)
        return kept
