"""
ProposalRanker (Track C, C0) — stage 2 of the pipeline (Generate -> Normalize -> **Rank** -> Verify).

Scientists don't verify every idea — they rank first, so scarce probes are spent on the proposals
most likely to pay off. Ranking is `raw_score() * prob_correct * reputation_weight`: economics is
intrinsic to the proposal (Stage 1's concern); reputation is extrinsic and applied ONLY here,
mirroring the Phase 5 `DecisionPolicy` separation between a candidate's own numbers and the
policy's weighting of them.
"""
from __future__ import annotations

from dataclasses import dataclass

from src.reasoning.ai.proposals import Proposal


@dataclass(frozen=True)
class RankedProposal:
    proposal: Proposal
    score: float

    def to_dict(self) -> dict:
        return {"proposal": self.proposal.to_dict(), "score": self.score}


class ReputationSource:
    """Minimal protocol the Ranker needs — satisfied by `AgentReputation` (src/reasoning/ai/
    reputation.py). A default weight of 1.0 for unseen agents means a new agent is never unfairly
    punished or boosted before it has a track record."""

    def weight(self, agent: str) -> float:  # pragma: no cover - protocol
        raise NotImplementedError


class _NeutralReputation(ReputationSource):
    def weight(self, agent: str) -> float:
        return 1.0


NEUTRAL_REPUTATION = _NeutralReputation()


class ProposalRanker:
    def __init__(self, reputation: ReputationSource | None = None) -> None:
        self._reputation = reputation or NEUTRAL_REPUTATION

    def rank(self, proposals: list[Proposal]) -> list[RankedProposal]:
        """Stable sort, highest score first. Ties broken by proposal id so ranking is deterministic
        regardless of input order (a MetaReasoner/eval-harness invariant)."""
        scored = [
            RankedProposal(
                proposal=p,
                score=round(p.economics.raw_score() * p.economics.estimated_prob_correct
                            * self._reputation.weight(p.agent), 6))
            for p in proposals
        ]
        return sorted(scored, key=lambda r: (-r.score, r.proposal.id))

    def prune(self, proposals: list[Proposal], top_k: int) -> list[RankedProposal]:
        """Rank then keep only the top K — the point where garbage never reaches the verifier."""
        return self.rank(proposals)[:max(0, top_k)]
