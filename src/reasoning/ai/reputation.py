"""
AgentReputation (Track C, C0) — per-agent track record, used ONLY by the `ProposalRanker` to weight
future proposals. Separate from `InvestigationMemory` (which tracks strategy attempts against the
world): this tracks how trustworthy a given agent's PROPOSALS have historically been, independent
of any one target's evidence.

An unseen agent gets weight 1.0 (neutral) — reputation only ever shifts a proposal's rank after it
has a track record, so a brand-new agent is never unfairly punished or boosted on its first output.
"""
from __future__ import annotations

from dataclasses import dataclass

from src.reasoning.ai.rank import ReputationSource
from src.reasoning.ai.store import ProposalStatus

_NEUTRAL_WEIGHT = 1.0
_MIN_WEIGHT = 0.1        # a bad agent is down-weighted, never fully silenced (still auditable)
_MAX_WEIGHT = 2.0        # a good agent is boosted, never allowed to dominate ranking outright


@dataclass
class _AgentStats:
    proposed: int = 0
    accepted: int = 0       # reached VERIFIED
    rejected: int = 0       # reached REJECTED


class AgentReputation(ReputationSource):
    """Implements `rank.ReputationSource` — pass an instance straight into `ProposalRanker`."""

    def __init__(self) -> None:
        self._stats: dict[str, _AgentStats] = {}

    def observe(self, agent: str, status: ProposalStatus) -> None:
        s = self._stats.setdefault(agent, _AgentStats())
        s.proposed += 1
        if status == ProposalStatus.VERIFIED:
            s.accepted += 1
        elif status == ProposalStatus.REJECTED:
            s.rejected += 1

    def acceptance_rate(self, agent: str) -> float:
        s = self._stats.get(agent)
        if s is None or s.proposed == 0:
            return 0.5   # unknown — neutral prior, not zero (zero would look like a bad track record)
        decided = s.accepted + s.rejected
        return s.accepted / decided if decided else 0.5

    def weight(self, agent: str) -> float:
        """The multiplier `ProposalRanker` applies on top of a proposal's intrinsic economy score.
        Linear interpolation from MIN to MAX around the neutral acceptance rate of 0.5, so an agent
        with a track record straddling coin-flip accuracy stays near NEUTRAL_WEIGHT."""
        s = self._stats.get(agent)
        if s is None or (s.accepted + s.rejected) == 0:
            return _NEUTRAL_WEIGHT
        rate = self.acceptance_rate(agent)
        # rate in [0,1] -> weight in [MIN_WEIGHT, MAX_WEIGHT], 0.5 -> NEUTRAL_WEIGHT
        if rate >= 0.5:
            return round(_NEUTRAL_WEIGHT + (rate - 0.5) * 2 * (_MAX_WEIGHT - _NEUTRAL_WEIGHT), 4)
        return round(_NEUTRAL_WEIGHT - (0.5 - rate) * 2 * (_NEUTRAL_WEIGHT - _MIN_WEIGHT), 4)

    def to_dict(self) -> dict:
        return {agent: {"proposed": s.proposed, "accepted": s.accepted, "rejected": s.rejected,
                        "acceptance_rate": self.acceptance_rate(agent), "weight": self.weight(agent)}
                for agent, s in self._stats.items()}
