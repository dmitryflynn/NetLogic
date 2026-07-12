"""
ProposalStore (Track C, C0) — the lifecycle ledger. Mirrors the dual-store pattern established by
`api/storage/reasoning_store.py` (in-memory here; a Postgres-backed store can be added later behind
the same interface without touching callers).

Lifecycle: Generated -> Validated -> Ranked -> Verified(Uncertainty) -> Archived. **Rejected
proposals are kept forever** — they are training/eval data for the future, not garbage. Nothing in
this module ever mutates a `Proposal` (they're frozen); it only tracks status transitions alongside
the proposal's own immutable audit trail.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from src.reasoning.ai.proposals import Proposal
from src.reasoning.ai.verifier import VerifyDecision


class ProposalStatus(str, Enum):
    GENERATED = "generated"
    VALIDATED = "validated"       # passed the Normalizer
    RANKED = "ranked"             # scored by the Ranker
    VERIFIED = "verified"         # passed all four Verifier stages (uncertainty advanced)
    REJECTED = "rejected"         # failed a Verifier stage — terminal, RETAINED forever
    ARCHIVED = "archived"         # accepted, then superseded/consumed by later work


@dataclass(frozen=True)
class ProposalRecord:
    proposal: Proposal
    status: ProposalStatus
    rank_score: Optional[float] = None
    stage_failed: str = ""
    reasons: tuple[str, ...] = ()
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {"proposal": self.proposal.to_dict(), "status": self.status.value,
                "rank_score": self.rank_score, "stage_failed": self.stage_failed,
                "reasons": list(self.reasons), "updated_at": self.updated_at}


class ProposalStore:
    """Process-local (mirrors `InMemoryReasoningStore`). Append-only history per proposal id —
    `record()` overwrites the CURRENT record but nothing is ever deleted from `_history`, so a
    rejected proposal's full lifecycle stays inspectable."""

    def __init__(self) -> None:
        self._current: dict[str, ProposalRecord] = {}
        self._history: list[ProposalRecord] = []
        self._order: list[str] = []

    def record(self, record: ProposalRecord) -> None:
        pid = record.proposal.id
        if pid not in self._current:
            self._order.append(pid)
        self._current[pid] = record
        self._history.append(record)

    def record_generated(self, proposal: Proposal) -> None:
        self.record(ProposalRecord(proposal=proposal, status=ProposalStatus.GENERATED))

    def record_ranked(self, proposal: Proposal, score: float) -> None:
        self.record(ProposalRecord(proposal=proposal, status=ProposalStatus.RANKED,
                                   rank_score=score))

    def record_decision(self, decision: VerifyDecision, *, rank_score: Optional[float] = None) -> None:
        status = ProposalStatus.VERIFIED if decision.accepted else ProposalStatus.REJECTED
        self.record(ProposalRecord(proposal=decision.proposal, status=status,
                                   rank_score=rank_score, stage_failed=decision.stage_failed,
                                   reasons=decision.reasons))

    def archive(self, proposal_id: str) -> bool:
        """Archiving only makes sense for a VERIFIED (accepted) proposal that's now superseded or
        consumed. Rejected proposals stay REJECTED forever; already-archived is a no-op."""
        rec = self._current.get(proposal_id)
        if rec is None or rec.status != ProposalStatus.VERIFIED:
            return False
        self.record(ProposalRecord(proposal=rec.proposal, status=ProposalStatus.ARCHIVED,
                                   rank_score=rec.rank_score))
        return True

    # ── Queries ──────────────────────────────────────────────────────────────────
    def get(self, proposal_id: str) -> Optional[ProposalRecord]:
        return self._current.get(proposal_id)

    def all(self) -> list[ProposalRecord]:
        return [self._current[pid] for pid in self._order]

    def by_status(self, status: ProposalStatus) -> list[ProposalRecord]:
        return [r for r in self.all() if r.status == status]

    def rejected(self) -> list[ProposalRecord]:
        """Every proposal ever rejected — retained forever, never dropped from `_history`."""
        return [r for r in self._history if r.status == ProposalStatus.REJECTED]

    def history_for(self, proposal_id: str) -> list[ProposalRecord]:
        return [r for r in self._history if r.proposal.id == proposal_id]

    def __len__(self) -> int:
        return len(self._order)
