"""
Evaluation harness (Track C, C0 deliverable) — cassette-based, deterministic, reproducible.

This is how we prove the cognitive layer makes NetLogic *smarter* from data, not intuition. A
`Cassette` is a fixed mapping from an agent name to a canned completion, so a whole agent run is
network-free and byte-deterministic — the same cassette always yields the same metrics. Wire real
recorded LLM responses into a cassette and you get a repeatable benchmark; wire synthetic ones and
you get unit-testable metric math.

Metrics (the first-class deliverable): proposal precision (verified ÷ proposed), acceptance rate,
rejection-by-stage breakdown, novel-hypothesis count, and refutation coverage (how many leading
hypotheses got at least one refutation objective). `false_novelty_rate` is left as a TODO hook —
it needs ground-truth labels a synthetic cassette can't supply.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from src.reasoning.ai.coordinator import AgentTask, AICoordinator
from src.reasoning.ai.proposals import ProposalKind
from src.reasoning.ai.store import ProposalStatus
from src.reasoning.ai.verifier import VerifierContext
from src.reasoning.state import ReasoningState


class Cassette:
    """A deterministic stand-in for an LLM: agent name -> fixed completion text. Passing
    `.completer_for(agent_name)` to an agent makes the whole run reproducible and offline."""

    def __init__(self, responses: dict[str, str]) -> None:
        self._responses = dict(responses)

    def completer_for(self, agent_name: str) -> Callable[[str, str], str]:
        text = self._responses.get(agent_name, "")

        def _complete(system: str, user: str) -> str:
            return text
        return _complete


@dataclass(frozen=True)
class EvalMetrics:
    proposed: int = 0
    accepted: int = 0
    rejected: int = 0
    precision: float = 0.0                  # accepted / proposed
    acceptance_rate: float = 0.0            # accepted / (accepted + rejected)
    rejection_by_stage: dict = field(default_factory=dict)
    novel_hypotheses: int = 0
    refutation_objectives: int = 0
    uncertainty_breakdown: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"proposed": self.proposed, "accepted": self.accepted, "rejected": self.rejected,
                "precision": self.precision, "acceptance_rate": self.acceptance_rate,
                "rejection_by_stage": dict(self.rejection_by_stage),
                "novel_hypotheses": self.novel_hypotheses,
                "refutation_objectives": self.refutation_objectives,
                "uncertainty_breakdown": dict(self.uncertainty_breakdown)}


def evaluate_agents(agents: list, state: ReasoningState, *,
                    ctx: Optional[VerifierContext] = None,
                    coordinator: Optional[AICoordinator] = None) -> EvalMetrics:
    """Run each agent through ONE shared coordinator against `state`, then compute metrics from the
    coordinator's store. Deterministic given deterministic agents (i.e. cassette completers)."""
    coordinator = coordinator or AICoordinator()
    ctx = ctx or VerifierContext()

    tasks: list[AgentTask] = []
    for agent in agents:
        tasks.extend(agent.generate(state))

    accepted = coordinator.run(tasks, ctx=ctx, top_k=len(tasks) or 1)

    records = coordinator.store.all()
    proposed = len(records)
    accepted_recs = [r for r in records if r.status == ProposalStatus.VERIFIED]
    rejected_recs = [r for r in records if r.status == ProposalStatus.REJECTED]

    by_stage: dict[str, int] = {}
    for r in rejected_recs:
        by_stage[r.stage_failed] = by_stage.get(r.stage_failed, 0) + 1

    novel = sum(1 for d in accepted
                if d.proposal.kind == ProposalKind.HYPOTHESIS
                and getattr(d.proposal.payload, "novel", False))
    refutations = sum(1 for d in accepted
                      if d.proposal.kind == ProposalKind.OBJECTIVE
                      and getattr(d.proposal.payload, "goal_name", "").startswith("refute:"))

    breakdown: dict[str, int] = {}
    for d in accepted:
        key = d.proposal.uncertainty.value
        breakdown[key] = breakdown.get(key, 0) + 1

    return EvalMetrics(
        proposed=proposed,
        accepted=len(accepted_recs),
        rejected=len(rejected_recs),
        precision=round(len(accepted_recs) / proposed, 4) if proposed else 0.0,
        acceptance_rate=round(len(accepted_recs) / (len(accepted_recs) + len(rejected_recs)), 4)
        if (accepted_recs or rejected_recs) else 0.0,
        rejection_by_stage=by_stage,
        novel_hypotheses=novel,
        refutation_objectives=refutations,
        uncertainty_breakdown=breakdown,
    )


def refutation_coverage(hypothesis_labels: list[str], refutation_goal_names: list[str]) -> float:
    """Fraction of leading hypotheses that received at least one refutation objective — the C11
    quality signal (are we actively trying to disprove our leading beliefs, or just confirming?)."""
    if not hypothesis_labels:
        return 0.0
    # A refutation goal is "refute:<candidate>:<check>"; match on the candidate segment.
    covered_candidates = {name.split(":", 2)[1] for name in refutation_goal_names
                          if name.startswith("refute:") and len(name.split(":", 2)) >= 2}
    covered = sum(1 for label in hypothesis_labels
                  if any(cand and cand in label for cand in covered_candidates))
    return round(covered / len(hypothesis_labels), 4)
