"""
Postcondition feedback (Phase 8c) — effects become real ONLY under authorized execution.

During planning (the default), an action's effects are *hypothetical*: the GoalPlanner applies them
to construct a chain, but they are never asserted as real world facts. Phase 8c closes the loop for
the authorized-execution case: when (and only when) an action was **authorized** (passed the gate)
**and executed successfully** via the external executor, its effects are asserted as new world facts
so the planner can advance the next link.

This keeps the core safe by construction: with no authorized execution, `assert_effects` returns the
facts unchanged — the world model never gains facts NetLogic didn't actually establish.
"""
from __future__ import annotations

from dataclasses import dataclass

from src.reasoning.actions import Action


@dataclass(frozen=True)
class ExecutionOutcome:
    """The result of an attempted action. `authorized` reflects the gate decision; `succeeded`
    reflects the external executor's confirmation."""
    action_id: str
    authorized: bool = False
    succeeded: bool = False

    @property
    def establishes_facts(self) -> bool:
        return self.authorized and self.succeeded


def assert_effects(action: Action, facts: dict, outcome: ExecutionOutcome) -> dict:
    """Return a NEW facts dict with the action's effects asserted — but ONLY if the action was
    authorized AND executed successfully. Otherwise the effects stay hypothetical (facts unchanged).
    """
    if outcome.action_id != action.id:
        return dict(facts)
    if not outcome.establishes_facts:
        return dict(facts)            # planning/validation-only → never assert real facts
    return action.apply(facts)


def proof_observation(action: Action, evidence: str = "") -> dict:
    """A confirmed step lands as an Observation(kind="proof") — reproducible, provenance-traced
    evidence, not a separate hierarchy. Returns the observe() kwargs for the EvidenceGraph."""
    return {"kind": "proof",
            "evidence": evidence or f"confirmed via {action.id}",
            "source": "investigation",
            "data": {"action_id": action.id,
                     "references": list(action.descriptor.references),
                     "risk_tier": action.risk_tier.name.lower()}}
