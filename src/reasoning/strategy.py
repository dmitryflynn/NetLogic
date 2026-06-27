"""
StrategyManager — meta-reasoning: how the investigation evolves.

See the Phase 2 plan §4 and design §2.1. Sits above the ReconDirector and owns the decisions
about *how* to investigate (not the target itself): whether to engage the adaptive loop at all,
which persona to be in, when to stop, and when a plateau means "switch persona / restart". All
deterministic in Phase 2 — no LLM in the control flow.
"""
from __future__ import annotations

from typing import Optional

from src.reasoning.budget import BudgetManager
from src.reasoning.state import ReasoningState

_HIGH_IMPACT = {"high", "critical"}
# Trigger threshold: a high/critical belief below this is "unresolved" and worth a loop.
ACTIVATE_CONF = 0.60
# Personas, in escalation order.
PERSONAS = ("service_discovery", "technology_fingerprinting", "cloud_discovery",
            "application_mapping", "misconfiguration_discovery", "cve_verification",
            "pivot_discovery")
# Plateau: this many consecutive no-gain cycles → switch persona / restart.
_PLATEAU_CYCLES = 3


_MODE_EXPLORE = "explore"
_MODE_EXPLOIT = "exploit"


class StrategyManager:
    """Deterministic meta-reasoning over the ReasoningState."""

    def __init__(self) -> None:
        self._mode: str = _MODE_EXPLORE

    @property
    def mode(self) -> str:
        return self._mode

    def should_activate(self, state: ReasoningState, *, has_ai_key: bool,
                        budget: BudgetManager) -> bool:
        # Activation is governed by the reasoning_enabled opt-in, NOT the AI key: a
        # deterministic baseline must run without AI, and a no-opt-in scan must stay
        # byte-identical. `has_ai_key` only decides whether AI augmentation layers in.
        if not getattr(state, "reasoning_enabled", False) or budget.exhausted():
            return False
        inv = state.investigation
        if inv.contradictions:
            return True
        if any(u.get("impact") in _HIGH_IMPACT for u in inv.unknowns):
            return True
        if self._has_contested(state):
            return True
        if state.investigation.hypotheses.forest_entropy() > 0.5:
            return True
        return bool(state.investigation.objectives.unsatisfied())

    def select_persona(self, state: ReasoningState) -> str:
        beliefs = state.world.belief_records
        if any(b.get("impact") in _HIGH_IMPACT and b.get("version_only")
               and float(b.get("confidence", 1.0)) < ACTIVATE_CONF for b in beliefs):
            return "cve_verification"
        if not state.world.technology:
            return "technology_fingerprinting"
        if any("cloud" in str(t).lower() or "aws" in str(t).lower() or "azure" in str(t).lower()
               for t in state.world.technology):
            return "cloud_discovery"
        return "misconfiguration_discovery"

    def should_stop(self, state: ReasoningState, *, budget: BudgetManager,
                    best_priority: Optional[float], no_gain_streak: int) -> tuple[bool, str]:
        if budget.exhausted():
            return True, "budget exhausted"
        if best_priority is None:
            return True, "no high-value actions remain"
        if best_priority <= 0.0:
            return True, "best expected information gain below threshold"
        if not self._has_contested(state):
            if self._all_objectives_satisfied(state):
                return True, "all objectives satisfied"
        if no_gain_streak >= _PLATEAU_CYCLES:
            return True, "information gain plateaued"
        return False, ""

    def should_switch_mode(self, state: ReasoningState) -> str | None:
        if self._mode == _MODE_EXPLORE:
            if not self._has_contested(state) or self._all_objectives_satisfied(state):
                self._mode = _MODE_EXPLOIT
                return _MODE_EXPLOIT
        return None

    def select_exploit_objective(self, state: ReasoningState) -> str | None:
        if self._mode != _MODE_EXPLOIT:
            return None
        ready = sorted(state.investigation.objectives.ready(),
                       key=lambda o: o.priority, reverse=True)
        if ready:
            top = ready[0]
            if top.priority >= 0.7:
                return top.name
        return None

    @staticmethod
    def _has_contested(state: ReasoningState) -> bool:
        return any(
            b.get("impact") in _HIGH_IMPACT and float(b.get("confidence", 1.0)) < ACTIVATE_CONF
            for b in state.world.belief_records
        )

    @staticmethod
    def _all_objectives_satisfied(state: ReasoningState) -> bool:
        return all(o.satisfied for o in state.investigation.objectives.all())
