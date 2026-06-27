"""
Tests for DecisionPolicy (Phase 5 §6).

Verifies: policy ranking, weight tuning, explain() output, backward compatibility with Scheduler.
"""
from __future__ import annotations

import pytest

from src.reasoning.decision_policy import DecisionPolicy, DefaultDecisionPolicy, RankedAction
from src.reasoning.scheduler import Scheduler, ScoredAction
from src.reasoning.registry import SensorStep, StepContext
from src.reasoning.state import ReasoningState


def _make_test_state() -> ReasoningState:
    """Create a minimal ReasoningState for testing."""
    state = ReasoningState(target="example.com:443", scope=["example.com:443"])
    # Add a high-impact, low-confidence belief (contested)
    state.world.belief_records = [
        {
            "claim": "WordPress 6.0",
            "kind": "framework",
            "impact": "high",
            "confidence": 0.5,
            "version_only": True,
        }
    ]
    return state


def _make_test_context(state: ReasoningState) -> StepContext:
    """Create a minimal StepContext for testing."""
    def _emit(*args, **kwargs):
        pass  # No-op emit for testing
    return StepContext(state=state, target="example.com:443", art={}, emit=_emit)


def _make_test_step(name: str = "test_step", base_gain: float = 1.0,
                   resolves: list | None = None, cost: dict | None = None) -> SensorStep:
    """Create a minimal SensorStep for testing."""
    if resolves is None:
        resolves = ["version_only"]
    if cost is None:
        cost = {"time_ms": 1000, "tokens": 0, "probes": 1}

    step = SensorStep(
        name=name,
        persona="service_discovery",
        run=lambda ctx: None,
        base_gain=base_gain,
        cost=cost,
        resolves=tuple(resolves),
        applies=lambda ctx: True,
    )
    return step


class TestDefaultDecisionPolicy:
    """Test DefaultDecisionPolicy ranking logic."""

    def test_policy_ranks_steps_by_priority(self):
        """Policy ranks steps highest priority first."""
        policy = DefaultDecisionPolicy()
        state = _make_test_state()
        ctx = _make_test_context(state)

        step1 = _make_test_step("step1", base_gain=1.0, cost={"time_ms": 1000, "tokens": 0, "probes": 1})
        step2 = _make_test_step("step2", base_gain=2.0, cost={"time_ms": 1000, "tokens": 0, "probes": 1})  # Higher gain

        ranked = policy.rank_actions([step1, step2], ctx)

        assert len(ranked) == 2
        assert ranked[0].step.name == "step2"  # Higher gain should be ranked first
        assert ranked[0].priority > ranked[1].priority

    def test_policy_respects_cost(self):
        """Steps with higher cost should have lower priority (other things equal)."""
        policy = DefaultDecisionPolicy()
        state = _make_test_state()
        ctx = _make_test_context(state)

        step_cheap = _make_test_step("cheap", base_gain=1.0,
                                    cost={"time_ms": 100, "tokens": 0, "probes": 1})
        step_expensive = _make_test_step("expensive", base_gain=1.0,
                                        cost={"time_ms": 5000, "tokens": 0, "probes": 1})

        ranked = policy.rank_actions([step_cheap, step_expensive], ctx)

        assert len(ranked) == 2
        assert ranked[0].step.name == "cheap"  # Lower cost should be ranked first
        assert ranked[0].priority > ranked[1].priority

    def test_sensorstep_ordering_is_weight_invariant(self):
        """The SensorStep path keeps the legacy multiplicative formula, so global weights
        cancel and ordering is invariant — this is what preserves equivalence with the Phase 4
        scheduler. (Weight *sensitivity* is a property of the Candidate path; see
        test_candidate_policy.py::test_default_weight_sensitivity.)"""
        policy_a = DefaultDecisionPolicy(info_gain_weight=10.0, budget_weight=0.1)
        policy_b = DefaultDecisionPolicy(info_gain_weight=0.1, budget_weight=10.0)

        state = _make_test_state()
        ctx = _make_test_context(state)

        hg = _make_test_step("hg_hc", base_gain=10.0,
                             cost={"time_ms": 5000, "tokens": 0, "probes": 1})
        lg = _make_test_step("lg_lc", base_gain=1.0,
                             cost={"time_ms": 100, "tokens": 0, "probes": 1})

        order_a = [r.step.name for r in policy_a.rank_actions([hg, lg], ctx)]
        order_b = [r.step.name for r in policy_b.rank_actions([hg, lg], ctx)]
        assert order_a == order_b   # weight-invariant on the SensorStep path

    def test_policy_excludes_seen_steps(self):
        """Policy should exclude steps already seen."""
        policy = DefaultDecisionPolicy()
        state = _make_test_state()
        ctx = _make_test_context(state)

        step1 = _make_test_step("step1")
        step2 = _make_test_step("step2")

        ranked = policy.rank_actions([step1, step2], ctx, seen={"step1"})

        assert len(ranked) == 1
        assert ranked[0].step.name == "step2"

    def test_policy_explain(self):
        """Policy should have a human-readable explanation."""
        policy = DefaultDecisionPolicy(info_gain_weight=1.0, entropy_weight=0.5)
        explanation = policy.explain()

        assert "DefaultDecisionPolicy" in explanation
        assert "1" in explanation  # info_gain_weight
        assert "0.5" in explanation  # entropy_weight


class TestSchedulerWithDecisionPolicy:
    """Test Scheduler integration with DecisionPolicy."""

    def test_scheduler_uses_policy(self):
        """Scheduler should use the provided policy."""
        policy = DefaultDecisionPolicy()
        scheduler = Scheduler(policy=policy)

        assert scheduler.policy is policy

    def test_scheduler_select_returns_scored_action(self):
        """Scheduler.select() should return a ScoredAction."""
        scheduler = Scheduler()
        state = _make_test_state()
        ctx = _make_test_context(state)

        step1 = _make_test_step("step1", base_gain=1.0)
        step2 = _make_test_step("step2", base_gain=2.0)

        result = scheduler.select([step1, step2], ctx)

        assert result is not None
        assert isinstance(result, ScoredAction)
        assert result.step.name == "step2"  # Higher gain
        assert result.priority > 0

    def test_scheduler_explores_sometimes(self):
        """Scheduler should explore (pick non-top) a fraction of the time."""
        import random
        # Seeded RNG for determinism
        rng = random.Random(42)
        scheduler = Scheduler(explore_reserve=0.5, rng=rng)  # 50% explore rate

        state = _make_test_state()
        ctx = _make_test_context(state)

        steps = [_make_test_step(f"step{i}", base_gain=float(i)) for i in range(5)]

        # Run multiple times, some should be top, some should be explore
        top_count = 0
        explore_count = 0
        for _ in range(100):
            result = scheduler.select(steps, ctx)
            if result:
                if result.step.name == "step4":  # step4 has highest gain
                    top_count += 1
                elif "[explore]" in result.rationale:
                    explore_count += 1

        # With 50% explore rate, we should see both top and explore picks
        assert top_count > 0
        assert explore_count > 0

    def test_scheduler_backward_compatible_score_method(self):
        """Scheduler.score() should still work (backward compatibility)."""
        scheduler = Scheduler()
        state = _make_test_state()
        ctx = _make_test_context(state)

        step = _make_test_step("test_step", base_gain=1.0)
        scored = scheduler.score(step, ctx)

        assert isinstance(scored, ScoredAction)
        assert scored.step is step
        assert scored.priority > 0
