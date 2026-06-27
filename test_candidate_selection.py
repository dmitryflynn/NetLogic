"""Lazy candidate selection (Phase 5 revised §4/§5): playbooks/capabilities are matched cheaply,
ranked by policy, and only the SELECTED candidates are instantiated. This is the fix for eager
playbook instantiation — no InvestigationGraph work for actions the scheduler won't pursue."""
from src.reasoning.candidate import Candidate
from src.reasoning.decision_policy import GreedyPolicy
from src.reasoning.intent import Intent, StopCondition
from src.reasoning.playbooks import Playbook, PlaybookRegistry
from src.reasoning.probe_plan import Condition, ConditionOp
from src.reasoning.state import ReasoningState


def _always_on_playbook(pid, name, gain):
    return Playbook(
        id=pid, name=name, trigger_rule=Condition(op=ConditionOp.TRUST),
        intent_template=Intent(goal=f"goal-{pid}"),
        default_stopping_condition=StopCondition(),
        metadata={"expected_information_gain": gain})


def _state():
    return ReasoningState(target="ex.com:80", scope=["ex.com:80"])


def test_registry_emits_playbook_candidates_lazily():
    reg = PlaybookRegistry()
    reg.register(_always_on_playbook("p1", "One", 1.0))
    cands = reg.to_candidates(_state())
    assert len(cands) == 1
    assert cands[0].source == "playbook"
    # nothing instantiated yet
    intents = cands[0].instantiate()
    assert intents[0].goal == "goal-p1"


def test_only_selected_candidates_instantiate():
    """Track instantiation calls; ranking must not trigger any, selection triggers only top-K."""
    calls = {"p1": 0, "p2": 0, "p3": 0}

    def _pb(pid, gain):
        pb = _always_on_playbook(pid, pid, gain)
        return pb

    reg = PlaybookRegistry()
    for pid, gain in [("p1", 3.0), ("p2", 2.0), ("p3", 1.0)]:
        reg.register(_pb(pid, gain))

    state = _state()
    # Wrap candidates to count instantiations
    raw = reg.to_candidates(state)
    counted = []
    for c in raw:
        pid = c.rationale.split("=")[1]
        def make_factory(c=c, pid=pid):
            def f():
                calls[pid] += 1
                return c.instantiate()
            return f
        counted.append(Candidate.deferred(
            source=c.source, kind=c.kind, gain=c.expected_information_gain,
            rationale=c.rationale, factory=make_factory()))

    ranked = GreedyPolicy().rank_candidates(counted)
    assert sum(calls.values()) == 0, "ranking must not instantiate anything"

    # select top 2
    for r in ranked[:2]:
        r.candidate.instantiate()
    assert calls["p1"] == 1 and calls["p2"] == 1
    assert calls["p3"] == 0, "unselected candidate must never instantiate"


def test_director_uses_lazy_selection(monkeypatch):
    """The director's _select_candidate_intents instantiates only top-K candidates."""
    from src.reasoning.director import ReconDirector
    from src.reasoning.scheduler import Scheduler
    from src.reasoning.strategy import StrategyManager
    from src.reasoning.budget import BudgetManager
    from src.reasoning.registry import StepContext

    # Build a director with a real scheduler (default policy) but no sensors.
    director = ReconDirector(
        scheduler=Scheduler(), strategy=StrategyManager(), budget=BudgetManager(),
        registry=[], has_ai_key=False)

    if not director._phase3_initialized:
        import pytest
        pytest.skip("phase3 not initialized in this environment")

    # Register three always-on playbooks; cap selection at 2.
    for pid, gain in [("a", 3.0), ("b", 2.0), ("c", 1.0)]:
        director._playbook_registry.register(_always_on_playbook(pid, pid, gain))
    director._max_selected_candidates = 2

    state = _state()
    events = []
    ctx = StepContext(state=state, target="ex.com:80", art={},
                      emit=lambda *a, **k: events.append((a, k)))

    intents = director._select_candidate_intents(state, ctx)
    # Two selected playbooks → two intents (one each)
    selected_events = [e for e in events if e[0][0] == "reasoning"
                       and e[0][1].get("event") == "candidate_selected"]
    assert len(selected_events) == 2
    assert len(intents) == 2
