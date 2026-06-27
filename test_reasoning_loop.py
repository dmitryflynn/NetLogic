"""Phase 2: BudgetManager, Scheduler, StrategyManager, and the ReconDirector loop.

Uses synthetic SensorSteps so the loop machinery is tested without network or AI.
"""
from src.reasoning import (BudgetManager, ReconDirector, ReasoningState, Scheduler,
                           SensorStep, StepContext, StrategyManager)


def _contested_state():
    """A state with one unresolved high-impact, version-only belief (the loop's trigger case).
    reasoning_enabled is on — activation is governed by that opt-in, not the AI key."""
    s = ReasoningState(target="ex.com", scope=["ex.com"], reasoning_enabled=True)
    s.world.belief_records = [{"claim": "cve-2021-40438", "node_id": "cve:cve-2021-40438",
                               "confidence": 0.5, "impact": "critical",
                               "rule_applied": "version_matched_cap", "supporting": ["nvd"],
                               "version_only": True}]
    s.world.beliefs = {"cve-2021-40438": 0.5}
    return s


def _fake_executor(spec):
    """Offline executor for unit tests — never touches the network."""
    from src.reasoning.trace import ExecutionResult
    return ExecutionResult(success=False, error="offline test executor")


# ── BudgetManager ────────────────────────────────────────────────────────────────
def test_budget_probe_ceiling_exhausts():
    b = BudgetManager(max_probes=2, max_tokens=10_000, max_wall_clock_s=1000, max_recursion=10)
    assert not b.exhausted()
    b.spend({"probes": 1}); b.spend({"probes": 1})
    assert b.exhausted()


def test_budget_can_afford_tokens():
    b = BudgetManager(max_tokens=100, max_probes=10, max_wall_clock_s=1000, max_recursion=10)
    assert b.can_afford({"tokens": 50})
    assert not b.can_afford({"tokens": 200})


# ── StrategyManager ──────────────────────────────────────────────────────────────
def test_should_activate_requires_reasoning_optin_and_work():
    b, sm = BudgetManager.for_tier("hosted"), StrategyManager()
    s = _contested_state()                                   # reasoning_enabled=True
    assert sm.should_activate(s, has_ai_key=False, budget=b)     # deterministic — no AI needed
    s_off = _contested_state(); s_off.reasoning_enabled = False
    assert not sm.should_activate(s_off, has_ai_key=True, budget=b)   # opt-in off → never
    empty = ReasoningState(reasoning_enabled=True)
    assert not sm.should_activate(empty, has_ai_key=True, budget=b)   # opted in but no work


def test_select_persona_targets_version_only_verification():
    assert StrategyManager().select_persona(_contested_state()) == "cve_verification"


def test_should_stop_on_budget_exhaustion():
    b = BudgetManager(max_probes=0, max_tokens=1, max_wall_clock_s=1000, max_recursion=10)
    stop, reason = StrategyManager().should_stop(_contested_state(), budget=b,
                                                 best_priority=5.0, no_gain_streak=0)
    assert stop and "budget" in reason


# ── Scheduler ────────────────────────────────────────────────────────────────────
def test_scheduler_prefers_persona_matched_resolving_step():
    s = _contested_state(); s.investigation.persona = "cve_verification"
    ctx = StepContext("ex.com", s, {}, lambda *a, **k: None)
    matching = SensorStep("cve_verification", "cve_verification", run=lambda c: [],
                          resolves=("version_only",), cost={"probes": 1})
    other = SensorStep("headers", "misconfiguration_discovery", run=lambda c: [], cost={"probes": 1})
    chosen = Scheduler(explore_reserve=0.0).select([other, matching], ctx)
    assert chosen.step.name == "cve_verification"


def test_scheduler_skips_seen_steps():
    s = _contested_state()
    ctx = StepContext("ex.com", s, {}, lambda *a, **k: None)
    step = SensorStep("cve_verification", "cve_verification", run=lambda c: [], cost={"probes": 1})
    assert Scheduler().select([step], ctx, seen={"cve_verification"}) is None


# ── ReconDirector loop ───────────────────────────────────────────────────────────
def test_loop_runs_resolves_and_terminates():
    s = _contested_state()
    ran = {"n": 0}

    def run(ctx):
        ran["n"] += 1
        return [{"node_kind": "cve", "node_key": "cve-2021-40438", "kind": "verifier",
                 "evidence": "probe confirmed", "source": "verifier"}]

    def refresh(st, art):   # simulate the verifier upgrading the belief
        st.world.belief_records = [{**st.world.belief_records[0], "confidence": 0.97,
                                    "version_only": False, "rule_applied": "probe_confirmed"}]

    step = SensorStep("cve_verification", "cve_verification", run=run,
                      resolves=("version_only", "cve"), cost={"time_ms": 100, "tokens": 10, "probes": 1})
    persisted = {}
    director = ReconDirector(Scheduler(), StrategyManager(), BudgetManager.for_tier("local"),
                             [step], has_ai_key=True, refresh=refresh, executor=_fake_executor,
                             persist=lambda st: persisted.update(done=True))
    events = []
    director.run(StepContext("ex.com", s, {}, lambda t, d=None: events.append((t, d))))

    assert ran["n"] == 1                                          # ran once, didn't repeat
    assert s.world.belief_records[0]["confidence"] >= 0.95        # belief resolved
    assert any(h["step"] == "cve_verification" for h in s.execution.execution_history)
    assert s.execution.budget["probes_run"] == 1                 # budget tracked
    assert persisted.get("done")                                 # persisted at boundary
    assert any(t == "reasoning" for t, _ in events)              # additive events emitted


def test_loop_is_noop_without_trigger():
    # reasoning_enabled on but nothing contested → loop never engages, emits nothing.
    events = []
    director = ReconDirector(Scheduler(), StrategyManager(), BudgetManager.for_tier("hosted"),
                             [], has_ai_key=True, executor=_fake_executor)
    director.run(StepContext("ex.com", ReasoningState(reasoning_enabled=True), {},
                             lambda t, d=None: events.append(t)))
    assert events == []


def test_loop_is_noop_when_reasoning_disabled():
    # reasoning_enabled OFF (default) → loop never engages even with contested work + AI.
    events = []
    s = _contested_state(); s.reasoning_enabled = False
    director = ReconDirector(Scheduler(), StrategyManager(), BudgetManager.for_tier("hosted"),
                             [], has_ai_key=True, executor=_fake_executor)
    director.run(StepContext("ex.com", s, {}, lambda t, d=None: events.append(t)))
    assert events == []


def test_loop_runs_deterministically_without_ai_key():
    # reasoning_enabled on, no AI key → the deterministic loop still engages.
    events = []
    director = ReconDirector(Scheduler(), StrategyManager(), BudgetManager.for_tier("hosted"),
                             [], has_ai_key=False, executor=_fake_executor)
    director.run(StepContext("ex.com", _contested_state(), {}, lambda t, d=None: events.append(t)))
    assert any(t == "reasoning" for t in events)
