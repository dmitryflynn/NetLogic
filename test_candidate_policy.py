"""Candidate interface + DecisionPolicy over candidates (Phase 5 revised, §2).

The decisive test gate the review demanded: deterministic ordering, tie-breaking, weight
sensitivity, budget dominance, genuinely-different policies, lazy instantiation, prerequisite
gating, custom-policy injection, and equivalence of the SensorStep path with the legacy formula.
"""
import pytest

from src.reasoning.candidate import Candidate, RankedCandidate
from src.reasoning.decision_policy import (
    BudgetPolicy,
    DefaultDecisionPolicy,
    FastPolicy,
    GreedyPolicy,
)
from src.reasoning.intent import Intent, ProbeCost


def _cand(source, kind, gain, time_ms=1000, probes=1, prereqs=()):
    return Candidate.deferred(
        source=source, kind=kind, gain=gain,
        cost=ProbeCost(time_ms=time_ms, probes=probes),
        prerequisites=prereqs,
        factory=lambda: [Intent(goal=kind)],
    )


# ── Candidate: the lazy boundary ──

def test_instantiate_is_lazy_not_called_until_selected():
    calls = {"n": 0}
    def factory():
        calls["n"] += 1
        return [Intent(goal="x")]
    c = Candidate.deferred(source="playbook", kind="wp", factory=factory, gain=5.0)

    # Building + ranking must not instantiate.
    GreedyPolicy().rank_candidates([c])
    assert calls["n"] == 0, "ranking must not call instantiate()"

    intents = c.instantiate()
    assert calls["n"] == 1
    assert intents and intents[0].goal == "x"


def test_from_intent_wraps_ready_intent():
    intent = Intent(goal="resolve cms", rationale="because")
    c = Candidate.from_intent(intent, source="generator", gain=2.0)
    assert c.source == "generator"
    assert c.instantiate() == [intent]


def test_candidate_equality_ignores_factory():
    a = Candidate.deferred(source="s", kind="k", factory=lambda: [], gain=1.0)
    b = Candidate.deferred(source="s", kind="k", factory=lambda: [Intent(goal="z")], gain=1.0)
    assert a == b, "candidates compare by rankable metadata, not factory identity"


# ── Ranking: determinism + tie-breaking ──

def test_ranking_is_deterministic():
    pool = [_cand("generator", "a", 1.0), _cand("playbook", "b", 3.0),
            _cand("capability", "c", 2.0)]
    p = GreedyPolicy()
    r1 = [r.candidate.kind for r in p.rank_candidates(pool)]
    r2 = [r.candidate.kind for r in p.rank_candidates(list(reversed(pool)))]
    assert r1 == r2 == ["b", "c", "a"]   # gain-sorted, independent of input order


def test_tie_break_is_stable_by_source_then_kind():
    # identical gain + cost → tie; resolved by (source, kind)
    pool = [_cand("playbook", "z", 1.0), _cand("capability", "a", 1.0),
            _cand("capability", "b", 1.0)]
    ranked = GreedyPolicy().rank_candidates(pool)
    assert [(r.candidate.source, r.candidate.kind) for r in ranked] == [
        ("capability", "a"), ("capability", "b"), ("playbook", "z")]


# ── Genuinely different policies (review point #2) ──

def test_policies_produce_different_orderings():
    high_gain_slow = _cand("playbook", "hg_slow", gain=10.0, time_ms=8000, probes=5)
    low_gain_fast = _cand("generator", "lg_fast", gain=1.0, time_ms=100, probes=1)
    pool = [high_gain_slow, low_gain_fast]

    greedy = [r.candidate.kind for r in GreedyPolicy().rank_candidates(pool)]
    fast = [r.candidate.kind for r in FastPolicy().rank_candidates(pool)]
    budget = [r.candidate.kind for r in BudgetPolicy().rank_candidates(pool)]

    assert greedy[0] == "hg_slow"     # greedy chases gain
    assert fast[0] == "lg_fast"       # fast chases low latency
    # budget = gain/cost: hg=10/~14≈0.7, lg=1/1=1.0 → lg wins
    assert budget[0] == "lg_fast"


def test_budget_dominance():
    # equal gain, very different cost → cheaper wins under BudgetPolicy
    cheap = _cand("a", "cheap", gain=5.0, time_ms=100, probes=1)
    pricey = _cand("a", "pricey", gain=5.0, time_ms=9000, probes=9)
    ranked = BudgetPolicy().rank_candidates([pricey, cheap])
    assert ranked[0].candidate.kind == "cheap"


# ── Weight sensitivity ──

def test_default_weight_sensitivity():
    hg_hc = _cand("p", "hg_hc", gain=10.0, time_ms=5000, probes=5)
    lg_lc = _cand("p", "lg_lc", gain=1.0, time_ms=100, probes=1)
    pool = [hg_hc, lg_lc]

    gain_heavy = DefaultDecisionPolicy(info_gain_weight=100.0, budget_weight=0.1)
    cost_heavy = DefaultDecisionPolicy(info_gain_weight=0.1, budget_weight=100.0)

    assert gain_heavy.rank_candidates(pool)[0].candidate.kind == "hg_hc"
    # cost_heavy still divides by the same cost, but gain weight is tiny → gain/cost favors lg_lc
    assert cost_heavy.rank_candidates(pool)[0].candidate.kind == "lg_lc"


# ── Prerequisite gating ──

def test_prerequisites_gate_candidates():
    needs_cms = _cand("capability", "exploit", gain=9.0, prereqs=("cms_resolved",))
    free = _cand("generator", "recon", gain=1.0)
    pool = [needs_cms, free]

    # prereq unmet → exploit dropped
    ranked = GreedyPolicy().rank_candidates(pool, satisfied=set())
    assert [r.candidate.kind for r in ranked] == ["recon"]

    # prereq met → exploit included and wins on gain
    ranked2 = GreedyPolicy().rank_candidates(pool, satisfied={"cms_resolved"})
    assert ranked2[0].candidate.kind == "exploit"


def test_prereq_gating_can_be_disabled():
    needs = _cand("capability", "x", gain=9.0, prereqs=("missing",))
    ranked = GreedyPolicy().rank_candidates([needs], exclude_unmet_prereqs=False)
    assert len(ranked) == 1


# ── Custom-policy injection ──

def test_custom_policy_injection():
    class AlphabeticalPolicy(DefaultDecisionPolicy):
        def _score_candidate(self, candidate):
            # earlier kind alphabetically → higher score
            return -float(ord(candidate.kind[0]))

    pool = [_cand("s", "zebra", 1.0), _cand("s", "apple", 1.0), _cand("s", "mango", 1.0)]
    ranked = AlphabeticalPolicy().rank_candidates(pool)
    assert [r.candidate.kind for r in ranked] == ["apple", "mango", "zebra"]


def test_empty_pool_yields_empty_ranking():
    assert GreedyPolicy().rank_candidates([]) == []


# ── Equivalence: the SensorStep path is unchanged by the refactor ──

def test_sensorstep_path_matches_legacy_formula():
    """DefaultDecisionPolicy.rank_actions must reproduce the legacy Scheduler ordering."""
    from src.reasoning.registry import SensorStep, StepContext
    from src.reasoning.state import ReasoningState

    state = ReasoningState(target="ex.com:443", scope=["ex.com:443"])
    state.world.belief_records = [
        {"claim": "cve-2021-1", "kind": "cve", "impact": "high", "confidence": 0.3},
    ]

    def _emit(*a, **k):
        pass
    ctx = StepContext(state=state, target="ex.com:443", art={}, emit=_emit)

    steps = [
        SensorStep(name="cheap_high", persona="service_discovery", run=lambda c: None,
                   base_gain=2.0, resolves=("cve",),
                   cost={"time_ms": 500, "tokens": 0, "probes": 1}),
        SensorStep(name="expensive_low", persona="service_discovery", run=lambda c: None,
                   base_gain=1.0, resolves=(),
                   cost={"time_ms": 5000, "tokens": 0, "probes": 3}),
    ]

    ranked = DefaultDecisionPolicy().rank_actions(steps, ctx)
    # cheap, high-gain, resolves a contested CVE → must outrank the expensive one
    assert ranked[0].step.name == "cheap_high"
    assert ranked[0].priority > ranked[1].priority
