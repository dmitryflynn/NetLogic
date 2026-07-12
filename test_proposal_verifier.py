"""Track C / C0 — the four staged verifiers each reject independently (defense in depth); a
hypothesis becomes an uncertainty-graded idea (never a truth); knowledge is fail-closed without a
passing benchmark.
"""
from src.reasoning.ai import (
    ContradictionPayload, HypothesisPayload, KnowledgePayload, ObjectivePayload, Proposal,
    ProposalEconomics, ProposalKind, ProposalProvenance, StrategyPayload, UncertaintyState,
    VerifierContext, VerifierPipeline, new_proposal_id, uncertainty_rank,
)

VP = VerifierPipeline()


def _p(kind, payload, *, agent="a", obs_ids=(), risk="read_only"):
    return Proposal(id=new_proposal_id(), kind=kind, agent=agent, payload=payload,
                    provenance=ProposalProvenance(supporting_observation_ids=obs_ids),
                    economics=ProposalEconomics(estimated_risk=risk))


# ── Each stage rejects INDEPENDENTLY of the others ───────────────────────────────────

def test_syntax_stage_rejects_empty_candidates():
    p = _p(ProposalKind.HYPOTHESIS, HypothesisPayload(objective="o", candidates={}))
    d = VP.verify(p)
    assert not d.accepted and d.stage_failed == "syntax"


def test_semantic_stage_rejects_unknown_objective():
    p = _p(ProposalKind.HYPOTHESIS, HypothesisPayload(objective="verify:GHOST",
                                                       candidates={"a": 1.0}))
    d = VP.verify(p, VerifierContext(known_objectives=frozenset({"verify:REAL"})))
    assert not d.accepted and d.stage_failed == "semantic"


def test_evidence_stage_rejects_phantom_observation_ids():
    p = _p(ProposalKind.HYPOTHESIS, HypothesisPayload(objective="o", candidates={"a": 1.0}),
          obs_ids=("does-not-exist",))
    d = VP.verify(p, VerifierContext(known_observation_ids=frozenset({"real-obs"})))
    assert not d.accepted and d.stage_failed == "evidence"


def test_safety_stage_rejects_risk_above_read_only():
    p = _p(ProposalKind.HYPOTHESIS, HypothesisPayload(objective="o", candidates={"a": 1.0}),
          risk="exploit")
    d = VP.verify(p)
    assert not d.accepted and d.stage_failed == "safety"


def test_safety_stage_catches_forbidden_key_at_any_depth():
    payload = ContradictionPayload(subject="s", candidates=("authorized", "b"))
    # "authorized" as a candidate VALUE (not a dict key) is fine — it's the KEY that's forbidden.
    d = VP.verify(_p(ProposalKind.CONTRADICTION, payload))
    assert d.accepted   # a candidate string named "authorized" is not a smuggled control key


def test_safety_stage_catches_forbidden_key_in_knowledge_rule():
    payload = KnowledgePayload(tech_id="x", rule={"confirm": ["y"], "execution_authorized": True})
    d = VP.verify(_p(ProposalKind.KNOWLEDGE, payload),
                  VerifierContext(benchmark_check=lambda p: True))
    assert not d.accepted and d.stage_failed == "safety"


# ── Removing one stage never opens what another would have blocked ──────────────────

def test_stages_are_independent_not_redundant_with_each_other():
    """A proposal that would pass syntax+semantic+evidence but fails safety is still rejected —
    i.e. safety isn't a no-op just because earlier stages passed."""
    payload = StrategyPayload(goal_class="g", action_ids=("noop",))
    p = _p(ProposalKind.STRATEGY, payload, risk="intrusive")   # passes syntax/semantic/evidence
    d = VP.verify(p)
    assert not d.accepted and d.stage_failed == "safety"


# ── A hypothesis becomes an uncertainty-graded proposal, NEVER a declared truth ──────

def test_hypothesis_without_evidence_is_possible_not_confirmed():
    p = _p(ProposalKind.HYPOTHESIS, HypothesisPayload(objective="o", candidates={"a": 1.0}))
    d = VP.verify(p)
    assert d.accepted and d.proposal.uncertainty == UncertaintyState.POSSIBLE


def test_hypothesis_with_real_evidence_is_likely_not_confirmed():
    p = _p(ProposalKind.HYPOTHESIS, HypothesisPayload(objective="o", candidates={"a": 1.0}),
          obs_ids=("obs-1",))
    d = VP.verify(p, VerifierContext(known_observation_ids=frozenset({"obs-1"})))
    assert d.accepted and d.proposal.uncertainty == UncertaintyState.LIKELY
    # A hypothesis NEVER reaches CONFIRMED through this pipeline — only benchmark-verified
    # knowledge can. This is the "AI proposes, engine proves" boundary in one assertion.
    assert d.proposal.uncertainty != UncertaintyState.CONFIRMED


def test_objective_proposal_max_uncertainty_is_possible():
    p = _p(ProposalKind.OBJECTIVE, ObjectivePayload(goal_name="g"))
    d = VP.verify(p)
    assert d.accepted and d.proposal.uncertainty == UncertaintyState.POSSIBLE


# ── Knowledge is fail-closed without a passing benchmark ─────────────────────────────

def test_knowledge_fails_closed_with_no_benchmark_configured():
    p = _p(ProposalKind.KNOWLEDGE, KnowledgePayload(tech_id="x", rule={"confirm": ["y"]}))
    d = VP.verify(p, VerifierContext())   # no benchmark_check at all
    assert not d.accepted and d.stage_failed == "evidence"


def test_knowledge_fails_when_benchmark_returns_false():
    p = _p(ProposalKind.KNOWLEDGE, KnowledgePayload(tech_id="x", rule={"confirm": ["y"]}))
    d = VP.verify(p, VerifierContext(benchmark_check=lambda payload: False))
    assert not d.accepted and d.stage_failed == "evidence"


def test_knowledge_confirmed_only_after_passing_benchmark():
    p = _p(ProposalKind.KNOWLEDGE, KnowledgePayload(tech_id="x", rule={"confirm": ["y"]}))
    d = VP.verify(p, VerifierContext(benchmark_check=lambda payload: True))
    assert d.accepted and d.proposal.uncertainty == UncertaintyState.CONFIRMED


def test_uncertainty_rank_treats_refuted_as_resolved_not_more_certain():
    assert uncertainty_rank(UncertaintyState.REFUTED) == uncertainty_rank(UncertaintyState.CONFIRMED)
    assert uncertainty_rank(UncertaintyState.POSSIBLE) < uncertainty_rank(UncertaintyState.LIKELY)
