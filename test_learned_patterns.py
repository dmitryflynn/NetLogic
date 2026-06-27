"""Learned patterns (Phase 5 revised §6): extract from provenance, validate, recall as
PriorityHints. The decisive guarantee is ISOLATION — history influences ordering only and never
mutates confidence, hypotheses, evidence, or beliefs."""
from src.reasoning.candidate import Candidate
from src.reasoning.decision_policy import DefaultDecisionPolicy, GreedyPolicy
from src.reasoning.inference import InferenceEngine
from src.reasoning.intent import Intent, ProbeCost
from src.reasoning.learned_patterns import (
    CandidatePattern,
    LearnedPattern,
    PatternExtractor,
    PatternRecall,
    PatternValidator,
    PriorityHint,
)
from src.reasoning.objective import Objective
from src.reasoning.provenance import ProvenanceBuilder
from src.reasoning.state import ReasoningState


def _confirmed_provenance():
    """Build a real provenance graph with a confirmed wordpress inference."""
    s = ReasoningState(target="ex.com", scope=["ex.com"])
    s.investigation.objectives.add(Objective(name="identify_framework:ex.com:80"))
    s.investigation.hypotheses.add_hypothesis(
        label="fw", likelihoods={"wordpress": 0.5, "spring_boot": 0.5},
        reason="identify_framework:ex.com:80")
    n = s.world.graph.upsert_node("service", "ex.com:80")
    s.world.graph.observe(n, kind="http_headers",
                          evidence="x-powered-by: wordpress wp-content/themes", source="phase3")
    steps = InferenceEngine().infer(s)
    return s, ProvenanceBuilder().build(s, steps).to_dict()


# ── Extraction ──

def test_extract_finds_confirmed_rule_pattern():
    _, prov = _confirmed_provenance()
    cands = PatternExtractor().extract(prov)
    assert cands, "expected at least one candidate pattern"
    assert any(c.rule == "wordpress" and c.confirmed for c in cands)


def test_extract_on_empty_provenance_is_empty():
    assert PatternExtractor().extract({"obs_inference": [], "inference_hypothesis": []}) == []


# ── Validation: raw counts, support thresholds ──

def test_validate_aggregates_raw_counts():
    cands = [CandidatePattern("wordpress", True), CandidatePattern("wordpress", True),
             CandidatePattern("wordpress", False)]
    patterns = PatternValidator(min_attempts=1, min_success_rate=0.0).validate(cands)
    lp = patterns["wordpress"]
    assert lp.attempts == 3 and lp.successes == 2
    assert abs(lp.success_rate() - 2 / 3) < 1e-9


def test_validate_filters_low_success_rate():
    cands = [CandidatePattern("flaky", False), CandidatePattern("flaky", False),
             CandidatePattern("flaky", True)]
    kept = PatternValidator(min_attempts=1, min_success_rate=0.5).validate(cands)
    assert "flaky" not in kept            # 1/3 < 0.5 → dropped


def test_validate_folds_into_existing():
    existing = {"wordpress": LearnedPattern("wordpress", successes=5, attempts=5)}
    cands = [CandidatePattern("wordpress", True)]
    kept = PatternValidator().validate(cands, existing=existing)
    assert kept["wordpress"].attempts == 6 and kept["wordpress"].successes == 6
    # existing dict not mutated in place
    assert existing["wordpress"].attempts == 5


# ── Recall → PriorityHint ──

def test_recall_emits_hint_per_pattern():
    patterns = {"wordpress": LearnedPattern("wordpress", successes=8, attempts=10)}
    hints = PatternRecall().hints(patterns)
    assert len(hints) == 1
    assert hints[0].tag == "wordpress"
    assert abs(hints[0].boost - 0.8) < 1e-9


# ── Influence is ordering-only ──

def test_hints_reorder_candidates_without_touching_gain():
    wp = Candidate.deferred(source="playbook", kind="WordPress Investigation",
                            factory=lambda: [Intent(goal="wp")], gain=1.0)
    generic = Candidate.deferred(source="generator", kind="Generic HTTP",
                                 factory=lambda: [Intent(goal="g")], gain=1.0)
    pool = [wp, generic]

    # Without hints: tie on gain → stable order by (source, kind): generator < playbook
    base = [r.candidate.kind for r in GreedyPolicy().rank_candidates(pool)]
    assert base == ["Generic HTTP", "WordPress Investigation"]

    # With a history hint favoring wordpress, WP jumps ahead — but gain is unchanged.
    hints = [PriorityHint(tag="wordpress", boost=5.0, reason="history")]
    boosted = GreedyPolicy().rank_candidates(pool, hints=hints)
    assert boosted[0].candidate.kind == "WordPress Investigation"
    assert boosted[0].candidate.expected_information_gain == 1.0   # gain untouched


# ── The hard isolation invariant ──

def test_learned_patterns_mutate_no_reasoning_state():
    s, prov = _confirmed_provenance()
    s.world.beliefs = {"wordpress": 0.5}

    before_beliefs = dict(s.world.beliefs)
    before_belief_records = [dict(b) for b in s.world.belief_records]
    before_status = {h.id: h.status for h in s.investigation.hypotheses.all()}
    before_likelihoods = {h.id: dict(h.likelihoods) for h in s.investigation.hypotheses.all()}
    before_obs = sorted(o.obs_id for node in s.world.graph.nodes() for o in node.observations())

    # Full pipeline: extract → validate → recall
    cands = PatternExtractor().extract(prov)
    patterns = PatternValidator().validate(cands)
    hints = PatternRecall().hints(patterns)
    # Apply hints through ranking too (the only consumer)
    DefaultDecisionPolicy().rank_candidates(
        [Candidate.deferred(source="playbook", kind="wordpress",
                            factory=lambda: [], gain=1.0)], hints=hints)

    # Nothing in the truth model changed.
    assert s.world.beliefs == before_beliefs
    assert [dict(b) for b in s.world.belief_records] == before_belief_records
    assert {h.id: h.status for h in s.investigation.hypotheses.all()} == before_status
    assert {h.id: dict(h.likelihoods) for h in s.investigation.hypotheses.all()} == before_likelihoods
    assert sorted(o.obs_id for node in s.world.graph.nodes()
                  for o in node.observations()) == before_obs


def test_learned_pattern_round_trip():
    lp = LearnedPattern("wordpress", successes=3, attempts=4)
    assert LearnedPattern.from_dict(lp.to_dict()) == lp
