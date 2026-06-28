"""Performance invariants (Phase 5 consolidation).

Algorithmic-property / operation-count guards — NOT wall-clock timings (which flake). They catch
the regressions that matter as NetLogic grows: accidental O(N^2) ranking, eager instantiation
sneaking back, or provenance growing unbounded relative to the evidence it describes.
"""
from src.reasoning.candidate import Candidate
from src.reasoning.decision_policy import GreedyPolicy
from src.reasoning.inference import InferenceEngine
from src.reasoning.intent import Intent
from src.reasoning.objective import Objective
from src.reasoning.playbooks import Playbook, PlaybookRegistry
from src.reasoning.probe_plan import Condition, ConditionOp
from src.reasoning.intent import StopCondition
from src.reasoning.provenance import ProvenanceBuilder
from src.reasoning.state import ReasoningState


# ── Ranking is linear in the candidate count ──

def test_ranking_scores_each_candidate_exactly_once():
    """O(N) scoring: _score_candidate is called exactly N times for N candidates — never N^2."""
    calls = {"n": 0}

    class CountingPolicy(GreedyPolicy):
        def _score_candidate(self, candidate):
            calls["n"] += 1
            return super()._score_candidate(candidate)

    pool = [Candidate.deferred(source="s", kind=f"k{i}", factory=lambda: [], gain=float(i))
            for i in range(50)]
    CountingPolicy().rank_candidates(pool)
    assert calls["n"] == 50, f"expected 50 score calls (linear), got {calls['n']}"


def test_ranking_never_instantiates():
    """Operation-count guard: ranking builds zero Intents (the lazy boundary holds)."""
    inst = {"n": 0}

    def factory():
        inst["n"] += 1
        return [Intent(goal="x")]

    pool = [Candidate.deferred(source="s", kind=f"k{i}", factory=factory, gain=float(i))
            for i in range(20)]
    GreedyPolicy().rank_candidates(pool)
    assert inst["n"] == 0, "ranking must not instantiate any candidate"


# ── Playbook matching does not instantiate unused playbooks ──

def test_playbook_matching_does_not_instantiate():
    inst = {"n": 0}

    class CountingPlaybook(Playbook):
        pass

    reg = PlaybookRegistry()
    for i in range(10):
        reg.register(Playbook(
            id=f"p{i}", name=f"P{i}", trigger_rule=Condition(op=ConditionOp.TRUST),
            intent_template=Intent(goal=f"g{i}"), default_stopping_condition=StopCondition()))

    state = ReasoningState(target="ex.com:80", scope=["ex.com:80"])

    # Wrap each emitted candidate's factory with a counter, then only MATCH/rank — never select.
    candidates = reg.to_candidates(state)
    counted = [Candidate.deferred(
        source=c.source, kind=c.kind, gain=c.expected_information_gain,
        factory=lambda c=c: (inst.__setitem__("n", inst["n"] + 1) or c.instantiate()))
        for c in candidates]
    GreedyPolicy().rank_candidates(counted)
    assert inst["n"] == 0, "matching/ranking 10 playbooks instantiated some — eager regression"


# ── Provenance growth is bounded by the evidence it describes ──

def test_provenance_edges_bounded_by_observations():
    """inference_hypothesis edges == #inference steps; obs_inference edges <=
    #observations * #inference steps. Provenance can't grow super-linearly in evidence."""
    s = ReasoningState(target="ex.com", scope=["ex.com"])
    s.investigation.objectives.add(Objective(name="identify_framework:ex.com:80"))
    s.investigation.hypotheses.add_hypothesis(
        label="fw", likelihoods={"wordpress": 0.5, "spring_boot": 0.5},
        reason="identify_framework:ex.com:80")
    n = s.world.graph.upsert_node("service", "ex.com:80")
    # several observations, one of which confirms wordpress
    for ev in ["wp-content", "wp-json", "x-powered-by: wordpress", "noise-1", "noise-2"]:
        s.world.graph.observe(n, kind="http_headers", evidence=ev, source="phase3")

    steps = InferenceEngine().infer(s)
    graph = ProvenanceBuilder().build(s, steps)

    num_obs = sum(1 for node in s.world.graph.nodes() for _ in node.observations())
    num_steps = len(steps)
    assert len(graph.inference_hypothesis) == num_steps
    assert len(graph.obs_inference) <= num_obs * max(1, num_steps)


def test_provenance_empty_when_no_inference():
    s = ReasoningState(target="ex.com", scope=["ex.com"])
    n = s.world.graph.upsert_node("service", "ex.com:80")
    for ev in ["nothing", "interesting", "here"]:
        s.world.graph.observe(n, kind="http_headers", evidence=ev, source="phase3")
    graph = ProvenanceBuilder().build(s, [])
    assert len(graph.obs_inference) == 0 and len(graph.inference_hypothesis) == 0
