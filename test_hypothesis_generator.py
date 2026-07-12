"""Track C / C1 — Hypothesis Generator: produces testable hypotheses through the C0 pipeline,
including novel-vulnerability leaps; fabricated deterministic objectives are rejected; broken AI
contributes nothing."""
import json

from src.reasoning.ai import AICoordinator, HypothesisGenerator, ProposalKind, VerifierContext
from src.reasoning.objective import Objective
from src.reasoning.state import ReasoningState


def _state():
    s = ReasoningState(target="ex.com:80", scope=["ex.com"])
    s.world.graph.upsert_node("service", "ex.com:80", label="ex.com:80")
    s.world.technology = ["nginx"]
    s.investigation.objectives.add(Objective(name="identify_framework:ex.com:80"))
    s.investigation.contradictions = [{"subject": "ex.com:80", "reason": "nginx + ASP.NET cookie"}]
    return s


def _cassette(items):
    def _complete(system, user):
        return json.dumps(items)
    return _complete


def test_generates_framework_and_novel_hypotheses():
    s = _state()
    gen = HypothesisGenerator(_cassette([
        {"objective": "identify_framework:ex.com:80", "candidates": {"wordpress": 0.7, "static": 0.3},
         "novel": False, "rationale": "wp-content", "information_gain": 2.5, "prob_correct": 0.7},
        {"objective": "novel:cache_poisoning", "candidates": {"vulnerable": 0.4, "safe": 0.6},
         "novel": True, "rationale": "cache mismatch", "information_gain": 4.0, "prob_correct": 0.5},
    ]))
    tasks = gen.generate(s)
    assert len(tasks) == 2
    coordinator = AICoordinator()
    accepted = coordinator.run(tasks, ctx=VerifierContext(
        known_objectives=frozenset({"identify_framework:ex.com:80"})))
    objectives = {d.proposal.payload.objective for d in accepted}
    assert "identify_framework:ex.com:80" in objectives
    assert "novel:cache_poisoning" in objectives   # a novel slug is allowed to introduce inquiry
    novel = [d for d in accepted if d.proposal.payload.novel]
    assert len(novel) == 1


def test_fresh_hypotheses_are_possible_not_evidence_backed():
    s = _state()
    gen = HypothesisGenerator(_cassette([
        {"objective": "novel:request_smuggling", "candidates": {"a": 0.5, "b": 0.5}, "novel": True},
    ]))
    accepted = AICoordinator().run(gen.generate(s), ctx=VerifierContext())
    assert len(accepted) == 1
    # A generated hypothesis is a proposal to investigate, not a conclusion.
    assert accepted[0].proposal.uncertainty.value == "possible"
    assert accepted[0].proposal.provenance.supporting_observation_ids == ()


def test_fabricated_deterministic_objective_is_rejected():
    s = _state()
    gen = HypothesisGenerator(_cassette([
        {"objective": "verify:CVE-DOES-NOT-EXIST", "candidates": {"a": 1.0}, "novel": False},
    ]))
    coordinator = AICoordinator()
    accepted = coordinator.run(gen.generate(s),
                               ctx=VerifierContext(known_objectives=frozenset({"verify:CVE-REAL"})))
    assert accepted == []
    rejected = coordinator.store.rejected()
    assert len(rejected) == 1 and rejected[0].stage_failed == "semantic"


def test_broken_ai_produces_no_tasks():
    s = _state()

    def _boom(system, user):
        raise RuntimeError("model down")

    assert HypothesisGenerator(_boom).generate(s) == []
    assert HypothesisGenerator(lambda sy, u: "not json").generate(s) == []
    assert HypothesisGenerator(lambda sy, u: "").generate(s) == []
    assert HypothesisGenerator(lambda sy, u: json.dumps({"not": "a list"})).generate(s) == []


def test_malformed_items_are_skipped_not_fatal():
    s = _state()
    gen = HypothesisGenerator(_cassette([
        {"objective": "novel:x", "candidates": {"a": 1.0}},   # good
        "not a dict",                                          # skipped
        {"candidates": {"a": 1.0}},                            # no objective -> skipped by agent
        {"objective": "novel:y"},                             # no candidates -> skipped by agent
    ]))
    tasks = gen.generate(s)
    assert len(tasks) == 1
    assert tasks[0].kind == ProposalKind.HYPOTHESIS


def test_novel_hypothesis_cannot_smuggle_risk():
    """Even if the LLM tries to attach elevated risk, the pipeline forces read_only."""
    s = _state()

    def _complete(system, user):
        return json.dumps([{"objective": "novel:x", "candidates": {"a": 1.0},
                            "economics": {"estimated_risk": "exploit"}}])

    accepted = AICoordinator().run(HypothesisGenerator(_complete).generate(s), ctx=VerifierContext())
    assert all(d.proposal.economics.estimated_risk == "read_only" for d in accepted)
