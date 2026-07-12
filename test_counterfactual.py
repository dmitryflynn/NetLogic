"""Track C / C11 — Counterfactual Reasoner: turns leading hypotheses into read-only refutation
objectives; only counters sufficiently-leading hypotheses; broken AI contributes nothing."""
import json

from src.reasoning.ai import AICoordinator, CounterfactualReasoner, ProposalKind, VerifierContext
from src.reasoning.state import ReasoningState


def _state_with_hypothesis(likelihoods):
    s = ReasoningState(target="ex.com:80", scope=["ex.com"])
    s.investigation.hypotheses.add_hypothesis(label="framework_of:ex.com:80", created_by="rule",
                                              likelihoods=likelihoods)
    return s


def _cassette(items):
    def _complete(system, user):
        return json.dumps(items)
    return _complete


def test_generates_refutation_objectives_for_leading_hypothesis():
    s = _state_with_hypothesis({"wordpress": 0.7, "django": 0.3})
    agent = CounterfactualReasoner(_cassette([
        {"refutes": "wordpress", "check": "no_wp_json", "information_gain": 3.0},
        {"refutes": "wordpress", "check": "no_wp_content", "information_gain": 2.0},
    ]))
    tasks = agent.generate(s)
    assert len(tasks) == 2
    assert all(t.kind == ProposalKind.OBJECTIVE for t in tasks)
    accepted = AICoordinator().run(tasks, ctx=VerifierContext())
    names = {d.proposal.payload.goal_name for d in accepted}
    assert "refute:wordpress:no_wp_json" in names
    assert "refute:wordpress:no_wp_content" in names


def test_refutation_objectives_are_read_only():
    s = _state_with_hypothesis({"wordpress": 0.9, "other": 0.1})
    agent = CounterfactualReasoner(_cassette([{"refutes": "wordpress", "check": "no_rest_api"}]))
    accepted = AICoordinator().run(agent.generate(s), ctx=VerifierContext())
    assert accepted and all(d.proposal.payload.risk_budget == "read_only" for d in accepted)


def test_ignores_hypotheses_with_no_clear_leader():
    # A flat 3-way split: no candidate clears the leading threshold, so nothing to refute.
    s = _state_with_hypothesis({"a": 0.34, "b": 0.33, "c": 0.33})
    agent = CounterfactualReasoner(_cassette([{"refutes": "a", "check": "x"}]))
    assert agent.generate(s) == []


def test_no_hypotheses_means_no_tasks():
    s = ReasoningState(target="ex.com:80", scope=["ex.com"])
    agent = CounterfactualReasoner(_cassette([{"refutes": "x", "check": "y"}]))
    assert agent.generate(s) == []


def test_broken_ai_produces_no_tasks():
    s = _state_with_hypothesis({"wordpress": 0.8, "other": 0.2})

    def _boom(system, user):
        raise RuntimeError("down")

    assert CounterfactualReasoner(_boom).generate(s) == []
    assert CounterfactualReasoner(lambda sy, u: "garbage").generate(s) == []
    assert CounterfactualReasoner(lambda sy, u: json.dumps({"not": "list"})).generate(s) == []


def test_counterfactual_is_grounded_in_observed_evidence_not_hallucinated():
    """Regression for the live Hitachi hallucination: C11 must hand the LLM the ACTUAL observed
    technologies/CVEs so it reasons about the real stack (IIS), and its prompt must forbid inventing
    products that aren't present."""
    s = ReasoningState(target="31.11.35.143:80", scope=["31.11.35.143"])
    s.world.technology = ["Microsoft IIS 10.0", "ASP.NET"]
    tn = s.world.graph.upsert_node("technology", "microsoft iis", label="microsoft iis")
    s.world.graph.observe(tn, kind="tech", evidence="tech: Microsoft IIS 10.0", source="stack")
    cn = s.world.graph.upsert_node("cve", "cve-2021-31166", label="CVE-2021-31166")
    s.world.graph.observe(cn, kind="vuln", evidence="iis 10.0: IIS HTTP.sys UAF RCE", source="nvd")
    s.investigation.hypotheses.add_hypothesis(
        label="exploitability_of:verify:CVE-2021-31166", created_by="rule",
        likelihoods={"exploitable": 0.35, "not_exploitable": 0.65})

    seen = {}
    def spy(system, user):
        seen["system"], seen["user"] = system, user
        return json.dumps([{"refutes": "not_exploitable", "check": "iis_version_range"}])

    CounterfactualReasoner(spy).generate(s)
    assert "microsoft iis" in seen["user"].lower()        # the real stack is in the prompt
    assert "HTTP.sys" in seen["user"]                     # the CVE description is too
    assert "invent" in seen["system"].lower()             # prompt forbids inventing technologies
