"""Track C / C2 — Investigation Designer: turns an AI-invented objective into an investigable one by
attaching gatherable evidence; the AI can only request evidence from a fixed read-only vocabulary."""
import json

from src.reasoning.ai import AICoordinator, InvestigationDesigner, ProposalKind, VerifierContext
from src.reasoning.objective import Objective
from src.reasoning.state import ReasoningState


def _state_with(*names):
    s = ReasoningState(target="ex.com:80", scope=["ex.com"])
    for n in names:
        s.investigation.objectives.add(Objective(name=n))
    return s


def _cassette(obj):
    def _complete(system, user):
        return json.dumps(obj)
    return _complete


def test_designs_evidence_only_for_ai_objectives():
    s = _state_with("novel:cache_poisoning", "identify_framework:ex.com:80")
    agent = InvestigationDesigner(_cassette(
        {"required_evidence": ["http_headers", "http_body"], "information_gain": 3.0}))
    tasks = agent.generate(s)
    # Only the AI-owned objective (novel:) is targeted; the deterministic one already has a mapping.
    assert len(tasks) == 1
    assert tasks[0].kind == ProposalKind.OBJECTIVE
    assert tasks[0].raw["payload"]["goal_name"] == "novel:cache_poisoning"


def test_required_evidence_is_filtered_to_gatherable_vocabulary():
    s = _state_with("novel:x")
    # AI tries to request an intrusive / made-up evidence type alongside valid ones.
    agent = InvestigationDesigner(_cassette(
        {"required_evidence": ["http_headers", "rce_probe", "sql_injection", "dns_records"]}))
    accepted = AICoordinator().run(agent.generate(s), ctx=VerifierContext())
    assert len(accepted) == 1
    ev = set(accepted[0].proposal.payload.required_evidence)
    assert ev == {"http_headers", "dns_records"}         # junk/intrusive types dropped


def test_ignores_objectives_that_already_have_evidence():
    s = ReasoningState(target="ex.com:80", scope=["ex.com"])
    o = Objective(name="novel:x", desired_evidence=("http_headers",))
    s.investigation.objectives.add(o)
    agent = InvestigationDesigner(_cassette({"required_evidence": ["http_body"]}))
    assert agent.generate(s) == []                        # already investigable → skip


def test_broken_ai_designs_nothing():
    s = _state_with("novel:x")

    def _boom(system, user):
        raise RuntimeError("down")

    assert InvestigationDesigner(_boom).generate(s) == []
    assert InvestigationDesigner(lambda sy, u: "garbage").generate(s) == []
    assert InvestigationDesigner(lambda sy, u: json.dumps({"required_evidence": []})).generate(s) == []


def test_empty_required_evidence_after_filtering_is_dropped():
    s = _state_with("novel:x")
    # Everything requested is outside the vocabulary → nothing usable → no objective proposal survives.
    agent = InvestigationDesigner(_cassette({"required_evidence": ["exploit", "rce", "shell"]}))
    accepted = AICoordinator().run(agent.generate(s), ctx=VerifierContext())
    assert all(not d.proposal.payload.required_evidence for d in accepted) or accepted == []
