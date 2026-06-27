"""Capability Registry (Phase 5 revised §3): capabilities are the optimization target; playbooks
implement them. Verifies relevance detection, capability→playbook selection, lazy Candidate
emission, and that capabilities compose with DecisionPolicy ranking."""
from src.reasoning.capability_registry import (
    Capability,
    CapabilityRegistry,
    open_question_tags,
)
from src.reasoning.decision_policy import GreedyPolicy
from src.reasoning.intent import Intent, ProbeCost, StopCondition
from src.reasoning.objective import Objective
from src.reasoning.playbooks import Playbook, PlaybookRegistry
from src.reasoning.probe_plan import Condition, ConditionOp
from src.reasoning.state import ReasoningState


def _state_with_open_framework_question():
    s = ReasoningState(target="ex.com:80", scope=["ex.com:80"])
    s.investigation.objectives.add(Objective(name="identify_framework:ex.com:80"))
    return s


def _wp_playbook(matches=True):
    trigger = Condition(op=ConditionOp.TRUST) if matches else Condition(
        op=ConditionOp.CONTAINS, field="technologies", value="never")
    return Playbook(
        id="wp_pb", name="WordPress Investigation", trigger_rule=trigger,
        intent_template=Intent(goal="resolve cms"),
        default_stopping_condition=StopCondition())


def _cms_capability():
    return Capability(
        id="resolve_cms", name="Resolve CMS",
        produces=("identify_framework",),
        expected_information_gain=5.0,
        estimated_cost=ProbeCost(time_ms=1000, probes=2),
        implemented_by_playbooks=("wp_pb",))


def test_open_question_tags_from_unsatisfied_objectives():
    s = _state_with_open_framework_question()
    tags = open_question_tags(s)
    assert "identify_framework" in tags


def test_satisfied_objective_is_not_open():
    s = _state_with_open_framework_question()
    s.investigation.objectives.satisfy("identify_framework:ex.com:80")
    assert "identify_framework" not in open_question_tags(s)


def test_relevant_capability_matches_open_question():
    s = _state_with_open_framework_question()
    reg = CapabilityRegistry()
    reg.register(_cms_capability())
    relevant = reg.relevant(s)
    assert len(relevant) == 1
    assert relevant[0].id == "resolve_cms"


def test_irrelevant_capability_excluded():
    s = ReasoningState(target="ex.com:80", scope=["ex.com:80"])  # no open framework question
    reg = CapabilityRegistry()
    reg.register(_cms_capability())
    assert reg.relevant(s) == []


def test_emits_candidate_when_playbook_available():
    s = _state_with_open_framework_question()
    cap_reg = CapabilityRegistry()
    cap_reg.register(_cms_capability())
    pb_reg = PlaybookRegistry()
    pb_reg.register(_wp_playbook(matches=True))

    candidates = cap_reg.to_candidates(s, pb_reg)
    assert len(candidates) == 1
    c = candidates[0]
    assert c.source == "capability"
    assert c.expected_information_gain == 5.0
    assert c.kind == "Resolve CMS"


def test_no_candidate_when_no_implementing_playbook():
    s = _state_with_open_framework_question()
    cap_reg = CapabilityRegistry()
    cap_reg.register(_cms_capability())
    pb_reg = PlaybookRegistry()  # empty — no implementing playbook registered
    assert cap_reg.to_candidates(s, pb_reg) == []


def test_no_candidate_when_playbook_does_not_match():
    s = _state_with_open_framework_question()
    cap_reg = CapabilityRegistry()
    cap_reg.register(_cms_capability())
    pb_reg = PlaybookRegistry()
    pb_reg.register(_wp_playbook(matches=False))   # registered but trigger won't fire
    assert cap_reg.to_candidates(s, pb_reg) == []


def test_candidate_instantiation_is_lazy():
    """Building capability candidates must not instantiate playbook intents."""
    s = _state_with_open_framework_question()
    cap_reg = CapabilityRegistry()
    cap_reg.register(_cms_capability())
    pb_reg = PlaybookRegistry()
    pb_reg.register(_wp_playbook(matches=True))

    candidates = cap_reg.to_candidates(s, pb_reg)
    # Intents materialize only on demand
    intents = candidates[0].instantiate()
    assert intents and all(isinstance(i, Intent) for i in intents)
    assert intents[0].goal == "resolve cms"


def test_capability_candidates_rank_with_policy():
    """Capability candidates rank in the same pool as any other Candidate."""
    s = _state_with_open_framework_question()
    cap_reg = CapabilityRegistry()
    cap_reg.register(_cms_capability())
    pb_reg = PlaybookRegistry()
    pb_reg.register(_wp_playbook(matches=True))

    candidates = cap_reg.to_candidates(s, pb_reg)
    ranked = GreedyPolicy().rank_candidates(candidates)
    assert ranked[0].candidate.source == "capability"
    assert ranked[0].priority == 5.0   # greedy = expected_information_gain
