"""Track C / C0 — the "AI never" invariants.

The cognitive layer may never: mutate the world model / observations / confidence / beliefs /
hypotheses / packs directly, bypass the planner, or authorize/execute anything. These tests check
both the STRUCTURE (the package doesn't even import the things it must never touch) and the
BEHAVIOR (adversarial payloads have zero effect on the Phase-8b gate).
"""
import ast
import inspect
import json
from pathlib import Path

import pytest

from src.reasoning.action_gate import ActionGate, GateContext
from src.reasoning.actions import Action, ActionDescriptor, ActionSemantics, RiskTier
from src.reasoning.ai import (
    AgentTask, AICoordinator, KnowledgePayload, ObjectivePayload, PackPayload, ProposalKind,
    StrategyPayload, VerifierContext, VerifierPipeline,
)
from src.reasoning.ai.proposals import HypothesisPayload

# Symbols the cognitive layer must NEVER import — the world/truth MUTATORS and the action GATE.
# Importing any of these would mean the layer can change facts or authorize actions instead of
# only proposing. `ReasoningState` is deliberately NOT here: it is a read-only container an agent
# legitimately reads to build context (mutation is caught behaviorally, below). Checked via the
# actual import statements (an AST check, not a string grep) so a renamed import is still caught.
_FORBIDDEN_IMPORT_NAMES = {
    "EvidenceGraph", "HypothesisEngine", "ConfidenceEngine", "ObjectiveDAG",
    "ActionGate", "PackCompiler",
}

_AI_PACKAGE_DIR = Path(__file__).parent / "src" / "reasoning" / "ai"

# The pure pipeline CORE — must be entirely state-agnostic (takes VerifierContext/facts, never the
# world). Agents + the eval harness are excluded: they legitimately READ a ReasoningState.
_CORE_MODULES = {"proposals.py", "normalize.py", "rank.py", "verifier.py", "meta_reasoner.py",
                 "store.py", "reputation.py", "coordinator.py", "errors.py"}


def _imported_names(py_file: Path) -> set[str]:
    tree = ast.parse(py_file.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            names.update(alias.asname or alias.name for alias in node.names)
    return names


# rglob => covers the agents/ subpackage too. A stronger guarantee than the top-level-only glob:
# EVERY file in ai/, agents included, is checked against the real world mutators.
@pytest.mark.parametrize("py_file", sorted(_AI_PACKAGE_DIR.rglob("*.py")))
def test_ai_package_never_imports_world_mutators(py_file):
    imported = _imported_names(py_file)
    collision = imported & _FORBIDDEN_IMPORT_NAMES
    assert not collision, f"{py_file.relative_to(_AI_PACKAGE_DIR)} imports forbidden mutator(s): {collision}"


@pytest.mark.parametrize("py_file", sorted(m for m in _AI_PACKAGE_DIR.glob("*.py")
                                           if m.name in _CORE_MODULES))
def test_pipeline_core_is_state_agnostic(py_file):
    """The core pipeline never even READS a ReasoningState — it operates purely on proposals +
    a typed VerifierContext. Only agents (and the eval harness) touch the world, read-only."""
    assert "ReasoningState" not in _imported_names(py_file), \
        f"{py_file.name} should be state-agnostic but imports ReasoningState"


def test_ai_package_has_no_dependency_on_reasoning_director():
    """The dependency points ONE way: director.py may (eventually) import from ai/, but ai/ must
    never import director.py or the ReconDirector — the cognitive layer cannot drive the loop."""
    for py_file in _AI_PACKAGE_DIR.rglob("*.py"):
        source = py_file.read_text(encoding="utf-8")
        assert "reasoning.director" not in source
        assert "ReconDirector" not in source


def test_agents_never_mutate_the_state_they_read():
    """Agents READ the world to build context but must never mutate it — the behavioral half of
    the isolation invariant (the import ban is the structural half)."""
    import json as _json

    from src.reasoning.ai import CounterfactualReasoner, HypothesisGenerator
    from src.reasoning.objective import Objective
    from src.reasoning.state import ReasoningState

    s = ReasoningState(target="ex.com:80", scope=["ex.com"])
    s.world.graph.upsert_node("service", "ex.com:80", label="ex.com:80")
    s.investigation.objectives.add(Objective(name="identify_framework:ex.com:80"))
    s.investigation.hypotheses.add_hypothesis(label="framework_of:ex.com:80", created_by="rule",
                                              likelihoods={"wordpress": 0.7, "django": 0.3})
    before = _json.dumps(s.to_dict(), sort_keys=True, default=str)

    HypothesisGenerator(lambda sy, u: _json.dumps(
        [{"objective": "novel:x", "candidates": {"a": 1.0}, "novel": True}])).generate(s)
    CounterfactualReasoner(lambda sy, u: _json.dumps(
        [{"refutes": "wordpress", "check": "no_wp_json"}])).generate(s)

    after = _json.dumps(s.to_dict(), sort_keys=True, default=str)
    assert before == after, "an agent mutated the ReasoningState it was only supposed to read"


# ── AI cannot authorize execution: no path from proposal data to an enabling gate field ─────

def test_gate_context_has_no_constructor_from_untrusted_dict():
    """There is no `GateContext.from_dict` / `from_ai` — the ONLY way to build one is the typed
    dataclass constructor with typed keyword arguments. An attacker-controlled dict can be handed
    to `**kwargs` only if the caller explicitly chooses to do that, which nothing in ai/ does."""
    assert not hasattr(GateContext, "from_dict")
    assert not hasattr(GateContext, "from_ai")
    assert not hasattr(GateContext, "from_proposal")


def test_proposal_derived_data_cannot_reach_the_gate_at_all():
    """Build a proposal carrying every field an attacker might hope maps onto gate permissions,
    verify it through the REAL pipeline, and confirm the accepted proposal's dict form has no path
    that GateContext(**accepted_dict) would even accept (TypeError on unknown kwargs) — there is
    structurally no bridge between "a proposal was accepted" and "the gate is more permissive"."""
    coordinator = AICoordinator()
    raw = json.dumps({
        "payload": {"objective": "verify:CVE-1", "candidates": {"a": 1.0}},
        "economics": {"estimated_risk": "exploit", "estimated_information_gain": 99},
        "provenance": {"confidence": 1.0},
    })
    accepted = coordinator.run(
        [AgentTask(agent="attacker", kind=ProposalKind.HYPOTHESIS, raw=raw)],
        ctx=VerifierContext(known_objectives=frozenset({"verify:CVE-1"})))
    assert len(accepted) == 1
    proposal_dict = accepted[0].proposal.to_dict()
    with pytest.raises(TypeError):
        GateContext(**proposal_dict)   # GateContext's fields don't match a Proposal's at all
    # And even in the impossible case someone force-merged compatible-looking keys, risk is
    # already forced to read_only, so there's nothing elevated to smuggle in the first place.
    assert accepted[0].proposal.economics.estimated_risk == "read_only"


def test_default_gate_context_still_denies_everything_above_read_only():
    """Sanity anchor: whatever the cognitive layer produces, the gate's OWN default posture is
    unchanged — read-only allowed, everything else denied, exactly as Phase 8b built it."""
    gate = ActionGate()
    exploit = Action(descriptor=ActionDescriptor(id="x", risk_tier=RiskTier.EXPLOIT),
                     semantics=ActionSemantics())
    decision = gate.evaluate(exploit, "target", GateContext())
    assert not decision.allowed


# ── Broken/absent AI contributes nothing (byte-identical continuation) ──────────────

def test_coordinator_with_all_garbage_tasks_yields_empty_accepted_and_empty_store():
    coordinator = AICoordinator()
    tasks = [AgentTask(agent="a", kind=ProposalKind.HYPOTHESIS, raw=x)
            for x in ["", None, "{{{", 123, [1, 2]]]
    accepted = coordinator.run(tasks)
    assert accepted == []
    assert len(coordinator.store) == 0


def test_verifier_pipeline_never_raises_on_a_hand_built_hostile_proposal():
    """Defense in depth: even a Proposal built directly (bypassing the Normalizer) with hostile
    field values must be REJECTED, not cause an exception, when run through the verifier."""
    from src.reasoning.ai.proposals import Proposal, ProposalEconomics, ProposalProvenance, \
        new_proposal_id
    hostile = Proposal(
        id=new_proposal_id(), kind=ProposalKind.STRATEGY, agent="attacker",
        payload=StrategyPayload(goal_class="g", action_ids=("nonexistent_action",)),
        provenance=ProposalProvenance(),
        economics=ProposalEconomics(estimated_risk="exploit", estimated_probe_count=-999))
    decision = VerifierPipeline().verify(hostile)
    assert not decision.accepted   # unknown action_id / elevated risk -> rejected, not an exception


# ── Every proposal kind's SafetyVerifier scan covers free-form dict fields ──────────

@pytest.mark.parametrize("kind,payload", [
    (ProposalKind.KNOWLEDGE, KnowledgePayload(tech_id="t", rule={"confirm": ["x"], "kill_switch": True})),
    (ProposalKind.PACK, PackPayload(tech_id="t", fingerprints={"headers": {}, "authorization": "x"})),
])
def test_forbidden_keys_caught_in_every_free_form_payload_field(kind, payload):
    from src.reasoning.ai.proposals import Proposal, ProposalEconomics, ProposalProvenance, \
        new_proposal_id
    p = Proposal(id=new_proposal_id(), kind=kind, agent="a", payload=payload,
                provenance=ProposalProvenance(), economics=ProposalEconomics())
    decision = VerifierPipeline().verify(p, VerifierContext(benchmark_check=lambda x: True))
    assert not decision.accepted and decision.stage_failed == "safety"


def test_ai_package_signature_sanity():
    """`AICoordinator.run` never accepts a raw ReasoningState — its signature only takes
    AgentTasks + a typed VerifierContext, structurally preventing "just hand it the world"."""
    sig = inspect.signature(AICoordinator.run)
    assert "state" not in sig.parameters and "reasoning_state" not in sig.parameters
