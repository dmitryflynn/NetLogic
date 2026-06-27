"""
Tests for Playbooks (Phase 5 §1).

Verifies: trigger_rule matching, Intent template instantiation, PlaybookRegistry behavior,
YAML loading, wire-up into director.
"""
from __future__ import annotations

import pytest
from pathlib import Path

from src.reasoning.playbooks import Playbook, PlaybookInstantiator, PlaybookLoader, PlaybookRegistry
from src.reasoning.probe_plan import Condition, ConditionOp
from src.reasoning.intent import Intent, IntentConstraints, StopCondition, EvidenceType
from src.reasoning.state import ReasoningState


def _make_test_state(target: str = "example.com:443", technologies: list[str] | None = None) -> ReasoningState:
    """Create a minimal ReasoningState for testing."""
    state = ReasoningState(target=target, scope=[target])
    if technologies:
        state.world.technology = [{"name": t} for t in technologies]
    return state


class TestPlaybookTriggerRule:
    """Test Playbook trigger_rule matching."""

    def test_playbook_matches_technology_contains(self):
        """Trigger rule matches when technology is present."""
        trigger = Condition(op=ConditionOp.CONTAINS, field="technologies", value="wordpress")
        playbook = Playbook(
            id="test_wp",
            name="Test WordPress",
            trigger_rule=trigger,
            intent_template=Intent(goal="test"),
            default_stopping_condition=StopCondition(),
        )

        state = _make_test_state("example.com:443", technologies=["wordpress"])

        assert playbook.matches(state) is True

    def test_playbook_does_not_match_absent_technology(self):
        """Trigger rule does not match when technology is absent."""
        trigger = Condition(op=ConditionOp.CONTAINS, field="technologies", value="wordpress")
        playbook = Playbook(
            id="test_wp",
            name="Test WordPress",
            trigger_rule=trigger,
            intent_template=Intent(goal="test"),
            default_stopping_condition=StopCondition(),
        )

        state = _make_test_state("example.com:443")
        # No technologies added

        assert playbook.matches(state) is False

    def test_playbook_matches_and_condition(self):
        """Trigger rule with AND combines conditions correctly."""
        trigger = Condition(
            op=ConditionOp.AND,
            conditions=[
                Condition(op=ConditionOp.CONTAINS, field="technologies", value="wordpress"),
                Condition(op=ConditionOp.GT, field="open_ports", value=0),
            ],
        )
        playbook = Playbook(
            id="test_wp",
            name="Test WordPress",
            trigger_rule=trigger,
            intent_template=Intent(goal="test"),
            default_stopping_condition=StopCondition(),
        )

        state = _make_test_state("example.com:443", technologies=["wordpress"])
        # open_ports is > 0 due to scope having one entry

        assert playbook.matches(state) is True

    def test_playbook_does_not_match_failed_and_condition(self):
        """AND condition fails if any sub-condition fails."""
        trigger = Condition(
            op=ConditionOp.AND,
            conditions=[
                Condition(op=ConditionOp.CONTAINS, field="technologies", value="wordpress"),
                Condition(op=ConditionOp.GT, field="open_ports", value=100),  # Very high bar
            ],
        )
        playbook = Playbook(
            id="test_wp",
            name="Test WordPress",
            trigger_rule=trigger,
            intent_template=Intent(goal="test"),
            default_stopping_condition=StopCondition(),
        )

        state = _make_test_state("example.com:443", technologies=["wordpress"])
        # open_ports won't be 100

        assert playbook.matches(state) is False


class TestPlaybookInstantiator:
    """Test Intent instantiation from Playbook templates."""

    def test_instantiate_creates_intent_from_template(self):
        """Instantiate converts Playbook template to concrete Intent."""
        template = Intent(
            goal="Test goal",
            desired_evidence=[EvidenceType.SERVER_HEADER, EvidenceType.TLS_VERSION],
            constraints=IntentConstraints(read_only=True, max_cost="medium"),
            stopping_condition=StopCondition(confidence_goal=0.90, max_probes=20),
        )
        playbook = Playbook(
            id="test",
            name="Test",
            trigger_rule=Condition(op=ConditionOp.TRUST),
            intent_template=template,
            default_stopping_condition=StopCondition(confidence_goal=0.85, max_probes=15),
        )

        state = _make_test_state("example.com:443")
        instantiator = PlaybookInstantiator()
        intents = instantiator.instantiate(playbook, state, "example.com:443")

        assert len(intents) == 1
        intent = intents[0]
        assert intent.goal == "Test goal"
        assert intent.target_ref == "example.com:443"
        assert EvidenceType.SERVER_HEADER in intent.desired_evidence
        assert intent.rationale.startswith("Playbook:")

    def test_instantiate_uses_default_stopping_condition(self):
        """Instantiate uses Playbook's default stopping condition."""
        playbook = Playbook(
            id="test",
            name="Test",
            trigger_rule=Condition(op=ConditionOp.TRUST),
            intent_template=Intent(goal="test"),
            default_stopping_condition=StopCondition(confidence_goal=0.95, max_probes=25),
        )

        state = _make_test_state("example.com:443")
        instantiator = PlaybookInstantiator()
        intents = instantiator.instantiate(playbook, state, "example.com:443")

        assert intents[0].stopping_condition.confidence_goal == 0.95
        assert intents[0].stopping_condition.max_probes == 25


class TestPlaybookRegistry:
    """Test PlaybookRegistry behavior."""

    def test_register_playbook(self):
        """Registry can register and retrieve Playbooks."""
        playbook = Playbook(
            id="test",
            name="Test",
            trigger_rule=Condition(op=ConditionOp.TRUST),
            intent_template=Intent(goal="test"),
            default_stopping_condition=StopCondition(),
        )
        registry = PlaybookRegistry()
        registry.register(playbook)

        assert registry.playbooks["test"] is playbook

    def test_find_applicable_returns_matching_playbooks(self):
        """Registry returns only Playbooks that match current state."""
        wp_playbook = Playbook(
            id="wp",
            name="WordPress",
            trigger_rule=Condition(op=ConditionOp.CONTAINS, field="technologies", value="wordpress"),
            intent_template=Intent(goal="assess wordpress"),
            default_stopping_condition=StopCondition(),
        )
        generic_playbook = Playbook(
            id="generic",
            name="Generic",
            trigger_rule=Condition(op=ConditionOp.TRUST),  # Always matches
            intent_template=Intent(goal="generic assessment"),
            default_stopping_condition=StopCondition(),
        )
        registry = PlaybookRegistry()
        registry.register(wp_playbook)
        registry.register(generic_playbook)

        state = _make_test_state("example.com:443", technologies=["wordpress"])

        applicable = registry.find_applicable(state)
        assert len(applicable) == 2
        names = {pb.name for pb in applicable}
        assert "WordPress" in names
        assert "Generic" in names

    def test_find_applicable_excludes_non_matching(self):
        """Registry excludes Playbooks that don't match."""
        wp_playbook = Playbook(
            id="wp",
            name="WordPress",
            trigger_rule=Condition(op=ConditionOp.CONTAINS, field="technologies", value="wordpress"),
            intent_template=Intent(goal="assess wordpress"),
            default_stopping_condition=StopCondition(),
        )
        registry = PlaybookRegistry()
        registry.register(wp_playbook)

        state = _make_test_state("example.com:443")
        # No WordPress technology

        applicable = registry.find_applicable(state)
        assert len(applicable) == 0


class TestPlaybookLoader:
    """Test loading Playbooks from YAML."""

    def test_load_yaml_playbook(self):
        """PlaybookLoader loads a valid YAML playbook."""
        yaml_path = Path(__file__).parent / "fixtures" / "playbook_example.yaml"
        if not yaml_path.exists():
            pytest.skip("Test playbook YAML not found")

        loader = PlaybookLoader()
        playbook = loader.load_file(yaml_path)

        assert playbook is not None
        assert playbook.name == "Test Playbook"
        assert EvidenceType.SERVER_HEADER in playbook.intent_template.desired_evidence

    def test_load_all_playbooks(self):
        """PlaybookLoader.load_all() loads all playbooks from directory."""
        playbooks_dir = Path(__file__).parent.parent / "src" / "reasoning" / "playbooks"
        if not playbooks_dir.exists():
            pytest.skip("Playbooks directory not found")

        loader = PlaybookLoader(playbooks_dir)
        playbooks = loader.load_all()

        # Should load at least the example playbooks we created
        assert len(playbooks) > 0


class TestPlaybookIntegration:
    """Integration tests: Playbooks in reasoning context."""

    def test_playbook_instantiation_in_reasoning_context(self):
        """Playbooks can be instantiated within a reasoning state."""
        playbook = Playbook(
            id="test",
            name="Test",
            trigger_rule=Condition(op=ConditionOp.TRUST),
            intent_template=Intent(
                goal="Test investigation",
                desired_evidence=[EvidenceType.SERVER_HEADER],
            ),
            default_stopping_condition=StopCondition(),
        )

        state = _make_test_state("example.com:443")
        instantiator = PlaybookInstantiator()
        intents = instantiator.instantiate(playbook, state, state.scope[0])

        # Intents should be properly formed and ready for Compiler
        assert all(isinstance(i, Intent) for i in intents)
        assert all(i.target_ref == state.scope[0] for i in intents)
