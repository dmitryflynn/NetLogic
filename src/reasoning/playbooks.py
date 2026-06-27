"""
Playbooks — reusable investigation strategies.

A Playbook is a templated, reusable source of Intent for known scenarios (e.g., "WordPress
vulnerability verification"). Playbooks produce Intent templates that the Compiler converts to
EvidenceRequests. Playbooks remain the sole producer of Intent; the Compiler remains the sole
producer of EvidenceRequest.

Design: Phase 5 §1. Triggering: Phase 5 ReconDirector._run_phase3_cycle queries PlaybookRegistry
for applicable playbooks before instantiating baseline Intents.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from src.reasoning.intent import EvidenceType, Intent, IntentConstraints, StopCondition
from src.reasoning.probe_plan import Condition, ConditionOp
from src.reasoning.state import ReasoningState

log = logging.getLogger("netlogic.reasoning.playbooks")


@dataclass
class Playbook:
    """A templated, reusable investigation strategy."""
    id: str
    name: str
    trigger_rule: Condition
    intent_template: Intent
    default_stopping_condition: StopCondition
    schema_version: str = "1.0"
    metadata: dict[str, Any] = field(default_factory=dict)

    def matches(self, state: ReasoningState) -> bool:
        """Check if this Playbook's trigger_rule applies to the current state."""
        # Extract technologies from world.technology (list of dicts)
        tech_names = set()
        if state.world.technology:
            for tech_dict in state.world.technology:
                if isinstance(tech_dict, dict) and "name" in tech_dict:
                    tech_names.add(tech_dict["name"].lower())
                elif isinstance(tech_dict, str):
                    tech_names.add(tech_dict.lower())

        # Extract framework beliefs
        framework_names = set()
        if state.world.belief_records:
            for belief_dict in state.world.belief_records:
                if isinstance(belief_dict, dict) and belief_dict.get("kind") == "framework":
                    framework_names.add(belief_dict.get("claim", "").lower())

        # Count unresolved objectives
        unresolved_count = 0
        try:
            for obj in state.investigation.objectives.all():
                if not obj.satisfied:
                    unresolved_count += 1
        except Exception:  # noqa: BLE001
            pass

        trigger_data = {
            "technologies": tech_names,
            "detected_frameworks": framework_names,
            "open_ports": len(state.scope) if state.scope else 0,
            "unresolved_objectives": unresolved_count,
        }
        return self.trigger_rule.evaluate(trigger_data)


class PlaybookLoader:
    """Loads Playbooks from YAML files."""

    def __init__(self, playbooks_dir: str | Path = "src/reasoning/playbooks") -> None:
        self.playbooks_dir = Path(playbooks_dir)

    def load_all(self) -> dict[str, Playbook]:
        """Load all YAML playbooks from the playbooks directory."""
        playbooks = {}
        if not self.playbooks_dir.exists():
            log.debug("Playbooks directory does not exist; no playbooks loaded")
            return playbooks

        for yaml_file in self.playbooks_dir.glob("*.yaml"):
            try:
                playbook = self.load_file(yaml_file)
                if playbook:
                    playbooks[playbook.id] = playbook
            except Exception as e:
                log.warning("Failed to load playbook %s: %s", yaml_file, e)

        return playbooks

    def load_file(self, path: Path | str) -> Playbook | None:
        """Load a single Playbook from a YAML file."""
        path = Path(path)
        with open(path) as f:
            data = yaml.safe_load(f)

        if not data:
            return None

        # Parse trigger_rule from YAML (dict format) into Condition
        trigger_rule = self._parse_condition(data.get("trigger_rule", {}))

        # Parse intent_template
        intent_data = data.get("intent_template", {})
        intent = Intent(
            goal=intent_data.get("goal", ""),
            desired_evidence=[
                EvidenceType(ev) for ev in intent_data.get("desired_evidence", [])
                if ev in EvidenceType._value2member_map_
            ],
            protocol_hints=intent_data.get("protocol_hints", []),
            constraints=IntentConstraints(
                read_only=intent_data.get("read_only", True),
                max_cost=intent_data.get("max_cost", "medium"),
                max_depth=intent_data.get("max_depth", 5),
            ),
        )

        # Parse stopping condition
        stop_cond_data = data.get("stopping_condition", {})
        stop_cond = StopCondition(
            confidence_goal=stop_cond_data.get("confidence_goal", 0.85),
            max_probes=stop_cond_data.get("max_probes", 15),
        )

        playbook = Playbook(
            id=data.get("id", f"playbook_{uuid.uuid4().hex[:8]}"),
            name=data.get("name", ""),
            trigger_rule=trigger_rule,
            intent_template=intent,
            default_stopping_condition=stop_cond,
            schema_version=data.get("schema_version", "1.0"),
            metadata=data.get("metadata", {}),
        )

        return playbook

    def _parse_condition(self, data: dict | str) -> Condition:
        """Parse a condition dict/YAML into a Condition object."""
        if isinstance(data, str):
            # Simple string conditions: "technology_contains:wordpress"
            if ":" in data:
                field_op, value = data.split(":", 1)
                if "_contains" in field_op:
                    field = field_op.replace("_contains", "")
                    return Condition(op=ConditionOp.CONTAINS, field=field, value=value)
                elif "_" in field_op:
                    field, op = field_op.rsplit("_", 1)
                    op_map = {"eq": ConditionOp.EQ, "ne": ConditionOp.NE, "gt": ConditionOp.GT,
                              "lt": ConditionOp.LT, "exists": ConditionOp.EXISTS}
                    return Condition(op=op_map.get(op, ConditionOp.EQ), field=field, value=value)
            return Condition(op=ConditionOp.TRUST)

        # Dict-based conditions (recursive)
        op_str = data.get("op", "trust").lower()
        op_map = {
            "eq": ConditionOp.EQ, "ne": ConditionOp.NE, "gt": ConditionOp.GT, "lt": ConditionOp.LT,
            "contains": ConditionOp.CONTAINS, "matches": ConditionOp.MATCHES, "exists": ConditionOp.EXISTS,
            "and": ConditionOp.AND, "or": ConditionOp.OR, "not": ConditionOp.NOT, "trust": ConditionOp.TRUST,
        }
        op = op_map.get(op_str, ConditionOp.TRUST)

        conditions = []
        if "conditions" in data:
            conditions = [self._parse_condition(c) for c in data["conditions"]]

        return Condition(
            op=op,
            field=data.get("field", ""),
            value=data.get("value"),
            conditions=conditions,
        )


class PlaybookInstantiator:
    """Instantiates Intents from Playbooks for a specific target + state."""

    def instantiate(self, playbook: Playbook, state: ReasoningState, target_ref: str) -> list[Intent]:
        """Create Intent(s) from a Playbook template for the given state."""
        intents = []

        # Adapt the intent_template to current state
        intent = Intent(
            goal=playbook.intent_template.goal,
            target_ref=target_ref,
            desired_evidence=list(playbook.intent_template.desired_evidence),
            protocol_hints=list(playbook.intent_template.protocol_hints),
            constraints=IntentConstraints(
                read_only=playbook.intent_template.constraints.read_only,
                max_cost=playbook.intent_template.constraints.max_cost,
                max_depth=playbook.intent_template.constraints.max_depth,
            ),
            stopping_condition=StopCondition(
                confidence_goal=playbook.default_stopping_condition.confidence_goal,
                max_probes=playbook.default_stopping_condition.max_probes,
            ),
            rationale=f"Playbook: {playbook.name}",
        )

        intents.append(intent)
        return intents


class PlaybookRegistry:
    """Registry of available Playbooks. Stateless; queries at each cycle."""

    def __init__(self, playbooks: dict[str, Playbook] | None = None) -> None:
        self.playbooks = playbooks or {}

    def register(self, playbook: Playbook) -> None:
        """Register a Playbook."""
        self.playbooks[playbook.id] = playbook

    def find_applicable(self, state: ReasoningState) -> list[Playbook]:
        """Find all Playbooks that match the current state."""
        return [pb for pb in self.playbooks.values() if pb.matches(state)]

    def to_candidates(self, state: ReasoningState, instantiator=None) -> list:
        """Emit Candidate(source='playbook') for each matching playbook (Phase 5 revised §4).

        Matching is cheap; instantiation is deferred. The candidate's factory builds the
        playbook's Intents only if DecisionPolicy selects it — no InvestigationGraph is
        constructed during matching/ranking.
        """
        from src.reasoning.candidate import Candidate  # noqa: PLC0415
        inst = instantiator or PlaybookInstantiator()
        target_ref = state.scope[0] if state.scope else state.target
        candidates = []
        for pb in self.find_applicable(state):
            gain = float(pb.metadata.get("expected_information_gain", 1.0))
            candidates.append(Candidate.deferred(
                source="playbook",
                kind=pb.name,
                gain=gain,
                rationale=f"playbook={pb.id}",
                factory=lambda p=pb: inst.instantiate(p, state, target_ref),
            ))
        return candidates

    def load_from_dir(self, playbooks_dir: str | Path = "src/reasoning/playbooks") -> None:
        """Load playbooks from a directory."""
        loader = PlaybookLoader(playbooks_dir)
        loaded = loader.load_all()
        self.playbooks.update(loaded)
        log.info("Loaded %d playbooks from %s", len(loaded), playbooks_dir)
