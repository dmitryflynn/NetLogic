"""
Capability Registry — the optimization target (Phase 5 revised, §3).

A Capability is *what* you can learn ("Resolve CMS"), independent of *how*. Playbooks implement
capabilities; the scheduler reasons about capabilities, not playbooks. This inverts the earlier
backwards dependency (capabilities no longer own playbooks — playbooks advertise the capabilities
they implement).

A Capability is **relevant** when what it `produces` intersects the investigation's currently open
questions (unsatisfied objectives + active competing hypotheses). Relevant capabilities are emitted
as `Candidate(source="capability")`, so DecisionPolicy ranks them in the same pool as generator and
playbook candidates and never needs to know the difference.

The candidate's factory is the lazy boundary: it instantiates the implementing Playbook's Intents
only if the policy selects the capability.

Why this earns its place over playbook metadata (the maintainer test): a capability can be
implemented by *several* playbooks, and `_pick_playbook` chooses the one that is APPLICABLE to the
current state. That "select the right implementation for this state" decision is something a lone
playbook's metadata cannot express. See test_architecture_invariants.py::
test_capability_selects_among_multiple_implementations — if that behavior ever disappears, this
registry collapses back into playbook metadata and should be removed.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from src.reasoning.candidate import Candidate
from src.reasoning.intent import ProbeCost

log = logging.getLogger("netlogic.reasoning.capability_registry")


@dataclass(frozen=True)
class Capability:
    """What can be learned, plus the playbooks that implement it. Metadata only — no behavior."""
    id: str
    name: str
    produces: tuple[str, ...]                    # open-question tags it can close, e.g. ("identify_framework",)
    required_evidence_types: tuple[str, ...] = ()
    expected_information_gain: float = 1.0
    risk: str = "read_only"
    estimated_cost: ProbeCost = field(default_factory=ProbeCost)
    implemented_by_playbooks: tuple[str, ...] = ()   # playbook ids that advertise this capability

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "produces": list(self.produces),
                "required_evidence_types": list(self.required_evidence_types),
                "expected_information_gain": self.expected_information_gain,
                "risk": self.risk,
                "implemented_by_playbooks": list(self.implemented_by_playbooks)}


def open_question_tags(state) -> set[str]:
    """The investigation's currently open questions, as coarse tags.

    Derived deterministically from state: the prefix of each unsatisfied objective name
    (``identify_framework:ex.com:80`` → ``identify_framework``) plus active hypothesis labels.
    """
    tags: set[str] = set()
    try:
        for obj in state.investigation.objectives.all():
            if not obj.satisfied:
                tags.add(obj.name.split(":", 1)[0])
    except Exception:  # noqa: BLE001
        pass
    try:
        for h in state.investigation.hypotheses.leaves():
            if getattr(h, "status", "active") == "active" and h.label:
                tags.add(h.label)
    except Exception:  # noqa: BLE001
        pass
    return tags


class CapabilityRegistry:
    """Catalog of capabilities. Emits ranked-pool candidates for the relevant ones."""

    def __init__(self, capabilities: dict[str, Capability] | None = None) -> None:
        self.capabilities = capabilities or {}

    def register(self, capability: Capability) -> None:
        self.capabilities[capability.id] = capability

    def relevant(self, state) -> list[Capability]:
        """Capabilities whose `produces` intersects the current open questions."""
        tags = open_question_tags(state)
        return [c for c in self.capabilities.values() if set(c.produces) & tags]

    def to_candidates(self, state, playbook_registry=None,
                      instantiator=None) -> list[Candidate]:
        """Emit Candidate(source='capability') for each relevant capability.

        The candidate's factory lazily instantiates an implementing Playbook (if one is registered
        and applicable). Building the registry of candidates touches no InvestigationGraphs.
        """
        candidates: list[Candidate] = []
        target_ref = state.scope[0] if state.scope else state.target

        for cap in self.relevant(state):
            playbook = self._pick_playbook(cap, state, playbook_registry)
            if playbook is None:
                continue
            inst = instantiator or _default_instantiator()
            candidates.append(Candidate.deferred(
                source="capability",
                kind=cap.name,
                gain=cap.expected_information_gain,
                cost=cap.estimated_cost,
                risk=cap.risk,
                rationale=f"capability={cap.id} via playbook={playbook.id}",
                factory=lambda pb=playbook: inst.instantiate(pb, state, target_ref),
            ))
        return candidates

    @staticmethod
    def _pick_playbook(cap: Capability, state, playbook_registry):
        """Choose an implementing playbook: advertised by the capability, registered, and applicable."""
        if playbook_registry is None:
            return None
        for pb_id in cap.implemented_by_playbooks:
            pb = playbook_registry.playbooks.get(pb_id)
            if pb is not None and pb.matches(state):
                return pb
        return None


def _default_instantiator():
    from src.reasoning.playbooks import PlaybookInstantiator  # noqa: PLC0415
    return PlaybookInstantiator()
