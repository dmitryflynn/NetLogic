"""
Candidate — the unified action interface (Phase 5 revised, the central decoupling).

Every action source (generator, playbook, capability, history) emits `Candidate`s. DecisionPolicy
ranks `Candidate[]` and knows nothing about where any candidate came from. This collapses three
incompatible object types the scheduler used to juggle (Intents, Playbooks, Capabilities) into one.

The key property is the **lazy boundary**: matching/scoring touches no InvestigationGraphs. Only
the *selected* candidate's `instantiate()` is called, and only then are Intents built. This is the
fix for eager playbook instantiation — matching is cheap, instantiation is deferred.

Contract (frozen — future features plug into this, they don't reach around it):
    CandidateSources  →  Candidate[]
    DecisionPolicy     →  ranks Candidate[]  →  SelectedCandidate[]
    Candidate.instantiate()  →  Intent[]
    Compiler           →  EvidenceRequest[]   (Compiler stays the sole EvidenceRequest producer)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from src.reasoning.intent import Intent, ProbeCost


@dataclass(frozen=True)
class Candidate:
    """One rankable action, independent of its source.

    `_factory` is the deferred instantiation thunk — excluded from equality/repr so candidates
    compare by their cheap, rankable metadata. It is invoked only via `instantiate()`, only when
    the policy selects this candidate.
    """
    source: str                                  # "generator" | "playbook" | "capability" | "history"
    kind: str                                    # what it would learn (human/debug label)
    expected_information_gain: float = 1.0
    estimated_cost: ProbeCost = field(default_factory=ProbeCost)
    risk: str = "read_only"
    prerequisites: tuple[str, ...] = ()
    rationale: str = ""
    _factory: Callable[[], list[Intent]] | None = field(
        default=None, compare=False, repr=False, hash=False)

    def instantiate(self) -> list[Intent]:
        """Lazy boundary: build Intents only when selected. Pure metadata until this is called."""
        if self._factory is None:
            return []
        return list(self._factory() or [])

    def cost_factor(self) -> float:
        """Normalized cost (>= 1.0): 1.0 baseline, higher = more expensive. Shared by policies."""
        c = self.estimated_cost
        return max(1.0, c.time_ms / 1000.0 + c.tokens / 1000.0 + c.probes)

    # ── ergonomic constructors so sources don't hand-roll the factory thunk ──

    @classmethod
    def from_intent(cls, intent: Intent, *, source: str, gain: float = 1.0,
                    kind: str | None = None, risk: str = "read_only",
                    prerequisites: tuple[str, ...] = ()) -> "Candidate":
        """Wrap a single ready Intent. instantiate() returns it unchanged."""
        return cls(
            source=source,
            kind=kind or intent.goal or "intent",
            expected_information_gain=gain,
            risk=risk,
            prerequisites=prerequisites,
            rationale=intent.rationale or "",
            _factory=lambda: [intent],
        )

    @classmethod
    def deferred(cls, *, source: str, kind: str, factory: Callable[[], list[Intent]],
                 gain: float = 1.0, cost: ProbeCost | None = None, risk: str = "read_only",
                 prerequisites: tuple[str, ...] = (), rationale: str = "") -> "Candidate":
        """A candidate whose Intents are expensive to build — `factory` runs only on selection."""
        return cls(
            source=source,
            kind=kind,
            expected_information_gain=gain,
            estimated_cost=cost or ProbeCost(),
            risk=risk,
            prerequisites=prerequisites,
            rationale=rationale,
            _factory=factory,
        )


@dataclass
class RankedCandidate:
    """A candidate with its policy-assigned priority + explanation."""
    candidate: Candidate
    priority: float
    rationale: str
