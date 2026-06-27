"""
Sensor registry — the loop's action set.

See the Phase 2 plan §5. A `SensorStep` is one re-invokable reconnaissance action the
ReconDirector can dispatch. In Phase 2 the steps wrap the *existing* sensor arsenal (the loop
re-orders / conditionally runs them); Phase 3 adds AI-synthesized probes behind the
ExecutionKernel. Steps are idempotent and bounded; the MemoryStore dedups equivalent runs.

The director executes a step's `run(ctx)`, which performs the work (mutating `ctx.art`,
emitting additive events, returning observations as plain dicts) and appends those observations
to the EvidenceGraph. Steps never raise into the loop — `run` is wrapped fail-soft by the
director.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from src.reasoning.state import ReasoningState


@dataclass
class StepContext:
    """Everything a step needs to run. Mirrors what run_scan has in scope."""
    target: str
    state: ReasoningState
    art: dict
    emit: Callable[..., None]
    args: object = None
    completer: Optional[Callable] = None
    extras: dict = field(default_factory=dict)   # engine objects passed via closure-friendly bag


# A step's run returns a list of observation dicts: {"node_kind","node_key","kind","evidence",
# "source","data"} — the director folds these into the EvidenceGraph.
RunFn = Callable[[StepContext], list]
AppliesFn = Callable[[StepContext], bool]


@dataclass
class SensorStep:
    """One re-invokable reconnaissance action."""
    name: str
    persona: str
    run: RunFn
    applies: AppliesFn = lambda ctx: True
    base_gain: float = 1.0
    resolves: tuple = ()                          # belief-state tags it can resolve, e.g. ("version_only",)
    cost: dict = field(default_factory=lambda: {"time_ms": 1000, "tokens": 0, "probes": 1})
    is_passive: bool = False                      # True = runs before AI config (pass 1 default sweep)

    def probe_spec(self, target: str) -> dict:
        """Identity for MemoryStore dedup — one entry per (step, target)."""
        return {"transport": "sensor", "protocol": self.name,
                "target_host": target, "target_port": None, "request_spec": {}}
