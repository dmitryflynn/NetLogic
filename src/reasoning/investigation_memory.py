"""
InvestigationMemory (Phase 8a) — don't repeat what already failed, until the world changes.

The planner consults this to **skip strategies that already failed** for a goal — *until change
detection (Phase 7) shows the relevant observations moved*. This is where Phase 7 pays off twice: a
re-scan re-attempts only what the world made worth re-attempting, instead of grinding the same dead
strategies every time.

A `StrategyAttempt` records (goal, strategy, outcome, confidence gained, cost, timestamp) plus a
**world fingerprint** — a hash of the facts relevant to the goal at attempt time. A failed strategy
is skipped while the fingerprint is unchanged; a different fingerprint (the world moved) makes it
eligible again.

Isolation invariant (carried forward from learned_patterns): memory informs **ordering / skip only**.
It never writes confidence, beliefs, hypotheses, or evidence.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field


def world_fingerprint(facts: dict) -> str:
    """Stable hash of the facts relevant to a goal. Two identical worlds → identical fingerprint."""
    blob = json.dumps(facts or {}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class StrategyAttempt:
    goal: str
    strategy_id: str
    outcome: str                  # "failed" | "succeeded" | "partial"
    confidence_gained: float = 0.0
    cost: float = 0.0
    world_fingerprint: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {"goal": self.goal, "strategy_id": self.strategy_id, "outcome": self.outcome,
                "confidence_gained": self.confidence_gained, "cost": self.cost,
                "world_fingerprint": self.world_fingerprint, "timestamp": self.timestamp}

    @classmethod
    def from_dict(cls, d: dict) -> "StrategyAttempt":
        return cls(goal=d["goal"], strategy_id=d["strategy_id"], outcome=d.get("outcome", "failed"),
                   confidence_gained=float(d.get("confidence_gained", 0.0)),
                   cost=float(d.get("cost", 0.0)),
                   world_fingerprint=d.get("world_fingerprint", ""),
                   timestamp=float(d.get("timestamp", time.time())))


class InvestigationMemory:
    """Cross-scan, goal-keyed record of strategy attempts. Generalizes the per-scan MemoryStore."""

    def __init__(self) -> None:
        self._attempts: list[StrategyAttempt] = []

    def record(self, goal: str, strategy_id: str, outcome: str, *, facts: dict | None = None,
               confidence_gained: float = 0.0, cost: float = 0.0) -> None:
        self._attempts.append(StrategyAttempt(
            goal=goal, strategy_id=strategy_id, outcome=outcome,
            confidence_gained=confidence_gained, cost=cost,
            world_fingerprint=world_fingerprint(facts or {})))

    def should_skip(self, goal: str, strategy_id: str, facts: dict) -> bool:
        """Skip a strategy that FAILED for this goal while the world (fingerprint) is unchanged.
        A changed world makes it eligible again."""
        fp = world_fingerprint(facts or {})
        for a in self._attempts:
            if a.goal == goal and a.strategy_id == strategy_id and a.outcome == "failed" \
                    and a.world_fingerprint == fp:
                return True
        return False

    def attempts_for(self, goal: str) -> list[StrategyAttempt]:
        return [a for a in self._attempts if a.goal == goal]

    def to_dict(self) -> dict:
        return {"attempts": [a.to_dict() for a in self._attempts]}

    @classmethod
    def from_dict(cls, d: dict | None) -> "InvestigationMemory":
        d = d or {}
        mem = cls()
        mem._attempts = [StrategyAttempt.from_dict(a) for a in d.get("attempts", [])]
        return mem
