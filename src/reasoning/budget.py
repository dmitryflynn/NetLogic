"""
BudgetManager — the loop's hard ceilings.

See the Phase 2 plan §1 and design §11.1. The reasoning loop fires real (existing) probes and
makes LLM calls, so it must be bounded: wall-clock, tokens, probe count, and recursion depth.
Hosted scans use conservative defaults for predictable cost; local `--gui` may raise them. The
manager owns `ExecutionState.budget`; exhaustion is a stopping condition.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

# Tier defaults. Hosted is conservative; local can be raised by the user.
_TIERS = {
    "hosted": {"max_wall_clock_s": 120.0, "max_tokens": 40_000, "max_probes": 40, "max_recursion": 6},
    "local":  {"max_wall_clock_s": 600.0, "max_tokens": 200_000, "max_probes": 200, "max_recursion": 12},
}


@dataclass
class BudgetManager:
    max_wall_clock_s: float = 120.0
    max_tokens: int = 40_000
    max_probes: int = 40
    max_recursion: int = 6
    started_at: float = field(default_factory=time.time)
    tokens_used: int = 0
    probes_run: int = 0
    depth: int = 0
    # Phase 6c: optional scan-wide parent. A per-host budget also debits the global aggregate, so
    # no host may exceed the global ceiling. Resource-only (tokens/probes/wall-clock); recursion
    # `depth` stays a per-host concept and is NOT propagated to the global parent.
    parent: Optional["BudgetManager"] = None

    @classmethod
    def for_tier(cls, tier: str = "hosted", **overrides) -> "BudgetManager":
        cfg = dict(_TIERS.get(tier, _TIERS["hosted"]))
        cfg.update({k: v for k, v in overrides.items() if v is not None})
        return cls(**cfg)

    # ── Queries ───────────────────────────────────────────────────────────────────
    def elapsed_s(self) -> float:
        return time.time() - self.started_at

    def can_afford(self, cost: Optional[dict] = None) -> bool:
        cost = cost or {}
        ok = (
            self.elapsed_s() < self.max_wall_clock_s
            and self.tokens_used + int(cost.get("tokens", 0)) <= self.max_tokens
            and self.probes_run + int(cost.get("probes", 1)) <= self.max_probes
            and self.depth < self.max_recursion
        )
        if ok and self.parent is not None:
            ok = self.parent._can_afford_resources(cost)
        return ok

    def _can_afford_resources(self, cost: Optional[dict] = None) -> bool:
        """Resource-only affordability (no recursion-depth gate) — used for the global aggregate."""
        cost = cost or {}
        return (
            self.elapsed_s() < self.max_wall_clock_s
            and self.tokens_used + int(cost.get("tokens", 0)) <= self.max_tokens
            and self.probes_run + int(cost.get("probes", 1)) <= self.max_probes
        )

    def exhausted(self) -> bool:
        mine = (
            self.elapsed_s() >= self.max_wall_clock_s
            or self.tokens_used >= self.max_tokens
            or self.probes_run >= self.max_probes
            or self.depth >= self.max_recursion
        )
        if mine:
            return True
        return self.parent is not None and self.parent._resources_exhausted()

    def _resources_exhausted(self) -> bool:
        return (
            self.elapsed_s() >= self.max_wall_clock_s
            or self.tokens_used >= self.max_tokens
            or self.probes_run >= self.max_probes
        )

    # ── Spend ─────────────────────────────────────────────────────────────────────
    def spend(self, cost: Optional[dict] = None) -> None:
        cost = cost or {}
        self.tokens_used += int(cost.get("tokens", 0))
        self.probes_run += int(cost.get("probes", 1))
        self.depth += 1
        if self.parent is not None:
            self.parent._spend_resources(cost)

    def _spend_resources(self, cost: Optional[dict] = None) -> None:
        """Debit only resources on the global aggregate (no depth increment)."""
        cost = cost or {}
        self.tokens_used += int(cost.get("tokens", 0))
        self.probes_run += int(cost.get("probes", 1))

    def to_dict(self) -> dict:
        return {
            "max_wall_clock_s": self.max_wall_clock_s, "max_tokens": self.max_tokens,
            "max_probes": self.max_probes, "max_recursion": self.max_recursion,
            "elapsed_s": round(self.elapsed_s(), 2), "tokens_used": self.tokens_used,
            "probes_run": self.probes_run, "depth": self.depth, "exhausted": self.exhausted(),
        }
