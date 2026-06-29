"""
Action gating (Phase 8b) — defense-in-depth before any action above read-only.

For eight phases the kernel has been fail-closed read-only. Phase 8 introduces the *concept* of
higher-risk actions but the **core never executes them**: this gate is the boundary. Multiple
INDEPENDENT validators each deny by default; removing any one never opens execution.

Hard rules baked in:
  • The core's enforceable ceiling is `SAFE_ACTIVE`. `INTRUSIVE`/`EXPLOIT` actions require an
    explicit **external authorized executor** that is absent by default → denied. The core ships no
    offensive execution.
  • Authorization is an explicit, per-engagement token: target-scoped, risk-capped, expiring. Never
    an env/config default; never derivable from AI output or reasoning state.
  • Gating keys on the action's **risk tier**, never on the objective's name.

`ActionGate.evaluate(...)` returns a `GateDecision` and appends an audit record for every attempt.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from src.reasoning.actions import Action, RiskTier

# The maximum tier the core itself will ever execute. Above this requires an external executor.
CORE_MAX_TIER = RiskTier.SAFE_ACTIVE


def _in_scope(target: str, scope: list[str]) -> bool:
    """Mirror execution_kernel.validate_scope at the host level (CFAA boundary)."""
    host = (target or "").strip().lower()
    if host.count(":") == 1:
        host = host.split(":", 1)[0]
    if not scope:
        return False
    for s in scope:
        s = (s or "").strip().lower()
        if s.count(":") == 1:
            s = s.split(":", 1)[0]
        if host == s or host.endswith("." + s):
            return True
    return False


@dataclass(frozen=True)
class AuthorizationToken:
    """Explicit per-engagement authorization. Constructed only from operator input — never from AI
    or reasoning state."""
    targets: tuple[str, ...]
    max_risk_tier: RiskTier
    expires_at: float
    issued_for: str = ""             # engagement / ticket id

    def permits(self, action: Action, target: str, now: float | None = None) -> bool:
        now = now if now is not None else time.time()
        if now >= self.expires_at:
            return False
        if action.risk_tier > self.max_risk_tier:
            return False
        return _in_scope(target, list(self.targets))


@dataclass
class GateContext:
    """Everything the gate needs. All execution-enabling fields default to the safe state."""
    scope: list[str] = field(default_factory=list)
    risk_ceiling: RiskTier = RiskTier.READ_ONLY        # max tier allowed this run
    active_validation_enabled: bool = False            # permits SAFE_ACTIVE
    execution_authorized: bool = False                 # permits INTRUSIVE/EXPLOIT (with token + executor)
    authorization: AuthorizationToken | None = None
    allow_irreversible: bool = False
    external_executor: object | None = None            # injected only for an authorized engagement
    kill_switch: bool = False
    now: float | None = None


@dataclass
class GateDecision:
    allowed: bool
    denials: tuple[str, ...] = ()
    risk_tier: str = "read_only"

    def to_dict(self) -> dict:
        return {"allowed": self.allowed, "denials": list(self.denials), "risk_tier": self.risk_tier}


@dataclass
class AuditRecord:
    action_id: str
    target: str
    risk_tier: str
    allowed: bool
    denials: tuple[str, ...]
    objective: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {"action_id": self.action_id, "target": self.target, "risk_tier": self.risk_tier,
                "allowed": self.allowed, "denials": list(self.denials), "objective": self.objective,
                "timestamp": self.timestamp}


class AuditLog:
    """Append-only record of every gating decision."""

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    def append(self, record: AuditRecord) -> None:
        self._records.append(record)

    def records(self) -> list[AuditRecord]:
        return list(self._records)

    def __len__(self) -> int:
        return len(self._records)


# ── Independent validators (defense in depth: each returns a denial reason or None) ──

def _v_kill_switch(action, target, ctx):
    return "kill_switch engaged" if ctx.kill_switch else None


def _v_scope(action, target, ctx):
    return None if _in_scope(target, ctx.scope) else f"target {target} not in scope"


def _v_reversibility(action, target, ctx):
    reversible = getattr(action.descriptor, "reversible", True)
    if not reversible and not ctx.allow_irreversible:
        return "irreversible action requires allow_irreversible"
    return None


def _v_risk_ceiling(action, target, ctx):
    # effective ceiling = the run ceiling, raised to SAFE_ACTIVE only if active validation is on.
    ceiling = ctx.risk_ceiling
    if ctx.active_validation_enabled and ceiling < RiskTier.SAFE_ACTIVE:
        ceiling = RiskTier.SAFE_ACTIVE
    if action.risk_tier > ceiling:
        return f"risk {action.risk_tier.name.lower()} exceeds ceiling {ceiling.name.lower()}"
    return None


def _v_authorization(action, target, ctx):
    if action.risk_tier <= RiskTier.SAFE_ACTIVE:
        return None                                   # read_only / safe_active need no token
    # INTRUSIVE / EXPLOIT:
    if not ctx.execution_authorized:
        return "execution not authorized"
    if ctx.authorization is None or not ctx.authorization.permits(action, target, ctx.now):
        return "no valid authorization token for this action/target"
    return None


def _v_core_ceiling(action, target, ctx):
    # The core NEVER executes above SAFE_ACTIVE; higher tiers need an external executor.
    if action.risk_tier > CORE_MAX_TIER and ctx.external_executor is None:
        return "above core ceiling: requires external authorized executor (absent)"
    return None


_VALIDATORS = (_v_kill_switch, _v_scope, _v_reversibility, _v_risk_ceiling,
               _v_authorization, _v_core_ceiling)


class ActionGate:
    """Composes every validator (any denial → deny) and audits the decision."""

    def __init__(self, audit: AuditLog | None = None) -> None:
        self.audit = audit or AuditLog()

    def evaluate(self, action: Action, target: str, ctx: GateContext,
                 objective: str = "") -> GateDecision:
        denials = tuple(d for d in (v(action, target, ctx) for v in _VALIDATORS) if d)
        decision = GateDecision(allowed=not denials, denials=denials,
                                risk_tier=action.risk_tier.name.lower())
        self.audit.append(AuditRecord(
            action_id=action.id, target=target, risk_tier=decision.risk_tier,
            allowed=decision.allowed, denials=denials, objective=objective))
        return decision
