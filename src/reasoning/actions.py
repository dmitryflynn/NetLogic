"""
Action model (Phase 8) — the atoms of goal-directed investigation.

An Action is a **descriptor**, not a payload: it declares *what must be true to attempt it*
(preconditions) and *what becomes true if it succeeds* (effects), plus a risk tier and references
(CVE/CWE/technique ids). The core ships descriptors only — never weaponized exploit code.

Two deliberately separated concerns (so the model can grow — cost/latency/retries/detection_risk/
cooldown/resources — without bloating one flat object, the Candidate/WorldState lesson again):
  • `ActionDescriptor` — identity + risk + citations.
  • `ActionSemantics` — preconditions + effects, as predicates over world facts.

Predicates are tiny, declarative, and evaluable against a flat `facts` dict (the planner's view of
the world model). `read_only < safe_active < intrusive < exploit` is the risk ordering the kernel
gates on (Phase 8b); the core never *executes* anything above `safe_active`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class RiskTier(IntEnum):
    """Ordered risk tiers. The kernel denies anything above the configured ceiling (default READ_ONLY)."""
    READ_ONLY = 0
    SAFE_ACTIVE = 1      # low-impact read-safe verification (e.g. a benign reachability/boolean check)
    INTRUSIVE = 2        # state-touching; external authorized executor only
    EXPLOIT = 3          # exploitation; external authorized executor only

    @classmethod
    def parse(cls, value) -> "RiskTier":
        if isinstance(value, RiskTier):
            return value
        if isinstance(value, int):
            return cls(value)
        return _RISK_BY_NAME.get(str(value).strip().lower(), cls.READ_ONLY)


_RISK_BY_NAME = {
    "read_only": RiskTier.READ_ONLY, "safe_active": RiskTier.SAFE_ACTIVE,
    "intrusive": RiskTier.INTRUSIVE, "exploit": RiskTier.EXPLOIT,
}


# ── Predicates over world facts ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class Predicate:
    """A declarative condition over a flat facts dict: facts[key] <op> value.

    `op` ∈ {exists, eq, ne, contains, lt, gt, true}. Predicates are the shared language of
    preconditions, effects, and goal predicates — pure, deterministic, no IO.
    """
    key: str
    op: str = "exists"
    value: object = None

    def evaluate(self, facts: dict) -> bool:
        actual = facts.get(self.key)
        if self.op == "true":
            return True
        if self.op == "exists":
            return actual is not None
        if self.op == "eq":
            return actual == self.value
        if self.op == "ne":
            return actual != self.value
        if self.op == "contains":
            try:
                return self.value in actual  # type: ignore[operator]
            except TypeError:
                return False
        if self.op in ("lt", "gt"):
            try:
                a, v = float(actual), float(self.value)  # type: ignore[arg-type]
                return a < v if self.op == "lt" else a > v
            except (TypeError, ValueError):
                return False
        return False

    def to_dict(self) -> dict:
        return {"key": self.key, "op": self.op, "value": self.value}

    @classmethod
    def from_dict(cls, d: dict) -> "Predicate":
        return cls(key=d["key"], op=d.get("op", "exists"), value=d.get("value"))

    @classmethod
    def from_spec(cls, spec) -> "Predicate":
        """Parse from YAML-friendly shapes: 'tech=wordpress', 'port_open:443', {key,op,value}, or 'framework_known'."""
        if isinstance(spec, Predicate):
            return spec
        if isinstance(spec, dict):
            return cls.from_dict(spec)
        s = str(spec)
        for sep, op in (("=", "eq"), (":", "exists")):
            if sep in s:
                k, _, v = s.partition(sep)
                if op == "exists":
                    return cls(key=s, op="exists")  # 'port_open:443' → presence of the literal key
                return cls(key=k.strip(), op=op, value=_coerce(v.strip()))
        return cls(key=s.strip(), op="exists")


def _coerce(v: str):
    try:
        return int(v)
    except ValueError:
        try:
            return float(v)
        except ValueError:
            return v


def satisfied(preds, facts: dict) -> bool:
    """True iff every predicate holds against `facts`."""
    return all(p.evaluate(facts) for p in preds)


# ── Action: descriptor + semantics ───────────────────────────────────────────────────

@dataclass(frozen=True)
class ActionDescriptor:
    """Identity, risk, and citations. No behavior, no payload."""
    id: str
    name: str = ""
    technique_ref: str = ""              # e.g. an ATT&CK / technique id
    risk_tier: RiskTier = RiskTier.READ_ONLY
    references: tuple[str, ...] = ()      # CVE/CWE/URL citations

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "technique_ref": self.technique_ref,
                "risk_tier": self.risk_tier.name.lower(), "references": list(self.references)}


@dataclass(frozen=True)
class ActionSemantics:
    """Preconditions to attempt + effects if it succeeds. Predicates over world facts."""
    preconditions: tuple[Predicate, ...] = ()
    effects: tuple[Predicate, ...] = ()

    def applicable(self, facts: dict) -> bool:
        return satisfied(self.preconditions, facts)

    def apply(self, facts: dict) -> dict:
        """Return a NEW facts dict with effects asserted (hypothetical during planning)."""
        out = dict(facts)
        for e in self.effects:
            if e.op in ("eq", "exists"):
                out[e.key] = e.value if e.op == "eq" else True
        return out


@dataclass(frozen=True)
class Action:
    """A descriptor + its semantics. The unit a Strategy yields and the planner chains."""
    descriptor: ActionDescriptor
    semantics: ActionSemantics = field(default_factory=ActionSemantics)

    @property
    def id(self) -> str:
        return self.descriptor.id

    @property
    def risk_tier(self) -> RiskTier:
        return self.descriptor.risk_tier

    def applicable(self, facts: dict) -> bool:
        return self.semantics.applicable(facts)

    def apply(self, facts: dict) -> dict:
        return self.semantics.apply(facts)

    def to_dict(self) -> dict:
        return {"descriptor": self.descriptor.to_dict(),
                "preconditions": [p.to_dict() for p in self.semantics.preconditions],
                "effects": [e.to_dict() for e in self.semantics.effects]}

    @classmethod
    def from_dict(cls, d: dict) -> "Action":
        desc = d.get("descriptor", d)
        return cls(
            descriptor=ActionDescriptor(
                id=desc["id"], name=desc.get("name", ""),
                technique_ref=desc.get("technique_ref", ""),
                risk_tier=RiskTier.parse(desc.get("risk_tier", "read_only")),
                references=tuple(desc.get("references", []))),
            semantics=ActionSemantics(
                preconditions=tuple(Predicate.from_spec(p) for p in d.get("preconditions", [])),
                effects=tuple(Predicate.from_spec(e) for e in d.get("effects", []))))


class ActionLibrary:
    """Compiled, immutable catalog of action descriptors (compiled once, like PackCompiler)."""

    def __init__(self, actions: dict[str, Action] | None = None) -> None:
        self._actions = actions or {}

    def register(self, action: Action) -> None:
        self._actions[action.id] = action

    def get(self, action_id: str) -> Action | None:
        return self._actions.get(action_id)

    def all(self) -> list[Action]:
        return list(self._actions.values())

    def __len__(self) -> int:
        return len(self._actions)

    @classmethod
    def from_specs(cls, specs: list[dict]) -> "ActionLibrary":
        lib = cls()
        for spec in specs or []:
            try:
                lib.register(Action.from_dict(spec))
            except Exception:  # noqa: BLE001 — a bad descriptor is skipped, not fatal
                pass
        return lib
