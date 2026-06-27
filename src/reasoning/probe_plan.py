from __future__ import annotations

import uuid
from dataclasses import dataclass, field as dc_field
from enum import Enum
from typing import Any, Literal


class ConditionOp(Enum):
    EQ = "eq"
    NE = "ne"
    GT = "gt"
    LT = "lt"
    CONTAINS = "contains"
    MATCHES = "matches"
    AND = "and"
    OR = "or"
    NOT = "not"
    EXISTS = "exists"
    TRUST = "trust"


@dataclass
class Condition:
    op: ConditionOp
    field: str = ""
    value: Any = None
    conditions: list[Condition] = dc_field(default_factory=list)

    def evaluate(self, data: dict) -> bool:
        if self.op == ConditionOp.TRUST:
            return True
        if self.op == ConditionOp.AND:
            return all(c.evaluate(data) for c in self.conditions)
        if self.op == ConditionOp.OR:
            return any(c.evaluate(data) for c in self.conditions)
        if self.op == ConditionOp.NOT:
            return not self.conditions[0].evaluate(data) if self.conditions else True
        actual = data.get(self.field)
        if self.op == ConditionOp.EXISTS:
            return actual is not None
        if self.op == ConditionOp.EQ:
            return actual == self.value
        if self.op == ConditionOp.NE:
            return actual != self.value
        if self.op == ConditionOp.GT:
            try:
                return float(actual) > float(self.value)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                return False
        if self.op == ConditionOp.LT:
            try:
                return float(actual) < float(self.value)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                return False
        if self.op == ConditionOp.CONTAINS:
            return str(self.value).lower() in str(actual).lower()  # type: ignore[arg-type]
        if self.op == ConditionOp.MATCHES:
            import re
            try:
                return bool(re.search(str(self.value), str(actual)))  # type: ignore[arg-type]
            except re.error:
                return False
        return True

    def to_dict(self) -> dict:
        d: dict = {"op": self.op.value}
        if self.field:
            d["field"] = self.field
        if self.value is not None:
            d["value"] = self.value
        if self.conditions:
            d["conditions"] = [c.to_dict() for c in self.conditions]
        return d

    @classmethod
    def from_dict(cls, data: dict) -> Condition:
        conds = [cls.from_dict(c) for c in data.get("conditions", [])]
        return cls(op=ConditionOp(data["op"]), field=data.get("field", ""),
                   value=data.get("value"), conditions=conds)


@dataclass
class ProbeSpec:
    id: str = ""
    transport: str = "tcp"
    protocol: str = ""
    target_host: str = ""
    target_port: int = 0
    request_spec: dict = dc_field(default_factory=dict)
    tls: bool = False
    timeout_s: float = 5.0

    def __post_init__(self) -> None:
        if not self.id:
            self.id = uuid.uuid4().hex[:12]

    def to_dict(self) -> dict:
        return {"id": self.id, "transport": self.transport, "protocol": self.protocol,
                "target_host": self.target_host, "target_port": self.target_port,
                "request_spec": dict(self.request_spec), "tls": self.tls,
                "timeout_s": self.timeout_s}

    @classmethod
    def from_dict(cls, data: dict) -> ProbeSpec:
        return cls(id=data.get("id", ""), transport=data.get("transport", "tcp"),
                   protocol=data.get("protocol", ""),
                   target_host=data.get("target_host", ""),
                   target_port=int(data.get("target_port", 0)),
                   request_spec=dict(data.get("request_spec", {})),
                   tls=bool(data.get("tls", False)),
                   timeout_s=float(data.get("timeout_s", 5.0)))

    @property
    def key(self) -> str:
        import hashlib, json
        raw = json.dumps({"transport": self.transport, "protocol": self.protocol,
                          "host": self.target_host, "port": self.target_port,
                          "request": self.request_spec}, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()[:24]


@dataclass
class ProbePlan:
    spec: ProbeSpec
    condition: Condition | None = None
    depends_on: list[str] = dc_field(default_factory=list)
    metadata: dict = dc_field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"spec": self.spec.to_dict(),
                "condition": self.condition.to_dict() if self.condition else None,
                "depends_on": list(self.depends_on),
                "metadata": dict(self.metadata)}

    @classmethod
    def from_dict(cls, data: dict) -> ProbePlan:
        cond = Condition.from_dict(data["condition"]) if data.get("condition") else None
        return cls(spec=ProbeSpec.from_dict(data["spec"]),
                   condition=cond,
                   depends_on=list(data.get("depends_on", [])),
                   metadata=dict(data.get("metadata", {})))


@dataclass
class ProbePlanGraph:
    plans: dict[str, ProbePlan] = dc_field(default_factory=dict)

    def add(self, plan: ProbePlan) -> None:
        self.plans[plan.spec.id] = plan

    def get(self, plan_id: str) -> ProbePlan | None:
        return self.plans.get(plan_id)

    def root_plans(self) -> list[ProbePlan]:
        return [p for p in self.plans.values() if not p.depends_on]

    def ready_plans(self, completed_ids: set[str]) -> list[ProbePlan]:
        return [p for p in self.plans.values()
                if p.spec.id not in completed_ids
                and all(d in completed_ids for d in p.depends_on)]

    def all_plans(self) -> list[ProbePlan]:
        return list(self.plans.values())

    def to_dict(self) -> list[dict]:
        return [p.to_dict() for p in self.plans.values()]

    @classmethod
    def from_dict(cls, data: list[dict]) -> ProbePlanGraph:
        g = cls()
        for item in data:
            g.add(ProbePlan.from_dict(item))
        return g

    def __len__(self) -> int:
        return len(self.plans)


class PlanWalker:
    """Iterates over a ProbePlanGraph in dependency order."""

    def __init__(self, graph: ProbePlanGraph) -> None:
        self._graph = graph
        self._completed: set[str] = set()
        self._paused: dict[str, str] = {}

    def next_ready(self) -> list[ProbePlan]:
        return self._graph.ready_plans(self._completed)

    def mark_completed(self, plan_id: str) -> None:
        self._completed.add(plan_id)

    def mark_failed(self, plan_id: str) -> None:
        self._completed.add(plan_id)

    @property
    def completed(self) -> set[str]:
        return self._completed

    @property
    def is_exhausted(self) -> bool:
        return len(self._completed) >= len(self._graph)
