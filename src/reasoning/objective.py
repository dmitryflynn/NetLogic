from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Literal


@dataclass(frozen=True)
class ObjectiveSource:
    """Provenance for WHY an objective exists (Phase 8). Mirrors KnowledgeSource.

    As objectives come from many producers (generators, deltas, the planner, AI hypotheses, the
    operator, recurring scans), this answers "why are we investigating this?".
    """
    generated_by: str = "generator"   # generator | delta | planner | ai_hypothesis | operator | recurring
    reason: str = ""
    confidence: float = 1.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {"generated_by": self.generated_by, "reason": self.reason,
                "confidence": self.confidence, "timestamp": self.timestamp}

    @classmethod
    def from_dict(cls, d: dict | None) -> "ObjectiveSource":
        d = d or {}
        return cls(generated_by=d.get("generated_by", "generator"), reason=d.get("reason", ""),
                   confidence=float(d.get("confidence", 1.0)),
                   timestamp=float(d.get("timestamp", time.time())))


@dataclass
class Objective:
    name: str
    priority: float = 0.5
    satisfied: bool = False
    dependencies: list[str] = field(default_factory=list)
    produced_by: str = ""
    consumed_by: list[str] = field(default_factory=list)
    host_scope: Literal["per-host", "environment"] = "per-host"
    created_at: float = field(default_factory=time.time)
    evidence_refs: list[str] = field(default_factory=list)
    # ── Phase 8: goal-directed planning fields (all optional; existing objectives unaffected) ──
    goal_predicate: list[dict] = field(default_factory=list)   # serialized Predicate specs (AND-ed)
    constraints: dict = field(default_factory=dict)            # planner constraints (e.g. max_steps)
    risk_budget: str = "read_only"                             # max risk tier the planner may use
    source: ObjectiveSource = field(default_factory=ObjectiveSource)
    # ── Track C / C2: evidence types this objective needs gathered (EvidenceType values). When set,
    # it overrides the static prefix→evidence table so an AI-invented objective becomes investigable
    # by the ordinary Phase-3 loop (generate_intents reads it). Empty ⇒ fall back to the static map. ──
    desired_evidence: tuple[str, ...] = ()

    def predicate_satisfied(self, facts: dict) -> bool:
        """True iff the goal predicate holds against `facts`. No predicate → falls back to `satisfied`."""
        if not self.goal_predicate:
            return self.satisfied
        from src.reasoning.actions import Predicate, satisfied  # noqa: PLC0415
        return satisfied([Predicate.from_spec(p) for p in self.goal_predicate], facts)

    def to_dict(self) -> dict:
        return {"name": self.name, "priority": self.priority, "satisfied": self.satisfied,
                "dependencies": list(self.dependencies), "produced_by": self.produced_by,
                "consumed_by": list(self.consumed_by), "host_scope": self.host_scope,
                "created_at": self.created_at, "evidence_refs": list(self.evidence_refs),
                "goal_predicate": list(self.goal_predicate), "constraints": dict(self.constraints),
                "risk_budget": self.risk_budget, "source": self.source.to_dict(),
                "desired_evidence": list(self.desired_evidence)}

    @classmethod
    def from_dict(cls, data: dict) -> Objective:
        return cls(name=data["name"], priority=float(data.get("priority", 0.5)),
                   satisfied=bool(data.get("satisfied", False)),
                   dependencies=list(data.get("dependencies", [])),
                   produced_by=data.get("produced_by", ""),
                   consumed_by=list(data.get("consumed_by", [])),
                   host_scope=data.get("host_scope", "per-host"),
                   created_at=float(data.get("created_at", time.time())),
                   evidence_refs=list(data.get("evidence_refs", [])),
                   goal_predicate=list(data.get("goal_predicate", [])),
                   constraints=dict(data.get("constraints", {})),
                   risk_budget=data.get("risk_budget", "read_only"),
                   source=ObjectiveSource.from_dict(data.get("source")),
                   desired_evidence=tuple(data.get("desired_evidence", []) or ()))


class ObjectiveDAG:
    def __init__(self) -> None:
        self._objectives: dict[str, Objective] = {}

    def add(self, obj: Objective) -> None:
        if obj.name in self._objectives:
            return
        if self._would_cycle(obj.name, obj.dependencies):
            raise ValueError(f"Adding {obj.name} would create a cycle")
        self._objectives[obj.name] = obj

    def _would_cycle(self, name: str, deps: list[str], visited: set[str] | None = None) -> bool:
        if visited is None:
            visited = set()
        for dep in deps:
            if dep == name:
                return True
            if dep in visited:
                continue
            visited.add(dep)
            dep_obj = self._objectives.get(dep)
            if dep_obj and self._would_cycle(dep, dep_obj.dependencies, visited):
                return True
        return False

    def get(self, name: str) -> Objective | None:
        return self._objectives.get(name)

    def all(self) -> list[Objective]:
        return list(self._objectives.values())

    def ready(self) -> list[Objective]:
        return [o for o in self._objectives.values()
                if not o.satisfied and all(d in self._objectives and self._objectives[d].satisfied
                                           for d in o.dependencies)]

    def unsatisfied(self) -> list[Objective]:
        return [o for o in self._objectives.values() if not o.satisfied]

    def satisfy(self, name: str, evidence_refs: list[str] | None = None) -> None:
        obj = self._objectives.get(name)
        if obj is None:
            raise KeyError(f"Objective '{name}' not found")
        obj.satisfied = True
        if evidence_refs:
            obj.evidence_refs.extend(evidence_refs)

    def reprioritize(self, name: str, new_priority: float) -> None:
        obj = self._objectives.get(name)
        if obj is None:
            raise KeyError(f"Objective '{name}' not found")
        obj.priority = max(0.0, min(1.0, new_priority))

    def dependency_path(self, name: str) -> list[str]:
        result: list[str] = []
        visited: set[str] = set()
        def _walk(n: str) -> None:
            if n in visited:
                return
            visited.add(n)
            obj = self._objectives.get(n)
            if obj:
                for dep in obj.dependencies:
                    _walk(dep)
                result.append(n)
        _walk(name)
        return result

    def topological_sort(self) -> list[Objective]:
        visited: set[str] = set()
        result: list[Objective] = []
        def _visit(name: str) -> None:
            if name in visited:
                return
            visited.add(name)
            obj = self._objectives.get(name)
            if obj:
                for dep in obj.dependencies:
                    _visit(dep)
                result.append(obj)
        for name in list(self._objectives.keys()):
            _visit(name)
        return result

    def remove(self, name: str) -> None:
        self._objectives.pop(name, None)

    def to_dict(self) -> list[dict]:
        return [o.to_dict() for o in self._objectives.values()]

    @classmethod
    def from_dict(cls, data: list[dict]) -> ObjectiveDAG:
        dag = cls()
        for item in data:
            dag.add(Objective.from_dict(item))
        return dag

    def __len__(self) -> int:
        return len(self._objectives)

    def __contains__(self, name: str) -> bool:
        return name in self._objectives
