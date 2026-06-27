from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TraceMetadata:
    hypothesis_id: str | None = None
    objective_id: str | None = None
    evidence_request_id: str | None = None
    rationale: str = ""
    probe_sequence: int = 0

    def to_dict(self) -> dict:
        return {"hypothesis_id": self.hypothesis_id,
                "objective_id": self.objective_id,
                "evidence_request_id": self.evidence_request_id,
                "rationale": self.rationale,
                "probe_sequence": self.probe_sequence}

    @classmethod
    def from_dict(cls, data: dict) -> TraceMetadata:
        return cls(hypothesis_id=data.get("hypothesis_id"),
                   objective_id=data.get("objective_id"),
                   evidence_request_id=data.get("evidence_request_id"),
                   rationale=data.get("rationale", ""),
                   probe_sequence=int(data.get("probe_sequence", 0)))


@dataclass
class ExecutionResult:
    success: bool = False
    data: dict = field(default_factory=dict)
    evidence: str = ""
    latency_ms: float = 0.0
    error: str | None = None
    status_code: int | None = None

    def to_dict(self) -> dict:
        return {"success": self.success, "data": dict(self.data),
                "evidence": self.evidence, "latency_ms": self.latency_ms,
                "error": self.error, "status_code": self.status_code}

    @classmethod
    def from_dict(cls, data: dict) -> ExecutionResult:
        return cls(success=bool(data.get("success", False)),
                   data=dict(data.get("data", {})),
                   evidence=data.get("evidence", ""),
                   latency_ms=float(data.get("latency_ms", 0.0)),
                   error=data.get("error"),
                   status_code=data.get("status_code"))


@dataclass
class TraceStep:
    step_id: str
    spec_id: str
    result: ExecutionResult | None = None
    metadata: TraceMetadata = field(default_factory=TraceMetadata)
    started_at: float = field(default_factory=time.time)
    completed_at: float | None = None

    @property
    def duration_ms(self) -> float:
        if self.completed_at is not None:
            return (self.completed_at - self.started_at) * 1000
        return (time.time() - self.started_at) * 1000

    def to_dict(self) -> dict:
        return {"step_id": self.step_id, "spec_id": self.spec_id,
                "result": self.result.to_dict() if self.result else None,
                "metadata": self.metadata.to_dict(),
                "started_at": self.started_at,
                "completed_at": self.completed_at}

    @classmethod
    def from_dict(cls, data: dict) -> TraceStep:
        res = ExecutionResult.from_dict(data["result"]) if data.get("result") else None
        meta = TraceMetadata.from_dict(data.get("metadata", {}))
        return cls(step_id=data["step_id"], spec_id=data["spec_id"],
                   result=res, metadata=meta,
                   started_at=float(data.get("started_at", time.time())),
                   completed_at=data.get("completed_at"))
