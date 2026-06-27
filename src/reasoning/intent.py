from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal


class EvidenceType(Enum):
    SERVER_HEADER = "server_header"
    TLS_VERSION = "tls_version"
    TLS_ALPN = "tls_alpn"
    COOKIE_SET = "cookie_set"
    FAVICON_HASH = "favicon_hash"
    FRAMEWORK = "framework"
    SSH_BANNER = "ssh_banner"
    HTTP_HEADERS = "http_headers"
    HTTP_BODY = "http_body"
    DNS_RECORDS = "dns_records"
    ASN_INFO = "asn_info"
    BANNER = "banner"
    TECHNOLOGY = "technology"
    OPEN_PORT = "open_port"
    SERVICE = "service"
    VERSION = "version"
    CVE = "cve"
    MISCONFIGURATION = "misconfiguration"
    TOPOLOGY = "topology"
    REACHABILITY = "reachability"
    OSINT = "osint"


@dataclass
class ProbeCost:
    time_ms: int = 1000
    tokens: int = 0
    probes: int = 1


@dataclass
class IntentConstraints:
    read_only: bool = True
    max_cost: str = "medium"  # "low" | "medium" | "high"
    max_depth: int = 5


@dataclass
class StopCondition:
    confidence_goal: float = 0.85
    max_probes: int = 15


@dataclass
class Intent:
    id: str = ""
    objective_id: str = ""
    hypothesis_id: str | None = None
    target_ref: str = ""
    goal: str = ""
    desired_evidence: list[EvidenceType] = field(default_factory=list)
    protocol_hints: list[str] = field(default_factory=list)
    constraints: IntentConstraints = field(default_factory=IntentConstraints)
    stopping_condition: StopCondition = field(default_factory=StopCondition)
    rationale: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            self.id = uuid.uuid4().hex[:12]

    def to_dict(self) -> dict:
        return {"id": self.id, "objective_id": self.objective_id,
                "hypothesis_id": self.hypothesis_id, "target_ref": self.target_ref,
                "goal": self.goal,
                "desired_evidence": [e.value for e in self.desired_evidence],
                "protocol_hints": list(self.protocol_hints),
                "constraints": {"read_only": self.constraints.read_only,
                                "max_cost": self.constraints.max_cost,
                                "max_depth": self.constraints.max_depth},
                "stopping_condition": {"confidence_goal": self.stopping_condition.confidence_goal,
                                       "max_probes": self.stopping_condition.max_probes},
                "rationale": self.rationale}

    @classmethod
    def from_dict(cls, data: dict) -> Intent:
        evs = [EvidenceType(v) for v in data.get("desired_evidence", [])
               if v in EvidenceType._value2member_map_]
        cons = data.get("constraints", {}) or {}
        stop = data.get("stopping_condition", {}) or {}
        return cls(id=data.get("id", ""), objective_id=data.get("objective_id", ""),
                   hypothesis_id=data.get("hypothesis_id"),
                   target_ref=data.get("target_ref", ""), goal=data.get("goal", ""),
                   desired_evidence=evs, protocol_hints=list(data.get("protocol_hints", [])),
                   constraints=IntentConstraints(
                       read_only=bool(cons.get("read_only", True)),
                       max_cost=cons.get("max_cost", "medium"),
                       max_depth=int(cons.get("max_depth", 5))),
                   stopping_condition=StopCondition(
                       confidence_goal=float(stop.get("confidence_goal", 0.85)),
                       max_probes=int(stop.get("max_probes", 15))),
                   rationale=data.get("rationale", ""))
