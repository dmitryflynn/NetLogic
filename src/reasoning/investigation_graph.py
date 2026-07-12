from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum


class DependencyType(Enum):
    REQUIRES = "requires"
    OPTIONAL = "optional"
    ALTERNATIVE = "alternative"
    ANY_OF = "any_of"
    ALL_OF = "all_of"


@dataclass
class Dependency:
    dep_type: DependencyType
    target_id: str

    def to_dict(self) -> dict:
        return {"dep_type": self.dep_type.value, "target_id": self.target_id}

    @classmethod
    def from_dict(cls, data: dict) -> Dependency:
        return cls(dep_type=DependencyType(data["dep_type"]),
                   target_id=data["target_id"])


@dataclass(frozen=True)
class EvidenceRequest:
    """The Compiler→ExecutionPlanner contract. Frozen (like Observation/Intent/ProbeSpec/
    ExecutionResult/TraceStep) so this stable boundary can't become a hidden mutable interface;
    build dependencies up front and construct, never mutate in place."""
    id: str = ""
    evidence_type: str = ""             # EvidenceType.value
    target_ref: str = ""
    protocol_hints: list[str] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    rationale: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            object.__setattr__(self, "id", uuid.uuid4().hex[:12])

    def to_dict(self) -> dict:
        return {"id": self.id, "evidence_type": self.evidence_type,
                "target_ref": self.target_ref,
                "protocol_hints": list(self.protocol_hints),
                "dependencies": [d.to_dict() for d in self.dependencies],
                "rationale": self.rationale}

    @classmethod
    def from_dict(cls, data: dict) -> EvidenceRequest:
        deps = [Dependency.from_dict(d) for d in data.get("dependencies", [])]
        return cls(id=data.get("id", ""), evidence_type=data.get("evidence_type", ""),
                   target_ref=data.get("target_ref", ""),
                   protocol_hints=list(data.get("protocol_hints", [])),
                   dependencies=deps, rationale=data.get("rationale", ""))


@dataclass
class EndpointInfo:
    host: str = ""
    port: int = 0
    transport: str = "tcp"
    protocol: str = ""
    tls: bool = False

    def to_dict(self) -> dict:
        return {"host": self.host, "port": self.port, "transport": self.transport,
                "protocol": self.protocol, "tls": self.tls}

    @classmethod
    def from_dict(cls, data: dict) -> EndpointInfo:
        return cls(host=data.get("host", ""), port=int(data.get("port", 0)),
                   transport=data.get("transport", "tcp"),
                   protocol=data.get("protocol", ""),
                   tls=bool(data.get("tls", False)))


@dataclass
class InvestigationGraph:
    requests: dict[str, EvidenceRequest] = field(default_factory=dict)

    def add(self, req: EvidenceRequest) -> None:
        self.requests[req.id] = req

    def get(self, req_id: str) -> EvidenceRequest | None:
        return self.requests.get(req_id)

    def all(self) -> list[EvidenceRequest]:
        return list(self.requests.values())

    def root_requests(self) -> list[EvidenceRequest]:
        return [r for r in self.requests.values() if not r.dependencies]

    def ready_requests(self, satisfied_ids: set[str]) -> list[EvidenceRequest]:
        def _satisfied(req: EvidenceRequest) -> bool:
            for dep in req.dependencies:
                if dep.dep_type in (DependencyType.REQUIRES, DependencyType.ALL_OF):
                    if dep.target_id not in satisfied_ids:
                        return False
                elif dep.dep_type == DependencyType.ANY_OF:
                    if not any(d.target_id in satisfied_ids for d in req.dependencies
                               if d.dep_type == DependencyType.ANY_OF):
                        return False
                elif dep.dep_type == DependencyType.OPTIONAL:
                    continue
                elif dep.dep_type == DependencyType.ALTERNATIVE:
                    continue
            return True
        return [r for r in self.requests.values()
                if r.id not in satisfied_ids and _satisfied(r)]

    def to_dict(self) -> list[dict]:
        return [r.to_dict() for r in self.requests.values()]

    @classmethod
    def from_dict(cls, data: list[dict]) -> InvestigationGraph:
        g = cls()
        for item in data:
            g.add(EvidenceRequest.from_dict(item))
        return g

    def __len__(self) -> int:
        return len(self.requests)


class EndpointResolver:
    """Maps target_ref strings to concrete EndpointInfo. Pure and stateless."""

    def resolve(self, target_ref: str, known_ports: list[dict]) -> list[EndpointInfo]:
        endpoints: list[EndpointInfo] = []
        for p in known_ports:
            port = int(p.get("port", 0))
            service = str(p.get("service", "") or "")
            tls = bool(p.get("tls", False))
            host = target_ref
            if target_ref.startswith("http://") or target_ref.startswith("https://"):
                from urllib.parse import urlparse
                parsed = urlparse(target_ref)
                host = parsed.hostname or host
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                tls = parsed.scheme == "https"
                service = parsed.scheme
                endpoints.append(EndpointInfo(host=host, port=port,
                                              protocol=service, tls=tls))
            elif "/" in target_ref:
                endpoints.append(EndpointInfo(host=host, port=0,
                                              protocol="generic"))
            else:
                endpoints.append(
                    EndpointInfo(host=host, port=port,
                                 protocol=("https" if tls else service or "tcp"),
                                 tls=tls))
        return endpoints or [EndpointInfo(host=target_ref, port=0, protocol="generic")]
