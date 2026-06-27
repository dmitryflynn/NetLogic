from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from src.reasoning.intent import EvidenceType, ProbeCost


@dataclass
class Primitive:
    name: str
    produces: list[EvidenceType] = field(default_factory=list)
    requires: list[str] = field(default_factory=list)     # e.g. "HTTP", "TLS"
    cost: ProbeCost = field(default_factory=ProbeCost)
    risk: Literal["read_only", "safe", "invasive"] = "read_only"
    confidence_gain: float = 0.1
    description: str = ""


class PrimitiveRegistry:
    """Purely declarative catalog of probe primitives. No ranking, no planning state."""

    def __init__(self) -> None:
        self._primitives: dict[str, Primitive] = {}

    def register(self, primitive: Primitive) -> None:
        self._primitives[primitive.name] = primitive

    def register_many(self, *primitives: Primitive) -> None:
        for p in primitives:
            self._primitives[p.name] = p

    def get(self, name: str) -> Primitive | None:
        return self._primitives.get(name)

    def produces(self, evidence_type: EvidenceType) -> list[Primitive]:
        return [p for p in self._primitives.values() if evidence_type in p.produces]

    def requires(self, requirement: str) -> list[Primitive]:
        return [p for p in self._primitives.values() if requirement in p.requires]

    def all(self) -> list[Primitive]:
        return list(self._primitives.values())

    def __len__(self) -> int:
        return len(self._primitives)


def default_registry() -> PrimitiveRegistry:
    """Return a registry pre-loaded with standard network primitives."""
    r = PrimitiveRegistry()
    r.register_many(
        Primitive(name="http_head", produces=[EvidenceType.HTTP_HEADERS, EvidenceType.SERVER_HEADER],
                  requires=["HTTP"], cost=ProbeCost(500, 0, 1), risk="read_only",
                  confidence_gain=0.15, description="HTTP HEAD request for headers only"),
        Primitive(name="http_get", produces=[EvidenceType.HTTP_BODY, EvidenceType.COOKIE_SET,
                                             EvidenceType.FAVICON_HASH, EvidenceType.FRAMEWORK],
                  requires=["HTTP"], cost=ProbeCost(1000, 200, 1), risk="read_only",
                  confidence_gain=0.2, description="HTTP GET request for full response"),
        Primitive(name="tls_connect", produces=[EvidenceType.TLS_VERSION, EvidenceType.TLS_ALPN,
                                                EvidenceType.SERVER_HEADER],
                  requires=["TLS"], cost=ProbeCost(1000, 0, 1), risk="read_only",
                  confidence_gain=0.12, description="TLS handshake probe"),
        Primitive(name="dns_lookup", produces=[EvidenceType.DNS_RECORDS],
                  requires=[], cost=ProbeCost(500, 0, 0), risk="read_only",
                  confidence_gain=0.08, description="DNS resolution query"),
        Primitive(name="service_banner", produces=[EvidenceType.BANNER, EvidenceType.SERVICE],
                  requires=[], cost=ProbeCost(2000, 0, 1), risk="read_only",
                  confidence_gain=0.1, description="TCP banner grab"),
        Primitive(name="port_scan", produces=[EvidenceType.OPEN_PORT],
                  requires=[], cost=ProbeCost(5000, 0, 100), risk="read_only",
                  confidence_gain=0.3, description="Port scan"),
        Primitive(name="web_fingerprint", produces=[EvidenceType.FRAMEWORK, EvidenceType.TECHNOLOGY],
                  requires=["HTTP"], cost=ProbeCost(3000, 500, 3), risk="read_only",
                  confidence_gain=0.25, description="Web application fingerprinting"),
        Primitive(name="stack_fingerprint", produces=[EvidenceType.TECHNOLOGY],
                  requires=["HTTP"], cost=ProbeCost(2000, 100, 2), risk="read_only",
                  confidence_gain=0.2, description="OS/stack fingerprint via HTTP"),
        Primitive(name="osint_query", produces=[EvidenceType.OSINT, EvidenceType.ASN_INFO],
                  requires=[], cost=ProbeCost(3000, 1000, 0), risk="read_only",
                  confidence_gain=0.15, description="Passive OSINT data collection"),
    )
    return r
