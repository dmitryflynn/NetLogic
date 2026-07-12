from __future__ import annotations


from src.reasoning.intent import Intent, IntentConstraints
from src.reasoning.investigation_graph import (
    Dependency,
    DependencyType,
    EvidenceRequest,
    InvestigationGraph,
)


class Compiler:
    """Compiles one Intent into an InvestigationGraph of EvidenceRequests.
    Purely deterministic — no ranking, no scoring, no heuristics."""

    def __init__(self) -> None:
        pass

    def compile(self, intent: Intent, known_ports: list[dict] | None = None) -> InvestigationGraph:
        graph = InvestigationGraph()
        for ev_type in intent.desired_evidence:
            # EvidenceRequest is a frozen contract — build dependencies first, then construct.
            dependencies = self._infer_dependencies(ev_type.value, known_ports)
            req = EvidenceRequest(
                evidence_type=ev_type.value,
                target_ref=intent.target_ref,
                protocol_hints=list(intent.protocol_hints),
                dependencies=dependencies,
                rationale=f"{intent.goal}: need {ev_type.value}",
            )
            graph.add(req)
        return graph

    def _infer_dependencies(self, evidence_type: str,
                             known_ports: list[dict] | None = None) -> list[Dependency]:
        deps: list[Dependency] = []
        if evidence_type in ("server_header", "http_headers", "http_body",
                             "cookie_set", "framework", "technology") and known_ports:
            has_open_port = any(p.get("port") in (80, 443, 8080, 8443)
                                and str(p.get("state", "") or "") == "open"
                                for p in known_ports)
            if not has_open_port:
                deps.append(Dependency(DependencyType.REQUIRES, "open_http_port"))
        if evidence_type in ("tls_version", "tls_alpn") and known_ports:
            has_tls = any(p.get("tls", False) or p.get("port") in (443, 8443)
                          for p in known_ports)
            if not has_tls:
                deps.append(Dependency(DependencyType.REQUIRES, "tls_port"))
        return deps

    def compile_many(self, intents: list[Intent],
                     known_ports: list[dict] | None = None) -> InvestigationGraph:
        graph = InvestigationGraph()
        for intent in intents:
            sub = self.compile(intent, known_ports)
            for req in sub.all():
                graph.add(req)
        return graph

    @staticmethod
    def estimate_intent_cost(intent: Intent) -> dict:
        base = {"time_ms": 1000, "tokens": 0, "probes": 1}
        if IntentConstraints.max_cost in ("high",):
            base["time_ms"] *= 3
            base["tokens"] *= 2
            base["probes"] *= 3
        return base
