from __future__ import annotations


from src.reasoning.intent import EvidenceType
from src.reasoning.investigation_graph import (
    EndpointInfo,
    EndpointResolver,
    EvidenceRequest,
    InvestigationGraph,
)
from src.reasoning.primitive_registry import PrimitiveRegistry
from src.reasoning.probe_plan import (
    ProbePlan,
    ProbePlanGraph,
    ProbeSpec,
)


class ExecutionPlanner:
    """Translates an InvestigationGraph (what evidence we need) into a
    ProbePlanGraph (how to gather it). Pure and deterministic."""

    def __init__(self, registry: PrimitiveRegistry,
                 endpoint_resolver: EndpointResolver | None = None) -> None:
        self._registry = registry
        self._resolver = endpoint_resolver or EndpointResolver()

    def plan(self, graph: InvestigationGraph,
             known_ports: list[dict] | None = None) -> ProbePlanGraph:
        plan_graph = ProbePlanGraph()
        satisfied: set[str] = set()
        for req in graph.root_requests():
            plans = self._plan_request(req, known_ports)
            for p in plans:
                plan_graph.add(p)
                satisfied.add(req.id)
        for req in graph.all():
            if req.id not in satisfied:
                deps_satisfied = all(
                    d.target_id in satisfied
                    for d in req.dependencies
                    if d.dep_type.value == "requires"
                )
                if deps_satisfied:
                    plans = self._plan_request(req, known_ports)
                    for p in plans:
                        plan_graph.add(p)
                        satisfied.add(req.id)
        return plan_graph

    def _plan_request(self, req: EvidenceRequest,
                      known_ports: list[dict] | None = None) -> list[ProbePlan]:
        endpoints = self._resolver.resolve(req.target_ref, known_ports or [])
        ev_type = EvidenceType(req.evidence_type) if req.evidence_type in EvidenceType._value2member_map_ else None
        if ev_type is None:
            return self._generic_plan(req, endpoints)

        primitives = self._registry.produces(ev_type)
        if not primitives:
            return self._generic_plan(req, endpoints)

        plans: list[ProbePlan] = []
        for prim in primitives:
            for ep in (endpoints or [EndpointInfo(host=req.target_ref)]):
                spec = ProbeSpec(
                    transport=ep.transport,
                    protocol=prim.requires[0] if prim.requires else ep.protocol,
                    target_host=ep.host,
                    target_port=ep.port,
                    tls=ep.tls,
                    request_spec={"primitive": prim.name},   # lets the executor pick a backend
                )
                plan = ProbePlan(
                    spec=spec,
                    metadata={"primitive": prim.name, "evidence_type": req.evidence_type,
                              "evidence_request_id": req.id, "rationale": req.rationale,
                              # risk + cost propagated so the kernel's safety validators can act
                              "risk": prim.risk,
                              "cost": {"time_ms": prim.cost.time_ms, "tokens": prim.cost.tokens,
                                       "probes": prim.cost.probes}},
                )
                plans.append(plan)
        return plans

    def _generic_plan(self, req: EvidenceRequest,
                      endpoints: list[EndpointInfo]) -> list[ProbePlan]:
        plans: list[ProbePlan] = []
        for ep in (endpoints or [EndpointInfo(host=req.target_ref)]):
            spec = ProbeSpec(
                protocol=ep.protocol or "tcp",
                target_host=ep.host,
                target_port=ep.port,
                tls=ep.tls,
            )
            plan = ProbePlan(
                spec=spec,
                metadata={"evidence_type": req.evidence_type,
                          "evidence_request_id": req.id,
                          "rationale": req.rationale,
                          "risk": "read_only"},   # generic plans are read-only by construction
            )
            plans.append(plan)
        return plans
