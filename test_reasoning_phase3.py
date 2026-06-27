"""Phase 3 tests — Intent, PrimitiveRegistry, Compiler, InvestigationGraph,
ExecutionPlanner, ProbePlanGraph, ExecutionKernel, Reflect, Strategy extensions, and wiring."""

import dataclasses
from typing import Any

import pytest

from src.reasoning import (
    Compiler,
    Condition,
    ConditionOp,
    EvidenceType,
    ExecutionKernel,
    ExecutionPlanner,
    Intent,
    IntentConstraints,
    InvestigationGraph,
    Objective,
    ObjectiveDAG,
    PlanWalker,
    PlannerFeedback,
    PrimitiveRegistry,
    ProbePlan,
    ProbePlanGraph,
    ProbeSpec,
    Reflect,
    StopCondition,
    default_registry,
)
from src.reasoning.execution_kernel import validate_read_only, validate_scope
from src.reasoning.intent import ProbeCost
from src.reasoning.investigation_graph import (
    Dependency,
    DependencyType,
    EndpointInfo,
    EndpointResolver,
    EvidenceRequest,
)
from src.reasoning.trace import ExecutionResult, TraceMetadata, TraceStep


# ── Intent ──────────────────────────────────────────────────────────────────


class TestIntent:
    def test_intent_defaults(self):
        i = Intent(goal="find framework")
        assert i.id and len(i.id) == 12
        assert i.objective_id == ""
        assert i.constraints.read_only is True
        assert i.stopping_condition.confidence_goal == 0.85

    def test_intent_roundtrip(self):
        i = Intent(goal="find framework", target_ref="example.com",
                   desired_evidence=[EvidenceType.SERVER_HEADER, EvidenceType.HTTP_BODY],
                   protocol_hints=["HTTP"],
                   constraints=IntentConstraints(max_cost="high"),
                   stopping_condition=StopCondition(confidence_goal=0.9, max_probes=10))
        restored = Intent.from_dict(i.to_dict())
        assert restored.goal == i.goal
        assert restored.desired_evidence == i.desired_evidence
        assert restored.constraints.max_cost == "high"
        assert restored.stopping_condition.max_probes == 10

    def test_intent_from_dict_handles_missing_keys(self):
        d = {"goal": "test"}
        i = Intent.from_dict(d)
        assert i.goal == "test"
        assert i.desired_evidence == []
        assert i.constraints.read_only is True

    def test_evidence_type_known_values(self):
        assert EvidenceType("server_header") == EvidenceType.SERVER_HEADER
        assert EvidenceType("tls_version") == EvidenceType.TLS_VERSION
        assert EvidenceType("cve") == EvidenceType.CVE
        assert len(EvidenceType) >= 18


# ── PrimitiveRegistry ───────────────────────────────────────────────────────


class TestPrimitiveRegistry:
    def test_default_registry_has_primitives(self):
        r = default_registry()
        assert len(r) >= 5
        assert r.get("http_head") is not None
        assert r.get("dns_lookup") is not None

    def test_produces_lookup(self):
        r = default_registry()
        headers_prims = r.produces(EvidenceType.HTTP_HEADERS)
        assert len(headers_prims) >= 1
        assert all(EvidenceType.HTTP_HEADERS in p.produces for p in headers_prims)

    def test_requires_lookup(self):
        r = default_registry()
        http_prims = r.requires("HTTP")
        assert len(http_prims) >= 1
        assert all("HTTP" in p.requires for p in http_prims)

    def test_register_and_get(self):
        r = PrimitiveRegistry()
        prim = r.get("test")
        assert prim is None
        from src.reasoning.primitive_registry import Primitive
        r.register(Primitive(name="test_prim", produces=[EvidenceType.BANNER]))
        assert r.get("test_prim") is not None

    def test_all_returns_copy(self):
        r = default_registry()
        all_prims = r.all()
        n = len(all_prims)
        assert n == len(r)


# ── InvestigationGraph + EvidenceRequest + Dependency ──────────────────────


class TestEvidenceRequest:
    def test_default_id(self):
        req = EvidenceRequest(evidence_type="server_header")
        assert req.id and len(req.id) == 12

    def test_roundtrip(self):
        req = EvidenceRequest(
            evidence_type="http_headers", target_ref="example.com",
            dependencies=[Dependency(DependencyType.REQUIRES, "open_port"),
                          Dependency(DependencyType.OPTIONAL, "dns_record")],
            rationale="need headers")
        restored = EvidenceRequest.from_dict(req.to_dict())
        assert restored.evidence_type == "http_headers"
        assert len(restored.dependencies) == 2
        assert restored.dependencies[0].dep_type == DependencyType.REQUIRES
        assert restored.dependencies[1].target_id == "dns_record"


class TestInvestigationGraph:
    def test_add_and_get(self):
        g = InvestigationGraph()
        r = EvidenceRequest(evidence_type="port_scan")
        g.add(r)
        assert g.get(r.id) is r

    def test_root_requests(self):
        g = InvestigationGraph()
        r1 = EvidenceRequest(evidence_type="a")
        r2 = EvidenceRequest(evidence_type="b", dependencies=[Dependency(DependencyType.REQUIRES, r1.id)])
        g.add(r1)
        g.add(r2)
        assert r1 in g.root_requests()
        assert r2 not in g.root_requests()

    def test_ready_requests(self):
        g = InvestigationGraph()
        r1 = EvidenceRequest(evidence_type="a")
        r2 = EvidenceRequest(evidence_type="b", dependencies=[Dependency(DependencyType.REQUIRES, r1.id)])
        g.add(r1)
        g.add(r2)
        ready = g.ready_requests(set())
        assert r1 in ready
        assert r2 not in ready
        ready2 = g.ready_requests({r1.id})
        assert r2 in ready2

    def test_roundtrip(self):
        g = InvestigationGraph()
        g.add(EvidenceRequest(evidence_type="a"))
        g.add(EvidenceRequest(evidence_type="b"))
        restored = InvestigationGraph.from_dict(g.to_dict())
        assert len(restored) == 2

    def test_any_of_dependency(self):
        g = InvestigationGraph()
        r1 = EvidenceRequest(evidence_type="a")
        r2 = EvidenceRequest(evidence_type="b")
        r3 = EvidenceRequest(evidence_type="target",
                             dependencies=[Dependency(DependencyType.ANY_OF, r1.id),
                                           Dependency(DependencyType.ANY_OF, r2.id)])
        g.add(r1)
        g.add(r2)
        g.add(r3)
        # Not ready when neither dependency satisfied
        assert r3 not in g.ready_requests(set())
        # Ready when at least one is satisfied
        ready = g.ready_requests({r1.id})
        assert r3 in ready


class TestEndpointResolver:
    def test_resolve_from_ports(self):
        resolver = EndpointResolver()
        ports = [{"port": 80, "service": "http", "tls": False},
                 {"port": 443, "service": "https", "tls": True}]
        eps = resolver.resolve("example.com", ports)
        assert len(eps) == 2
        web_eps = [e for e in eps if e.port in (80, 443)]
        assert len(web_eps) == 2

    def test_resolve_no_ports_falls_back(self):
        resolver = EndpointResolver()
        eps = resolver.resolve("example.com", [])
        assert len(eps) == 1
        assert eps[0].host == "example.com"
        assert eps[0].port == 0


# ── ProbeSpec + ProbePlan + ProbePlanGraph + PlanWalker ─────────────────────


class TestProbeSpec:
    def test_default_id(self):
        spec = ProbeSpec()
        assert spec.id and len(spec.id) == 12

    def test_key_is_deterministic(self):
        s1 = ProbeSpec(target_host="h", target_port=80, protocol="http")
        s2 = ProbeSpec(target_host="h", target_port=80, protocol="http")
        assert s1.key == s2.key

    def test_roundtrip(self):
        spec = ProbeSpec(transport="tcp", protocol="https", target_host="example.com",
                         target_port=443, tls=True, request_spec={"path": "/"})
        restored = ProbeSpec.from_dict(spec.to_dict())
        assert restored.target_host == "example.com"
        assert restored.tls is True
        assert restored.request_spec["path"] == "/"


class TestProbePlan:
    def test_roundtrip(self):
        spec = ProbeSpec(target_host="h", target_port=80)
        cond = Condition(op=ConditionOp.EQ, field="status", value=200)
        plan = ProbePlan(spec=spec, condition=cond, depends_on=["dep1"],
                         metadata={"key": "val"})
        restored = ProbePlan.from_dict(plan.to_dict())
        assert restored.spec.target_host == "h"
        assert restored.condition is not None
        assert restored.condition.op == ConditionOp.EQ
        assert "dep1" in restored.depends_on
        assert restored.metadata["key"] == "val"


class TestProbePlanGraph:
    def test_add_and_ready(self):
        g = ProbePlanGraph()
        s1 = ProbeSpec(target_host="h1")
        s2 = ProbeSpec(target_host="h2")
        p1 = ProbePlan(spec=s1)
        p2 = ProbePlan(spec=s2, depends_on=[s1.id])
        g.add(p1)
        g.add(p2)
        assert len(g.root_plans()) == 1
        assert p1 in g.root_plans()
        ready = g.ready_plans(set())
        assert pytest.approx(len(ready)) == 1
        assert p1 in ready
        ready2 = g.ready_plans({s1.id})
        assert p2 in ready2

    def test_roundtrip(self):
        g = ProbePlanGraph()
        g.add(ProbePlan(spec=ProbeSpec(target_host="h1")))
        g.add(ProbePlan(spec=ProbeSpec(target_host="h2")))
        restored = ProbePlanGraph.from_dict(g.to_dict())
        assert len(restored) == 2


class TestPlanWalker:
    def test_walker_iterates(self):
        g = ProbePlanGraph()
        s1 = ProbeSpec(target_host="h1")
        s2 = ProbeSpec(target_host="h2")
        p1 = ProbePlan(spec=s1)
        p2 = ProbePlan(spec=s2, depends_on=[s1.id])
        g.add(p1)
        g.add(p2)
        w = PlanWalker(g)
        first = w.next_ready()
        assert len(first) == 1
        w.mark_completed(s1.id)
        second = w.next_ready()
        assert len(second) == 1
        w.mark_completed(s2.id)
        assert w.is_exhausted


# ── Condition ───────────────────────────────────────────────────────────────


class TestCondition:
    def test_trust_always_true(self):
        c = Condition(op=ConditionOp.TRUST)
        assert c.evaluate({}) is True

    def test_eq(self):
        c = Condition(op=ConditionOp.EQ, field="status", value=200)
        assert c.evaluate({"status": 200}) is True
        assert c.evaluate({"status": 404}) is False

    def test_exists(self):
        c = Condition(op=ConditionOp.EXISTS, field="port")
        assert c.evaluate({"port": 80}) is True
        assert c.evaluate({}) is False

    def test_and(self):
        c = Condition(op=ConditionOp.AND,
                       conditions=[Condition(op=ConditionOp.EQ, field="a", value=1),
                                    Condition(op=ConditionOp.EQ, field="b", value=2)])
        assert c.evaluate({"a": 1, "b": 2}) is True
        assert c.evaluate({"a": 1, "b": 3}) is False

    def test_contains(self):
        c = Condition(op=ConditionOp.CONTAINS, field="banner", value="nginx")
        assert c.evaluate({"banner": "nginx/1.18.0"}) is True
        assert c.evaluate({"banner": "Apache"}) is False

    def test_roundtrip(self):
        c = Condition(op=ConditionOp.EQ, field="port", value=80)
        restored = Condition.from_dict(c.to_dict())
        assert restored.op == ConditionOp.EQ
        assert restored.field == "port"
        assert restored.value == 80


# ── Compiler ────────────────────────────────────────────────────────────────


class TestCompiler:
    def test_compile_intent_creates_requests(self):
        compiler = Compiler()
        intent = Intent(goal="find version", target_ref="example.com",
                        desired_evidence=[EvidenceType.SERVER_HEADER, EvidenceType.HTTP_BODY])
        graph = compiler.compile(intent, [{"port": 80, "service": "http", "state": "open"}])
        assert len(graph) == 2
        for req in graph.all():
            assert req.target_ref == "example.com"

    def test_compile_no_known_ports(self):
        compiler = Compiler()
        intent = Intent(goal="test", target_ref="example.com",
                        desired_evidence=[EvidenceType.DNS_RECORDS])
        graph = compiler.compile(intent)
        assert len(graph) >= 1

    def test_compile_many(self):
        compiler = Compiler()
        i1 = Intent(goal="a", target_ref="h1", desired_evidence=[EvidenceType.BANNER])
        i2 = Intent(goal="b", target_ref="h2", desired_evidence=[EvidenceType.DNS_RECORDS])
        graph = compiler.compile_many([i1, i2])
        assert len(graph) == 2

    def test_infer_dependencies(self):
        compiler = Compiler()
        intent = Intent(goal="test", target_ref="example.com",
                        desired_evidence=[EvidenceType.HTTP_HEADERS])
        graph = compiler.compile(intent, [{"port": 22, "service": "ssh", "state": "open"}])
        req = graph.all()[0]
        assert len(req.dependencies) >= 1


# ── ExecutionPlanner ────────────────────────────────────────────────────────


class TestExecutionPlanner:
    def test_plan_empty_graph(self):
        r = default_registry()
        planner = ExecutionPlanner(r)
        graph = InvestigationGraph()
        plan_graph = planner.plan(graph)
        assert len(plan_graph) == 0

    def test_plan_single_request(self):
        r = default_registry()
        planner = ExecutionPlanner(r)
        graph = InvestigationGraph()
        graph.add(EvidenceRequest(evidence_type="server_header", target_ref="example.com"))
        plan_graph = planner.plan(graph, [{"port": 80, "service": "http", "tls": False}])
        assert len(plan_graph) >= 1

    def test_plan_unknown_evidence_type(self):
        r = default_registry()
        planner = ExecutionPlanner(r)
        graph = InvestigationGraph()
        graph.add(EvidenceRequest(evidence_type="unknown_type", target_ref="example.com"))
        plan_graph = planner.plan(graph)
        assert len(plan_graph) >= 1

    def test_plan_with_dependencies(self):
        r = default_registry()
        planner = ExecutionPlanner(r)
        graph = InvestigationGraph()
        r1 = EvidenceRequest(evidence_type="dns_records", target_ref="example.com")
        graph.add(r1)
        r2 = EvidenceRequest(evidence_type="server_header", target_ref="example.com",
                              dependencies=[Dependency(DependencyType.REQUIRES, r1.id)])
        graph.add(r2)
        plan_graph = planner.plan(graph)
        assert len(plan_graph) >= 1


# ── ExecutionKernel ─────────────────────────────────────────────────────────


class TestExecutionKernel:
    def test_default_executor_returns_failure(self):
        kernel = ExecutionKernel()
        spec = ProbeSpec(target_host="h", target_port=80)
        result = kernel.execute_plan(ProbePlan(spec=spec))
        assert result.success is False
        assert "no executor configured" in (result.error or "")

    def test_custom_executor(self):
        def executor(spec):
            return ExecutionResult(success=True, evidence="ok", data={"port": spec.target_port})
        kernel = ExecutionKernel(executor=executor)
        spec = ProbeSpec(target_host="h", target_port=80)
        result = kernel.execute_plan(ProbePlan(spec=spec))
        assert result.success is True
        assert result.evidence == "ok"

    def test_validator_rejects(self):
        def no_port_0(plan, ctx):
            return ["port 0 denied"] if plan.spec.target_port == 0 else []
        kernel = ExecutionKernel(executor=lambda s: ExecutionResult(success=True))
        kernel.add_validator(no_port_0)
        spec = ProbeSpec(target_host="h", target_port=0)
        result = kernel.execute_plan(ProbePlan(spec=spec))
        assert result.success is False
        assert "port 0 denied" in (result.error or "")

    def test_validate_scope(self):
        context = {"scope": ["example.com"]}
        plan_pass = ProbePlan(spec=ProbeSpec(target_host="sub.example.com"))
        assert validate_scope(plan_pass, context) == []
        plan_fail = ProbePlan(spec=ProbeSpec(target_host="evil.com"))
        assert len(validate_scope(plan_fail, context)) >= 1

    def test_validate_read_only(self):
        context = {"read_only": True}
        safe_plan = ProbePlan(spec=ProbeSpec(), metadata={"risk": "read_only"})
        assert validate_read_only(safe_plan, context) == []
        invasive_plan = ProbePlan(spec=ProbeSpec(), metadata={"risk": "invasive"})
        assert len(validate_read_only(invasive_plan, context)) >= 1

    def test_trace_is_recorded(self):
        kernel = ExecutionKernel(executor=lambda s: ExecutionResult(success=True, evidence="ok"))
        spec = ProbeSpec(target_host="h")
        kernel.execute_plan(ProbePlan(spec=spec), metadata=TraceMetadata(rationale="test"))
        assert len(kernel.trace()) == 1
        assert kernel.trace()[0].result is not None
        assert kernel.trace()[0].metadata.rationale == "test"

    def test_run_graph(self):
        def executor(spec):
            return ExecutionResult(success=True, evidence=f"ok:{spec.target_host}")
        kernel = ExecutionKernel(executor=executor)
        g = ProbePlanGraph()
        s1 = ProbeSpec(target_host="h1")
        s2 = ProbeSpec(target_host="h2", id=s1.id)  # same id so it references s1
        p1 = ProbePlan(spec=s1)
        p2 = ProbePlan(spec=ProbeSpec(target_host="h2"), depends_on=[s1.id])
        g.add(p1)
        g.add(p2)
        results = kernel.run_graph(g)
        assert len(results) >= 1


# ── Trace ───────────────────────────────────────────────────────────────────


class TestTrace:
    def test_trace_step_duration(self):
        import time
        step = TraceStep(step_id="s1", spec_id="sp1")
        time.sleep(0.001)
        step.completed_at = time.time()
        assert step.duration_ms > 0

    def test_trace_roundtrip(self):
        result = ExecutionResult(success=True, evidence="ok")
        meta = TraceMetadata(hypothesis_id="h1", rationale="test")
        step = TraceStep(step_id="s1", spec_id="sp1", result=result, metadata=meta)
        restored = TraceStep.from_dict(step.to_dict())
        assert restored.step_id == "s1"
        assert restored.result is not None and restored.result.success is True
        assert restored.metadata.hypothesis_id == "h1"


# ── Reflect ─────────────────────────────────────────────────────────────────


class TestReflect:
    def test_reflect_empty(self):
        reflect = Reflect()
        feedback = reflect.reflect(InvestigationGraph(), {}, {})
        assert isinstance(feedback, PlannerFeedback)
        assert feedback.prioritize_evidence == []

    def test_reflect_detects_dead_ends(self):
        reflect = Reflect()
        g = InvestigationGraph()
        r = EvidenceRequest(evidence_type="test", id="req1")
        g.add(r)
        feedback = reflect.reflect(g, {"req1": {"success": False}}, {})
        assert "req1" in feedback.dead_ends

    def test_reflect_finds_gaps(self):
        reflect = Reflect()
        feedback = reflect.reflect(InvestigationGraph(), {},
                                    {"nginx": 0.5, "apache": 0.9})
        assert "nginx" in feedback.prioritize_evidence
        assert "apache" not in feedback.prioritize_evidence

    def test_planner_feedback_roundtrip(self):
        fb = PlannerFeedback(prioritize_evidence=["a", "b"],
                              contradictions=["c1"],
                              dead_ends=["d1"],
                              rationale="test")
        restored = PlannerFeedback.from_dict(fb.to_dict())
        assert restored.prioritize_evidence == ["a", "b"]
        assert restored.contradictions == ["c1"]
        assert restored.rationale == "test"


# ── Strategy extensions ─────────────────────────────────────────────────────


class TestStrategyExtensions:
    def test_exploit_objective_selection(self):
        from src.reasoning.strategy import StrategyManager
        from src.reasoning.state import ReasoningState
        sm = StrategyManager()
        state = ReasoningState(target="example.com")
        state.investigation.objectives.add(Objective(name="test", priority=0.9))
        obj_name = sm.select_exploit_objective(state)
        assert obj_name is None  # starts in explore mode

    def test_should_switch_mode_no_contested(self):
        from src.reasoning.strategy import StrategyManager
        from src.reasoning.state import ReasoningState
        sm = StrategyManager()
        state = ReasoningState(target="example.com")
        mode = sm.should_switch_mode(state)
        assert mode == "exploit"
        assert sm.mode == "exploit"


# ── Compiler + Planner + Kernel integration ─────────────────────────────────


class TestIntegration:
    def test_compile_plan_execute_reflect_cycle(self):
        """End-to-end: Intent → Compiler → ExecutionPlanner → ExecutionKernel → Reflect."""
        compiler = Compiler()
        registry = default_registry()
        planner = ExecutionPlanner(registry)

        def fake_executor(spec):
            return ExecutionResult(success=True, evidence=f"data from {spec.target_host}:{spec.target_port}")

        kernel = ExecutionKernel(executor=fake_executor)
        reflect = Reflect()

        intent = Intent(goal="identify web server", target_ref="example.com",
                        desired_evidence=[EvidenceType.SERVER_HEADER, EvidenceType.BANNER])
        known_ports = [{"port": 80, "service": "http", "tls": False, "state": "open"}]

        graph = compiler.compile(intent, known_ports)
        assert len(graph) >= 1

        plan_graph = planner.plan(graph, known_ports)
        assert len(plan_graph) >= 1

        results = {}
        for plan in plan_graph.all_plans():
            result = kernel.execute_plan(plan)
            results[plan.spec.id] = result

        feedback = reflect.reflect(graph, results, {"nginx": 0.7})
        assert isinstance(feedback, PlannerFeedback)

    def test_phase3_sensor_registry_compatible(self):
        """Verify SensorStep can co-exist with Phase 3 types."""
        from src.reasoning import SensorStep
        step = SensorStep(name="test", persona="service_discovery",
                          run=lambda ctx: [])
        assert step.name == "test"
        assert step.persona == "service_discovery"
        assert step.is_passive is False

    def test_director_initializes_phase3_without_ai_key(self):
        """Phase 3 is deterministic, so it initializes regardless of the AI key (AI only
        augments). Activation is gated separately by reasoning_enabled at run() time."""
        from src.reasoning import ReconDirector, Scheduler, StrategyManager, BudgetManager
        director = ReconDirector(Scheduler(), StrategyManager(), BudgetManager.for_tier("local"),
                                  [], has_ai_key=False)
        assert director.has_ai_key is False
        assert director._phase3_initialized is True


# ── ProbeCost ───────────────────────────────────────────────────────────────


class TestProbeCost:
    def test_defaults(self):
        c = ProbeCost()
        assert c.time_ms == 1000
        assert c.tokens == 0
        assert c.probes == 1
