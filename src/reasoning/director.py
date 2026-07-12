"""
ReconDirector — the stateless observe→reason→act loop.

See the Phase 2 plan §3 and design §2.2/§7.1. The director runs one investigation loop over a
ReasoningState: select persona (StrategyManager) → score + pick an action (Scheduler) → run it
(a SensorStep over the existing arsenal) → fold observations into the EvidenceGraph → recompute
confidence → record the probe → repeat until a stopping condition.

Phase 3 extends the loop: after the sensor sweep satisfies stopping, the director runs the
Compiler → ExecutionPlanner → ExecutionKernel → Reflect cycle to generate and execute AI-driven
probe plans.

It is **stateless**: everything lives in the passed-in ReasoningState (which can be loaded from
persistence), and the director persists it at the boundary.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Optional

from src.reasoning.budget import BudgetManager
from src.reasoning.memory import MemoryStore
from src.reasoning.registry import SensorStep, StepContext
from src.reasoning.scheduler import Scheduler
from src.reasoning.state import ReasoningState
from src.reasoning.strategy import ACTIVATE_CONF, StrategyManager

log = logging.getLogger("netlogic.reasoning.director")

_HIGH_IMPACT = {"high", "critical"}


class ReconDirector:
    def __init__(self, scheduler: Scheduler, strategy: StrategyManager, budget: BudgetManager,
                 registry: list[SensorStep], *, has_ai_key: bool, ai_completer: Any | None = None,
                 refresh: Optional[Callable[[ReasoningState, dict], None]] = None,
                 persist: Optional[Callable[[ReasoningState], None]] = None,
                 executor: Any | None = None, ai_driven: bool = False) -> None:
        # ai_driven: give the AI decision authority over findings the deterministic engine can't
        # verify (capability gaps). Default OFF ⇒ the AI only ever proposes ⇒ byte-identical baseline.
        self.ai_driven = ai_driven
        self.scheduler = scheduler
        self.strategy = strategy
        self.budget = budget
        self.registry = registry
        self.has_ai_key = has_ai_key
        self.ai_completer = ai_completer
        self.refresh = refresh
        self.persist = persist
        self._executor = executor   # ProbeExecutor (default real); tests inject a fake

        # Phase 3 is deterministic (real executor + rule-based generators), so it is
        # initialized regardless of the AI key; AI only augments it. Activation is gated by
        # reasoning_enabled at run() time.
        self._phase3_initialized = False
        self._init_phase3()

    def _init_phase3(self) -> None:
        try:
            from src.reasoning import (
                Compiler, ExecutionKernel, ExecutionPlanner, PrimitiveRegistry,
                Reflect, default_registry,
            )
            from src.reasoning.execution_kernel import (
                validate_budget, validate_dedup, validate_depth,
                validate_read_only, validate_scope,
            )
            from src.reasoning.probe_executor import ProbeExecutor
            from src.reasoning.playbooks import PlaybookRegistry  # noqa: PLC0415
            from src.reasoning.capability_registry import CapabilityRegistry  # noqa: PLC0415
            self._phase3_registry: PrimitiveRegistry = default_registry()
            self._phase3_compiler = Compiler()
            self._phase3_planner = ExecutionPlanner(self._phase3_registry)
            # Real read-only executor (Phase 3 Activation) replaces the no-op default; an
            # injected executor (tests) takes precedence so unit tests stay offline.
            self._phase3_kernel = ExecutionKernel(executor=self._executor or ProbeExecutor())
            # Safety pipeline: scope (CFAA) → read-only → budget → dedup → depth.
            for v in (validate_scope, validate_read_only, validate_budget,
                      validate_dedup, validate_depth):
                self._phase3_kernel.add_validator(v)
            self._phase3_reflect = Reflect()
            # Phase 5: Playbook Registry (load playbooks from directory) + Capability Registry.
            # The capability registry is empty by default (capabilities are registered by callers);
            # an empty registry simply emits no capability candidates.
            self._playbook_registry = PlaybookRegistry()
            self._playbook_registry.load_from_dir()
            self._capability_registry = CapabilityRegistry()
            # Phase 6.5: compile the Technology Pack library ONCE and fold it into the engine —
            # pack inference rules merge with the built-in JSON rules (so fingerprinting/inference
            # is pack-driven), and pack capabilities populate the registry. A bad/absent library is
            # non-fatal: inference falls back to the built-in rules. Compiled once, reused per cycle.
            self._inference_rules = None
            try:
                import os as _os  # noqa: PLC0415
                from src.reasoning.inference import RuleLoader  # noqa: PLC0415
                from src.reasoning import packs as _packs_pkg  # noqa: PLC0415
                from src.reasoning.packs.compiler import PackCompiler  # noqa: PLC0415
                # Absolute path to the pack library so it resolves regardless of process cwd.
                _lib_dir = _os.path.join(_os.path.dirname(_packs_pkg.__file__), "library")
                lib = PackCompiler().compile_dir(_lib_dir)
                pack_rules = lib.to_inference_rules()
                if pack_rules:
                    self._inference_rules = {**RuleLoader.load(), **pack_rules}
                    # The capability registry starts empty (no caller-registered caps), so adopt
                    # the pack-derived one outright — its capabilities now drive candidate generation.
                    self._capability_registry = lib.to_capabilities()
                    log.info("loaded %d technology pack rule(s) into inference", len(pack_rules))
            except Exception as exc:  # noqa: BLE001 — packs are additive; never block init
                log.warning("technology pack load skipped (%s)", exc)
            # How many ranked playbook/capability candidates to actually instantiate per cycle.
            self._max_selected_candidates = 3
            # Phase 6c: breadth cap on multi-host expansion per scan (bounds fan-out).
            self._max_hosts = 8
            self._phase3_initialized = True
        except Exception as exc:
            log.warning("Phase 3 initialization failed (%s) — running Phase 2 only", exc)
            self._phase3_initialized = False

    def run(self, ctx: StepContext) -> ReasoningState:
        state = ctx.state
        if not self.strategy.should_activate(state, has_ai_key=self.has_ai_key, budget=self.budget):
            return state

        # Primary host: the existing single-host pipeline, unchanged. When world modeling is OFF
        # (default) this is the entire run → output byte-identical to Phase 5.
        self._reason_one_host(state, ctx, self.budget)

        # Phase 6c: live multi-host dispatch — only when explicitly enabled. The primary's own
        # budget is the scan-wide ceiling; spawned hosts get child budgets parented to it.
        if state.world_modeling_enabled and self._phase3_initialized:
            try:
                self._run_multi_host(state, ctx)
            except Exception as exc:  # noqa: BLE001 — multi-host must never break a single-host scan
                log.warning("multi-host dispatch failed (%s) — primary host result kept", exc)

        # Phase 8 (analysis-only): run the GoalPlanner over the generated objectives so the
        # read-only investigation plans / attack chains are produced and surfaced. Executes nothing
        # (the ActionGate + an absent external executor remain the only path above read-only).
        try:
            from src.reasoning.planning_pass import plan_investigations  # noqa: PLC0415
            plans = plan_investigations(state)
            state.execution.investigation_plans = plans
            if plans:
                ctx.emit("reasoning", {"event": "planned", "plans": len(plans)})
        except Exception:  # noqa: BLE001 — planning must never break a scan
            log.warning("investigation planning skipped", exc_info=True)

        # Integrity audit — catch state corruption immediately (fail-soft: log, never abort).
        try:
            from src.reasoning.reasoning_validator import ReasoningValidator  # noqa: PLC0415
            issues = ReasoningValidator().audit(state)
            if issues:
                state.execution.execution_history.append({"audit": [i.to_dict() for i in issues]})
                for i in issues:
                    if i.severity in ("error", "fatal"):
                        log.warning("reasoning audit %s [%s] %s", i.severity, i.code, i.message)
        except Exception:  # noqa: BLE001
            pass

        state.execution.budget = self.budget.to_dict()
        if self.persist:
            try:
                self.persist(state)
            except Exception:
                log.warning("reasoning persistence skipped", exc_info=True)
        return state

    def _reason_one_host(self, state: ReasoningState, ctx: StepContext, budget) -> None:
        """One host's complete reasoning pass: Phase 2 sensor sweep + Phase 3 cycle, bounded by
        `budget`. Extracted verbatim from the original single-host loop so the primary host (passed
        `self.budget`) behaves identically; spawned hosts pass a child budget parented to the global."""
        memory = MemoryStore()
        seen: set[str] = set()
        no_gain = 0
        ctx.emit("reasoning", {"event": "loop_start", "persona": state.investigation.persona})

        while True:
            persona = self.strategy.select_persona(state)
            if persona != state.investigation.persona:
                state.investigation.persona = persona
                ctx.emit("persona", {"persona": persona})

            scored = self.scheduler.select(self.registry, ctx, seen)
            best_priority = scored.priority if scored else None
            stop, reason = self.strategy.should_stop(
                state, budget=budget, best_priority=best_priority, no_gain_streak=no_gain)
            if stop:
                ctx.emit("reasoning", {"event": "stop", "reason": reason})
                break

            step = scored.step
            spec = step.probe_spec(ctx.target)
            if memory.seen(spec) or not budget.can_afford(step.cost):
                seen.add(step.name)
                continue

            before = self._contested_count(state)
            obs = self._run_step(step, ctx)
            budget.spend(step.cost)
            memory.record(spec, success=bool(obs), result_summary=step.name)
            seen.add(step.name)
            self._fold(state, obs)
            if self.refresh:
                try:
                    self.refresh(state, ctx.art)
                except Exception:
                    pass
            gained = bool(obs) or self._contested_count(state) < before
            no_gain = 0 if gained else no_gain + 1

            state.execution.execution_history.append(
                {"step": step.name, "persona": persona, "priority": best_priority,
                 "gained": gained, "rationale": scored.rationale})
            state.execution.explanations.append(
                {"decision": "probe", "evidence_ids": [], "supporting_obs": [step.name],
                 "confidence_delta": 0.0, "rule_applied": f"scheduled:{step.name}", "ai_summary": ""})
            ctx.emit("reasoning", {"event": "action", "step": step.name, "persona": persona,
                                    "priority": best_priority, "gained": gained})

        if self._phase3_initialized:
            self._run_phase3_cycle(state, ctx, budget=budget)

    def _run_multi_host(self, state: ReasoningState, ctx: StepContext) -> None:
        """Live multi-host dispatch (Phase 6c). Discovers in-scope neighbors from each reasoned
        host's evidence, authorizes them (ScopeAuthorizer), and runs each as its own HostReasoner
        with a child budget parented to the scan-wide ceiling. Loop-level, breadth-bounded, and
        hard-gated by scope + global budget."""
        from src.reasoning.budget import BudgetManager  # noqa: PLC0415
        from src.reasoning.cross_host import (  # noqa: PLC0415
            AuthDecision, ScopeAuthorizer, derive_cross_host_edges,
        )
        from src.reasoning.registry import StepContext as _StepContext  # noqa: PLC0415
        from src.reasoning.world_state import WorldState  # noqa: PLC0415

        ws = WorldState.single_host(state, global_budget=self.budget)
        authorizer = ScopeAuthorizer()
        scope = list(state.scope)
        primary_host = state.target or ""
        visited: set[str] = {primary_host}

        def _enqueue_from(graph, queue: list[str]) -> None:
            for edge in derive_cross_host_edges(graph):
                ws.environment.cross_host_graph.add_edge(edge)   # record discovery (facts)
                if edge.dest_host in visited or edge.dest_host in ws.hosts:
                    continue
                if authorizer.evaluate(edge, scope) is AuthDecision.AUTHORIZE:
                    queue.append(edge.dest_host)

        queue: list[str] = []
        _enqueue_from(state.world.graph, queue)   # neighbors discovered by the primary

        expanded: list[str] = []
        while queue and len(expanded) < self._max_hosts and not self.budget.exhausted():
            host = queue.pop(0)
            if host in visited:
                continue
            visited.add(host)

            # A spawned host is a complete reasoning context with its own child budget.
            child_state = ReasoningState(
                target=host, scope=list(scope),
                reasoning_enabled=True, world_modeling_enabled=True)
            child_budget = BudgetManager(
                max_wall_clock_s=self.budget.max_wall_clock_s,
                max_tokens=self.budget.max_tokens, max_probes=self.budget.max_probes,
                max_recursion=self.budget.max_recursion, parent=self.budget)
            ws.hosts.create(host, child_state)
            host_ctx = _StepContext(target=host, state=child_state, art={}, emit=ctx.emit)
            ctx.emit("reasoning", {"event": "host_expand", "host": host})
            try:
                self._reason_one_host(child_state, host_ctx, child_budget)
            except Exception as exc:  # noqa: BLE001 — one host's failure must not abort the world
                log.warning("host %s reasoning failed (%s)", host, exc)
                continue
            expanded.append(host)
            _enqueue_from(child_state.world.graph, queue)   # neighbors discovered by this host

        # Surface the world summary on the primary state for reporting (single source of record).
        state.execution.execution_history.append({
            "multi_host": {
                "primary": primary_host,
                "expanded_hosts": expanded,
                "discovered_edges": [e.to_dict() for e in ws.environment.cross_host_graph.edges],
                "rejected_or_deferred": authorizer.terminal_hosts(),
            }
        })
        ctx.emit("reasoning", {"event": "multi_host_done",
                                "hosts": len(ws.hosts), "expanded": len(expanded)})

    def _select_candidate_intents(self, state: ReasoningState, ctx: StepContext) -> list:
        """Build the Candidate pool (playbooks + capabilities), rank it with the active
        DecisionPolicy, and instantiate ONLY the top selections (Phase 5 revised §4/§5).

        Lazy boundary: `to_candidates` performs cheap matching; `instantiate()` builds Intents
        for selected candidates alone. Returns the flattened Intent list (possibly empty).
        """
        try:
            pool = []
            pool.extend(self._playbook_registry.to_candidates(state))
            pool.extend(self._capability_registry.to_candidates(state, self._playbook_registry))
            if not pool:
                return []

            policy = getattr(self.scheduler, "policy", None)
            if policy is not None:
                satisfied = {o.name.split(":", 1)[0]
                             for o in state.investigation.objectives.all() if o.satisfied}
                ranked = policy.rank_candidates(pool, satisfied=satisfied)
                selected = [r.candidate for r in ranked[:self._max_selected_candidates]]
            else:
                selected = pool[:self._max_selected_candidates]

            out = []
            for cand in selected:
                try:
                    cand_intents = cand.instantiate()   # only here is a graph's worth of work done
                    out.extend(cand_intents)
                    ctx.emit("reasoning", {"event": "candidate_selected",
                                           "source": cand.source, "kind": cand.kind})
                except Exception as e:  # noqa: BLE001
                    log.warning("candidate instantiation failed (%s): %s", cand.kind, e)
            return out
        except Exception as exc:  # noqa: BLE001
            log.warning("candidate selection failed (%s) — baseline intents only", exc)
            return []

    def _run_phase3_cycle(self, state: ReasoningState, ctx: StepContext, budget=None) -> None:
        budget = budget if budget is not None else self.budget
        try:
            from src.reasoning import Intent
            from src.reasoning.investigation_graph import InvestigationGraph

            from src.reasoning import generators  # noqa: PLC0415
            from src.reasoning.memory import MemoryStore  # noqa: PLC0415
            generators.populate(state)                       # deterministic objectives + hypotheses

            # Track C (cognitive layer): C1 proposes hypotheses (incl. novel-vuln) and C11 proposes
            # read-only refutation objectives, verified through the deterministic proposal pipeline.
            # Accepted proposals are SEEDED into the world HERE (in the core; the AI layer only
            # proposes) BEFORE intents are generated, so AI-seeded objectives get evidence-gathering
            # intents like any other. Broken/absent AI seeds nothing ⇒ deterministic baseline is
            # byte-identical. Returns the reasoning-replay transcript (or None).
            transcript = self._run_cognitive_layer(state, ctx)

            intents: list[Intent] = generators.generate_intents(state)

            # Phase 5 (revised): Playbooks/Capabilities as lazy Candidates. Matching is cheap;
            # only the policy-SELECTED candidates are instantiated — no InvestigationGraph is
            # built for an action the scheduler won't pursue. Generator intents remain the
            # always-on baseline; selected candidates are additive.
            intents.extend(self._select_candidate_intents(state, ctx))

            if not intents:
                if transcript is not None:
                    state.execution.ai_transcript = transcript.to_dict()
                return
            phase3_memory = MemoryStore()

            known_ports = self._known_ports(ctx.art)
            graph: InvestigationGraph = self._phase3_compiler.compile_many(intents, known_ports)
            plan_graph = self._phase3_planner.plan(graph, known_ports)

            mode_change = self.strategy.should_switch_mode(state)
            if mode_change:
                ctx.emit("reasoning", {"event": "mode_switch", "mode": mode_change})

            exploit_obj = self.strategy.select_exploit_objective(state)
            if exploit_obj:
                obj = state.investigation.objectives.get(exploit_obj)
                if obj:
                    ctx.emit("reasoning", {"event": "exploit", "objective": exploit_obj})

            ctx.emit("reasoning", {"event": "phase3_cycle",
                                    "intents": len(intents),
                                    "requests": len(graph),
                                    "plans": len(plan_graph)})

            def _metadata_fn(plan) -> Any:
                from src.reasoning.trace import TraceMetadata
                mid = plan.metadata.get("evidence_request_id", "")
                return TraceMetadata(evidence_request_id=mid,
                                      rationale=plan.metadata.get("rationale", ""))

            results = self._phase3_kernel.run_graph(
                plan_graph, metadata_fn=_metadata_fn,
                context={"scope": list(state.scope), "read_only": True,
                         "budget": budget, "memory": phase3_memory,
                         "depth": 0, "max_depth": budget.max_recursion})

            # The kernel keys results by spec.id; Reflect looks them up by evidence_request_id.
            # Re-key so reflection actually matches its requests.
            results_by_req: dict[str, Any] = {}
            for plan in plan_graph.all_plans():
                rid = plan.metadata.get("evidence_request_id", "")
                res = results.get(plan.spec.id)
                if rid and res is not None:
                    results_by_req[rid] = res

            feedback = self._phase3_reflect.reflect(graph, results_by_req, state.world.beliefs)
            state.investigation.contradictions.extend(
                {"signal": c, "source": "phase3"} for c in feedback.contradictions)
            for dead_id in feedback.dead_ends:
                state.investigation.dead_ends.append(
                    {"request_id": dead_id, "reason": "phase3_failure"})

            # ── Close the loop: fold successful evidence into the EvidenceGraph + refresh ──
            succeeded_ev: set[str] = set()
            for plan in plan_graph.all_plans():
                res = results.get(plan.spec.id)
                if res and res.success:
                    ev_type = plan.metadata.get("evidence_type", "evidence")
                    succeeded_ev.add(ev_type)
                    self._fold(state, [{
                        "node_kind": "service",
                        "node_key": f"{plan.spec.target_host}:{plan.spec.target_port}",
                        "kind": ev_type, "evidence": (res.evidence or "")[:300],
                        "source": "phase3", "data": dict(res.data or {})}])
                    state.execution.probe_history.append({
                        "spec_id": plan.spec.id, "host": plan.spec.target_host,
                        "port": plan.spec.target_port, "protocol": plan.spec.protocol,
                        "evidence": (res.evidence or "")[:500], "source": "phase3"})
            if self.refresh:
                try:
                    self.refresh(state, ctx.art)
                except Exception:
                    pass

            # Deterministic inference: resolve framework hypotheses from evidence CONTENT
            # (rule packs) — confirms/refutes, satisfies objectives, records contradictions.
            try:
                from src.reasoning.inference import InferenceEngine  # noqa: PLC0415
                # Use the pack-merged rule set when available (Phase 6.5); else built-in rules.
                inference_steps = InferenceEngine(self._inference_rules).infer(state)
                for s in inference_steps:
                    state.execution.explanations.append({
                        "decision": s.decision, "evidence_ids": list(s.evidence_refs),
                        "supporting_obs": [s.rule], "confidence_delta": 0.0,
                        "rule_applied": f"inference:{s.rule}", "ai_summary": ""})
                # Phase 5 §1: build the irreproducible provenance core (Observation→Inference→
                # Hypothesis). Additive + read-only — never perturbs the byte-identical invariant.
                try:
                    from src.reasoning.provenance import ProvenanceBuilder  # noqa: PLC0415
                    prov = ProvenanceBuilder().build(state, inference_steps)
                    state.execution.provenance = prov.to_dict()
                except Exception:  # noqa: BLE001
                    pass
            except Exception:  # noqa: BLE001
                pass

            # Novel-vulnerability inference (Track C): deterministically REFUTE or mark LIKELY the
            # novel hypotheses C1 invented, from the same evidence blob. Never CONFIRMS (that needs
            # active validation). This is what turns a novel hypothesis from 'unresolved' into a real
            # outcome — the loop the A/B benchmark showed was open.
            try:
                from src.reasoning.novel_inference import NovelInferenceEngine  # noqa: PLC0415
                for s in NovelInferenceEngine().infer(state):
                    state.execution.explanations.append({
                        "decision": s.decision, "evidence_ids": list(s.evidence_refs),
                        "supporting_obs": [s.rule], "confidence_delta": 0.0,
                        "rule_applied": f"inference:{s.rule}", "ai_summary": ""})
            except Exception:  # noqa: BLE001
                pass

            # Satisfy objectives whose discriminating evidence arrived this cycle (by type;
            # content-based satisfaction above takes precedence). `evidence_for` honors an
            # objective's own C2-assigned desired_evidence, so AI-invented objectives satisfy too.
            from src.reasoning.generators import evidence_for  # noqa: PLC0415
            for obj in list(state.investigation.objectives.ready()):
                wanted = set(evidence_for(obj))
                if wanted and (wanted & succeeded_ev):
                    state.investigation.objectives.satisfy(obj.name)

            # AI-driven adjudication (opt-in): the deterministic engine has now done everything it
            # CAN. Anything still stuck at its prior (a version-matched CVE with no sensor) is where
            # the AI takes the wheel — it decides the disposition and the core applies the verdict.
            # This runs BEFORE the transcript resolution so adjudicated hypotheses flow into it.
            if self.ai_driven:
                self._run_ai_adjudication(state, ctx, transcript)

            # Track C: link deterministic outcomes back to the AI proposals that seeded them, then
            # freeze the transcript (the reasoning replay) onto the state. A seeded hypothesis the
            # InferenceEngine resolved becomes "confirmed"; a satisfied AI-seeded objective becomes
            # "confirmed"; everything else stays honestly "unresolved".
            if transcript is not None:
                resolved: dict[str, str] = {}
                for h in state.investigation.hypotheses.all():
                    if h.status in ("confirmed", "refuted"):
                        resolved[h.label] = h.status
                for obj in state.investigation.objectives.all():
                    if obj.satisfied and obj.name not in resolved:
                        resolved[obj.name] = "confirmed"
                transcript.resolve_outcomes(resolved)
                state.execution.ai_transcript = transcript.to_dict()

            ctx.emit("reasoning", {"event": "phase3_done",
                                    "executed": len(results),
                                    "gathered": len(succeeded_ev),
                                    "dead_ends": len(feedback.dead_ends)})
        except Exception as exc:
            log.warning("Phase 3 cycle failed (%s) — continuing with Phase 2 results", exc)

    def _run_cognitive_layer(self, state: ReasoningState, ctx: StepContext):
        """Track C: run C1 (Hypothesis Generator) + C11 (Counterfactual Reasoner) through the
        AICoordinator, then SEED the accepted proposals into the world. Seeding happens HERE, in
        the deterministic core reading typed accepted proposals — the AI layer only ever proposes,
        never mutates (isolation preserved). Returns an InvestigationTranscript, or None.

        Fail-soft: absent/broken AI ⇒ no tasks ⇒ nothing seeded ⇒ byte-identical baseline."""
        completer = self.ai_completer
        if completer is None:
            return None
        try:
            from src.reasoning.ai import (  # noqa: PLC0415
                AICoordinator, InvestigationTranscript, ProposalKind, VerifierContext,
                VerifyDecision,
            )
            from src.reasoning.ai.agents import (  # noqa: PLC0415
                CounterfactualReasoner, HypothesisGenerator, InvestigationDesigner,
            )
            from src.reasoning.objective import Objective, ObjectiveSource  # noqa: PLC0415

            known = frozenset(o.name for o in state.investigation.objectives.all())
            tasks = HypothesisGenerator(completer).generate(state)
            tasks += CounterfactualReasoner(completer).generate(state)
            if not tasks:
                return None
            coordinator = AICoordinator()
            accepted = coordinator.run(tasks, ctx=VerifierContext(known_objectives=known))
        except Exception as exc:  # noqa: BLE001 — any cognitive-layer failure contributes nothing
            log.warning("cognitive layer skipped (%s)", exc)
            return None

        transcript = InvestigationTranscript()
        for d in accepted:
            p = d.proposal
            seeded = ""
            if p.kind == ProposalKind.HYPOTHESIS:
                seeded = f"ai:{p.payload.objective}"
                # reason "<objective>:ai" lets the InferenceEngine map this hypothesis back to its
                # objective (it splits on ':ai') so a confirmed AI framework hypothesis satisfies it.
                state.investigation.hypotheses.add_hypothesis(
                    label=seeded, created_by=p.agent, likelihoods=dict(p.payload.candidates),
                    reason=f"{p.payload.objective}:ai")
                if p.payload.novel and p.payload.objective not in known:
                    state.investigation.objectives.add(Objective(
                        name=p.payload.objective, priority=0.5, produced_by=p.agent,
                        source=ObjectiveSource(generated_by=f"ai_{p.agent}",
                                               reason="novel hypothesis",
                                               confidence=p.economics.estimated_prob_correct)))
            elif p.kind == ProposalKind.OBJECTIVE:
                seeded = p.payload.goal_name
                if seeded not in state.investigation.objectives:
                    state.investigation.objectives.add(Objective(
                        name=seeded, priority=p.payload.priority, produced_by=p.agent,
                        source=ObjectiveSource(generated_by=f"ai_{p.agent}", reason="refutation")))
            transcript.record(d, trigger=p.agent, seeded_as=seeded)

        # C2 (Investigation Designer): now that C1/C11 have seeded the AI objectives (novel:/refute:),
        # design HOW to investigate them — attach the gatherable evidence that makes them reachable by
        # the ordinary Phase-3 loop. A second, atomic coordinator pass. The AI only chooses evidence
        # types (filtered to a read-only vocabulary); attaching them to the objective is done HERE.
        try:
            c2_tasks = InvestigationDesigner(completer).generate(state)
            if c2_tasks:
                c2_known = frozenset(o.name for o in state.investigation.objectives.all())
                c2_coord = AICoordinator()
                for d in c2_coord.run(c2_tasks, ctx=VerifierContext(known_objectives=c2_known)):
                    obj = state.investigation.objectives.get(d.proposal.payload.goal_name)
                    req = getattr(d.proposal.payload, "required_evidence", ())
                    if obj is not None and req:
                        obj.desired_evidence = tuple(req)
                    transcript.record(d, trigger="investigation_designer",
                                      seeded_as=d.proposal.payload.goal_name)
                for rec in c2_coord.store.rejected():
                    transcript.record(
                        VerifyDecision(accepted=False, proposal=rec.proposal,
                                       stage_failed=rec.stage_failed, reasons=rec.reasons),
                        trigger="rejected")
        except Exception as exc:  # noqa: BLE001 — designer failure never breaks the scan
            log.warning("investigation designer skipped (%s)", exc)

        # Record rejections too, so the replay shows what the pipeline caught and why.
        for rec in coordinator.store.rejected():
            transcript.record(
                VerifyDecision(accepted=False, proposal=rec.proposal,
                               stage_failed=rec.stage_failed, reasons=rec.reasons),
                trigger="rejected")
        ctx.emit("reasoning", {"event": "cognitive", "accepted": len(accepted),
                                "rejected": len(coordinator.store.rejected())})
        return transcript

    def _run_ai_adjudication(self, state: ReasoningState, ctx: StepContext, transcript) -> None:
        """AI-DRIVEN mode: let the AI resolve the exploitability findings the deterministic engine
        couldn't. The agent RETURNS verdicts (data); the core APPLIES them here (resolves the
        hypothesis + records the rationale) — so the AI owns the JUDGEMENT while the isolation
        invariant (AI never mutates the world) is preserved. Fail-soft: no completer / broken AI /
        no decisions ⇒ nothing changes ⇒ identical to ai_driven OFF.

        Verdict → world:
          ruled_out          → hypothesis REFUTED  → investigation reads NOT EXPLOITABLE
          likely_exploitable → exploitable mass raised over 0.5 (still active, never auto-confirmed)
                               → investigation reads POSSIBLY EXPLOITABLE
          needs_active_check → left at its prior → stays a lead (UNVERIFIED)
        """
        completer = self.ai_completer
        if completer is None:
            return
        try:
            from src.reasoning.ai.agents import FindingAdjudicator  # noqa: PLC0415
            decisions = FindingAdjudicator(completer).decide(state)
        except Exception as exc:  # noqa: BLE001 — adjudication never breaks the scan
            log.warning("ai adjudication skipped (%s)", exc)
            return
        if not decisions:
            return

        hyps = {h.label: h for h in state.investigation.hypotheses.all()}
        applied = 0
        for d in decisions:
            hyp = hyps.get(d["hypothesis_label"])
            if hyp is None or hyp.status != "active":
                continue
            verdict = d["verdict"]
            rationale = d["rationale"]
            if verdict == "ruled_out":
                state.investigation.hypotheses.resolve(hyp.id, "refuted")
            elif verdict == "likely_exploitable":
                # Never manufacture a CONFIRMED vuln from a bare LLM call — just make "exploitable"
                # lead so the finding surfaces as POSSIBLY EXPLOITABLE for a human/active check.
                hyp.likelihoods = {"exploitable": 0.6, "not_exploitable": 0.4}
            else:  # needs_active_check — leave it a lead, but record the AI looked
                pass
            # Mark the AI's authorship for the analyst view (dynamic attr; degrades gracefully if the
            # state is ever re-serialized — the status change is the durable part).
            hyp.ai_adjudicated = True
            hyp.ai_rationale = rationale
            applied += 1
            if transcript is not None:
                try:
                    transcript.record_note(
                        agent="finding_adjudicator", summary=f"{d['cve']} → {verdict}",
                        rationale=rationale, outcome=("refuted" if verdict == "ruled_out"
                                                      else "possible" if verdict == "likely_exploitable"
                                                      else "unresolved"))
                except Exception:  # noqa: BLE001 — transcript is a nicety, not load-bearing
                    pass
        ctx.emit("reasoning", {"event": "ai_adjudication", "decided": applied})

    @staticmethod
    def _known_ports(art: dict) -> list[dict]:
        host = art.get("host_result")
        if host and hasattr(host, "ports"):
            return [{"port": p.port, "service": getattr(p, "service", ""),
                     "tls": getattr(p, "tls", False),
                     "state": getattr(p, "state", "open")}
                    for p in host.ports]
        return []

    # ── Helpers ──

    @staticmethod
    def _contested_count(state: ReasoningState) -> int:
        return sum(1 for b in state.world.belief_records
                   if b.get("impact") in _HIGH_IMPACT and float(b.get("confidence", 1.0)) < ACTIVATE_CONF)

    @staticmethod
    def _run_step(step: SensorStep, ctx: StepContext) -> list:
        try:
            return step.run(ctx) or []
        except Exception as exc:
            log.warning("sensor step %s failed (%s)", step.name, exc)
            return []

    @staticmethod
    def _fold(state: ReasoningState, observations: list) -> None:
        graph = state.world.graph
        for o in observations or []:
            if not isinstance(o, dict):
                continue
            kind = o.get("node_kind", "claim")
            key = o.get("node_key", "")
            node = graph.upsert_node(kind, key, label=str(o.get("label", key)))
            graph.observe(node, kind=o.get("kind", "obs"), evidence=str(o.get("evidence", ""))[:600],
                          source=o.get("source", "loop"), data=o.get("data") or {})
