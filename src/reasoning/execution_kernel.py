from __future__ import annotations

import time
import traceback
from typing import Callable, Protocol

from src.reasoning.probe_plan import ProbePlan, ProbePlanGraph, ProbeSpec, PlanWalker
from src.reasoning.trace import ExecutionResult, TraceMetadata, TraceStep


class ProbeExecutor(Protocol):
    def __call__(self, spec: ProbeSpec) -> ExecutionResult:
        ...


ValidationFn = Callable[[ProbePlan, dict], list[str]]


class ExecutionKernel:
    """Validates, executes, and traces probes.
    The kernel knows nothing about hypotheses or objectives — strict execution boundary."""

    def __init__(self, executor: ProbeExecutor | None = None) -> None:
        self._executor = executor or self._default_executor
        self._validators: list[ValidationFn] = []
        self._trace: list[TraceStep] = []

    def add_validator(self, fn: ValidationFn) -> None:
        self._validators.append(fn)

    def validate(self, plan: ProbePlan, context: dict) -> list[str]:
        errors: list[str] = []
        for v in self._validators:
            try:
                errors.extend(v(plan, context))
            except Exception as exc:
                errors.append(f"validator error: {exc}")
        return errors

    def execute_plan(self, plan: ProbePlan, metadata: TraceMetadata | None = None,
                     context: dict | None = None) -> ExecutionResult:
        errors = self.validate(plan, context or {})
        if errors:
            return ExecutionResult(success=False, error="; ".join(errors),
                                   evidence="validation failed")

        step = TraceStep(step_id=plan.spec.id, spec_id=plan.spec.id,
                         metadata=metadata or TraceMetadata())
        self._trace.append(step)

        try:
            result = self._executor(plan.spec)
        except Exception as exc:
            result = ExecutionResult(success=False, error=str(exc),
                                     evidence=traceback.format_exc())

        step.result = result
        step.completed_at = time.time()

        # Record into the probe ledger (cross-cycle dedup) and spend budget, if provided.
        memory = (context or {}).get("memory")
        if memory is not None:
            try:
                memory.record(plan.spec.to_dict(), success=result.success,
                              latency_ms=result.latency_ms, result_summary=plan.spec.protocol)
            except Exception:
                pass
        budget = (context or {}).get("budget")
        if budget is not None:
            try:
                budget.spend(plan.metadata.get("cost") or {})
            except Exception:
                pass
        return result

    def run_graph(self, graph: ProbePlanGraph,
                  metadata_fn: Callable[[ProbePlan], TraceMetadata] | None = None,
                  context: dict | None = None) -> dict[str, ExecutionResult]:
        walker = PlanWalker(graph)
        results: dict[str, ExecutionResult] = {}
        while not walker.is_exhausted:
            ready = walker.next_ready()
            if not ready:
                break
            for plan in ready:
                meta = metadata_fn(plan) if metadata_fn else TraceMetadata()
                result = self.execute_plan(plan, metadata=meta, context=context)
                results[plan.spec.id] = result
                if result.success:
                    walker.mark_completed(plan.spec.id)
                else:
                    walker.mark_failed(plan.spec.id)
        return results

    def trace(self) -> list[TraceStep]:
        return list(self._trace)

    def clear_trace(self) -> None:
        self._trace.clear()

    @staticmethod
    def _default_executor(spec: ProbeSpec) -> ExecutionResult:
        return ExecutionResult(success=False, error="no executor configured",
                               evidence="default_executor: not implemented")


def validate_scope(plan: ProbePlan, context: dict) -> list[str]:
    scope = context.get("scope", [])
    host = plan.spec.target_host
    if scope and host:
        in_scope = any(host == s or host.endswith("." + s) for s in scope)
        if not in_scope:
            return [f"host {host} not in scope {scope}"]
    return []


def validate_read_only(plan: ProbePlan, context: dict) -> list[str]:
    """Reject anything not explicitly read-only when the read_only policy is on (default).
    Risk is propagated from the primitive by the planner; an unknown/missing risk is treated
    as NOT read-only (fail-closed)."""
    if context.get("read_only", True):
        risk = plan.metadata.get("risk")
        if risk != "read_only":
            return [f"probe {plan.spec.id} risk={risk!r} denied by read_only policy"]
    return []


def validate_budget(plan: ProbePlan, context: dict) -> list[str]:
    """Reject a probe the BudgetManager can't afford."""
    budget = context.get("budget")
    if budget is not None and not budget.can_afford(plan.metadata.get("cost") or {}):
        return [f"probe {plan.spec.id} denied: budget exhausted"]
    return []


def validate_dedup(plan: ProbePlan, context: dict) -> list[str]:
    """Reject an equivalent probe already recorded in the MemoryStore."""
    memory = context.get("memory")
    if memory is not None and memory.seen(plan.spec.to_dict()):
        return [f"probe {plan.spec.id} denied: duplicate of a prior probe"]
    return []


def validate_depth(plan: ProbePlan, context: dict) -> list[str]:
    """Reject a probe beyond the recursion/plan-depth ceiling."""
    depth = int(context.get("depth", 0))
    max_depth = int(context.get("max_depth", 6))
    if depth >= max_depth:
        return [f"probe {plan.spec.id} denied: max recursion depth {max_depth} reached"]
    return []
