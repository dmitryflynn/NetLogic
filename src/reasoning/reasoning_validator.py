"""
ReasoningValidator — continuous integrity audit of the ReasoningState.

See the Phase 4 plan §2. This is an *audit* (state integrity), not schema validation. It runs
after every reasoning cycle and in the benchmark/injection suites so corruption is caught
immediately instead of propagating. It never mutates state and never aborts a scan; it returns
machine-readable issues. `fatal` issues fail tests; `warning` does not.
"""
from __future__ import annotations

from dataclasses import dataclass

# Severity ordering for callers that gate on it.
SEVERITIES = ("warning", "error", "fatal")


@dataclass(frozen=True)
class ValidationIssue:
    severity: str            # "warning" | "error" | "fatal"
    code: str
    message: str
    object_ref: str = ""

    def to_dict(self) -> dict:
        return {"severity": self.severity, "code": self.code,
                "message": self.message, "object_ref": self.object_ref}


class ReasoningValidator:
    """Audits a ReasoningState (and, optionally, transient graphs) for integrity invariants."""

    def audit(self, state) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        inv = state.investigation

        # ── Objectives: dependencies must exist; the DAG must be acyclic ──
        obj_names = {o.name for o in inv.objectives.all()}
        for o in inv.objectives.all():
            for dep in o.dependencies:
                if dep not in obj_names:
                    issues.append(ValidationIssue(
                        "error", "orphan-objective-dependency",
                        f"objective '{o.name}' depends on missing '{dep}'", o.name))
        if self._objectives_have_cycle(inv.objectives):
            issues.append(ValidationIssue("fatal", "objective-cycle",
                                          "objective dependency graph has a cycle"))

        # ── Hypotheses: confirmed→evidence; parent/child/belief refs valid ──
        hyp_ids = {h.id for h in inv.hypotheses.all()}
        for h in inv.hypotheses.all():
            if h.status == "confirmed" and not h.evidence_refs:
                issues.append(ValidationIssue("error", "confirmed-without-evidence",
                                              f"hypothesis '{h.id}' confirmed with no evidence", h.id))
            if h.parent_id and h.parent_id not in hyp_ids:
                issues.append(ValidationIssue("error", "missing-parent-hypothesis",
                                              f"hypothesis '{h.id}' parent '{h.parent_id}' missing", h.id))
            for c in h.children:
                if c not in hyp_ids:
                    issues.append(ValidationIssue("error", "missing-child-hypothesis",
                                                  f"hypothesis '{h.id}' child '{c}' missing", h.id))
            if h.belief_ref and h.belief_ref not in state.world.beliefs:
                issues.append(ValidationIssue("warning", "missing-belief-ref",
                                              f"hypothesis '{h.id}' belief_ref '{h.belief_ref}' missing", h.id))

        # ── Explanations: evidence_ids must reference real graph nodes ──
        node_ids = {n.id for n in state.world.graph.nodes()}
        for i, ex in enumerate(state.execution.explanations):
            for eid in (ex.get("evidence_ids", []) if isinstance(ex, dict) else []):
                if eid and eid not in node_ids:
                    issues.append(ValidationIssue("warning", "dangling-evidence-id",
                                                  f"explanation #{i} references unknown node '{eid}'", str(eid)))
        return issues

    # ── Transient-graph audits (called per cycle on the live graphs) ──
    @staticmethod
    def audit_plan_graph(plan_graph) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        ids = set(plan_graph.plans.keys())
        for pid, plan in plan_graph.plans.items():
            for dep in plan.depends_on:
                if dep not in ids:
                    issues.append(ValidationIssue("error", "dangling-plan-dependency",
                                                  f"plan '{pid}' depends on missing '{dep}'", pid))
        if ReasoningValidator._plan_graph_has_cycle(plan_graph):
            issues.append(ValidationIssue("fatal", "plan-graph-cycle", "ProbePlanGraph has a cycle"))
        return issues

    # ── Cycle detection helpers ──
    @staticmethod
    def _objectives_have_cycle(dag) -> bool:
        objs = {o.name: o.dependencies for o in dag.all()}
        WHITE, GRAY, BLACK = 0, 1, 2
        color = {n: WHITE for n in objs}

        def visit(n: str) -> bool:
            color[n] = GRAY
            for d in objs.get(n, []):
                if d not in color:
                    continue
                if color[d] == GRAY or (color[d] == WHITE and visit(d)):
                    return True
            color[n] = BLACK
            return False

        return any(color[n] == WHITE and visit(n) for n in objs)

    @staticmethod
    def _plan_graph_has_cycle(plan_graph) -> bool:
        deps = {pid: list(p.depends_on) for pid, p in plan_graph.plans.items()}
        WHITE, GRAY, BLACK = 0, 1, 2
        color = {n: WHITE for n in deps}

        def visit(n: str) -> bool:
            color[n] = GRAY
            for d in deps.get(n, []):
                if d not in color:
                    continue
                if color[d] == GRAY or (color[d] == WHITE and visit(d)):
                    return True
            color[n] = BLACK
            return False

        return any(color[n] == WHITE and visit(n) for n in deps)
