"""
Track C Validation — the investigation-level A/B benchmark. Does the cognitive layer actually
produce *better investigations*, or just more boxes?

This runs the SAME investigation twice against the SAME deterministic fixture — once with the AI off
(the deterministic baseline) and once with a cassette-driven AI on — and reports the measured delta:
objectives created, probes spent, hypotheses proposed/confirmed/refuted, novel hypotheses, and the
transcript's estimated cost. Because both runs use a fixed evidence stub + a cassette completer, the
comparison is byte-deterministic and reproducible — the honest instrument that answers "is the AI
worth it?" from data, not intuition.

It measures whatever actually happens (it does not engineer a favorable result). In particular it
makes the current C2 gap visible: novel/refutation objectives are seeded but, lacking investigation
strategies, cost ~0 extra probes and resolve as 'unresolved' — exactly the signal that tells you
what C2 must fix.

LOCATION: this harness lives OUTSIDE `src/reasoning/ai/` on purpose. An A/B run drives the full
`ReconDirector`, and the cognitive layer's isolation invariant forbids anything inside `ai/` from
importing the director. The benchmark sits ABOVE both the deterministic core and the cognitive layer
and orchestrates them — it is not part of the cognitive layer itself.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from src.reasoning.state import ReasoningState


@dataclass(frozen=True)
class InvestigationMetrics:
    """A single investigation's measurable outcome (AI-off or AI-on)."""
    objectives: int = 0
    objectives_investigable: int = 0    # objectives with an evidence-gathering path (C2's effect)
    objectives_satisfied: int = 0
    hypotheses: int = 0
    hypotheses_confirmed: int = 0
    hypotheses_refuted: int = 0
    ai_hypotheses: int = 0
    novel_hypotheses: int = 0
    refutation_objectives: int = 0
    probes: int = 0
    proposed: int = 0
    accepted: int = 0
    est_information_gain: float = 0.0

    def to_dict(self) -> dict:
        return {"objectives": self.objectives,
                "objectives_investigable": self.objectives_investigable,
                "objectives_satisfied": self.objectives_satisfied,
                "hypotheses": self.hypotheses, "hypotheses_confirmed": self.hypotheses_confirmed,
                "hypotheses_refuted": self.hypotheses_refuted,
                "ai_hypotheses": self.ai_hypotheses, "novel_hypotheses": self.novel_hypotheses,
                "refutation_objectives": self.refutation_objectives, "probes": self.probes,
                "proposed": self.proposed, "accepted": self.accepted,
                "est_information_gain": self.est_information_gain}


@dataclass(frozen=True)
class BenchmarkComparison:
    baseline: InvestigationMetrics
    with_ai: InvestigationMetrics
    deltas: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"baseline": self.baseline.to_dict(), "with_ai": self.with_ai.to_dict(),
                "deltas": dict(self.deltas)}


def _metrics_from_state(state: ReasoningState) -> InvestigationMetrics:
    from src.reasoning.generators import evidence_for  # noqa: PLC0415
    objectives = state.investigation.objectives.all()
    hyps = state.investigation.hypotheses.all()
    transcript = state.execution.ai_transcript or {}
    summary = transcript.get("summary", {})
    return InvestigationMetrics(
        objectives=len(objectives),
        objectives_investigable=sum(1 for o in objectives if evidence_for(o)),
        objectives_satisfied=sum(1 for o in objectives if o.satisfied),
        hypotheses=len(hyps),
        hypotheses_confirmed=sum(1 for h in hyps if h.status == "confirmed"),
        hypotheses_refuted=sum(1 for h in hyps if h.status == "refuted"),
        ai_hypotheses=sum(1 for h in hyps if h.label.startswith("ai:")),
        novel_hypotheses=sum(1 for o in objectives if o.name.startswith("novel:")),
        refutation_objectives=sum(1 for o in objectives if o.name.startswith("refute:")),
        probes=len(state.execution.probe_history),
        proposed=int(summary.get("proposed", 0)),
        accepted=int(summary.get("accepted", 0)),
        est_information_gain=float(summary.get("est_information_gain", 0.0)),
    )


def run_investigation(state_factory: Callable[[], ReasoningState], *,
                      completer=None, executor=None) -> ReasoningState:
    """Run ONE full director investigation over a fresh state and return the resolved state.
    `state_factory` must return an identical fresh state each call so A/B is apples-to-apples."""
    from src.reasoning import (  # noqa: PLC0415
        BudgetManager, ReconDirector, Scheduler, StepContext, StrategyManager,
    )
    state = state_factory()
    state.reasoning_enabled = True
    director = ReconDirector(
        Scheduler(), StrategyManager(), BudgetManager.for_tier("local"), [],
        has_ai_key=(completer is not None), ai_completer=completer,
        refresh=lambda st, a: None, executor=executor)
    director.run(StepContext(state.target, state, {}, lambda *a, **k: None))
    return state


def compare_investigations(state_factory: Callable[[], ReasoningState], *,
                           completer, executor=None) -> BenchmarkComparison:
    """Run the investigation AI-off then AI-on over identical fresh states; return the measured
    comparison. Deterministic given a cassette `completer` + a fixed `executor`."""
    baseline = _metrics_from_state(run_investigation(state_factory, completer=None, executor=executor))
    with_ai = _metrics_from_state(run_investigation(state_factory, completer=completer, executor=executor))
    deltas = {
        "objectives": with_ai.objectives - baseline.objectives,
        "objectives_investigable": with_ai.objectives_investigable - baseline.objectives_investigable,
        "hypotheses": with_ai.hypotheses - baseline.hypotheses,
        "hypotheses_confirmed": with_ai.hypotheses_confirmed - baseline.hypotheses_confirmed,
        "hypotheses_refuted": with_ai.hypotheses_refuted - baseline.hypotheses_refuted,
        "probes": with_ai.probes - baseline.probes,
        "ai_hypotheses": with_ai.ai_hypotheses,
        "novel_hypotheses": with_ai.novel_hypotheses,
        "refutation_objectives": with_ai.refutation_objectives,
    }
    return BenchmarkComparison(baseline=baseline, with_ai=with_ai, deltas=deltas)


# ══════════════════════════════════════════════════════════════════════════════════════════════
# Research evaluation suite — the comprehensive per-investigation metrics that let every future
# component justify itself with a number. This is instrumentation, not architecture: it only READS
# a resolved investigation and computes metrics. Honest about what needs a labeled corpus.
# ══════════════════════════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class ResearchReport:
    # ── investigation quality ──
    hypotheses: int = 0
    confirmed: int = 0
    refuted: int = 0
    resolved: int = 0
    unresolved: int = 0
    resolution_rate: float = 0.0
    # ── reasoning quality ──
    uncertainty_reduction: float = 0.0        # summed entropy of hypotheses that reached certainty
    mean_entropy_remaining: float = 0.0       # mean entropy of still-open hypotheses (lower = sharper)
    contradictions: int = 0
    est_information_gain: float = 0.0
    evidence_observations: int = 0
    evidence_reuse: float = 0.0               # observations per probe (higher = each probe reused more)
    # ── cost ──
    probes: int = 0
    runtime_s: float = 0.0
    tokens: int = 0
    api_cost: float = 0.0
    planner_iterations: int = 0
    # ── latency: how fast the FIRST reliable answer arrives (None if nothing was confirmed) ──
    time_to_first_confirmation_s: Optional[float] = None
    # ── efficiency (the budget-aware-reasoning story) ──
    uncertainty_reduction_per_probe: float = 0.0
    resolved_per_probe: float = 0.0
    info_gain_per_probe: float = 0.0
    # ── reliability (None unless a ground-truth label set is supplied) ──
    true_positives: Optional[int] = None
    false_positives: Optional[int] = None
    false_negatives: Optional[int] = None
    precision: Optional[float] = None
    recall: Optional[float] = None

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


def _vuln_type(label: str, reason: str) -> str:
    src = f"{reason or ''} {label or ''}"
    return src.split("novel:", 1)[1].split(":")[0].strip() if "novel:" in src else ""


def _hypothesis_claim(h) -> str:
    """The thing a resolved hypothesis asserts, for scoring against ground truth: a novel hypothesis
    claims its vuln type; a framework hypothesis claims its leading candidate."""
    vt = _vuln_type(h.label, h.reason or "")
    if vt:
        return vt
    post = h.normalized_posterior()
    return max(post, key=post.get) if post else ""


def _shannon(probs) -> float:
    import math
    return round(-sum(p * math.log2(p) for p in probs if p > 0), 4)


def _reliability(state, ground_truth: dict) -> dict:
    """Score resolved hypotheses against a label set `{claim: truly_present}`:
      confirmed & true → TP · confirmed & false → FP · refuted & true → FN · refuted & false → TN."""
    tp = fp = fn = 0
    gt = {str(k).lower(): bool(v) for k, v in ground_truth.items()}
    for h in state.investigation.hypotheses.all():
        if h.status not in ("confirmed", "refuted"):
            continue
        claim = _hypothesis_claim(h).lower()
        truth = next((v for k, v in gt.items() if k == claim or k in claim or claim in k), None)
        if truth is None:
            continue
        if h.status == "confirmed":
            tp += 1 if truth else 0
            fp += 0 if truth else 1
        else:                       # refuted
            fn += 1 if truth else 0
    precision = round(tp / (tp + fp), 4) if (tp + fp) else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) else 0.0
    return {"true_positives": tp, "false_positives": fp, "false_negatives": fn,
            "precision": precision, "recall": recall}


def research_report(state: ReasoningState, *, runtime_s: float = 0.0, tokens: int = 0,
                    api_cost: float = 0.0, ground_truth: Optional[dict] = None) -> ResearchReport:
    """Compute the full research-evaluation suite for ONE resolved investigation. Pure (reads state).
    `tokens`/`api_cost` are 0 for cassette/offline runs — a real run threads them from the completer.
    `ground_truth` ({claim: truly_present}) unlocks precision/recall/FP/FN; absent ⇒ those stay None."""
    hyps = state.investigation.hypotheses.all()
    confirmed = sum(1 for h in hyps if h.status == "confirmed")
    refuted = sum(1 for h in hyps if h.status == "refuted")
    resolved = confirmed + refuted
    total = len(hyps)
    unresolved = total - resolved

    # A resolved hypothesis collapsed from its entropy to certainty ⇒ that entropy was eliminated.
    unc_reduction = round(sum(h.entropy for h in hyps if h.status in ("confirmed", "refuted")), 4)
    open_hyps = [h for h in hyps if h.status == "active"]
    mean_open_entropy = round(sum(_shannon(h.normalized_posterior().values()) for h in open_hyps)
                              / len(open_hyps), 4) if open_hyps else 0.0

    obs = sum(len(n.observations()) for n in state.world.graph.nodes())
    probes = len(state.execution.probe_history)
    transcript = state.execution.ai_transcript or {}
    est_gain = float(transcript.get("summary", {}).get("est_information_gain", 0.0))
    planner_iters = len(state.execution.execution_history)
    p = max(probes, 1)

    # Time-to-first-confirmation: from investigation start to the earliest confirmed hypothesis.
    # Security engineers care about the FIRST reliable answer, not just the eventual one.
    confirmed_ts = [h.resolved_at for h in hyps if h.status == "confirmed" and h.resolved_at]
    ttfc = round(min(confirmed_ts) - state.started_at, 4) if confirmed_ts else None

    rel = _reliability(state, ground_truth) if ground_truth is not None else {}
    return ResearchReport(
        time_to_first_confirmation_s=ttfc,
        hypotheses=total, confirmed=confirmed, refuted=refuted, resolved=resolved,
        unresolved=unresolved,
        resolution_rate=round(resolved / total, 4) if total else 0.0,
        uncertainty_reduction=unc_reduction, mean_entropy_remaining=mean_open_entropy,
        contradictions=len(state.investigation.contradictions), est_information_gain=est_gain,
        evidence_observations=obs, evidence_reuse=round(obs / p, 4),
        probes=probes, runtime_s=round(runtime_s, 4), tokens=tokens, api_cost=api_cost,
        planner_iterations=planner_iters,
        uncertainty_reduction_per_probe=round(unc_reduction / p, 4),
        resolved_per_probe=round(resolved / p, 4),
        info_gain_per_probe=round(est_gain / p, 4),
        true_positives=rel.get("true_positives"), false_positives=rel.get("false_positives"),
        false_negatives=rel.get("false_negatives"), precision=rel.get("precision"),
        recall=rel.get("recall"))


def run_and_report(state_factory: Callable[[], ReasoningState], *, completer=None, executor=None,
                   ground_truth: Optional[dict] = None) -> ResearchReport:
    """Time a single investigation and return its full research report (measures real runtime)."""
    t0 = time.perf_counter()
    state = run_investigation(state_factory, completer=completer, executor=executor)
    return research_report(state, runtime_s=time.perf_counter() - t0, ground_truth=ground_truth)
