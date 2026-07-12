"""
Validation infrastructure — the corpus runner, aggregate reporting, and regression harness.

This is the "continuously measured research platform" layer: NOT new reasoning architecture, just the
tooling that turns single `ResearchReport`s into science. It runs a CORPUS of investigations (fixture
cases today; real authorized scans ingest identically), aggregates them into corpus-level statistics
(avg uncertainty reduction, info gain, probes, runtime, precision/recall, FP/FN rates), exports
JSON/CSV, and — the piece that makes it continuous — compares a run against a stored baseline so a
commit that regresses false positives or probe cost FAILS a threshold.

Like `ai_benchmark`, this lives OUTSIDE `src/reasoning/ai/`: it drives the director and orchestrates
the cognitive layer; it is not part of it.
"""
from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from statistics import mean
from typing import Callable, Optional

from src.reasoning.ai_benchmark import ResearchReport, run_and_report
from src.reasoning.state import ReasoningState


@dataclass(frozen=True)
class BenchmarkCase:
    """One corpus entry. `state_factory` yields a fresh identical state per run; completer/executor
    are the (cassette / stub) drivers; ground_truth ({claim: truly_present}) unlocks precision/recall."""
    name: str
    state_factory: Callable[[], ReasoningState]
    completer: object = None
    executor: object = None
    ground_truth: Optional[dict] = None
    label: str = ""                       # tech/class tag, e.g. "wordpress", "static"


@dataclass(frozen=True)
class CaseResult:
    name: str
    label: str
    report: ResearchReport

    def to_dict(self) -> dict:
        return {"name": self.name, "label": self.label, **self.report.to_dict()}


@dataclass(frozen=True)
class AggregateStats:
    n: int = 0
    avg_resolution_rate: float = 0.0
    avg_uncertainty_reduction: float = 0.0
    avg_information_gain: float = 0.0
    avg_probes: float = 0.0
    avg_runtime_s: float = 0.0
    avg_evidence_reuse: float = 0.0
    avg_uncertainty_reduction_per_probe: float = 0.0
    # reliability — aggregated (micro) over the cases that carried ground-truth labels
    labeled_cases: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: Optional[float] = None
    recall: Optional[float] = None
    fp_rate: Optional[float] = None       # FP / scored resolutions
    fn_rate: Optional[float] = None       # FN / (TP + FN)  (miss rate)

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


@dataclass(frozen=True)
class CorpusResult:
    results: list[CaseResult] = field(default_factory=list)

    def aggregate(self) -> AggregateStats:
        reps = [r.report for r in self.results]
        if not reps:
            return AggregateStats()
        labeled = [rp for rp in reps if rp.precision is not None]
        tp = sum(rp.true_positives or 0 for rp in labeled)
        fp = sum(rp.false_positives or 0 for rp in labeled)
        fn = sum(rp.false_negatives or 0 for rp in labeled)
        rel: dict = {}
        if labeled:
            scored = tp + fp + fn
            rel = {
                "labeled_cases": len(labeled),
                "true_positives": tp, "false_positives": fp, "false_negatives": fn,
                "precision": round(tp / (tp + fp), 4) if (tp + fp) else 0.0,
                "recall": round(tp / (tp + fn), 4) if (tp + fn) else 0.0,
                "fp_rate": round(fp / scored, 4) if scored else 0.0,
                "fn_rate": round(fn / (tp + fn), 4) if (tp + fn) else 0.0,
            }
        return AggregateStats(
            n=len(reps),
            avg_resolution_rate=round(mean(rp.resolution_rate for rp in reps), 4),
            avg_uncertainty_reduction=round(mean(rp.uncertainty_reduction for rp in reps), 4),
            avg_information_gain=round(mean(rp.est_information_gain for rp in reps), 4),
            avg_probes=round(mean(rp.probes for rp in reps), 4),
            avg_runtime_s=round(mean(rp.runtime_s for rp in reps), 6),
            avg_evidence_reuse=round(mean(rp.evidence_reuse for rp in reps), 4),
            avg_uncertainty_reduction_per_probe=round(
                mean(rp.uncertainty_reduction_per_probe for rp in reps), 4),
            **rel)

    def to_dict(self) -> dict:
        return {"cases": [r.to_dict() for r in self.results], "aggregate": self.aggregate().to_dict()}

    def to_csv(self) -> str:
        """One row per case — the flat table you'd load into a notebook / spreadsheet for plots."""
        if not self.results:
            return ""
        rows = [r.to_dict() for r in self.results]
        cols = list(rows[0].keys())
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=cols)
        w.writeheader()
        for row in rows:
            w.writerow(row)
        return buf.getvalue()


def run_corpus(cases: list[BenchmarkCase]) -> CorpusResult:
    """Run every case, timing each, and collect its ResearchReport. Deterministic given deterministic
    (cassette/stub) drivers, so the whole corpus run is reproducible."""
    results: list[CaseResult] = []
    for case in cases:
        report = run_and_report(case.state_factory, completer=case.completer,
                                executor=case.executor, ground_truth=case.ground_truth)
        results.append(CaseResult(name=case.name, label=case.label, report=report))
    return CorpusResult(results=results)


# ── Persistence + regression ──────────────────────────────────────────────────────────────────

def save_baseline(agg: AggregateStats, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(agg.to_dict(), fh, indent=2)


def load_baseline(path: str) -> AggregateStats:
    with open(path, encoding="utf-8") as fh:
        return AggregateStats(**json.load(fh))


# Default regression gates. A commit that crosses any of these vs the stored baseline FAILS.
_DEFAULT_THRESHOLDS = {
    "max_fp_rate_increase": 0.02,          # false positives may not climb > 2 points
    "max_avg_probes_increase_pct": 0.15,   # probe cost may not grow > 15%
    "min_uncertainty_reduction_ratio": 0.90,  # uncertainty reduction may not drop > 10%
}


@dataclass(frozen=True)
class RegressionResult:
    passed: bool
    deltas: dict = field(default_factory=dict)
    failures: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"passed": self.passed, "deltas": dict(self.deltas), "failures": list(self.failures)}


def regression_check(current: AggregateStats, baseline: AggregateStats,
                     thresholds: Optional[dict] = None) -> RegressionResult:
    """Compare a corpus run against a stored baseline; FAIL if any gate is crossed. This is what
    turns NetLogic into a continuously-measured platform: run it in CI against `main`'s baseline."""
    t = {**_DEFAULT_THRESHOLDS, **(thresholds or {})}
    failures: list[str] = []

    d_probes = current.avg_probes - baseline.avg_probes
    d_unc = current.avg_uncertainty_reduction - baseline.avg_uncertainty_reduction
    cur_fp = current.fp_rate if current.fp_rate is not None else 0.0
    base_fp = baseline.fp_rate if baseline.fp_rate is not None else 0.0
    d_fp = cur_fp - base_fp
    deltas = {
        "avg_probes": round(d_probes, 4),
        "avg_uncertainty_reduction": round(d_unc, 4),
        "fp_rate": round(d_fp, 4),
        "avg_runtime_s": round(current.avg_runtime_s - baseline.avg_runtime_s, 6),
    }

    if d_fp > t["max_fp_rate_increase"]:
        failures.append(f"false-positive rate rose {d_fp:.3f} (> {t['max_fp_rate_increase']})")
    if baseline.avg_probes > 0 and d_probes / baseline.avg_probes > t["max_avg_probes_increase_pct"]:
        failures.append(f"avg probes rose {d_probes/baseline.avg_probes:.0%} "
                        f"(> {t['max_avg_probes_increase_pct']:.0%})")
    if baseline.avg_uncertainty_reduction > 0 and \
            current.avg_uncertainty_reduction / baseline.avg_uncertainty_reduction \
            < t["min_uncertainty_reduction_ratio"]:
        failures.append("uncertainty reduction dropped below "
                        f"{t['min_uncertainty_reduction_ratio']:.0%} of baseline")
    return RegressionResult(passed=not failures, deltas=deltas, failures=failures)


# ── Per-validator quality (the "should this validator exist?" questions, answered with numbers) ──

@dataclass(frozen=True)
class ValidatorQuality:
    """How a single safe-active validator actually behaves across a corpus — the benchmark questions
    a validator must answer to earn its place: does it confirm correctly, confirm wrongly, or run
    with no information?"""
    validator: str
    ran: int = 0
    correct_confirm: int = 0        # confirmed AND truly present (needs a ground-truth label)
    incorrect_confirm: int = 0      # confirmed BUT not truly present → a false positive
    unlabeled_confirm: int = 0      # confirmed, but no ground-truth label to score it
    no_info: int = 0                # ran but did not confirm (added no information this time)
    precision: Optional[float] = None   # correct / (correct + incorrect); None if nothing labeled-confirmed

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


def validator_quality(results, ground_truth: Optional[dict] = None) -> list[ValidatorQuality]:
    """Aggregate active-validation results into per-validator quality stats. `results` is a list of
    `ValidationResult` (or their dicts, e.g. from art['active_validation']); `ground_truth` maps a
    validator's `confirms` key → whether it is truly present, unlocking correct/incorrect scoring.

    Only EXECUTED probes count (a gate-denied probe never ran). Deterministic; pure."""
    gt = {str(k).lower(): bool(v) for k, v in (ground_truth or {}).items()}
    agg: dict[str, dict] = {}
    for r in results:
        d = r.to_dict() if hasattr(r, "to_dict") else dict(r)
        if not d.get("executed"):
            continue
        name = str(d.get("confirms") or d.get("probe") or "?")
        a = agg.setdefault(name, {"ran": 0, "cc": 0, "ic": 0, "uc": 0, "ni": 0})
        a["ran"] += 1
        if d.get("succeeded"):
            truth = gt.get(name.lower())
            if truth is True:
                a["cc"] += 1
            elif truth is False:
                a["ic"] += 1
            else:
                a["uc"] += 1
        else:
            a["ni"] += 1
    out: list[ValidatorQuality] = []
    for name, a in sorted(agg.items()):
        labeled = a["cc"] + a["ic"]
        out.append(ValidatorQuality(
            validator=name, ran=a["ran"], correct_confirm=a["cc"], incorrect_confirm=a["ic"],
            unlabeled_confirm=a["uc"], no_info=a["ni"],
            precision=round(a["cc"] / labeled, 4) if labeled else None))
    return out
