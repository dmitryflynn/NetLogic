"""
Fusion layer — the benchmark harness.

This is the measurement infrastructure for THE BET: that the sensors→gate→AI
pipeline keeps incumbent-grade recall while slashing the noise that makes raw
scanners (and Tenable/Qualys) unusable. It scores the pipeline against a labeled
corpus and reports the two metrics that decide whether we win the lane:

  • FP reduction vs a raw scanner  — must be ≥ 80%.
  • Critical recall                — must be EXACTLY 100% (zero dropped real criticals).

A "raw scanner" baseline reports every flagged subject as a finding (perfect recall,
terrible precision — the incumbent profile). The pipeline is scored as: a subject is
"reported" if its final decision is confirmed or potential, "suppressed" if discarded.

The LLM is pluggable (`complete`). Tests use a deterministic ground-truth ORACLE to
measure the *upper bound* of the deterministic machinery; pointing `complete` at a
real model + real labeled targets measures the real adjudicator. The harness math is
identical either way.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable, Optional

from src.fusion.gate import adjudicate
from src.fusion.adjudicator import run_adjudication
from src.fusion.signals import Signal

# Pass thresholds (the metric we committed to).
MIN_FP_REDUCTION = 0.80
REQUIRED_CRITICAL_RECALL = 1.0

_REPORTED = ("confirmed", "potential")


@dataclass
class LabeledCase:
    """One target's worth of sensor signals plus per-subject ground truth.

    truth maps a subject key (host, port, claim_lower) → {"is_real": bool,
    "severity": "critical|high|medium|low"}. Only subjects a sensor flagged are
    scored here (sensor *coverage* is a separate benchmark).
    """
    name: str
    signals: list[Signal]
    truth: dict[tuple, dict] = field(default_factory=dict)

    def truth_for(self, host, port, claim) -> Optional[dict]:
        return self.truth.get((host, port, str(claim).lower().strip()))


@dataclass
class BenchmarkReport:
    cases: int
    subjects: int
    tp: int
    fp: int
    fn: int
    tn: int
    precision: float
    recall: float
    critical_recall: float
    critical_fn: int
    raw_fp: int
    raw_precision: float
    fp_reduction: float
    passed: bool

    def summary(self) -> str:
        return (
            f"cases={self.cases} subjects={self.subjects} | "
            f"precision {self.precision:.0%} (raw {self.raw_precision:.0%}) | "
            f"recall {self.recall:.0%} | critical-recall {self.critical_recall:.0%} | "
            f"FP -{self.fp_reduction:.0%} (raw {self.raw_fp}->{self.fp}) | "
            f"{'PASS' if self.passed else 'FAIL'}"
        )


def run_pipeline(case: LabeledCase, complete: Optional[Callable] = None) -> dict[tuple, str]:
    """Run sensors-output → gate → AI on a case; return {subject_key: decision}."""
    verdicts = adjudicate(case.signals)
    run_adjudication(verdicts, complete=complete)
    return {(v.host, v.port, v.claim.lower().strip()): v.decision for v in verdicts}


def score(cases: list[LabeledCase], complete: Optional[Callable] = None,
          complete_for: Optional[Callable[["LabeledCase"], Callable]] = None) -> BenchmarkReport:
    """Score the pipeline over a corpus.

    Pass `complete` to use one LLM call for all cases (real model), or `complete_for`
    to build a per-case `complete` (used by the ground-truth oracle).
    """
    tp = fp = fn = tn = 0
    raw_fp = 0
    crit_real = crit_reported = crit_fn = 0
    subjects = 0

    for case in cases:
        comp = complete_for(case) if complete_for else complete
        decisions = run_pipeline(case, comp)
        for skey, gt in case.truth.items():
            subjects += 1
            reported = decisions.get(skey) in _REPORTED
            is_real = bool(gt.get("is_real"))
            is_crit = is_real and gt.get("severity") == "critical"

            if is_real and reported:
                tp += 1
            elif (not is_real) and reported:
                fp += 1
            elif is_real and not reported:
                fn += 1
                if is_crit:
                    crit_fn += 1
            else:
                tn += 1

            # Raw baseline reports EVERY flagged subject → every noise subject is a FP.
            if not is_real:
                raw_fp += 1

            if is_crit:
                crit_real += 1
                if reported:
                    crit_reported += 1

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    critical_recall = crit_reported / crit_real if crit_real else 1.0
    raw_tp = tp + fn  # raw reports all real ones too
    raw_precision = raw_tp / (raw_tp + raw_fp) if (raw_tp + raw_fp) else 1.0
    fp_reduction = (raw_fp - fp) / raw_fp if raw_fp else 1.0
    passed = fp_reduction >= MIN_FP_REDUCTION and critical_recall >= REQUIRED_CRITICAL_RECALL

    return BenchmarkReport(
        cases=len(cases), subjects=subjects, tp=tp, fp=fp, fn=fn, tn=tn,
        precision=precision, recall=recall, critical_recall=critical_recall,
        critical_fn=crit_fn, raw_fp=raw_fp, raw_precision=raw_precision,
        fp_reduction=fp_reduction, passed=passed,
    )


# ── Ground-truth oracle (upper-bound "perfect AI") ──────────────────────────────

def oracle_complete(case: LabeledCase) -> Callable[[str, str], str]:
    """A `complete` that answers each gray item from the case's ground truth — i.e.
    a perfect adjudicator. Measures what the deterministic machinery + safety floors
    deliver when the AI is right; the real model is measured by swapping this out."""
    def complete(system: str, user: str) -> str:
        items = json.loads(user.split("```json", 1)[1].rsplit("```", 1)[0])
        out = []
        for it in items:
            gt = case.truth_for(it.get("host"), it.get("port"), it.get("subject"))
            real = bool(gt and gt.get("is_real"))
            out.append({
                "id": it["id"],
                "verdict": "real" if real else "false_positive",
                "severity": (gt or {}).get("severity", "low"),
                "confidence": 1.0, "reason": "oracle", "benign_ruled_out": [],
            })
        return json.dumps(out)
    return complete


def score_with_oracle(cases: list[LabeledCase]) -> BenchmarkReport:
    """Score the corpus using each case's ground-truth oracle as the AI — the
    perfect-AI upper bound of what the deterministic machinery + safety floors deliver."""
    return score(cases, complete_for=oracle_complete)


# ── A small synthetic labeled corpus (offline demo) ─────────────────────────────

def _s(source, kind, claim, host, port, **kw) -> Signal:
    return Signal(source=source, kind=kind, claim=claim, host=host, port=port, **kw)


def demo_corpus() -> list[LabeledCase]:
    """Hand-authored labeled cases exercising the realistic mix: pinned criticals,
    corroborated real findings, droppable low/medium noise, and the safety-floor
    cost (a high-impact false positive the pipeline keeps as 'potential')."""
    cases: list[LabeledCase] = []

    # Case A — a Linux web host with a real exploited critical + lots of inventory noise.
    h = "10.0.0.10"
    sigs = [
        _s("nvd", "vuln", "CVE-2021-44228", h, 8080, cvss=10.0, kev=True, exploit_available=True,
           evidence="Log4Shell JNDI lookup reflected"),                       # real critical (pinned)
        _s("wappalyzer", "tech", "nginx", h, 443, reliability="medium", evidence="Server: nginx/1.25"),  # noise
        _s("wappalyzer", "tech", "wordpress", h, 443, reliability="medium", evidence="meta generator"),  # noise
        _s("banner", "tech", "php", h, 443, reliability="low", evidence="X-Powered-By: PHP"),             # noise
        _s("nuclei", "misconfig", "dir-listing", h, 443, reliability="medium", cvss=5.0,
           evidence="Index of /backup"),                                      # noise (medium, lone → discarded)
    ]
    cases.append(LabeledCase("linux-web", sigs, {
        (h, 8080, "cve-2021-44228"): {"is_real": True, "severity": "critical"},
        (h, 443, "nginx"): {"is_real": False, "severity": "low"},
        (h, 443, "wordpress"): {"is_real": False, "severity": "low"},
        (h, 443, "php"): {"is_real": False, "severity": "low"},
        (h, 443, "dir-listing"): {"is_real": False, "severity": "medium"},
    }))

    # Case B — corroborated real finding + a high-impact FALSE positive (the safety cost).
    h = "10.0.0.20"
    sigs = [
        _s("nuclei", "vuln", "CVE-2022-1388", h, 443, cvss=9.8, reliability="medium",
           evidence="iControl REST auth bypass confirmed via X-F5-Auth"),
        _s("probe", "vuln", "CVE-2022-1388", h, 443, cvss=9.8, reliability="high",
           evidence="POST /mgmt/tm/util/bash returned command output"),       # probe-confirmed → pinned real
        _s("nuclei", "vuln", "CVE-2099-9999", h, 443, cvss=9.1, reliability="medium",
           evidence="title contains 'Admin' (generic)"),                      # high-impact FALSE positive
        _s("banner", "tech", "f5-big-ip", h, 443, reliability="low"),          # noise
    ]
    cases.append(LabeledCase("f5-host", sigs, {
        (h, 443, "cve-2022-1388"): {"is_real": True, "severity": "critical"},
        (h, 443, "cve-2099-9999"): {"is_real": False, "severity": "high"},     # FP, but high-impact → kept as potential
        (h, 443, "f5-big-ip"): {"is_real": False, "severity": "low"},
    }))

    # Case C — mostly noise: parked/patched host. Everything should be suppressed.
    h = "10.0.0.30"
    sigs = [
        _s("wappalyzer", "tech", "apache", h, 80, reliability="medium", evidence="Server: Apache/2.4.58"),
        _s("nuclei", "misconfig", "default-page", h, 80, reliability="medium", cvss=4.0,
           evidence="It works! default apache page"),
        _s("banner", "tech", "apache", h, 80, reliability="low", evidence="Server: Apache"),  # corroborates apache
    ]
    cases.append(LabeledCase("parked", sigs, {
        (h, 80, "apache"): {"is_real": False, "severity": "low"},
        (h, 80, "default-page"): {"is_real": False, "severity": "low"},
    }))

    return cases
