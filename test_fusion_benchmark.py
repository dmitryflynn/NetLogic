"""Tests for the benchmark harness — the thing that measures the bet.

No network: the demo corpus is scored with the ground-truth oracle, and the
contrived cases never produce a gray band (so the AI is never called).
"""

from src.fusion.benchmark import (
    LabeledCase, score, score_with_oracle, demo_corpus, run_pipeline, oracle_complete,
)
from src.fusion.signals import Signal


# ── The demo corpus: documents the real numbers the pipeline delivers ───────────

def test_demo_corpus_metrics_with_oracle():
    r = score_with_oracle(demo_corpus())
    assert (r.tp, r.fp, r.fn, r.tn) == (2, 1, 0, 7)
    assert r.subjects == 10
    assert r.raw_fp == 8
    assert abs(r.fp_reduction - 0.875) < 1e-9       # 87.5% fewer false positives than raw
    assert r.critical_recall == 1.0 and r.critical_fn == 0
    assert abs(r.raw_precision - 0.20) < 1e-9        # raw scanner: 20% precision
    assert abs(r.precision - (2 / 3)) < 1e-9         # pipeline: 67% precision
    assert r.recall == 1.0
    assert r.passed is True


def test_pipeline_precision_beats_raw():
    r = score_with_oracle(demo_corpus())
    assert r.precision > r.raw_precision              # the entire value proposition


def test_pipeline_never_drops_a_real_critical():
    for c in demo_corpus():
        dec = run_pipeline(c, oracle_complete(c))
        for skey, gt in c.truth.items():
            if gt.get("is_real") and gt.get("severity") == "critical":
                assert dec.get(skey) in ("confirmed", "potential"), (c.name, skey)


# ── Harness math / guarantees ───────────────────────────────────────────────────

def test_no_noise_means_full_fp_reduction_and_pass():
    s = Signal(source="nvd", kind="vuln", claim="CVE-z", host="h", port=1, cvss=9.8, kev=True)
    case = LabeledCase("clean", [s], {("h", 1, "cve-z"): {"is_real": True, "severity": "critical"}})
    r = score([case])                                 # KEV → pinned, no gray band, no AI
    assert r.tp == 1 and r.fp == 0
    assert r.fp_reduction == 1.0 and r.passed is True


def test_harness_catches_a_dropped_critical_and_fails():
    # Contrived: mislabel a lone low-impact signal as a real critical. The gate
    # discards it (low impact) → the harness must register the critical FN and FAIL.
    s = Signal(source="banner", kind="tech", claim="x", host="h", port=1, reliability="low", cvss=0.0)
    case = LabeledCase("mislabel", [s], {("h", 1, "x"): {"is_real": True, "severity": "critical"}})
    r = score([case])
    assert r.fn == 1 and r.critical_fn == 1
    assert r.critical_recall == 0.0
    assert r.passed is False                          # zero-critical-FN gate trips


def test_below_threshold_fp_reduction_fails():
    # Two noise subjects, both kept (one discardable mislabeled as high-impact noise
    # that survives) — FP reduction below 80% must fail even with perfect critical recall.
    sigs = [
        Signal(source="nuclei", kind="vuln", claim="a", host="h", port=1, cvss=9.0, reliability="medium"),
        Signal(source="nuclei", kind="vuln", claim="b", host="h", port=2, cvss=9.0, reliability="medium"),
    ]
    case = LabeledCase("noisy", sigs, {
        ("h", 1, "a"): {"is_real": False, "severity": "high"},
        ("h", 2, "b"): {"is_real": False, "severity": "high"},
    })
    # Oracle says false_positive, but both are high-impact → kept as "potential" → both FP.
    r = score([case], complete_for=oracle_complete)
    assert r.fp == 2 and r.fp_reduction == 0.0
    assert r.passed is False


def test_summary_is_ascii_safe_and_labeled():
    r = score_with_oracle(demo_corpus())
    r.summary().encode("ascii")                       # must not raise on a Windows console
    assert "PASS" in r.summary()
