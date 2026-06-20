"""
Fusion layer — cassette-corpus benchmark runner + CLI.

Loads HTTP cassettes (Vulhub + clean recordings), runs the real sensors against the
recorded traffic, pushes the resulting signals through gate -> AI, scores against the
cassettes' ground truth, and exports a research-paper-ready report.

CLI:
  python -m src.fusion.corpus --oracle                       # perfect-AI upper bound
  python -m src.fusion.corpus --provider ollama --model glm-5:cloud \
      --base-url https://ollama.com/v1 --api-key $KEY \
      --export report.md --format md
"""

from __future__ import annotations

from typing import Callable, Optional

from src.fusion.benchmark import (
    LabeledCase, BenchmarkReport, score, score_with_oracle, oracle_complete, run_pipeline,
)
from src.fusion.cassette import Cassette, load_cassettes, signals_from_cassette, cassette_truth


def cassette_to_case(cassette: Cassette) -> LabeledCase:
    return LabeledCase(
        name=cassette.name,
        signals=signals_from_cassette(cassette),
        truth=cassette_truth(cassette),
    )


def cases_from_cassettes(directory: Optional[str] = None) -> list[LabeledCase]:
    return [cassette_to_case(c) for c in load_cassettes(directory)]


def score_cassettes(directory: Optional[str] = None, complete: Optional[Callable] = None,
                    oracle: bool = False) -> BenchmarkReport:
    cases = cases_from_cassettes(directory)
    if oracle:
        return score_with_oracle(cases)
    return score(cases, complete=complete)


# ── CLI ─────────────────────────────────────────────────────────────────────────

def main(argv=None) -> int:
    import argparse  # noqa: PLC0415

    p = argparse.ArgumentParser(
        prog="python -m src.fusion.corpus",
        description="Run the fusion benchmark over an HTTP-cassette corpus (Vulhub + clean).",
    )
    p.add_argument("--cassettes", default="", help="Directory of cassette .json files (default: bundled seeds).")
    p.add_argument("--provider", default="ollama", help="AI provider (default: ollama).")
    p.add_argument("--model", default="", help="Model id (e.g. glm-5:cloud).")
    p.add_argument("--base-url", default="", help="OpenAI-compatible base URL (e.g. https://ollama.com/v1).")
    p.add_argument("--api-key", default="", help="API key if the endpoint needs one.")
    p.add_argument("--oracle", action="store_true", help="Use the ground-truth oracle (no model).")
    p.add_argument("--verbose", "-v", action="store_true", help="Print per-subject decisions.")
    p.add_argument("--export", default="", help="Write the report to this path.")
    p.add_argument("--format", default="md", choices=["md", "json", "latex"], help="Export format.")
    args = p.parse_args(argv)

    directory = args.cassettes or None
    cases = cases_from_cassettes(directory)
    if not cases:
        raise SystemExit("No cassettes found.")

    if args.oracle:
        label = "ORACLE (perfect-AI upper bound)"
        completer_for = oracle_complete
    else:
        from src.fusion.ai import make_completer  # noqa: PLC0415
        from src import ai_analyst as aa  # noqa: PLC0415
        cfg = aa.AIConfig(api_key=(args.api_key or None), provider=args.provider,
                          model=(args.model or None), base_url=(args.base_url or None)).resolve()
        usable, reason = cfg.is_usable()
        if not usable:
            raise SystemExit(f"AI config not usable: {reason}")
        print(f"Model: {cfg.provider} / {cfg.model}  @ {cfg.base_url}  (key {'set' if cfg.api_key else 'none'})")
        completer = make_completer(cfg)
        completer_for = (lambda _c: completer)
        label = "REAL MODEL"

    decisions = {c.name: run_pipeline(c, completer_for(c)) for c in cases}

    if args.verbose:
        print("\nPer-subject decisions:")
        for c in cases:
            for (host, port, claim), dec in decisions[c.name].items():
                print(f"  {c.name:24} {host}:{port:<5} {claim:24} -> {dec}")

    from src.fusion.benchmark import _score_precomputed  # noqa: PLC0415
    report = _score_precomputed(cases, decisions)

    print()
    print(f"=== {label} ===")
    print(report.summary())
    print(f"  precision   : {report.precision:.0%}   (raw scanner {report.raw_precision:.0%})")
    print(f"  recall      : {report.recall:.0%}")
    print(f"  crit-recall : {report.critical_recall:.0%}   (critical FNs: {report.critical_fn})")
    print(f"  FP reduction: {report.fp_reduction:.0%}   (raw {report.raw_fp} -> pipeline {report.fp})")
    print(f"  PASS GATE   : {'PASS' if report.passed else 'FAIL'}")

    if args.export:
        content = {"md": report.to_markdown, "json": report.to_json, "latex": report.to_latex}[args.format]()
        with open(args.export, "w", encoding="utf-8") as fh:
            fh.write(content + "\n")
        print(f"\nExported {args.format} report -> {args.export}")

    return 0 if report.passed else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
