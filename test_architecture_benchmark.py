"""Architecture-detection benchmark — the reproducible number for NetLogic's differentiator.

Scores the real summarize_architecture against a LABELED corpus (component precision/recall/F1,
stack-kind accuracy, attack-surface coverage). Pure + deterministic, so the number is CI-gateable.
"""
from src.architecture_benchmark import (
    ArchCase, builtin_cases, run_arch_corpus, score_case,
)


def test_builtin_corpus_scores_high():
    rep = run_arch_corpus(builtin_cases())
    agg = rep.aggregate()
    # NetLogic should model these labeled architectures well — this pins the differentiator's number.
    assert agg["n"] == 3
    assert agg["mean_f1"] >= 0.85
    assert agg["stack_kind_accuracy"] == 1.0          # every labeled stack kind identified
    assert agg["mean_surface_recall"] >= 0.9


def test_perfect_case_is_precision_recall_1():
    case = next(c for c in builtin_cases() if "serverless" in c.name)
    s = score_case(case)
    assert s.recall == 1.0                            # all four labeled components found
    assert s.stack_kind_correct
    assert s.surface_recall >= 0.8


def test_scorer_penalises_a_miss():
    # expect a component that isn't there → recall drops, FN counted
    bad = ArchCase(name="miss", artifact={"header_audit": {"server_banner": "Vercel"}},
                   expected_components={("hosting", "vercel"), ("auth", "clerk")},
                   expected_stack_kind="mixed")
    s = score_case(bad)
    assert s.tp == 1 and s.fn == 1
    assert s.recall == 0.5


def test_stack_kind_mismatch_flagged():
    case = ArchCase(name="wrongkind",
                    artifact={"stack_result": {"technologies": [
                        {"category": "Server", "name": "nginx", "confidence": "HIGH"}]}},
                    expected_components={("server", "nginx")},
                    expected_stack_kind="serverless-spa")   # actually traditional-server
    s = score_case(case)
    assert s.stack_kind_correct is False


def test_report_to_csv_and_aggregate_shapes():
    rep = run_arch_corpus(builtin_cases())
    csv = rep.to_csv()
    assert csv.splitlines()[0].startswith("name,precision,recall,f1")
    assert len(csv.splitlines()) == 4                 # header + 3 cases
    assert set(rep.aggregate()) >= {"mean_precision", "mean_recall", "mean_f1", "stack_kind_accuracy"}
