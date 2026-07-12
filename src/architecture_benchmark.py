"""
Architecture-detection benchmark — the reproducible number for NetLogic's differentiator.

NetLogic's edge is NOT "did it pop the box" (that's an exploitation agent's game) — it's *does it
correctly MODEL the application's architecture*. This harness measures exactly that against a LABELED
corpus: for each case it runs the real `summarize_architecture` and scores component precision/recall/
F1, stack-kind accuracy, and attack-surface coverage, then aggregates.

It is PURE + deterministic (no AI, no network — cases carry pre-captured artifacts), so the number is
reproducible and CI-gateable. Real targets / CVE-Bench cases ingest identically — capture a scan
artifact + label the expected architecture and drop it in `builtin_cases()` or pass your own.

    python -m src.architecture_benchmark            # run the built-in corpus, print the report
"""
from __future__ import annotations

from dataclasses import dataclass, field

from src.architecture import summarize_architecture


@dataclass
class ArchCase:
    name: str
    artifact: dict
    expected_components: set          # {(role, name_substring_lower)}
    expected_stack_kind: str
    expected_surfaces: set = field(default_factory=set)   # keyword substrings expected in surfaces


@dataclass
class CaseScore:
    name: str
    precision: float
    recall: float
    f1: float
    stack_kind_correct: bool
    surface_recall: float
    tp: int
    fp: int
    fn: int

    def to_dict(self) -> dict:
        return {"name": self.name, "precision": round(self.precision, 3),
                "recall": round(self.recall, 3), "f1": round(self.f1, 3),
                "stack_kind_correct": self.stack_kind_correct,
                "surface_recall": round(self.surface_recall, 3),
                "tp": self.tp, "fp": self.fp, "fn": self.fn}


def _match(detected_name: str, expected_sub: str) -> bool:
    d, e = detected_name.lower(), expected_sub.lower()
    return e in d or d in e


def score_case(case: ArchCase) -> CaseScore:
    summ = summarize_architecture(case.artifact)
    detected = [(c.role, c.name) for c in (summ.components if summ else [])]

    matched_exp = set()
    matched_det = set()
    for (er, en) in case.expected_components:
        for i, (dr, dn) in enumerate(detected):
            if dr == er and _match(dn, en) and i not in matched_det:
                matched_exp.add((er, en))
                matched_det.add(i)
                break
    tp = len(matched_exp)
    fn = len(case.expected_components) - tp
    fp = len(detected) - len(matched_det)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    sk_ok = bool(summ) and summ.stack_kind == case.expected_stack_kind
    surfaces_blob = " ".join(summ.attack_surfaces).lower() if summ else ""
    surf_hit = sum(1 for s in case.expected_surfaces if s.lower() in surfaces_blob)
    surf_recall = surf_hit / len(case.expected_surfaces) if case.expected_surfaces else 1.0

    return CaseScore(case.name, precision, recall, f1, sk_ok, surf_recall, tp, fp, fn)


@dataclass
class ArchBenchmarkReport:
    cases: list = field(default_factory=list)   # CaseScore

    def aggregate(self) -> dict:
        n = len(self.cases) or 1
        return {
            "n": len(self.cases),
            "mean_precision": round(sum(c.precision for c in self.cases) / n, 3),
            "mean_recall": round(sum(c.recall for c in self.cases) / n, 3),
            "mean_f1": round(sum(c.f1 for c in self.cases) / n, 3),
            "stack_kind_accuracy": round(sum(1 for c in self.cases if c.stack_kind_correct) / n, 3),
            "mean_surface_recall": round(sum(c.surface_recall for c in self.cases) / n, 3),
        }

    def to_csv(self) -> str:
        rows = ["name,precision,recall,f1,stack_kind_correct,surface_recall,tp,fp,fn"]
        for c in self.cases:
            rows.append(f"{c.name},{c.precision:.3f},{c.recall:.3f},{c.f1:.3f},"
                        f"{int(c.stack_kind_correct)},{c.surface_recall:.3f},{c.tp},{c.fp},{c.fn}")
        return "\n".join(rows)


def run_arch_corpus(cases) -> ArchBenchmarkReport:
    return ArchBenchmarkReport(cases=[score_case(c) for c in cases])


# ── Built-in labeled corpus (deterministic; extend with real captured artifacts) ─────────────────
def builtin_cases() -> list:
    serverless_spa = ArchCase(
        name="serverless-spa (React+Vercel+Clerk+Supabase)",
        artifact={
            "web_fingerprint": {"frontend": "React SPA", "is_spa": True,
                                "js_endpoints": ["/api/x"], "exposed_files": [],
                                "saas": [{"service": "Clerk", "category": "auth", "evidence": "i", "severity": "MEDIUM"},
                                         {"service": "Supabase", "category": "backend", "evidence": "p", "severity": "LOW"}]},
            "header_audit": {"server_banner": "Vercel", "powered_by": None},
            "tls_results": [{"port": 443}],
            "dns_result": {"mx_records": [{"provider": "Google Workspace"}], "email_spoofable": True},
        },
        expected_components={("frontend", "react"), ("hosting", "vercel"),
                             ("auth", "clerk"), ("backend", "supabase"), ("email", "google")},
        expected_stack_kind="serverless-spa",
        expected_surfaces={"authentication", "api endpoint", "supabase", "tls", "email"},
    )
    wordpress = ArchCase(
        name="traditional (WordPress on nginx/PHP)",
        artifact={
            "stack_result": {"technologies": [
                {"category": "Server", "name": "nginx", "confidence": "HIGH", "evidence": "Server hdr"},
                {"category": "CMS", "name": "WordPress", "confidence": "HIGH", "evidence": "/wp-json"},
                {"category": "Language", "name": "PHP", "confidence": "MEDIUM", "evidence": "x-powered-by"},
            ], "waf": {"detected": False}},
            "tls_results": [{"port": 443}],
        },
        expected_components={("server", "nginx"), ("server", "wordpress"), ("language", "php")},
        expected_stack_kind="traditional-server",
        expected_surfaces={"tls"},
    )
    django = ArchCase(
        name="traditional (Django behind Cloudflare)",
        artifact={
            "stack_result": {"technologies": [
                {"category": "Framework", "name": "Django", "confidence": "HIGH", "evidence": "csrftoken"},
                {"category": "CDN", "name": "Cloudflare", "confidence": "HIGH", "evidence": "cf-ray"},
            ], "hosting": "AWS", "waf": {"detected": True, "name": "Cloudflare WAF", "evidence": "cf"}},
            "tls_results": [{"port": 443}],
        },
        expected_components={("server", "django"), ("cdn", "cloudflare"), ("hosting", "aws"),
                             ("waf", "cloudflare")},
        expected_stack_kind="traditional-server",
        expected_surfaces={"tls"},
    )
    return [serverless_spa, wordpress, django]


def _main() -> None:
    rep = run_arch_corpus(builtin_cases())
    agg = rep.aggregate()
    print("NetLogic — Architecture-Detection Benchmark\n" + "=" * 44)
    print(rep.to_csv())
    print("-" * 44)
    print(f"cases={agg['n']}  precision={agg['mean_precision']}  recall={agg['mean_recall']}  "
          f"F1={agg['mean_f1']}  stack-kind-acc={agg['stack_kind_accuracy']}  "
          f"surface-recall={agg['mean_surface_recall']}")


if __name__ == "__main__":
    _main()
