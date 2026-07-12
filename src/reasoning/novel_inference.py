"""
Novel-vulnerability inference (deterministic) — resolve C1's novel hypotheses from gathered evidence.

Framework inference (`inference.py`) answers "which framework is this?" from evidence content. This
is its sibling for the novel-vulnerability hypotheses C1 invents ("possible cache poisoning / request
smuggling / open redirect / auth bypass"). It closes the loop the A/B benchmark exposed: a novel
hypothesis no longer dead-ends at 'unresolved' — passive evidence can REFUTE it or mark it LIKELY.

HONEST BOUNDARY (deliberate): this engine never CONFIRMS an exploitable vulnerability. Confirming
exploitability requires ACTIVE testing (Phase-8 `safe_active` behind the ActionGate + an external
executor), which the deterministic core does not run. Passive evidence can only rule a vuln OUT or
raise suspicion — which is exactly the counterfactual/refutation value: deterministically seeking
disconfirming evidence rather than only confirming.

No AI. Pure predicate matching over the evidence blob, exactly like framework inference. The rules
are DATA — a small built-in starter set here; it grows via technology packs and the Knowledge Miner.
"""
from __future__ import annotations

from dataclasses import dataclass

from src.reasoning.inference import InferenceEngine, InferenceStep


@dataclass(frozen=True)
class NovelRule:
    vuln_type: str
    refute: tuple[str, ...] = ()        # evidence that RULES OUT the vuln → REFUTED
    suggestive: tuple[str, ...] = ()    # evidence that raises suspicion → LIKELY (never CONFIRMED here)


# Starter detection heuristics over passively-gathered evidence — NOT exploit logic. Markers are
# matched case-insensitively against the observation blob (same contract as framework rules).
_BUILTIN_NOVEL_RULES: dict[str, NovelRule] = {
    "cache_poisoning": NovelRule(
        "cache_poisoning",
        refute=("cache-control: no-store", "cache-control: private", "no-cache", "pragma: no-cache"),
        suggestive=("x-cache", "age:", "x-forwarded-host", "x-forwarded-server", "vary:")),
    "request_smuggling": NovelRule(
        "request_smuggling",
        refute=("http/2", "http/3"),
        suggestive=("transfer-encoding", "content-length", "connection: keep-alive", "via:")),
    "open_redirect": NovelRule(
        "open_redirect",
        suggestive=("location:", "?url=", "?next=", "?redirect=", "?return=")),
    "auth_bypass": NovelRule(
        "auth_bypass",
        refute=("www-authenticate:", "401 unauthorized"),
        suggestive=("x-forwarded-for", "x-original-url", "x-rewrite-url")),
}


class NovelInferenceEngine:
    """Resolve novel-vuln hypotheses (label/reason contains 'novel:<type>') from the evidence blob."""

    def __init__(self, rules: dict[str, NovelRule] | None = None) -> None:
        self._rules = rules if rules is not None else _BUILTIN_NOVEL_RULES

    def infer(self, state) -> list[InferenceStep]:
        blob = InferenceEngine._evidence_blob(state)      # reuse the framework engine's blob builder
        steps: list[InferenceStep] = []
        for h in state.investigation.hypotheses.leaves():
            if h.status != "active":
                continue
            vt = self._vuln_type(h)
            rule = self._rules.get(vt)
            if rule is None:
                continue
            # Refutation first (ruling out is the sound, high-value deterministic conclusion).
            hit = next((n for n in rule.refute if n and n in blob), "")
            if hit:
                state.investigation.hypotheses.resolve(h.id, "refuted", evidence_refs=[hit])
                steps.append(InferenceStep(hypothesis_id=h.id, rule=f"novel:{vt}",
                                           decision="refuted", matched=hit, evidence_refs=(hit,)))
                continue
            # Otherwise, suggestive evidence marks it LIKELY (a candidate for ACTIVE validation —
            # which this engine never performs). Recorded as provenance; status stays active.
            sug = next((n for n in rule.suggestive if n and n in blob), "")
            if sug:
                steps.append(InferenceStep(hypothesis_id=h.id, rule=f"novel:{vt}",
                                           decision="likely", matched=sug, evidence_refs=(sug,)))
        return steps

    @staticmethod
    def _vuln_type(h) -> str:
        src = f"{h.reason or ''} {h.label or ''}"
        if "novel:" in src:
            return src.split("novel:", 1)[1].split(":")[0].strip()
        return ""
