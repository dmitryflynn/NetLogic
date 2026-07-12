"""
ProposalNormalizer (Track C, C0) — the total validation gate for raw agent output.

Mirrors the Phase 4 `proposal_parser.ProposalParser` contract exactly: for ANY input it returns a
result, never an uncontrolled exception, never partial/garbage state. `decode_total` reuses the
same decode shape (strip code fences, bounded-size JSON parse, NaN-safe numerics) so the AI input
boundary has one consistent behavior across the codebase.

This is the FIRST stage of the pipeline (Generate -> **Normalize** -> Rank -> Verify). A proposal
that fails normalization never reaches the Ranker or Verifier — it simply isn't produced.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Any, Optional

from src.reasoning.ai.errors import ValidationError
from src.reasoning.ai.proposals import (
    ContradictionPayload, ExplanationPayload, HypothesisPayload, KnowledgePayload,
    Proposal, ProposalEconomics, ProposalKind, ProposalProvenance, ObjectivePayload,
    PackPayload, Payload, ReflectionPayload, StrategyPayload, TemplatePayload,
    new_proposal_id,
)

_MAX_INPUT_CHARS = 20_000
_MAX_STR = 256
_MAX_LONG_STR = 2_000
_MAX_ITEMS = 32

# The ONLY evidence types C2 may request — read-only, deterministically gatherable by the Phase-3
# loop. Anything outside this set is silently dropped, so the AI can shape an investigation but can
# never conjure an evidence type the engine can't safely obtain (defense in depth, like the risk cap).
_GATHERABLE_EVIDENCE = frozenset({
    "server_header", "http_headers", "http_body", "cookie_set", "favicon_hash",
    "tls_version", "tls_alpn", "dns_records", "banner", "service", "technology", "version", "cve",
})


def _finite(v: Any, default: float = 0.0) -> float:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return default
    return f if math.isfinite(f) else default


def _clamp01(v: float) -> float:
    return max(0.0, min(1.0, v))


def _str(v: Any, max_len: int = _MAX_STR) -> str:
    return str(v)[:max_len] if isinstance(v, (str, int, float)) else ""


def decode_total(raw: Any, max_chars: int = _MAX_INPUT_CHARS) -> Any:
    """Total: returns decoded JSON (dict/list/...) or raises ValidationError. Never anything else."""
    if isinstance(raw, (dict, list)):
        return raw
    if not isinstance(raw, str):
        raise ValidationError("input is not text, dict, or list")
    if len(raw) > max_chars:
        raise ValidationError(f"input exceeds {max_chars} chars")
    text = raw.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1].rsplit("```", 1)[0] if "\n" in text else text[3:]
        text = text.strip()
    try:
        return json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise ValidationError(f"not valid JSON: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 — any decoder surprise is a validation failure
        raise ValidationError(f"decode failed: {exc}") from exc


@dataclass(frozen=True)
class NormalizeResult:
    """Never raises out of `normalize()` — inspect `.proposal is None` to detect rejection."""
    proposal: Optional[Proposal]
    reason: str = ""


def _provenance_from(d: Any, agent: str) -> ProposalProvenance:
    d = d if isinstance(d, dict) else {}
    return ProposalProvenance(
        model=_str(d.get("model", "")), prompt_version=_str(d.get("prompt_version", "")),
        temperature=_clamp01(_finite(d.get("temperature", 0.0))),
        reasoning_hash=_str(d.get("reasoning_hash", ""), 128),
        confidence=_clamp01(_finite(d.get("confidence", 0.0))),
        supporting_observation_ids=tuple(
            _str(v, 128) for v in (d.get("supporting_observation_ids") or [])[:_MAX_ITEMS]
            if isinstance(v, (str, int))))


def _economics_from(d: Any) -> ProposalEconomics:
    d = d if isinstance(d, dict) else {}
    gain = max(0.0, _finite(d.get("estimated_information_gain", 0.0)))
    runtime = max(0.01, _finite(d.get("estimated_runtime", 1.0), 1.0))
    cost = max(0.0, _finite(d.get("estimated_api_cost", 0.0)))
    probes = max(1, int(_finite(d.get("estimated_probe_count", 1), 1.0)))
    prob = _clamp01(_finite(d.get("estimated_prob_correct", 0.5), 0.5))
    # AI can NEVER claim risk above read_only through economics — whatever the input says, this
    # field is unconditionally forced to "read_only" (the SafetyVerifier enforces this again
    # independently later; this is defense in depth, not the sole gate).
    return ProposalEconomics(estimated_information_gain=gain, estimated_runtime=runtime,
                             estimated_api_cost=cost, estimated_probe_count=probes,
                             estimated_risk="read_only", estimated_prob_correct=prob)


def _build_payload(kind: ProposalKind, d: Any) -> Optional[Payload]:
    """Total per-kind payload builder: bounded, defensive, returns None on any structural failure."""
    if not isinstance(d, dict):
        return None
    try:
        if kind == ProposalKind.HYPOTHESIS:
            objective = d.get("objective")
            if not isinstance(objective, str) or not objective:
                return None
            cands_raw = d.get("candidates")
            cands: dict[str, float] = {}
            if isinstance(cands_raw, dict):
                for k, v in list(cands_raw.items())[:_MAX_ITEMS]:
                    if isinstance(k, str) and isinstance(v, (int, float)):
                        f = _finite(v)
                        if f > 0:
                            cands[k[:64]] = f
            return HypothesisPayload(objective=objective[:_MAX_STR], candidates=cands,
                                     novel=bool(d.get("novel", False)),
                                     rationale=_str(d.get("rationale", ""), _MAX_LONG_STR))

        if kind == ProposalKind.OBJECTIVE:
            goal_name = d.get("goal_name")
            if not isinstance(goal_name, str) or not goal_name:
                return None
            preds_raw = d.get("goal_predicate") or []
            preds = tuple(_str(p, 128) for p in preds_raw[:_MAX_ITEMS] if isinstance(p, str))
            # C2: required_evidence, filtered to the gatherable read-only vocabulary (order-preserving,
            # deduped). Anything the AI requests outside the vocabulary is dropped.
            ev_raw = d.get("required_evidence") or []
            seen: set[str] = set()
            req_ev: list[str] = []
            for e in ev_raw[:_MAX_ITEMS] if isinstance(ev_raw, list) else []:
                e = str(e).strip().lower()
                if e in _GATHERABLE_EVIDENCE and e not in seen:
                    seen.add(e)
                    req_ev.append(e)
            return ObjectivePayload(goal_name=goal_name[:_MAX_STR], goal_predicate=preds,
                                    priority=_clamp01(_finite(d.get("priority", 0.5), 0.5)),
                                    risk_budget="read_only",   # AI proposals never carry risk
                                    required_evidence=tuple(req_ev))

        if kind == ProposalKind.STRATEGY:
            goal_class = d.get("goal_class")
            if not isinstance(goal_class, str) or not goal_class:
                return None
            ids_raw = d.get("action_ids") or []
            ids = tuple(_str(a, 64) for a in ids_raw[:_MAX_ITEMS] if isinstance(a, str))
            return StrategyPayload(goal_class=goal_class[:_MAX_STR], action_ids=ids,
                                   rationale=_str(d.get("rationale", ""), _MAX_LONG_STR))

        if kind == ProposalKind.REFLECTION:
            subject = d.get("subject")
            if not isinstance(subject, str) or not subject:
                return None
            return ReflectionPayload(subject=subject[:_MAX_STR],
                                     optimization=_str(d.get("optimization", "")),
                                     detail=_str(d.get("detail", ""), _MAX_LONG_STR))

        if kind == ProposalKind.KNOWLEDGE:
            tech_id = d.get("tech_id")
            if not isinstance(tech_id, str) or not tech_id:
                return None
            rule = d.get("rule") if isinstance(d.get("rule"), dict) else {}
            fixtures_raw = d.get("fixtures") or []
            fixtures = tuple(f for f in fixtures_raw[:_MAX_ITEMS] if isinstance(f, dict))
            return KnowledgePayload(tech_id=tech_id[:_MAX_STR], rule=rule, fixtures=fixtures)

        if kind == ProposalKind.TEMPLATE:
            goal_class = d.get("goal_class")
            if not isinstance(goal_class, str) or not goal_class:
                return None
            stages_raw = d.get("stages") or ["default"]
            stages = tuple(_str(s, 64) for s in stages_raw[:_MAX_ITEMS] if isinstance(s, str)) \
                or ("default",)
            return TemplatePayload(goal_class=goal_class[:_MAX_STR], stages=stages)

        if kind == ProposalKind.PACK:
            tech_id = d.get("tech_id")
            if not isinstance(tech_id, str) or not tech_id:
                return None
            fps = d.get("fingerprints") if isinstance(d.get("fingerprints"), dict) else {}
            return PackPayload(tech_id=tech_id[:_MAX_STR], fingerprints=fps)

        if kind == ProposalKind.EXPLANATION:
            subject = d.get("subject")
            if not isinstance(subject, str) or not subject:
                return None
            return ExplanationPayload(subject=subject[:_MAX_STR],
                                      text=_str(d.get("text", ""), _MAX_LONG_STR))

        if kind == ProposalKind.CONTRADICTION:
            subject = d.get("subject")
            if not isinstance(subject, str) or not subject:
                return None
            cands_raw = d.get("candidates") or []
            cands = tuple(_str(c, 64) for c in cands_raw[:_MAX_ITEMS] if isinstance(c, str))
            ev_raw = d.get("evidence_node_ids") or []
            ev = tuple(_str(e, 128) for e in ev_raw[:_MAX_ITEMS] if isinstance(e, str))
            return ContradictionPayload(subject=subject[:_MAX_STR], candidates=cands,
                                        evidence_node_ids=ev)
    except Exception:  # noqa: BLE001 — any structural surprise is a normalization failure
        return None
    return None


class ProposalNormalizer:
    """Stage 1 of the pipeline. `normalize` is TOTAL: it never raises."""

    def normalize(self, raw: Any, *, kind: ProposalKind, agent: str) -> NormalizeResult:
        try:
            data = decode_total(raw)
        except ValidationError as exc:
            return NormalizeResult(proposal=None, reason=str(exc))
        if not isinstance(data, dict):
            return NormalizeResult(proposal=None, reason="expected a JSON object")
        payload = _build_payload(kind, data.get("payload"))
        if payload is None:
            return NormalizeResult(proposal=None, reason=f"invalid {kind.value} payload")
        provenance = _provenance_from(data.get("provenance"), agent)
        economics = _economics_from(data.get("economics"))
        proposal = Proposal(id=new_proposal_id(), kind=kind, agent=agent[:_MAX_STR],
                            payload=payload, provenance=provenance, economics=economics)
        return NormalizeResult(proposal=proposal)
