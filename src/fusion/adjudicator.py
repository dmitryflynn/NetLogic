"""
Fusion layer — the AI adjudication pass (gray band only).

The deterministic gate already settled the certain cases. This pass asks an LLM to
judge ONLY the gray band — the ambiguous middle — so AI cost scales with ambiguity,
not asset count. It is built around three safety properties from the design:

  1. The AI sees only label-stripped `to_ai()` bundles — no sensor names, no
     pre-assigned severity — so it judges the evidence, not scary software names.
  2. Mandatory disconfirmation: the prompt forces it to rule out benign
     explanations before calling something real.
  3. Zero-false-negative-on-criticals, enforced in CODE (not just the prompt):
     a high/critical-impact gray item can be promoted or demoted to "potential"
     (report + verify) but the AI can NEVER discard it. Unjudged or AI-failed
     items also fall back to "potential", never silently dropped.

Fail-soft: any AI/transport error leaves the gray band as "potential" (reported,
needs verification) — a scan never breaks, and nothing real is ever dropped.

`decision` values after this pass: "confirmed" | "discarded" | "potential".
The default LLM call reuses src.ai_analyst's transport; tests inject `complete`.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

from src.fusion.gate import Verdict, gray_band

log = logging.getLogger("netlogic.fusion.adjudicator")

# (system, user) -> raw model text
CompleteFn = Callable[[str, str], str]


@dataclass
class AIVerdict:
    verdict: str            # "real" | "false_positive" | "uncertain"
    severity: str = "low"   # the model's own severity read (informational only)
    confidence: float = 0.0
    reason: str = ""
    benign_ruled_out: list[str] = field(default_factory=list)


_SYSTEM = (
    "You are a precision security analyst adjudicating AMBIGUOUS scanner observations. "
    "For each item you are given ONLY observed evidence (HTTP bytes, exposure) and a "
    "deterministic_impact band — NOT the tool that produced it and NOT any pre-assigned "
    "severity. The 'subject' is an UNVERIFIED label: never assign severity from a "
    "software name; judge the evidence.\n\n"
    "For each item decide whether it is a REAL finding or noise:\n"
    "  • \"real\": the evidence genuinely demonstrates the issue. Before choosing this, "
    "rule out benign explanations against the actual bytes (default/parked page, generic "
    "title, auth-gated panel, WAF/block page, decoy/honeypot-like response).\n"
    "  • \"false_positive\": the evidence does NOT support a real issue.\n"
    "  • \"uncertain\": the evidence is insufficient to decide.\n\n"
    "HARD RULES:\n"
    "  • If deterministic_impact is \"high\" or \"critical\" and you cannot positively "
    "establish the finding as real, return \"uncertain\" — NEVER \"false_positive\". "
    "Do not drop high-impact items.\n"
    "  • Judge ONLY the provided evidence. Never invent facts, versions, or CVEs.\n\n"
    "Respond with a JSON array ONLY — no prose, no markdown fences. Exactly one object "
    "per input id, reusing the same ids:\n"
    "[{\"id\": <int>, \"verdict\": \"real|false_positive|uncertain\", "
    "\"severity\": \"critical|high|medium|low\", \"confidence\": <0..1>, "
    "\"reason\": \"<one sentence grounded in the evidence>\", "
    "\"benign_ruled_out\": [\"<...>\"]}]"
)


def build_user(gray: list[Verdict]) -> str:
    """Build the user message: a JSON array of label-stripped, id-tagged bundles."""
    items = []
    for i, v in enumerate(gray):
        bundle = v.to_ai()
        bundle["id"] = i
        items.append(bundle)
    return (
        "Adjudicate each observation. Return one JSON object per id, ids unchanged.\n\n"
        "```json\n" + json.dumps(items, indent=2, default=str) + "\n```"
    )


def parse_ai_response(text: str, gray: list[Verdict]) -> dict[int, AIVerdict]:
    """Map the model's JSON array back to {gray_index: AIVerdict}. Tolerant of junk."""
    from src.fusion.ai import robust_json_array  # noqa: PLC0415
    arr = robust_json_array(text)
    out: dict[int, AIVerdict] = {}
    if not isinstance(arr, list):
        return out
    for obj in arr:
        if not isinstance(obj, dict):
            continue
        try:
            idx = int(obj.get("id"))
        except (TypeError, ValueError):
            continue
        if not (0 <= idx < len(gray)):
            continue
        verdict = str(obj.get("verdict", "")).strip().lower()
        if verdict not in ("real", "false_positive", "uncertain"):
            verdict = "uncertain"
        try:
            conf = max(0.0, min(1.0, float(obj.get("confidence", 0.0))))
        except (TypeError, ValueError):
            conf = 0.0
        ruled = obj.get("benign_ruled_out") or []
        if not isinstance(ruled, list):
            ruled = [str(ruled)]
        out[idx] = AIVerdict(
            verdict=verdict,
            severity=str(obj.get("severity", "low")).strip().lower(),
            confidence=conf,
            reason=str(obj.get("reason", ""))[:400],
            benign_ruled_out=[str(x)[:120] for x in ruled][:6],
        )
    return out


def apply_ai_verdicts(gray: list[Verdict], ai_by_id: dict[int, AIVerdict]) -> None:
    """Apply AI verdicts to the gray verdicts IN PLACE, with the safety constraints.

    A high/critical-impact item is never discarded by the AI — at worst it becomes
    "potential" (report + verify). Unjudged items also become "potential".
    """
    for i, v in enumerate(gray):
        a = ai_by_id.get(i)
        v.ai = a                       # traceability (dynamic attribute)
        v.ai_safety_override = False
        if a is None:
            v.decision = "potential"   # the AI didn't (or couldn't) judge it → verify
            continue
        if a.verdict == "real":
            v.decision = "confirmed"
        elif a.verdict == "false_positive":
            if v.impact in ("high", "critical"):
                # SAFETY: the AI may not drop a high-impact finding. Demote to verify.
                v.decision = "potential"
                v.ai_safety_override = True
            else:
                v.decision = "discarded"
        else:  # uncertain
            v.decision = "potential"


def run_adjudication(verdicts: list[Verdict], complete: Optional[CompleteFn] = None) -> list[Verdict]:
    """Adjudicate the gray band of `verdicts` with an LLM, returning the same list
    with gray decisions resolved to confirmed/discarded/potential. Fail-soft."""
    gray = gray_band(verdicts)
    if not gray:
        return verdicts

    if complete is None:
        from src.fusion.ai import make_completer  # noqa: PLC0415
        complete = make_completer()
    fn = complete
    try:
        text = fn(_SYSTEM, build_user(gray))
        ai_by_id = parse_ai_response(text, gray)
    except Exception as exc:  # noqa: BLE001 — never break a scan; never drop a finding
        log.warning("AI adjudication unavailable (%s) — gray band → 'potential'", exc)
        ai_by_id = {}

    apply_ai_verdicts(gray, ai_by_id)
    return verdicts
