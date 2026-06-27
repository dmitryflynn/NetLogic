"""
Fusion layer — the AI adjudication pass (gray band only) + host-context discovery.

The deterministic gate already settles the certain cases. This pass asks an LLM to
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

Additionally, the AI receives FULL HOST CONTEXT (open ports, HTTP responses, tech
stack, TLS, DNS) and is instructed to proactively DISCOVER new security issues
the deterministic sensors missed — security headers, exposed services, weak TLS,
info leaks, email spoofing, application-level flaws visible in the raw data.

Fail-soft: any AI/transport error leaves the gray band as "potential" (reported,
needs verification) — a scan never breaks, and nothing real is ever dropped.

`decision` values after this pass: "confirmed" | "discarded" | "potential".
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

from src.fusion.gate import Verdict, gray_band, adjudicate
from src.fusion.signals import Signal

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
    "You are a security analyst assessing ALL available evidence from a host. "
    "Your tasks:\n"
    "  1. ADJUDICATE each observation below — decide if it is a REAL finding, "
    "FALSE POSITIVE, or UNCERTAIN.\n"
    "  2. DISCOVER new security issues from the host context that were not flagged "
    "by automated sensors.\n\n"
    "For ADJUDICATION: each observation gives you observed evidence, a "
    "deterministic_impact band, and raw HTTP/network data in `observed_data` (actual "
    "response headers, status code, body snippet, banner text, etc.). The 'subject' is "
    "an UNVERIFIED label — judge the observed_data and evidence, not the name.\n"
    "  • \"real\": evidence genuinely demonstrates the issue. Before choosing this, "
    "rule out benign explanations against the actual bytes (default/parked page, generic "
    "title, auth-gated panel, WAF/block page, decoy/honeypot-like response).\n"
    "  • \"false_positive\": evidence does NOT support a real issue.\n"
    "  • \"uncertain\": insufficient evidence to decide.\n\n"
    "For DISCOVERY: examine the host context for security issues including:\n"
    "  • Missing security headers (HSTS, CSP, X-Frame-Options, "
    "X-Content-Type-Options, Referrer-Policy, Permissions-Policy)\n"
    "  • Exposed sensitive services (FTP, Telnet, databases) on the public internet\n"
    "  • Weak TLS configuration (low grade, missing HSTS, weak protocols)\n"
    "  • Email security issues (SPF/DMARC misconfiguration allowing spoofing)\n"
    "  • Information leaks in HTTP responses (internal IPs, stack traces, directory "
    "listings, exposed config files)\n"
    "  • Open redirects or other application-logic issues visible in the data\n"
    "  • Technology-specific weaknesses not caught by automated matching\n"
    "  • Any other realistic security concern visible in the evidence\n\n"
    "HARD RULES:\n"
    "  • If deterministic_impact is \"high\" or \"critical\" and you cannot positively "
    "establish the finding as real, return \"uncertain\" — NEVER \"false_positive\". "
    "Do not drop high-impact items.\n"
    "  • Version-only matches: the observed_data shows a product+version string from "
    "a service banner (e.g. 'Apache 2.4.7'). A banner version below the fixed version "
    "does NOT mean the host is vulnerable — Linux distributions backport security "
    "fixes without changing the version number. If the evidence is ONLY a version "
    "comparison (no active exploit probe, no distinctive response), return \"uncertain\".\n"
    "  • Never invent facts, versions, or CVEs. Ground every finding in the provided data.\n"
    "  • For new discoveries, explain what specific evidence supports them.\n"
    "  • Quality over quantity: flag only what you can specifically support.\n\n"
    "Respond with a JSON array ONLY — no prose, no markdown fences. Each item is EITHER "
    "an adjudication (reusing input ids) OR a new finding:\n"
    "ADJUDICATION: {\"id\": <int>, \"verdict\": \"real|false_positive|uncertain\", "
    "\"severity\": \"critical|high|medium|low\", \"confidence\": <0..1>, "
    "\"reason\": \"<one sentence grounded in the evidence>\", "
    "\"benign_ruled_out\": [\"<...>\"]}\n"
    "NEW FINDING: {\"new_finding\": {\"subject\": \"<descriptive name>\", "
    "\"kind\": \"vuln|exposure|misconfig\", "
    "\"severity\": \"critical|high|medium|low\", "
    "\"evidence\": \"<what was observed>\", "
    "\"reason\": \"<why this is a security issue>\"}}"
)


# ── Severity → approximate CVSS mapping for AI-discovered findings ──────────────
_SEV_IMPACT = {"critical": 9.0, "high": 7.0, "medium": 5.0, "low": 0.0}


def build_user(gray: list[Verdict], context: Optional[dict] = None) -> str:
    """Build the user message: host context (if any) + adjudication items."""
    items = []
    for i, v in enumerate(gray):
        bundle = v.to_ai()
        bundle["id"] = i
        items.append(bundle)

    parts = []
    if context:
        parts.append("HOST CONTEXT:\n```json\n" + json.dumps(context, indent=2, default=str) + "\n```")
    parts.append("OBSERVATIONS:\n```json\n" + json.dumps(items, indent=2, default=str) + "\n```")
    parts.append(
        "Adjudicate each observation (using original ids) AND discover new issues "
        "from the host context. Return ONE JSON array containing adjudication objects "
        "and any new_finding objects."
    )
    return "\n\n".join(parts)


def parse_ai_response(text: str, gray: list[Verdict]) -> tuple[dict[int, AIVerdict], list[dict]]:
    """Map the model's JSON array back to {gray_index: AIVerdict} AND extract any
    new_finding objects the AI discovered from host context."""
    from src.fusion.ai import robust_json_array  # noqa: PLC0415
    arr = robust_json_array(text)
    out: dict[int, AIVerdict] = {}
    new_findings: list[dict] = []
    if not isinstance(arr, list):
        return out, new_findings
    for obj in arr:
        if not isinstance(obj, dict):
            continue
        # New finding discovered from host context
        if "new_finding" in obj:
            nf = obj["new_finding"]
            if isinstance(nf, dict) and str(nf.get("subject", "")).strip():
                new_findings.append(nf)
            continue
        # Existing adjudication by id
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
    return out, new_findings


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
        # Version-only: every signal is a banner/version match, none probe-confirmed or
        # KEV. Patch level is unverifiable from a banner (distros backport security fixes
        # without bumping the version), so the AI cannot promote these to "confirmed" no
        # matter how confidently it says "real" — cap at "potential" pending active probe.
        version_only = (not v.pinned and v.signals
                        and all(s.version_matched for s in v.signals)
                        and not any(s.is_probe_confirmed or s.kev for s in v.signals))
        if a.verdict == "real":
            if version_only:
                v.decision = "potential"
                v.ai_safety_override = True
            else:
                v.decision = "confirmed"
        elif a.verdict == "false_positive":
            if v.impact in ("high", "critical"):
                v.decision = "potential"
                v.ai_safety_override = True
            else:
                v.decision = "discarded"
        else:  # uncertain
            v.decision = "potential"


def ai_finding_to_signal(finding: dict, context: Optional[dict] = None) -> Optional[Signal]:
    """Convert an AI-discovered finding (from host-context analysis) into a Signal
    for deterministic impact computation through the gate."""
    # AI output is unpredictable — a findings array can contain non-object items
    # (a stray string, null, a number). Skip anything that isn't a dict rather
    # than crash adjudication.
    if not isinstance(finding, dict):
        return None
    subject = str(finding.get("subject", "")).strip()
    if not subject:
        return None
    host = (context or {}).get("host", "unknown")
    port = (context or {}).get("port")
    severity = str(finding.get("severity", "low")).lower()
    cvss = _SEV_IMPACT.get(severity, 0.0)
    return Signal(
        source="ai",
        kind=finding.get("kind", "exposure"),
        claim=subject.lower()[:120],
        host=host,
        port=port,
        evidence=str(finding.get("evidence", ""))[:600] or subject,
        cvss=cvss,
        reliability="medium",
        raw_metadata={"ai_reason": str(finding.get("reason", ""))[:400]},
    )


def apply_new_findings(new_findings: list[dict], context: Optional[dict] = None) -> list[Verdict]:
    """Convert AI-discovered findings to Signals, run through the deterministic gate,
    and return Verdicts always marked as 'potential' (never auto-confirmed or discarded)."""
    if not new_findings or not isinstance(new_findings, list):
        return []
    signals: list[Signal] = []
    for nf in new_findings:
        s = ai_finding_to_signal(nf, context)
        if s is not None:
            signals.append(s)
    if not signals:
        return []
    verdicts = adjudicate(signals)
    for v in verdicts:
        v.decision = "potential"
        v.rationale = "ai-discovered in host context analysis"
        v.pinned = False
    return verdicts


def run_adjudication(verdicts: list[Verdict],
                     context: Optional[dict] = None,
                     complete: Optional[CompleteFn] = None) -> tuple[list[Verdict], list[Verdict]]:
    """Adjudicate the gray band of `verdicts` with an LLM, returning the same list
    with gray decisions resolved, PLUS any newly discovered findings from host-context
    analysis (as Verdicts marked 'potential'). Fail-soft."""
    gray = gray_band(verdicts)

    new_verdicts: list[Verdict] = []
    if not gray:
        return verdicts, new_verdicts

    if complete is None:
        from src.fusion.ai import make_completer  # noqa: PLC0415
        complete = make_completer()
    fn = complete
    try:
        text = fn(_SYSTEM, build_user(gray, context=context))
        ai_by_id, new_findings = parse_ai_response(text, gray)
    except Exception as exc:  # noqa: BLE001 — never break a scan; never drop a finding
        log.warning("AI adjudication unavailable (%s) — gray band → 'potential'", exc)
        ai_by_id, new_findings = {}, []

    apply_ai_verdicts(gray, ai_by_id)

    if new_findings:
        try:
            new_verdicts = apply_new_findings(new_findings, context)
            log.info("AI discovered %d new findings from host context", len(new_verdicts))
        except Exception as exc:  # noqa: BLE001
            log.warning("AI new-finding processing failed (%s) — skipping discoveries", exc)

    return verdicts, new_verdicts
