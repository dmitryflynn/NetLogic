"""
Fusion layer — synthesis passes.

Two modes:
  1. Attack-chain narration over a REAL graph (`synthesize`).
  2. Full 6-section executive report (`full_synthesize`) — the unified AI Analysis
     that incorporates ALL verdicts (confirmed + potential + ai_discovered +
     discarded) and replaces the separate `ai_analyst.analyze_scan()` call.

LLMs cannot do zero-shot graph traversal — dump a flat list of findings and they
hallucinate impossible pivots (XSS on a public marketing site -> internal DB on a
different subnet). So we DETERMINISTICALLY pre-compute the reachability edges from
the confirmed findings' exposure context, hand the model an explicit graph, and ask
it to EXPLAIN paths along real edges — never to discover topology.

Edge rules (deterministic):
  • same-host: after compromising one service on a host, its other services are
    reachable (local post-exploitation) — an edge both ways.
  • explicit reach: a finding whose exposure carries `reaches: ["host:port"|"host"]`
    gets an edge to matching findings (network-reachable from there).
Entry points = findings whose exposure reachability is "public".

The model call is injected (`complete`) so this is offline-testable; the live
narration uses the configured model via src.fusion.ai.make_completer().
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from src.fusion.gate import Verdict


@dataclass
class GraphNode:
    id: int
    host: str
    port: Optional[int]
    claim: str
    impact: str
    exposure: dict


@dataclass
class GraphEdge:
    src: int
    dst: int
    reason: str


@dataclass
class AttackGraph:
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    entry_points: list[int] = field(default_factory=list)


def _exposure_of(v: Verdict) -> dict:
    for s in v.signals:
        if s.exposure:
            return s.exposure
    return {"reachability": "unknown"}


def _reaches(exposure: dict, host: str, port) -> bool:
    targets = exposure.get("reaches") or []
    if not isinstance(targets, list):
        return False
    want = {f"{host}:{port}", str(host)}
    return any(str(t) in want for t in targets)


def build_attack_graph(findings: list[Verdict]) -> AttackGraph:
    """Compute the deterministic reachability graph over confirmed findings."""
    nodes = [
        GraphNode(i, v.host, v.port, v.claim, v.impact, _exposure_of(v))
        for i, v in enumerate(findings)
    ]
    edges: list[GraphEdge] = []
    for a in nodes:
        for b in nodes:
            if a.id >= b.id:
                continue
            if a.host == b.host:
                edges.append(GraphEdge(a.id, b.id, "same-host post-exploitation"))
                edges.append(GraphEdge(b.id, a.id, "same-host post-exploitation"))
            else:
                if _reaches(a.exposure, b.host, b.port):
                    edges.append(GraphEdge(a.id, b.id, "network-reachable"))
                if _reaches(b.exposure, a.host, a.port):
                    edges.append(GraphEdge(b.id, a.id, "network-reachable"))
    entry = [n.id for n in nodes if (n.exposure or {}).get("reachability") == "public"]
    return AttackGraph(nodes=nodes, edges=edges, entry_points=entry)


_SYNTH_SYSTEM = (
    "You are a red-team lead writing the attack-chain narrative for a set of CONFIRMED "
    "findings. You are given: the findings, an explicit reachability GRAPH (directed "
    "edges between finding ids), and which findings are public ENTRY POINTS.\n\n"
    "Construct attack chains ONLY along the provided edges. NEVER invent connectivity "
    "between findings that the graph does not contain — if two findings are not connected "
    "by an edge, they are on separate paths. Every chain must START at a public entry "
    "point and pivot strictly along edges.\n\n"
    "Output GitHub-Flavored Markdown:\n"
    "## Attack Chains\n"
    "For each chain:\n"
    "### Chain <N> — <short title>\n"
    "- **Steps:** numbered; each step names the finding (by subject and id) it exploits "
    "and, for a pivot, the edge reason used.\n"
    "- **Impact:** what the attacker ultimately gains.\n"
    "- **Breaks if:** the single control that defeats this chain.\n"
    "If no multi-step path exists along the edges, output exactly: "
    "`_No multi-step attack chain across the confirmed findings._`"
)

_FULL_SYSTEM = (
    "You are a senior penetration tester producing the unified analysis for an "
    "AUTHORIZED assessment. Your inputs are:\n"
    "1. **Host context** — open ports, tech stack, TLS/DNS posture, exposure info, "
    "authenticated ground truth, changes since last scan, and web fingerprint "
    "(title, generator, version_markers, exposed_files, favicon, "
    "is_default_lander).\n"
    "2. **Detected vulnerabilities** — findings the system has already processed "
    "through its precision funnel (some confirmed, some potential, some "
    "AI-discovered from host context). Each carries: subject, host, port, decision "
    "(confirmed|potential), impact (critical|high|medium|low), pinned status, "
    "rationale, and the AI adjudicator's verdict/reasoning if applicable.\n"
    "3. **Discarded findings** — signals the system filtered out as noise.\n"
    "4. **Attack graph** — reachability edges computed over CONFIRMED findings.\n"
    "5. **Cross-host context** (present only when scanning multiple hosts) — "
    "groupings of related findings across hosts by shared service/version. "
    "Use these to identify lateral-movement paths, widespread vulnerabilities "
    "affecting multiple hosts, and shared attack surface that a single compromise "
    "could cascade across.\n\n"
    "Your job is INTERPRETATION — the system reports facts and verdicts; YOU decide "
    "what is likely real, how risks chain together, and what the operator should "
    "prioritise. Reason like an attacker about this SPECIFIC host using ALL the "
    "evidence — never generic advice.\n\n"
    "═══ TECH-STACK BINDING RULE ═══\n"
    "You MUST NOT suggest application-specific remediations (WordPress, Joomla, "
    "Drupal, Tomcat, Django, Rails, or any other CMS/framework-specific action) "
    "unless that framework is EXPLICITLY listed in `tech_stack` or "
    "`web_fingerprint.version_markers`. If no CMS/framework is confirmed in the "
    "evidence, keep remediation at the infrastructure level (TLS, headers, service "
    "configuration, port exposure). If `web_fingerprint.is_default_lander` is "
    "`true`, the web root is a hosting provider default page (no application "
    "deployed). In that case do NOT generate CMS-specific advice. Instead, flag "
    "this as an infrastructure finding: "
    "*\"Default hosting lander exposed — no application content served from this "
    "host. Deploy the target application or restrict access.\"*\n\n"
    "═══ EVIDENCE WEIGHTING ═══\n"
    "• **Confirmed + pinned** findings → treat as real and urgent.\n"
    "• **Potential** findings → leads that may be false positive (patched, backported, "
    "coarse version, or auth-gated); say so, don't assert.\n"
    "• **AI-discovered** findings → system found them from host context; evaluate "
    "their credibility.\n"
    "• **AI adjudicator** reasoning → use it; it is the system's best analysis.\n"
    "• **Discarded** findings → explain why they were filtered.\n"
    "• **CISA KEV / public-exploit** CVEs → call out as urgent IF the match "
    "is credible — a KEV with a credible version match matters far more than a "
    "CVSS 9.8 with EPSS near zero.\n"
    "• **EPSS** is the probability (0-1) a CVE is exploited in the wild — use it to "
    "PRIORITISE: a high-EPSS (>0.1) or KEV finding matters far more than a "
    "CVSS-9.8 with EPSS near 0. Lead with high-EPSS/KEV; treat low-EPSS criticals "
    "as lower priority even if the CVSS is high.\n"
    "• **Exploitability preconditions** are protocol-level attributes (SMBv1 enabled, "
    "RDP NLA not required, SNMP default community, web surface open vs auth-gated). "
    "Use them decisively: if a CVE's precondition is CONFIRMED present (the field "
    "`enables_cves` lists the CVE), promote it; if the precondition is absent or "
    "the surface is auth-gated, downgrade or discard the version-only match.\n"
    "• **Web fingerprint** (generator, version markers, favicon, exposed files, "
    "JS secrets) is precise CONTENT evidence — prefer its exact versions over coarse "
    "banners, and treat exposed files / JS secrets as real findings.\n"
    "• **Origin caveat**: if `exposure.waf` or `exposure.cdn` is present, a CDN or "
    "proxy fronts the host — be cautious that version-banner CVEs may target the "
    "edge, not the origin.\n"
    "• **Authenticated ground truth** (if present in host context as "
    "`confirmed_vulns`): installed package versions read over SSH override banner "
    "versions. If a package is 'backported', the distro patched it despite an "
    "old-looking version → treat its version-only CVEs as likely PATCHED.\n"
    "• **Changes since last scan** (if present as `scan_diff`): new ports/versions/"
    "CVEs are where fresh exposure appears — call them out prominently.\n"
    "• Use **topology** (ASN, reverse-DNS, IPv6, hops) to reason about blast radius "
    "and lateral movement.\n\n"
    "═══ BEYOND KNOWN CVEs ═══\n"
    "The verdicts are only the floor. A host that has patched every known CVE can "
    "still be attackable. You MUST also reason about:\n"
    "  • **Non-CVE weaknesses**: exposed admin/management interfaces, dangerous "
    "services reachable without auth, information disclosure, weak/legacy protocols, "
    "default or guessable configurations, permissive CORS/headers, secrets leaked "
    "in served JS, overly large attack surface.\n"
    "  • **Undiscovered / zero-day-class risk**: where the detected stack is "
    "END-OF-LIFE, unmaintained, a known-fragile class of software (custom web apps, "
    "deserialization-heavy frameworks, file-upload endpoints, exposed RPC/IPC), or "
    "simply old enough that unpatched-but-undisclosed bugs are LIKELY. State these "
    "as HYPOTHESES with your reasoning — never as confirmed CVEs and never with "
    "an invented CVE ID.\n"
    "  • **Emergent risk from CHAINING** individually-benign facts: a single fact "
    "may be harmless, but combined with others it becomes an attack path "
    "(e.g. info leak + exposed login + password reuse; verbose error + known "
    "framework; internal hostname in cert SAN + open management port). This "
    "combinational reasoning is the MAIN value you add — actively look for it.\n\n"
    "═══ OUTPUT CONTRACT (follow EXACTLY) ═══\n"
    "Respond in GitHub-Flavored Markdown ONLY — no preamble, no sign-off, no text "
    "outside the sections below. Use these six `##` sections, in this exact order "
    "and with these exact titles:\n\n"
    "## Executive Summary\n"
    "2–4 sentences on the real risk posture of THIS host, grounded in the evidence. "
    "End with: "
    "`**Overall risk:** <CRITICAL|HIGH|MEDIUM|LOW>`\n\n"
    "## Key Findings\n"
    "A Markdown table, highest priority first (KEV/high-EPSS/probe-confirmed at top). "
    "Columns EXACTLY:\n"
    "`| Impact | Finding | Port/Service | Decision | AI Verdict | Rationale |`\n"
    "Impact ∈ CRITICAL|HIGH|MEDIUM|LOW. "
    "Decision ∈ Confirmed|Likely|Potential "
    "(Confirmed = pinned or probe-verified; Likely = AI adjudicator confirmed with "
    "good reasoning; Potential = unverified lead from gray band or AI discovery). "
    "AI Verdict = the adjudicator's verdict or `—`. "
    "Rationale = the specific evidence that supports or refutes this finding. "
    "One row per finding. If none, write: "
    "`_No credible findings from the current evidence._`\n\n"
    "## Attack Chains\n"
    "Use the explicit reachability graph. Each chain MUST use this template:\n"
    "### Chain <N> — <short title> `[<IMPACT>]`\n"
    "- **Objective:** <attacker goal>\n"
    "- **Entry point:** <finding subject>\n"
    "- **Steps:**\n"
    "  1. <concrete action> — exploit `<finding>` → <result>\n"
    "  2. <next step> …\n"
    "- **Impact:** what the attacker ultimately gains.\n"
    "- **Breaks if:** the single control/patch that defeats this chain.\n"
    "If no multi-step path exists along the edges, output exactly: "
    "`_No multi-step attack chain from the current evidence._`\n\n"
    "## Beyond Known CVEs\n"
    "The analyst-grade section: weaknesses and risks NOT captured by a CVE match. "
    "Cover (only where the evidence supports it): exposed/attackable surface, "
    "end-of-life or unmaintained software, dangerous defaults, information "
    "disclosure, and plausible UNDISCOVERED vulnerability classes for this specific "
    "stack. Format as bullet list; tag each item with its kind in backticks:\n"
    "`[Exposure]` `[EOL]` `[Design]` `[Info-leak]` `[Hypothesis]`\n"
    "Each bullet: **<weakness>** `[<kind>]` — why it is a risk for THIS host, "
    "grounded in a specific scan fact, even though no CVE flags it. A `[Hypothesis]` "
    "item is an UNVERIFIED informed prediction (e.g. \"EOL `nginx 1.14` likely "
    "carries undisclosed bugs; no upstream fixes since 2019\") — phrase it as a "
    "hypothesis to validate, never as a confirmed vulnerability, and never attach "
    "a fabricated CVE ID. If the host genuinely presents no surface beyond the "
    "verdicts above, write exactly: `_No additional attack surface beyond the "
    "findings above._`\n\n"
    "## False Positives & Noise\n"
    "Bullet list: each discarded/low-impact/low-EPSS lead you are de-prioritising "
    "and the one-line reason (patched, backported, coarse version, auth-gated, "
    "edge-not-origin). If none, write `_None._`\n\n"
    "## Remediation\n"
    "Bullet list ordered to match Key Findings. Each: "
    "`**<fix>**` — <concrete action> (and, where useful, the exact follow-up probe "
    "to CONFIRM the finding).\n\n"
    "═══ RULES ═══\n"
    "Never present invented ports, services, versions, or CVE IDs as FACT, and never "
    "fabricate a CVE identifier. Facts (Key Findings, Attack-Chain evidence) must be "
    "grounded in the provided data. You MAY, however, reason beyond the data in the "
    "'Beyond Known CVEs' section and in chain analysis — provided such reasoning is "
    "clearly labeled a `[Hypothesis]`/prediction and built on an observed fact "
    "(e.g. an EOL version, an exposed interface), not pulled from thin air. Keep "
    "the distinction sharp: the Key Findings table is for what the evidence supports; "
    "hypotheses and emergent risks live in their own section so they never masquerade "
    "as confirmed. Use `inline code` for ports, versions, CVE IDs, and file paths. "
    "Prefer a correct, well-grounded assessment over an exhaustive speculative one — "
    "but do NOT stay silent about a real risk just because no CVE names it. Do not "
    "restate the raw JSON; interpret it."
)


def _build_user(graph: AttackGraph) -> str:
    payload = {
        "findings": [
            {"id": n.id, "subject": n.claim, "host": n.host, "port": n.port,
             "impact": n.impact, "exposure": n.exposure}
            for n in graph.nodes
        ],
        "edges": [{"from": e.src, "to": e.dst, "reason": e.reason} for e in graph.edges],
        "entry_points": graph.entry_points,
    }
    return (
        "Narrate the attack chains over this graph. Use ONLY the provided edges.\n\n"
        "```json\n" + json.dumps(payload, indent=2, default=str) + "\n```"
    )


def _row_for_ai(v: Verdict) -> dict:
    ai = getattr(v, "ai", None)
    return {
        "subject": v.claim, "host": v.host, "port": v.port,
        "decision": v.decision, "impact": v.impact,
        "pinned": v.pinned, "agreement": v.agreement, "rationale": v.rationale,
        "ai_verdict": ai.verdict if ai else None,
        "ai_reason": ai.reason if ai else None,
        "exposure": _exposure_of(v),
    }


def _build_full_user(confirmed: list[Verdict], potential: list[Verdict],
                     ai_discovered: list[Verdict], discarded: list[Verdict],
                     context: Optional[dict] = None,
                     cross_host: Optional[dict] = None) -> str:
    graph = build_attack_graph(confirmed)
    payload = {
        "host_context": context or {},
        "detected_vulnerabilities": [_row_for_ai(v) for v in confirmed + potential + ai_discovered],
        "discarded_findings": [_row_for_ai(v) for v in discarded],
        "attack_graph": {
            "nodes": [
                {"id": n.id, "subject": n.claim, "host": n.host, "port": n.port,
                 "impact": n.impact, "exposure": n.exposure}
                for n in graph.nodes
            ],
            "edges": [{"from": e.src, "to": e.dst, "reason": e.reason} for e in graph.edges],
            "entry_points": graph.entry_points,
        },
    }
    if cross_host:
        payload["cross_host_context"] = cross_host
    return (
        "Produce the full security analysis from the data below.\n\n"
        "```json\n" + json.dumps(payload, indent=2, default=str) + "\n```"
    )


def _extract_beyond_cves(markdown: str) -> list[str]:
    """Parse the ## Beyond Known CVEs section from the AI markdown and return
    each bullet item's text (without the leading `- ` or `* `)."""
    items: list[str] = []
    in_section = False
    for line in markdown.split("\n"):
        stripped = line.strip()
        if stripped.startswith("## Beyond Known CVEs"):
            in_section = True
            continue
        if in_section and stripped.startswith("## "):
            break
        if in_section and (stripped.startswith("- ") or stripped.startswith("* ")):
            text = stripped[2:].strip()
            if text:
                items.append(text)
    return items


def full_synthesize(confirmed: list[Verdict], potential: list[Verdict],
                    ai_discovered: list[Verdict], discarded: list[Verdict],
                    context: Optional[dict] = None,
                    cross_host: Optional[dict] = None,
                    complete: Optional[Callable[[str, str], str]] = None,
                    on_token: Optional[Callable[[str], None]] = None,
                    cfg=None) -> tuple[str, list[str]]:
    """Unified 6-section synthesis: Executive Summary, Key Findings, Attack Chains,
    Beyond Known CVEs, False Positives & Noise, Remediation.

    When ``on_token`` is provided, uses a streaming LLM call that calls
    ``on_token(delta)`` for each text delta as it arrives (so the caller can emit
    progressive "ai" SSE events). ``cfg`` is the AIConfig instance needed for the
    streaming adapter.

    Returns (markdown, beyond_cves_list).
    Includes ALL verdicts (confirmed + potential + ai_discovered + discarded) plus
    host context. Fail-soft: returns an error note and empty list.
    """
    has_any = bool(confirmed or potential or ai_discovered or discarded)
    if not has_any:
        return ("_No findings to analyze._", [])

    if on_token is not None:
        from src.fusion.ai import make_stream_completer  # noqa: PLC0415
        sc = make_stream_completer(cfg)
        worker = lambda s, u: sc(s, u, on_token)
    else:
        if complete is None:
            from src.fusion.ai import make_completer  # noqa: PLC0415
            complete = make_completer()
        worker = complete

    try:
        user_msg = _build_full_user(confirmed, potential, ai_discovered, discarded,
                                    context, cross_host)
        md = worker(_FULL_SYSTEM, user_msg).strip()
        return (md, _extract_beyond_cves(md))
    except Exception as exc:  # noqa: BLE001 — never break the report
        return (f"_Unified analysis unavailable ({exc})._", [])


def synthesize(findings: list[Verdict], complete: Optional[Callable[[str, str], str]] = None) -> str:
    """Build the reachability graph from confirmed findings and narrate attack chains
    over its real edges. Returns markdown. Fail-soft: returns a clear note on error."""
    if not findings:
        return "_No confirmed findings to synthesize._"
    graph = build_attack_graph(findings)

    if complete is None:
        from src.fusion.ai import make_completer  # noqa: PLC0415
        complete = make_completer()

    try:
        return complete(_SYNTH_SYSTEM, _build_user(graph)).strip()
    except Exception as exc:  # noqa: BLE001 — never break the report
        return f"_Attack-chain synthesis unavailable ({exc})._"
