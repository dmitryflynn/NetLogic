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
    "• **AI agent tool proof** (`host_context.ai_agent`, findings with status "
    "`confirmed`, and `tool_observations` with vulnerable_signal / crash_probe / "
    "probe markers) is the HIGHEST rank. The investigation agent already ran live "
    "tools. Treat those subjects as **Confirmed** in Findings, cite the observation "
    "ids / tool summaries as Proof of concept evidence, raise Overall risk "
    "accordingly, and NEVER list them under False Positives as version-only noise.\n"
    "• **Confirmed + pinned** findings → treat as real and urgent.\n"
    "• **Potential** findings → leads that may be false positive (patched, backported, "
    "coarse version, or auth-gated); say so, don't assert.\n"
    "• **AI-discovered** findings → system found them from host context; evaluate "
    "their credibility.\n"
    "• **AI adjudicator** reasoning → use it; it is the system's best analysis.\n"
    "• **Discarded** findings → explain why they were filtered **unless** the same "
    "subject appears agent-confirmed (then the discard is obsolete — use the agent "
    "proof instead).\n"
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
    "and lateral movement.\n"
    "• **Composite control postures** (`host_context.control_postures`): when present, "
    "these are multi-layer control families (e.g. email_auth bundles SPF/DKIM/DMARC "
    "plus a computed `spoofable` flag). Judge risk from the *whole* posture, not one "
    "layer alone. If a posture flag says the risk is not present (`spoofable: false`), "
    "do NOT promote single-layer hygiene notes about that family into Findings or "
    "Beyond Known CVEs — put residual best-practice notes under False Positives only, "
    "or omit them. Same rule for any future composite posture families.\n\n"
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
    "## Findings\n"
    "ONE `###` subsection PER *vulnerability* (not a bare CVE list), highest priority first "
    "(KEV / high-EPSS / probe-confirmed at the top). Title the finding by the weakness "
    "(e.g. 'Unauthenticated remote code execution via HTTP.sys'), not only by CVE id. "
    "If a CVE applies, mention it as related catalog context under What or Technical detail.\n"
    "Header EXACTLY (impact + decision each in backticks):\n"
    "### <n>. <vulnerability title> `[<IMPACT>]` `[<Confirmed|Likely|Potential>]`\n"
    "(Confirmed = pinned, probe-verified, or agent tool-confirmed with observation ids; "
    "do NOT invent Confirmed from speculation. Likely = adjudicator with good reasoning; "
    "Potential = unverified lead.) Under each header, these bold labels — every "
    "value grounded in THIS host's evidence, concrete, naming the exact port/version/path:\n"
    "- `**What:**` one sentence — the weakness and where it lives (`port`, `service`); "
    "if known, add `Related: CVE-…`.\n"
    "- `**Technical detail:**` the specific mechanism — why this exact version/config is "
    "vulnerable, the affected component, and the precondition that makes it reachable here.\n"
    "- `**Proof of concept / How to reproduce:**` REQUIRED on EVERY finding (no exceptions). "
    "Structure it so an operator can run it without guessing:\n"
    "  1) one-line **Setup** (what host/path/param),\n"
    "  2) fenced command (prefer `poc.curl` / exact path from evidence),\n"
    "  3) **Observed** (quote actual status/headers/body markers from tool evidence — "
    "never invent a Location/status the scan did not record),\n"
    "  4) **Vulnerable if** vs **Safe if** (two concrete, distinguishable outcomes).\n"
    "Redirect findings: vulnerable ONLY if Location *host* is external to the target "
    "(www/apex of the same site with attacker URL only in a query string is NOT open redirect). "
    "If unverified, state that clearly and give the check that would confirm — do not "
    "mark Confirmed. NEVER fabricate exploit output, invent a CVE id, or invent response bytes.\n"
    "- `**Remediation:**` the SPECIFIC fix for THIS finding (follow the Remediation rules below).\n"
    "If there are no credible findings, write exactly: "
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
    "A prioritized action plan, most urgent first — one bullet per finding, in the same order "
    "as Findings. Each bullet MUST be SPECIFIC and actionable for THIS host:\n"
    "`**<finding>**` — the exact fix: the precise version to upgrade to (e.g. `upgrade OpenSSH "
    "to >= 9.6`), the exact config directive/value to set (e.g. `SSLProtocol -all +TLSv1.2 "
    "+TLSv1.3`), the exact header to add (`Strict-Transport-Security: max-age=63072000; "
    "includeSubDomains`), the exact port to firewall, or the exact file to remove — include the "
    "command where it helps. Do NOT write vague advice like \"update the software\", \"apply "
    "patches\", or \"harden the configuration\": name the specific version/directive/value. ONLY "
    "if a specific fix genuinely cannot be derived from the evidence, say so and state exactly "
    "what to check to determine it. Respect the TECH-STACK BINDING RULE above.\n\n"
    "═══ RULES ═══\n"
    "Never present invented ports, services, versions, or CVE IDs as FACT, and never "
    "fabricate a CVE identifier. Facts (the Findings section, Attack-Chain evidence) must be "
    "grounded in the provided data. You MAY, however, reason beyond the data in the "
    "'Beyond Known CVEs' section and in chain analysis — provided such reasoning is "
    "clearly labeled a `[Hypothesis]`/prediction and built on an observed fact "
    "(e.g. an EOL version, an exposed interface), not pulled from thin air. Keep "
    "the distinction sharp: the Findings section is for what the evidence supports; "
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


def _poc_from_verdict(v: Verdict) -> Optional[dict]:
    """Pull a structured PoC from probe/agent signal observed_data if present."""
    for s in (getattr(v, "signals", None) or []):
        od = getattr(s, "observed_data", None) or {}
        if not isinstance(od, dict):
            continue
        poc = od.get("poc")
        if isinstance(poc, dict) and (poc.get("curl") or poc.get("expected")):
            return {
                "curl": poc.get("curl"),
                "expected": poc.get("expected"),
                "how_to_reproduce": poc.get("how_to_reproduce"),
            }
        # Fall back to raw evidence as the expected signal for reproduction notes
        ev = od.get("evidence") or getattr(s, "evidence", None)
        if ev:
            host = getattr(v, "host", "TARGET") or "TARGET"
            port = getattr(v, "port", None)
            port_s = f":{port}" if port else ""
            return {
                "curl": None,
                "expected": str(ev)[:300],
                "how_to_reproduce": (
                    f"Re-run the confirming check against {host}{port_s}. "
                    f"Expected signal: {str(ev)[:200]}"
                ),
            }
    return None


def _row_for_ai(v: Verdict) -> dict:
    ai = getattr(v, "ai", None)
    poc = _poc_from_verdict(v)
    # Prefer first non-empty signal evidence for the model
    evidence_bits = []
    for s in (getattr(v, "signals", None) or [])[:3]:
        ev = getattr(s, "evidence", None)
        if ev:
            evidence_bits.append(str(ev)[:300])
    return {
        "subject": v.claim, "host": v.host, "port": v.port,
        "decision": v.decision, "impact": v.impact,
        "pinned": v.pinned, "agreement": v.agreement, "rationale": v.rationale,
        "ai_verdict": ai.verdict if ai else None,
        "ai_reason": ai.reason if ai else None,
        "exposure": _exposure_of(v),
        "evidence": evidence_bits,
        "poc": poc,
        "poc_required": True,
    }


def build_repro_ledger(context: Optional[dict]) -> list[dict]:
    """Deterministic ledger of *what tools actually ran* and what they observed.

    The synthesis model must build PoCs only from these rows — never invent curls
    or response bytes that do not appear here.
    """
    ctx = context or {}
    host = str(ctx.get("host") or "TARGET")
    ledger: list[dict] = []

    def _add(row: dict) -> None:
        if not row:
            return
        # Dedup by curl+observed
        key = (str(row.get("curl") or ""), str(row.get("observed") or row.get("summary") or ""))
        for existing in ledger:
            if (str(existing.get("curl") or ""), str(existing.get("observed") or existing.get("summary") or "")) == key:
                return
        ledger.append(row)

    agent = ctx.get("ai_agent") or {}
    for o in (agent.get("tool_observations") or agent.get("observations") or []):
        if not isinstance(o, dict):
            continue
        tool = str(o.get("tool") or "")
        if tool in ("assert_finding", "chain_link", "stop", "record_poc", "scope_check",
                    "severity_suggest", "submit_readiness", "set_session", "clear_session"):
            continue
        data = o.get("data") if isinstance(o.get("data"), dict) else {}
        # Prefer engine-built curl if attached
        curl = None
        if isinstance(data.get("poc"), dict):
            curl = data["poc"].get("curl")
        path = data.get("path") or o.get("path") or ""
        method = str(data.get("method") or o.get("method") or "GET").upper()
        status = (
            data.get("status") or o.get("status")
            or data.get("status_redirect") or data.get("status_reflect")
        )
        loc = data.get("location") or o.get("location") or ""
        if not loc and isinstance(data.get("headers"), dict):
            loc = data["headers"].get("location") or data["headers"].get("Location") or ""
        loc_host = data.get("location_host") or o.get("location_host") or ""
        observed = data.get("observed_summary") or o.get("observed_summary") or ""
        if not observed:
            bits = [f"tool={tool}"]
            if status is not None:
                bits.append(f"HTTP {status}")
            if loc:
                bits.append(f"Location: {str(loc)[:160]}")
            if loc_host:
                bits.append(f"location_host={loc_host}")
            if data.get("open_redirect_signal") is True:
                bits.append("open_redirect_signal=true")
            if data.get("open_redirect_signal") is False:
                bits.append("open_redirect_signal=false")
            sigs = data.get("proof_signals") or data.get("signals")
            if sigs:
                bits.append(f"signals={sigs}")
            if o.get("summary"):
                bits.append(str(o.get("summary"))[:120])
            observed = "; ".join(bits)

        if not curl and path:
            scheme = "https" if str(path).startswith("https") else "https"
            # Reconstruct a minimal repro from path when possible
            p = path if str(path).startswith("/") else f"/{path}"
            curl = f"curl -sk -D- -X {method} 'https://{host}{p}'"

        _add({
            "observation_id": o.get("observation_id"),
            "tool": tool,
            "path": path or None,
            "method": method,
            "curl": curl,
            "observed": observed[:400],
            "location": str(loc)[:200] if loc else None,
            "location_host": loc_host or None,
            "open_redirect_signal": data.get("open_redirect_signal"),
            "vulnerable_signal": data.get("vulnerable_signal"),
            "proof_signals": data.get("proof_signals") or data.get("signals"),
            "status": status,
        })

    # Agent-recorded PoCs
    for p in (agent.get("pocs") or []):
        if isinstance(p, dict) and p.get("curl"):
            _add({
                "observation_id": p.get("observation_id"),
                "tool": "record_poc",
                "curl": p.get("curl"),
                "observed": p.get("expected") or p.get("notes") or "",
                "finding_id": p.get("finding_id"),
            })
    for f in (agent.get("findings") or []):
        if not isinstance(f, dict):
            continue
        poc = f.get("poc") if isinstance(f.get("poc"), dict) else None
        if poc and poc.get("curl"):
            _add({
                "observation_id": poc.get("observation_id"),
                "tool": "finding_poc",
                "curl": poc.get("curl"),
                "observed": poc.get("expected") or "",
                "finding_id": f.get("id"),
                "status": f.get("status"),
            })

    for item in (ctx.get("confirmed_vulns") or []):
        if isinstance(item, dict) and isinstance(item.get("poc"), dict) and item["poc"].get("curl"):
            _add({
                "tool": "probe",
                "curl": item["poc"].get("curl"),
                "observed": item["poc"].get("expected") or item.get("evidence") or "",
                "finding_id": item.get("cve") or item.get("title"),
            })

    return ledger[:80]


def allowed_confirmed_subjects(confirmed: list[Verdict], context: Optional[dict]) -> list[str]:
    """Subjects that may appear as `[Confirmed]` in the report — nothing else."""
    out: list[str] = []
    for v in confirmed or []:
        if getattr(v, "claim", None):
            out.append(str(v.claim))
    agent = (context or {}).get("ai_agent") or {}
    for f in (agent.get("findings") or []):
        if not isinstance(f, dict):
            continue
        if str(f.get("status") or "").lower() != "confirmed":
            continue
        for k in (f.get("id"), f.get("title")):
            if k:
                out.append(str(k))
    for item in ((context or {}).get("confirmed_vulns") or []):
        if isinstance(item, dict):
            for k in (item.get("cve"), item.get("title")):
                if k:
                    out.append(str(k))
        elif item:
            out.append(str(item))
    # unique preserve order
    seen: set[str] = set()
    uniq: list[str] = []
    for s in out:
        sl = s.lower()
        if sl not in seen:
            seen.add(sl)
            uniq.append(s)
    return uniq


def _build_full_user(confirmed: list[Verdict], potential: list[Verdict],
                     ai_discovered: list[Verdict], discarded: list[Verdict],
                     context: Optional[dict] = None,
                     cross_host: Optional[dict] = None) -> str:
    graph = build_attack_graph(confirmed)
    ledger = build_repro_ledger(context)
    allowed = allowed_confirmed_subjects(confirmed, context)
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
        # Ground-truth rails — synthesis may not invent outside these lists
        "reproducible_evidence": ledger,
        "allowed_confirmed_subjects": allowed,
        "evidence_rules": {
            "confirmed_only_if_in_allowed_list": True,
            "poc_must_use_reproducible_evidence": True,
            "observed_must_quote_ledger": True,
            "no_invented_response_bytes": True,
        },
    }
    if cross_host:
        payload["cross_host_context"] = cross_host
    return (
        "Produce the full security analysis from the data below.\n"
        "HARD REQUIREMENTS:\n"
        "1) Tag a finding `[Confirmed]` ONLY if its subject appears in "
        "`allowed_confirmed_subjects` (or is clearly the same agent/probe-confirmed id). "
        "Everything else is `[Likely]` or `[Potential]` — never invent Confirmed.\n"
        "2) Every PoC command and every **Observed** line MUST come from "
        "`reproducible_evidence` (copy the curl and the observed status/Location/signals). "
        "If the ledger has no matching check, say so and do not invent a curl or a "
        "hypothetical `Location: https://evil.com` response.\n"
        "3) When a ledger row has open_redirect_signal=false or same_site_redirect / "
        "marker_echoed_in_same_site_location_query, that is NOT an open redirect.\n\n"
        "```json\n" + json.dumps(payload, indent=2, default=str) + "\n```"
    )


def ensure_findings_have_poc(markdown: str, context: Optional[dict] = None,
                             verdicts: Optional[list[Verdict]] = None) -> str:
    """Post-process synthesis markdown so every `###` finding has a PoC section.

    LLMs occasionally omit the required Proof-of-concept block. Inject a
    deterministic one from structured ``poc`` / evidence when missing.
    """
    if not markdown or "### " not in markdown:
        return markdown

    # Build lookup: subject lower → poc dict
    poc_map: dict[str, dict] = {}
    ctx = context or {}
    for item in (ctx.get("confirmed_vulns") or []):
        if isinstance(item, dict) and item.get("poc"):
            key = str(item.get("cve") or item.get("title") or "").lower()
            if key:
                poc_map[key] = item["poc"]
            tkey = str(item.get("title") or "").lower()
            if tkey:
                poc_map[tkey] = item["poc"]
        elif isinstance(item, str):
            pass
    agent = ctx.get("ai_agent") or {}
    for f in (agent.get("findings") or []):
        if isinstance(f, dict) and f.get("poc"):
            for k in (f.get("id"), f.get("title")):
                if k:
                    poc_map[str(k).lower()] = f["poc"]
    for v in (verdicts or []):
        p = _poc_from_verdict(v)
        if p:
            poc_map[str(v.claim).lower()] = p

    lines = markdown.split("\n")
    out: list[str] = []
    i = 0
    in_findings = False
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped.startswith("## Findings"):
            in_findings = True
            out.append(line)
            i += 1
            continue
        if in_findings and stripped.startswith("## ") and not stripped.startswith("## Findings"):
            in_findings = False
            out.append(line)
            i += 1
            continue
        if in_findings and stripped.startswith("### "):
            # Collect this finding block until next ### or ##
            block = [line]
            i += 1
            while i < len(lines):
                nxt = lines[i]
                ns = nxt.strip()
                if ns.startswith("### ") or (ns.startswith("## ") and not ns.startswith("###")):
                    break
                block.append(nxt)
                i += 1
            block_text = "\n".join(block)
            has_poc = (
                "proof of concept" in block_text.lower()
                or "how to reproduce" in block_text.lower()
            )
            if not has_poc:
                # Match subject from header: ### 1. CVE-… `[HIGH]` …
                header = block[0]
                subject = header.lstrip("#").strip()
                # Drop leading number. and trailing badges
                if ". " in subject:
                    subject = subject.split(". ", 1)[1]
                subject = subject.split("`")[0].strip()
                poc = (
                    poc_map.get(subject.lower())
                    or poc_map.get(subject.split()[0].lower() if subject else "")
                )
                # Fuzzy: any key contained in subject
                if not poc:
                    sl = subject.lower()
                    for k, val in poc_map.items():
                        if k and (k in sl or sl in k):
                            poc = val
                            break
                curl = (poc or {}).get("curl") if isinstance(poc, dict) else None
                expected = (poc or {}).get("expected") if isinstance(poc, dict) else None
                how = (poc or {}).get("how_to_reproduce") if isinstance(poc, dict) else None
                if not curl:
                    host = (ctx.get("host") or "TARGET")
                    curl = f"# Manual check for {subject} on {host}\ncurl -sk -D- 'https://{host}/'"
                inject = [
                    "",
                    "- **Proof of concept / How to reproduce:**",
                    "```",
                    str(curl),
                    "```",
                ]
                if expected:
                    inject.append(f"  Vulnerable signal: {expected}")
                elif how:
                    inject.append(f"  {how}")
                else:
                    inject.append(
                        "  Confirm the response matches the scan evidence for this finding; "
                        "safe response shows no vulnerable marker / no external Location host."
                    )
                # Insert before Remediation if present, else at end of block
                inserted = False
                new_block: list[str] = []
                for bl in block:
                    if (not inserted) and (
                        "**Remediation:**" in bl or "**remediation:**" in bl.lower()
                    ):
                        new_block.extend(inject)
                        inserted = True
                    new_block.append(bl)
                if not inserted:
                    new_block.extend(inject)
                out.extend(new_block)
            else:
                out.extend(block)
            continue
        out.append(line)
        i += 1
    return "\n".join(out)


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


_CONFIRMED_TAG_RE = re.compile(
    r"`\[Confirmed\]`|\[Confirmed\]", re.I
)
_REDIRECT_WORDS_RE = re.compile(
    r"open\s*redirect|cwe-?601|unvalidated\s+redirect|callbackurl|returnurl",
    re.I,
)


def ground_synthesis_markdown(
    markdown: str,
    context: Optional[dict] = None,
    confirmed: Optional[list[Verdict]] = None,
) -> str:
    """Fail-closed post-process: demote invented Confirmed tags; fix redirect hallucinations.

    The LLM sometimes invents Confirmed findings and PoCs (e.g. claims
    ``Location: https://evil.com`` when tools only saw a same-site bounce). This
    pass cannot re-write every hallucination, but it:
      • demotes `[Confirmed]` when the subject is not in the allowed list
      • rewrites open-redirect claims when the ledger has no external redirect
    """
    if not markdown:
        return markdown
    ctx = context or {}
    allowed = {s.lower() for s in allowed_confirmed_subjects(confirmed or [], ctx)}
    ledger = build_repro_ledger(ctx)

    has_external_redirect = any(
        r.get("open_redirect_signal") is True
        or "external_redirect" in str(r.get("proof_signals") or "")
        or "expect_marker_in_external_location" in str(r.get("proof_signals") or "")
        for r in ledger
    )
    same_site_only = any(
        r.get("open_redirect_signal") is False
        or "same_site_redirect" in str(r.get("proof_signals") or "")
        or "marker_echoed_in_same_site_location_query" in str(r.get("proof_signals") or "")
        for r in ledger
    )
    # Observed locations for quoting in demotion notes
    observed_locs = [
        str(r.get("location") or r.get("observed") or "")[:160]
        for r in ledger
        if r.get("location") or (r.get("observed") and "Location" in str(r.get("observed")))
    ]

    lines = markdown.split("\n")
    out: list[str] = []
    i = 0
    in_findings = False
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped.startswith("## Findings"):
            in_findings = True
            out.append(line)
            i += 1
            continue
        if in_findings and stripped.startswith("## ") and not stripped.startswith("###"):
            in_findings = False
            out.append(line)
            i += 1
            continue
        if in_findings and stripped.startswith("### "):
            block = [line]
            i += 1
            while i < len(lines):
                nxt = lines[i]
                ns = nxt.strip()
                if ns.startswith("### ") or (ns.startswith("## ") and not ns.startswith("###")):
                    break
                block.append(nxt)
                i += 1
            header = block[0]
            body = "\n".join(block)
            # Extract subject for allow-list check
            subject = header.lstrip("#").strip()
            if ". " in subject:
                subject = subject.split(". ", 1)[1]
            subject = subject.split("`")[0].strip()
            subj_l = subject.lower()

            # Demote invented Confirmed
            if _CONFIRMED_TAG_RE.search(header):
                allowed_hit = any(
                    a in subj_l or subj_l in a or a.split()[0] in subj_l
                    for a in allowed
                ) if allowed else False
                # Also allow if any allowed token appears (cve ids etc.)
                if not allowed_hit and allowed:
                    for a in allowed:
                        token = a.lower().replace("_", "-")
                        if token and token in subj_l.replace("_", "-"):
                            allowed_hit = True
                            break
                if not allowed_hit:
                    block[0] = _CONFIRMED_TAG_RE.sub("`[Potential]`", header)
                    block.append(
                        "\n> _NetLogic evidence gate: demoted from Confirmed — no matching "
                        "tool-confirmed subject in scan evidence._"
                    )

            # Open-redirect hallucination gate
            if _REDIRECT_WORDS_RE.search(body) and not has_external_redirect:
                # Rewrite invented evil.com Location claims
                new_block = []
                for bl in block:
                    if re.search(r"Location:\s*https?://evil", bl, re.I):
                        if observed_locs:
                            bl = re.sub(
                                r"Location:\s*https?://evil[^\s`]*",
                                f"Location: (observed same-site — e.g. {observed_locs[0][:100]})",
                                bl,
                                flags=re.I,
                            )
                        else:
                            bl = re.sub(
                                r"Location:\s*https?://evil[^\s`]*",
                                "Location: (no external Location observed in tool evidence)",
                                bl,
                                flags=re.I,
                            )
                    new_block.append(bl)
                block = new_block
                if same_site_only or not has_external_redirect:
                    # Force Potential if still Confirmed
                    block[0] = _CONFIRMED_TAG_RE.sub("`[Potential]`", block[0])
                    note = (
                        "\n> _NetLogic evidence gate: tools did not observe an external "
                        "Location host (same-site bounce / query echo only is not CWE-601). "
                        "Do not treat as confirmed open redirect._"
                    )
                    if note.strip() not in "\n".join(block):
                        block.append(note)

            out.extend(block)
            continue
        out.append(line)
        i += 1
    return "\n".join(out)


def full_synthesize(confirmed: list[Verdict], potential: list[Verdict],
                    ai_discovered: list[Verdict], discarded: list[Verdict],
                    context: Optional[dict] = None,
                    cross_host: Optional[dict] = None,
                    complete: Optional[Callable[[str, str], str]] = None,
                    on_token: Optional[Callable[[str], None]] = None,
                    cfg=None) -> tuple[str, list[str]]:
    """Unified 6-section synthesis: Executive Summary, Key Findings, Attack Chains,
    Findings (per-finding), Beyond Known CVEs, False Positives & Noise, Remediation.

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
        # Ensure host_context carries full agent observations for the ledger
        ctx = dict(context or {})
        user_msg = _build_full_user(confirmed, potential, ai_discovered, discarded,
                                    ctx, cross_host)
        md = worker(_FULL_SYSTEM, user_msg).strip()
        all_v = list(confirmed or []) + list(potential or []) + list(ai_discovered or [])
        md = ensure_findings_have_poc(md, context=ctx, verdicts=all_v)
        md = ground_synthesis_markdown(md, context=ctx, confirmed=confirmed)
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
