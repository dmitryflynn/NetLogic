"""
Fusion layer — live-engine bridge.

Converts the scan engine's artifacts (CVE correlations, probe-confirmed findings,
service misconfigs, tech fingerprint, exposure context) into fusion `Signal`s, runs
them through the deterministic gate + AI adjudication, and returns a structured
verdict summary. This is what makes a real `netlogic` scan benefit from the
sensors→gate→AI precision funnel instead of only the raw correlator output.

ADDITIVE + FAIL-SOFT by design: the engine calls this in a guarded block, so a
missing dependency or an AI outage never breaks a scan — the original report
(every vuln_match) is untouched; fusion just adds a "what's confirmed vs noise"
view on top.
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

from src.fusion.adjudicator import run_adjudication
from src.fusion.gate import adjudicate, Verdict
from src.fusion.signals import Signal
from src.fusion.synthesis import full_synthesize

log = logging.getLogger("netlogic.fusion.bridge")

# Engine detection_confidence → sensor reliability tier. A version-confirmed (HIGH)
# correlator hit is a medium-reliability lead, not ground truth; POTENTIAL is low.
_CONF_TO_REL = {"HIGH": "medium", "MEDIUM": "low", "POTENTIAL": "low"}
_SEV_TO_CVSS = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0, "INFO": 0.0}


def _attr(obj, name, default=None):
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _exposure(art: dict) -> dict:
    """A network scan reached the target, so it's publicly reachable. Carry WAF/CDN
    context (origin-vs-edge caveat) — reachability 'public' means the gate never
    demotes impact for these findings.

    When fusion has computed a post-compromise reachability matrix
    (``art["reachability"]``), collapse it into a single ``reaches`` list so every
    signal's exposure carries the full lateral-movement picture for the attack graph.
    """
    stack = art.get("stack_result")
    waf = None
    cdn = None
    if stack is not None:
        w = _attr(stack, "waf")
        if w is not None and _attr(w, "detected"):
            waf = _attr(w, "name")
        cdn = _attr(stack, "cloud_provider") or _attr(stack, "cdn")
    reach = art.get("reachability") or {}
    # Collapse all reachable targets into one flat set (every signal on this host
    # reaches every other discovered service post-compromise).
    reaches: set[str] = set()
    for targets in reach.values():
        reaches.update(targets)
    return {"reachability": "public", "waf": waf, "cdn": cdn,
            "reaches": sorted(reaches)}


def _web_port(art: dict) -> Optional[int]:
    hr = art.get("host_result")
    for p in (_attr(hr, "ports", []) or []):
        if _attr(p, "service") in ("http", "https", "http-alt", "https-alt"):
            return _attr(p, "port")
    return None


def signals_from_artifacts(art: dict) -> list[Signal]:
    """Turn engine artifacts into evidence-bearing Signals for the gate."""
    sigs: list[Signal] = []
    exposure = _exposure(art)
    hr = art.get("host_result")
    host = _attr(hr, "ip") or _attr(hr, "target") or "target"

    # 1. CVE correlations (the correlator is ONE source → no self-corroboration).
    for vm in (art.get("vuln_matches") or []):
        port = _attr(vm, "port")
        service = _attr(vm, "service", "") or ""
        product = _attr(vm, "product", "") or ""
        version = _attr(vm, "version", "") or ""
        rel = _CONF_TO_REL.get(str(_attr(vm, "detection_confidence", "")).upper(), "low")
        for c in (_attr(vm, "cves", []) or []):
            cid = str(_attr(c, "id", "") or "")
            if not cid:
                continue
            sigs.append(Signal(
                source="nvd", kind="vuln", claim=cid, host=host, port=port, service=service,
                reliability=rel,
                # Correlator hits are product/version (banner) matches, never patch-level
                # or actively probed — so they must NOT pin on EPSS/exploit alone. The gate's
                # version_matched guard keeps these as candidates for verification (KEV still
                # pins via its own branch; an actual probe confirmation comes in as source=probe).
                version_matched=True,
                evidence=f"{product} {version} on {port}/{service}: {(_attr(c, 'description', '') or '')[:200]}",
                cvss=float(_attr(c, "cvss_score", 0.0) or 0.0),
                kev=bool(_attr(c, "kev", False)),
                epss=float(_attr(c, "epss", 0.0) or 0.0),
                exploit_available=bool(_attr(c, "exploit_available", False)
                                       or _attr(c, "has_metasploit", False)
                                       or _attr(c, "has_public_exploit", False)),
                observed_data={"banner": f"{product} {version}".strip(), "product": product,
                               "version": version or None, "matched_service": service or None},
                exposure=exposure,
            ))

    # 2. Probe-CONFIRMED vulns → pinned ground truth (high reliability).
    vpr = art.get("vuln_probe_result")
    for f in (_attr(vpr, "confirmed", []) or []):
        if _attr(f, "confirmed", True) is False:
            continue
        claim = str(_attr(f, "cve_id", "") or _attr(f, "title", "") or "")
        if not claim:
            continue
        title = _attr(f, "title", claim)
        detail = _attr(f, "detail", "") or ""
        evidence_raw = _attr(f, "evidence", "") or ""
        poc = _attr(f, "poc", None) or {}
        if not isinstance(poc, dict):
            poc = {}
        sigs.append(Signal(
            source="probe", kind="vuln", claim=claim, host=host, port=_attr(f, "port"),
            service="http", reliability="high", exploit_available=True, cvss=8.0,
            evidence=(evidence_raw or f"probe-confirmed: {title}")[:600],
            observed_data={
                "probe_detail": detail or title,
                "method": _attr(f, "method", "GET"),
                "evidence": evidence_raw[:400] if evidence_raw else None,
                "poc": {
                    "curl": poc.get("curl"),
                    "expected": poc.get("expected"),
                    "how_to_reproduce": poc.get("how_to_reproduce"),
                } if poc.get("curl") else None,
            },
            exposure=exposure,
        ))

    # 3. Service misconfigurations (probe findings) → high reliability.
    spr = art.get("service_probe_result")
    for f in (_attr(spr, "findings", []) or []):
        title = str(_attr(f, "title", "") or "")
        if not title:
            continue
        detail = _attr(f, "detail", "") or ""
        sigs.append(Signal(
            source="probe", kind="misconfig", claim=title.lower()[:64], host=host, port=_attr(f, "port"),
            reliability="high", evidence=f"probe finding: {title}",
            cvss=_SEV_TO_CVSS.get(str(_attr(f, "severity", "")).upper(), 0.0),
            observed_data={"detail": detail or title, "service": _attr(f, "service", "") or None},
            exposure=exposure,
        ))

    # 4. Technology fingerprint (corroboration / inventory).
    wport = _web_port(art)
    stack = art.get("stack_result")
    for t in (_attr(stack, "technologies", []) or []):
        name = str(_attr(t, "name", "") or "").lower()
        if not name:
            continue
        ver = _attr(t, "version", "") or ""
        sigs.append(Signal(
            source="stack", kind="tech", claim=name, host=host, port=wport, service="http",
            reliability="medium", evidence=f"tech: {_attr(t, 'name', '')} {ver}".strip(),
            observed_data={"version": ver or None} if ver else None,
            exposure=exposure,
        ))

    # 5. Nuclei external scanner results (MIT-licensed binary, community templates).
    nuclei_raw = art.get("nuclei_results")
    if nuclei_raw:
        from src.external.nuclei_runner import extract_technologies, extract_cves, extract_exposures

        for tech in extract_technologies(nuclei_raw):
            name = tech["name"].lower()
            sigs.append(Signal(
                source="nuclei", kind="tech", claim=name, host=host, port=wport, service="http",
                reliability="high", evidence=f"nuclei tech: {tech['name']}",
                exposure=exposure,
            ))

        for cve in extract_cves(nuclei_raw):
            cid = cve["cve_id"]
            # Nuclei template hits are active HTTP/network matches, not pure
            # banner→NVD pattern correlation — treat as real sensor evidence.
            sigs.append(Signal(
                source="nuclei", kind="vuln", claim=cid, host=host,
                port=cve.get("port") or wport, service="http",
                reliability="high", evidence=f"nuclei CVE: {cid} — {cve.get('name', '')}",
                cvss=_SEV_TO_CVSS.get(str(cve["severity"]).upper(), 0.0),
                kev=False, epss=0.0, exploit_available=False,
                version_matched=False,
                observed_data={"matched_at": cve.get("matched_at", ""),
                               "description": cve.get("description", ""),
                               "detail": cve.get("name", "")},
                exposure=exposure,
            ))

        for exp in extract_exposures(nuclei_raw):
            sigs.append(Signal(
                source="nuclei", kind="misconfig", claim=exp["name"].lower()[:64],
                host=host, port=exp.get("port") or wport, service="http",
                reliability="high", evidence=f"nuclei exposure: {exp['name']}",
                cvss=_SEV_TO_CVSS.get(str(exp["severity"]).upper(), 0.0),
                observed_data={"detail": exp.get("description", "") or exp.get("name", ""),
                               "matched_at": exp.get("matched_at", "")},
                exposure=exposure,
            ))

    # 6. AI-driven verifier signals (probe-confirmed ground truth).
    # These come from the verifier engine which generated per-CVE test plans,
    # executed them via raw sockets, and captured response evidence. Every signal
    # is already set with is_probe_confirmed=True so the gate pins it as confirmed.
    for vsig in (art.get("verifier_signals") or []):
        if isinstance(vsig, Signal):
            sigs.append(vsig)

    # 7. AI Investigation Agent confirmations — tool-executed proof (crash_probe,
    # http_request markers, etc.). These are the same class as probe_confirmed:
    # the agent already spent tools; the gate must pin them so fusion cannot
    # re-discard them as "version/banner only" and starve the AI summary of truth.
    from src.ip_scope import normalize_finding_id  # noqa: PLC0415

    agent = art.get("ai_agent") or {}
    obs_by_id = {
        str(o.get("observation_id") or ""): o
        for o in (agent.get("observations") or [])
        if isinstance(o, dict) and o.get("observation_id")
    }
    web = _web_port(art)
    seen_agent_claims: set[str] = set()
    for f in (agent.get("findings") or []):
        if not isinstance(f, dict) or str(f.get("status") or "").lower() != "confirmed":
            continue
        raw_id = str(f.get("id") or f.get("title") or "").strip()
        if not raw_id:
            continue
        # Canonical id (ssdp-exposed ≈ ssdp_exposure; CVE case/variants).
        claim = normalize_finding_id(raw_id, str(f.get("title") or ""))
        if claim.startswith("cve-"):
            claim = claim.upper()
        # Inventory tech markers are not vulnerability subjects for fusion pin
        if claim.startswith("tech_"):
            continue
        if claim.lower() in seen_agent_claims:
            continue
        seen_agent_claims.add(claim.lower())

        refs = f.get("evidence_refs") or []
        obs_bits = []
        for rid in refs:
            o = obs_by_id.get(str(rid))
            if not o:
                continue
            obs_bits.append(
                f"{o.get('tool')}: {o.get('summary')}"
                + (f" ({(o.get('data') or {}).get('cve_id')})" if isinstance(o.get("data"), dict) else "")
            )
        evidence = (
            f"AI agent tool-confirmed: {f.get('title') or claim}. "
            f"{f.get('rationale') or ''} "
            + (" | ".join(obs_bits) if obs_bits else "")
        ).strip()[:600]

        # Prefer port from matching vuln_match if present
        port = web
        for vm in (art.get("vuln_matches") or []):
            for c in (_attr(vm, "cves", []) or []):
                if str(_attr(c, "id", "") or "").upper() == claim.upper():
                    port = _attr(vm, "port") or port
                    break

        sigs.append(Signal(
            source="probe",
            kind="vuln",
            claim=claim,
            host=host,
            port=port,
            service="http" if port in (80, 443, 8080, 8443) else "",
            reliability="high",
            probe_confirmed=True,
            version_matched=False,
            evidence=evidence,
            cvss=9.8 if claim.upper().startswith("CVE-") else 7.5,
            exploit_available=True,
            observed_data={
                "agent_status": "confirmed",
                "evidence_refs": list(refs),
                "tool_summaries": obs_bits[:6],
                "rationale": str(f.get("rationale") or "")[:300],
            },
            exposure=exposure,
            raw_metadata={"source": "ai_agent"},
        ))

    return sigs


def _merge_tls(art: dict) -> dict:
    """Extract a summary dict from the first TLS result (if any)."""
    results = art.get("tls_results") or []
    if results:
        r = results[0] if isinstance(results, list) else results
        return {
            "grade": _attr(r, "grade"),
            "protocols": _attr(r, "protocols"),
            "hsts": _attr(r, "hsts", False),
            "cert_expires": (_attr(r, "cert_expires") or _attr(_attr(r, "cert") or {}, "not_after")),
        }
    return {}


def _is_default_lander(wf) -> bool:
    """Check if the web root is a known hosting provider default/placeholder page."""
    title = (_attr(wf, "title") or "").lower()
    # Known hosting provider default page titles
    default_titles = {
        "inmotion hosting", "inmotionhosting",
        "cpanel", "cpanel®", "cpanel default page",
        "apache2 ubuntu default page", "apache2 default page",
        "it works!", "welcome to nginx", "welcome",
        "plesk", "centos web panel", "webuzo",
        "hsphere", "godaddy", "hostgator", "bluehost", "siteground",
        "default web site page", "default page",
        "coming soon", "under construction",
        "index of /", "directory listing",
    }
    return any(t == title or (t in title and len(title) < 40) for t in default_titles)


def build_engine_context(art: dict) -> dict:
    """Build host-level context from engine artifacts for the AI adjudicator."""
    hr = art.get("host_result") or {}
    stack = art.get("stack_result") or {}
    dns_result = art.get("dns_result") or {}
    vpr = art.get("vuln_probe_result") or {}
    wf = art.get("web_fingerprint")

    ports = []
    for p in (_attr(hr, "ports") or []):
        ports.append({
            "port": _attr(p, "port"),
            "protocol": _attr(p, "protocol", "tcp"),
            "service": _attr(p, "service", ""),
            "banner": (str(_attr(p, "banner", ""))[:200] or None) if _attr(p, "banner") else None,
        })

    techs = []
    for t in (_attr(stack, "technologies") or []):
        techs.append({
            "name": _attr(t, "name", ""),
            "version": _attr(t, "version", "") or None,
        })

    confirmed_vulns = []
    confirmed_vuln_ids: list[str] = []
    for f in (_attr(vpr, "confirmed", []) or []):
        if _attr(f, "confirmed", True) is not False:
            cve = str(_attr(f, "cve_id", "") or _attr(f, "title", "") or "")
            if not cve:
                continue
            confirmed_vuln_ids.append(cve)
            poc = _attr(f, "poc", None) or {}
            if not isinstance(poc, dict):
                poc = {}
            confirmed_vulns.append({
                "cve": cve,
                "title": _attr(f, "title", cve),
                "severity": _attr(f, "severity", ""),
                "evidence": (_attr(f, "evidence", "") or "")[:400],
                "detail": (_attr(f, "detail", "") or "")[:400],
                "remediation": (_attr(f, "remediation", "") or "")[:300],
                "poc": {
                    "curl": poc.get("curl"),
                    "expected": poc.get("expected"),
                    "how_to_reproduce": poc.get("how_to_reproduce"),
                } if poc.get("curl") else None,
            })

    web_fp = None
    is_default = False
    if wf is not None:
        is_default = _is_default_lander(wf)
        web_fp = {
            "title": _attr(wf, "title"),
            "generator": _attr(wf, "generator"),
            "app_name": _attr(wf, "app_name"),
            "version_markers": _attr(wf, "version_markers", []),
            "exposed_files": _attr(wf, "exposed_files", []),
            "favicon_mmh3": _attr(wf, "favicon_mmh3"),
            "is_default_lander": is_default,
        }

    # Cross-host context for lateral-movement reasoning
    probed = art.get("probed_hosts") or []
    adjacent_hosts: dict[str, list[int]] = {}
    for host_ip, port in probed:
        adjacent_hosts.setdefault(host_ip, []).append(port)
    reach = art.get("reachability") or {}
    # Collapse to readable form: host:port → [targets]
    reaches_readable = {}
    for src_key, targets in reach.items():
        reaches_readable[src_key] = sorted(targets)

    # AI agent tool transcript — primary ground truth for synthesis when present.
    agent = art.get("ai_agent") or {}
    agent_ctx = None
    if agent:
        agent_findings = []
        agent_pocs = list(agent.get("pocs") or [])
        poc_by_fid = {}
        for p in agent_pocs:
            if isinstance(p, dict) and p.get("finding_id"):
                poc_by_fid[str(p["finding_id"])] = p
        for f in (agent.get("findings") or []):
            if not isinstance(f, dict):
                continue
            fid = str(f.get("id") or "")
            poc = f.get("poc") if isinstance(f.get("poc"), dict) else poc_by_fid.get(fid)
            agent_findings.append({
                "id": f.get("id"),
                "title": f.get("title"),
                "status": f.get("status"),
                "severity": f.get("severity"),
                "rationale": (f.get("rationale") or "")[:400],
                "evidence_refs": f.get("evidence_refs") or [],
                "poc": {
                    "curl": (poc or {}).get("curl"),
                    "expected": (poc or {}).get("expected"),
                    "how_to_reproduce": (poc or {}).get("how_to_reproduce")
                    or (poc or {}).get("notes"),
                } if poc and (poc.get("curl") or poc.get("expected")) else None,
            })
        # Compact tool observations — include repro-critical fields so synthesis
        # can build PoCs from what was *actually* run (status, Location, signals).
        agent_obs = []
        for o in (agent.get("observations") or [])[:60]:
            if not isinstance(o, dict):
                continue
            data = o.get("data") if isinstance(o.get("data"), dict) else {}
            loc = data.get("location") or ""
            if not loc and isinstance(data.get("headers"), dict):
                loc = (data["headers"].get("location")
                       or data["headers"].get("Location") or "")
            agent_obs.append({
                "observation_id": o.get("observation_id"),
                "tool": o.get("tool"),
                "ok": o.get("ok"),
                "summary": (o.get("summary") or "")[:200],
                "vulnerable_signal": data.get("vulnerable_signal"),
                "cve_id": data.get("cve_id"),
                "path": data.get("path"),
                "method": data.get("method"),
                "status": data.get("status") or data.get("status_redirect") or data.get("status_reflect"),
                "location": str(loc)[:200] if loc else None,
                "location_host": data.get("location_host"),
                "open_redirect_signal": data.get("open_redirect_signal"),
                "proof_signals": data.get("proof_signals") or data.get("signals"),
                "observed_summary": data.get("observed_summary"),
                "data": {
                    k: data.get(k)
                    for k in (
                        "path", "method", "status", "location", "location_host",
                        "open_redirect_signal", "proof_signals", "signals",
                        "vulnerable_signal", "observed_summary", "body_template",
                        "param", "marker",
                    )
                    if data.get(k) is not None
                },
            })
        agent_ctx = {
            "confirmed_count": agent.get("confirmed") or sum(
                1 for f in agent_findings if str(f.get("status") or "").lower() == "confirmed"
            ),
            "leads": agent.get("leads"),
            "steps_used": agent.get("steps_used"),
            "requests_used": agent.get("requests_used"),
            "stopped_reason": agent.get("stopped_reason"),
            "findings": agent_findings,
            "pocs": list(agent.get("pocs") or [])[:20],
            "chains": (agent.get("chains") or [])[:12],
            "tool_observations": agent_obs,
            # Full observations kept compact-adjacent for repro ledger
            "observations": agent_obs,
            "note": (
                "AGENT TOOL PROOF outranks version/banner correlator decisions. "
                "Any finding with status=confirmed here was verified with live tools "
                "(e.g. crash_probe, http_request). Treat as Confirmed in the report; "
                "do NOT put them in False Positives as 'version-only'. "
                "PoCs MUST quote tool_observations (path/status/Location) — never invent responses."
            ),
        }
        # Also surface agent-confirmed CVE ids next to probe-confirmed list
        for f in agent_findings:
            if str(f.get("status") or "").lower() != "confirmed":
                continue
            fid = str(f.get("id") or "")
            if fid.lower().startswith("cve-"):
                cid = fid.upper().replace("-CONFIRMED", "")
                if cid not in confirmed_vuln_ids:
                    confirmed_vuln_ids.append(cid)
                    confirmed_vulns.append({
                        "cve": cid,
                        "title": f.get("title") or cid,
                        "severity": f.get("severity") or "",
                        "evidence": (f.get("rationale") or "")[:400],
                        "poc": f.get("poc"),
                    })

    # Composite control postures: joint views so synthesis reasons over a
    # *family* of controls (not one checklist item). Fail-soft if DNS missing.
    control_postures: dict = {}
    try:
        from src.dns_security import email_auth_posture_for_ai  # noqa: PLC0415
        email_auth = email_auth_posture_for_ai(dns_result)
        if email_auth:
            control_postures["email_auth"] = email_auth
    except Exception:  # noqa: BLE001
        pass

    ctx = {
        "host": _attr(hr, "ip") or _attr(hr, "target", ""),
        "open_ports": ports,
        "tech_stack": techs,
        "web_fingerprint": web_fp,
        "tls": _merge_tls(art),
        "dns": {
            "reverse_dns": _attr(dns_result, "reverse_dns"),
            "spoofable": _attr(dns_result, "email_spoofable", False),
            "spf": _attr(dns_result, "spf"),
            "dmarc": _attr(dns_result, "dmarc"),
        },
        "exposure": _exposure(art),
        "confirmed_vulns": confirmed_vulns,
        "ai_agent": agent_ctx,
        "adjacent_hosts": adjacent_hosts,
        "reaches": reaches_readable,
        "poc_contract": (
            "Every finding in the Executive Summary / Findings section MUST include a "
            "concrete **Proof of concept** / **How to reproduce** (curl or equivalent). "
            "Prefer poc.curl + poc.expected from confirmed_vulns / ai_agent.findings when present."
        ),
    }
    if control_postures:
        ctx["control_postures"] = control_postures
    return ctx


def _row(v: Verdict) -> dict:
    ai = getattr(v, "ai", None)
    return {
        "subject": v.claim, "port": v.port, "decision": v.decision, "impact": v.impact,
        "pinned": v.pinned, "agreement": v.agreement, "rationale": v.rationale,
        "ai": ({"verdict": ai.verdict, "reason": ai.reason} if ai else None),
        "safety_override": bool(getattr(v, "ai_safety_override", False)),
    }


def run_fusion(art: dict, cfg=None, complete=None, skip_synthesis: bool = False,
               on_token: Optional[Callable[[str], None]] = None,
               cross_host: Optional[dict] = None) -> dict:
    """Build signals from artifacts, adjudicate (gate + AI gray band), return a summary.

    When ``on_token`` is provided, the synthesis LLM call streams token deltas
    through the callback so the caller can emit progressive "ai" SSE events.

    Fail-soft: with no usable AI config the gray band degrades to 'potential' (never
    dropped). Pinned criticals are confirmed regardless of the AI.

    Returns:
        confirmed, potential, ai_discovered, discarded — legacy breakdowns
        detected_vulnerabilities — combined + sorted list (confirmed + potential + ai_discovered)
        ai_analysis — full 6-section markdown from synthesis (None if synthesis is skipped)
        beyond_cves — list of beyond-CVE findings from the AI analysis
        summary — counts and metadata
    """
    signals = signals_from_artifacts(art)
    verdicts = adjudicate(signals)

    if on_token is None:
        # Non-streaming path: build the standard complete function if not injected
        if complete is None:
            if cfg is not None:
                try:
                    usable, _ = cfg.is_usable()
                    if usable:
                        from src.fusion.ai import make_completer  # noqa: PLC0415
                        complete = make_completer(cfg)
                except Exception:  # noqa: BLE001
                    complete = None
            if complete is None:
                def complete(system, user):  # noqa: ARG001
                    raise RuntimeError("AI not configured for fusion adjudication")
    else:
        # Streaming path: keep a fallback for adjudication (non-streaming), but the
        # synthesis call uses the streaming adapter directly.
        if complete is None:
            # Fallback for run_adjudication — adjudication is NOT streamed
            if cfg is not None:
                try:
                    usable, _ = cfg.is_usable()
                    if usable:
                        from src.fusion.ai import make_completer  # noqa: PLC0415
                        complete = make_completer(cfg)
                except Exception:  # noqa: BLE001
                    complete = None
            if complete is None:
                def complete(system, user):  # noqa: ARG001
                    raise RuntimeError("AI not configured for fusion adjudication")

    context = build_engine_context(art)
    verdicts, new_verdicts = run_adjudication(verdicts, context=context, complete=complete)

    confirmed = [_row(v) for v in verdicts if v.decision == "confirmed"]
    potential = [_row(v) for v in verdicts if v.decision == "potential"]
    discarded = [_row(v) for v in verdicts if v.decision == "discarded"]
    ai_discovered = [_row(v) for v in new_verdicts if v.decision == "potential"]

    confirmed.sort(key=lambda r: ("low", "medium", "high", "critical").index(r["impact"]), reverse=True)
    potential.sort(key=lambda r: ("low", "medium", "high", "critical").index(r["impact"]), reverse=True)
    ai_discovered.sort(key=lambda r: ("low", "medium", "high", "critical").index(r["impact"]), reverse=True)

    # Unified detected_vulnerabilities list
    seen = set()
    detected_vulns = []
    for r in confirmed + potential + ai_discovered:
        dedup_key = (r["subject"], r["port"])
        if dedup_key not in seen:
            seen.add(dedup_key)
            detected_vulns.append(r)

    # Unified AI analysis via synthesis (if we have an AI completer)
    ai_markdown = None
    beyond_cves: list[str] = []
    if not skip_synthesis:
        try:
            # Get Verdict objects for synthesis (not the serialized rows)
            all_confirmed = [v for v in verdicts if v.decision == "confirmed"]
            all_potential = [v for v in verdicts if v.decision == "potential"]
            all_discarded = [v for v in verdicts if v.decision == "discarded"]
            all_new = list(new_verdicts)
            ai_markdown, beyond_cves = full_synthesize(
                all_confirmed, all_potential, all_new, all_discarded,
                context=context, cross_host=cross_host,
                complete=complete, on_token=on_token, cfg=cfg,
            )
        except Exception:  # noqa: BLE001
            ai_markdown = None

    return {
        "confirmed": confirmed,
        "potential": potential,
        "ai_discovered": ai_discovered,
        "discarded": discarded,
        "detected_vulnerabilities": detected_vulns,
        "ai_analysis": ai_markdown,
        "beyond_cves": beyond_cves,
        "summary": {
            "signals": len(signals),
            "confirmed": len(confirmed),
            "potential": len(potential),
            "ai_discovered": len(ai_discovered),
            "discarded": len(discarded),
            "ai_adjudicated": sum(1 for v in verdicts if getattr(v, "ai", None) is not None),
        },
    }
