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
from typing import Optional

from src.fusion.adjudicator import run_adjudication
from src.fusion.gate import adjudicate, Verdict
from src.fusion.signals import Signal

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
    demotes impact for these findings."""
    stack = art.get("stack_result")
    waf = None
    cdn = None
    if stack is not None:
        w = _attr(stack, "waf")
        if w is not None and _attr(w, "detected"):
            waf = _attr(w, "name")
        cdn = _attr(stack, "cloud_provider") or _attr(stack, "cdn")
    return {"reachability": "public", "waf": waf, "cdn": cdn}


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
                evidence=f"{product} {version} on {port}/{service}: {(_attr(c, 'description', '') or '')[:200]}",
                cvss=float(_attr(c, "cvss_score", 0.0) or 0.0),
                kev=bool(_attr(c, "kev", False)),
                epss=float(_attr(c, "epss", 0.0) or 0.0),
                exploit_available=bool(_attr(c, "exploit_available", False)
                                       or _attr(c, "has_metasploit", False)
                                       or _attr(c, "has_public_exploit", False)),
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
        sigs.append(Signal(
            source="probe", kind="vuln", claim=claim, host=host, port=_attr(f, "port"),
            service="http", reliability="high", exploit_available=True, cvss=8.0,
            evidence=f"probe-confirmed: {_attr(f, 'title', claim)}", exposure=exposure,
        ))

    # 3. Service misconfigurations (probe findings) → high reliability.
    spr = art.get("service_probe_result")
    for f in (_attr(spr, "findings", []) or []):
        title = str(_attr(f, "title", "") or "")
        if not title:
            continue
        sigs.append(Signal(
            source="probe", kind="misconfig", claim=title.lower()[:64], host=host, port=_attr(f, "port"),
            reliability="high", evidence=f"probe finding: {title}",
            cvss=_SEV_TO_CVSS.get(str(_attr(f, "severity", "")).upper(), 0.0), exposure=exposure,
        ))

    # 4. Technology fingerprint (corroboration / inventory).
    wport = _web_port(art)
    stack = art.get("stack_result")
    for t in (_attr(stack, "technologies", []) or []):
        name = str(_attr(t, "name", "") or "").lower()
        if not name:
            continue
        sigs.append(Signal(
            source="stack", kind="tech", claim=name, host=host, port=wport, service="http",
            reliability="medium", evidence=f"tech: {_attr(t, 'name', '')} {_attr(t, 'version', '') or ''}".strip(),
            exposure=exposure,
        ))

    return sigs


def _row(v: Verdict) -> dict:
    ai = getattr(v, "ai", None)
    return {
        "subject": v.claim, "port": v.port, "decision": v.decision, "impact": v.impact,
        "pinned": v.pinned, "agreement": v.agreement, "rationale": v.rationale,
        "ai": ({"verdict": ai.verdict, "reason": ai.reason} if ai else None),
        "safety_override": bool(getattr(v, "ai_safety_override", False)),
    }


def run_fusion(art: dict, cfg=None, complete=None) -> dict:
    """Build signals from artifacts, adjudicate (gate + AI gray band), return a summary.

    Fail-soft: with no usable AI config the gray band degrades to 'potential' (never
    dropped). Pinned criticals are confirmed regardless of the AI.
    """
    signals = signals_from_artifacts(art)
    verdicts = adjudicate(signals)

    if complete is None:
        if cfg is not None:
            try:
                usable, _ = cfg.is_usable()
                if usable:
                    from src.fusion.ai import make_completer  # noqa: PLC0415
                    complete = make_completer(cfg)
            except Exception:  # noqa: BLE001
                complete = None
        # No usable cfg and no injected completer → explicit "AI unavailable" so the
        # gray band degrades to 'potential'. We never silently reach for env config.
        if complete is None:
            def complete(system, user):  # noqa: ARG001
                raise RuntimeError("AI not configured for fusion adjudication")

    run_adjudication(verdicts, complete=complete)

    confirmed = [_row(v) for v in verdicts if v.decision == "confirmed"]
    potential = [_row(v) for v in verdicts if v.decision == "potential"]
    discarded = [_row(v) for v in verdicts if v.decision == "discarded"]
    confirmed.sort(key=lambda r: ("low", "medium", "high", "critical").index(r["impact"]), reverse=True)
    potential.sort(key=lambda r: ("low", "medium", "high", "critical").index(r["impact"]), reverse=True)

    return {
        "confirmed": confirmed,
        "potential": potential,
        "discarded": discarded,
        "summary": {
            "signals": len(signals),
            "confirmed": len(confirmed),
            "potential": len(potential),
            "discarded": len(discarded),
            "ai_adjudicated": sum(1 for v in verdicts if getattr(v, "ai", None) is not None),
        },
    }
