"""Build a compact SurfaceSummary for the AI investigation agent from scan artifacts."""
from __future__ import annotations

from typing import Any


def build_surface_summary(
    target: str,
    art: dict | None = None,
    *,
    scope: list[str] | None = None,
    state: Any = None,
) -> dict:
    """Compact, JSON-serializable picture of the attack surface after baseline sensors.

    Intentionally small so every agent turn stays within context budgets.
    """
    art = art or {}
    ports: list[dict] = []
    # Engine stores PortResult objects on host_result.ports; some paths use plain dicts.
    raw_ports = art.get("ports") or art.get("open_ports") or []
    hr = art.get("host_result")
    if not raw_ports and hr is not None:
        raw_ports = getattr(hr, "ports", None) or []
    for p in list(raw_ports)[:40]:
        if isinstance(p, dict):
            ports.append({
                "port": p.get("port"),
                "service": p.get("service") or p.get("name") or "",
                "banner": str(p.get("banner") or p.get("product") or "")[:120],
            })
        else:
            banner = getattr(p, "banner", None)
            banner_s = ""
            if banner is not None:
                banner_s = str(getattr(banner, "raw", None) or getattr(banner, "product", None) or banner or "")[:120]
            ports.append({
                "port": getattr(p, "port", None),
                "service": getattr(p, "service", "") or "",
                "banner": banner_s,
            })

    techs: list[str] = []
    stack = art.get("stack") or art.get("technologies") or []
    sr = art.get("stack_result")
    if not stack and sr is not None:
        stack = getattr(sr, "technologies", None) or getattr(sr, "stack", None) or []
        if not stack and hasattr(sr, "to_dict"):
            try:
                stack = (sr.to_dict() or {}).get("technologies") or []
            except Exception:  # noqa: BLE001
                stack = []
    if isinstance(stack, list):
        for t in stack[:24]:
            if isinstance(t, str):
                techs.append(t[:80])
            elif isinstance(t, dict):
                techs.append(str(t.get("name") or t.get("tech") or t)[:80])
    elif isinstance(stack, dict):
        for k in list(stack.keys())[:24]:
            techs.append(str(k)[:80])
    # Infer tech from port banners when stack fingerprint is empty
    for p in ports:
        b = (p.get("banner") or "").lower()
        if "apache" in b and "apache" not in " ".join(techs).lower():
            techs.append("apache")
        if "nginx" in b and "nginx" not in " ".join(techs).lower():
            techs.append("nginx")
        if "microsoft-iis" in b or "iis/" in b:
            if "iis" not in " ".join(techs).lower():
                techs.append("iis")

    # World graph tech (reasoning state) if present
    if state is not None:
        try:
            for n in state.world.graph.nodes("technology"):
                label = (n.label or n.key or "")[:80]
                if label and label not in techs:
                    techs.append(label)
        except Exception:  # noqa: BLE001
            pass

    cve_leads: list[dict] = []
    raw_vulns = art.get("vulns") or art.get("cves") or art.get("vuln_matches") or []
    for v in list(raw_vulns)[:30]:
        if isinstance(v, dict):
            cve_leads.append({
                "id": v.get("id") or v.get("cve_id") or v.get("cve"),
                "cvss": v.get("cvss") or v.get("cvss_score"),
                "service": v.get("service") or "",
                "port": v.get("port"),
                "note": str(v.get("description") or v.get("title") or "")[:160],
            })
            continue
        # VulnMatch / similar objects from correlate()
        cves = getattr(v, "cves", None) or []
        port = getattr(v, "port", None)
        service = getattr(v, "service", "") or ""
        if cves:
            for c in cves[:8]:
                if isinstance(c, dict):
                    cve_leads.append({
                        "id": c.get("id") or c.get("cve_id"),
                        "cvss": c.get("cvss") or c.get("cvss_score"),
                        "service": service, "port": port,
                        "note": str(c.get("description") or "")[:160],
                    })
                else:
                    cve_leads.append({
                        "id": getattr(c, "id", None) or str(c),
                        "cvss": getattr(c, "cvss_score", None) or getattr(c, "cvss", None),
                        "service": service, "port": port,
                        "note": str(getattr(c, "description", "") or "")[:160],
                    })
        else:
            cid = getattr(v, "cve_id", None) or getattr(v, "id", None)
            if cid:
                cve_leads.append({
                    "id": cid,
                    "cvss": getattr(v, "cvss_score", None) or getattr(v, "cvss", None),
                    "service": service, "port": port,
                    "note": str(getattr(v, "description", "") or "")[:160],
                })

    tls = art.get("tls") or art.get("tls_results") or []
    tls_brief: list[dict] = []
    if isinstance(tls, list):
        for t in tls[:8]:
            if isinstance(t, dict):
                tls_brief.append({
                    "port": t.get("port"),
                    "version": t.get("version") or t.get("protocol"),
                    "issues": (t.get("issues") or t.get("findings") or [])[:5]
                    if isinstance(t.get("issues") or t.get("findings"), list) else [],
                })

    headers = art.get("headers") or art.get("header_audit") or {}
    header_brief = {}
    if isinstance(headers, dict):
        for k in ("server", "Server", "x-powered-by", "X-Powered-By", "missing", "findings"):
            if k in headers:
                header_brief[k] = headers[k] if not isinstance(headers[k], list) else headers[k][:8]

    leads: list[str] = []
    for c in cve_leads:
        if c.get("id"):
            leads.append(f"cve_lead:{c['id']}")
    for t in techs[:12]:
        leads.append(f"tech:{t}")

    # Reasoning hypotheses as open leads
    if state is not None:
        try:
            for h in state.investigation.hypotheses.all():
                if getattr(h, "status", "") == "active":
                    leads.append(f"hypothesis:{h.label}"[:120])
                    if len(leads) >= 40:
                        break
        except Exception:  # noqa: BLE001
            pass

    return {
        "target": target,
        "scope": list(scope or ([target.split(":")[0]] if target else [])),
        "ports": ports,
        "technologies": techs[:24],
        "cve_leads": cve_leads,
        "tls": tls_brief,
        "headers": header_brief,
        "open_leads": leads[:40],
        "notes": [
            "Baseline only — version/banner CVE hits are LEADS until tool proof.",
            "You control next tools. Prefer non-destructive proof. "
            "crash_probe needs allow_crash_probes; http_proof needs allow_freeform_proof; "
            "exploit_request (any method + freeform body, authorized targets) needs "
            "allow_exploit_requests. Only tools listed in the catalog are available.",
        ],
    }
