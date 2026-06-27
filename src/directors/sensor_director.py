"""AI-driven sensor selection.

After port scan + CVE correlation, asks the LLM which subsequent sensors
to prioritise and with what focus — skipping irrelevant checks and drilling
deeper where findings justify it.

Fail-soft: returns a plan where all sensors are enabled (current behaviour).
"""

from __future__ import annotations

import json
import logging
from typing import Callable, Optional

log = logging.getLogger("netlogic.directors.sensor_director")

SYSTEM = (
    "You are a penetration testing coordinator. Given a target's open ports, "
    "services, and detected CVEs, decide which next-phase sensors to run and "
    "how to prioritise them.\n\n"
    "Available sensors:\n"
    "  - takeover: subdomain takeover checks (DNS-based)\n"
    "  - probes: active HTTP service and vulnerability probes\n"
    "  - subnet_probe: scan adjacent /24 hosts for lateral movement targets\n"
    "  - service_enum: deep service exploitability enumeration (SSH, SMB, etc.)\n"
    "  - web_fingerprint: web-app fingerprinting (generator, exposed files, favicon)\n"
    "  - nuclei: community template-based scanner (CVE/tech/exposure checks)\n\n"
    "RULES:\n"
    "  • Skip sensors that have nothing to work with (no HTTP → skip web_fingerprint).\n"
    "  • Prioritise sensors that match the detected tech stack and CVEs.\n"
    "  • Set priority 1 for sensors most likely to confirm/reject key findings.\n"
    "  • Set priority 5 for sensors that are unlikely to find anything new.\n"
    "  • Include a brief skip_reason when a sensor is disabled.\n\n"
    "Respond with a JSON object ONLY — no prose, no markdown fences:\n"
    '{"takeover": {"enabled": true, "priority": 3, "params": {}},\n'
    ' "probes": {"enabled": true, "priority": 1, "params": {"focus": "apache"}},\n'
    ' "subnet_probe": {"enabled": true, "priority": 2, "params": {}},\n'
    ' "service_enum": {"enabled": true, "priority": 2, "params": {}},\n'
    ' "web_fingerprint": {"enabled": true, "priority": 1, "params": {}},\n'
    ' "nuclei": {"enabled": true, "priority": 1, "params": {}},\n'
    ' "skip_reasons": {"skipped_sensor": "why it was skipped"}}'
)

ALL_SENSORS = ["takeover", "probes", "subnet_probe", "service_enum",
               "web_fingerprint", "nuclei"]


def build_sensor_plan(
    open_ports: list[dict],
    vuln_matches: Optional[list] = None,
    tech_stack: Optional[list[dict]] = None,
    complete: Optional[Callable[[str, str], str]] = None,
) -> dict:
    """Return a SensorPlan dict with per-sensor config.

    Returned shape:
      {sensor_name: {"enabled": bool, "priority": int, "params": dict},
       "skip_reasons": {sensor_name: str}}
    """
    if complete is None:
        return _default_plan()

    ports_summary = []
    for p in open_ports:
        pnum = p.get("port", "")
        svc = p.get("service", "")
        # Defensive: callers should pass a banner string, but a ServiceBanner object or
        # other non-str must never crash the director (it's fail-soft). Coerce to its raw
        # string if present, else str(), before slicing.
        _raw = p.get("banner") or ""
        if not isinstance(_raw, str):
            _raw = getattr(_raw, "raw", "") or str(_raw)
        banner = _raw[:80]
        if pnum:
            entry = f"{pnum}/{svc}"
            if banner:
                entry += f" ({banner})"
            ports_summary.append(entry)

    cve_summary = []
    for vm in (vuln_matches or []):
        for c in (vm.get("cves", []) or []):
            cid = c.get("id", "")
            cvss = c.get("cvss_score", "?")
            if cid:
                cve_summary.append(f"{cid} (CVSS {cvss})")

    tech_summary = []
    for t in (tech_stack or []):
        name = t.get("name", "")
        ver = t.get("version", "")
        if name:
            tech_summary.append(f"{name} {ver}".strip())

    user = (
        "Target context:\n"
        f"  Open ports: {', '.join(ports_summary) or 'none reported'}\n"
        f"  Tech stack: {', '.join(tech_summary) or 'none detected'}\n"
        f"  CVE matches: {', '.join(cve_summary[:10]) or 'none'}\n\n"
        "Which sensors should run next and at what priority?"
    )

    try:
        text = complete(SYSTEM, user).strip()
        return _parse_plan(text)
    except Exception as exc:
        log.warning("SensorDirector failed (%s) — running all sensors", exc)
        return _default_plan()


def _default_plan() -> dict:
    plan = {}
    for name in ALL_SENSORS:
        plan[name] = {"enabled": True, "priority": 3, "params": {}}
    plan["skip_reasons"] = {}
    return plan


def _parse_plan(text: str) -> dict:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[-1] if "\n" in cleaned else cleaned[3:]
        cleaned = cleaned.rsplit("```", 1)[0].strip()
    try:
        obj = json.loads(cleaned)
    except json.JSONDecodeError:
        log.warning("Could not parse sensor plan: %.200s", text)
        return _default_plan()
    if not isinstance(obj, dict):
        return _default_plan()

    plan = {}
    for name in ALL_SENSORS:
        cfg = obj.get(name, {})
        if isinstance(cfg, dict):
            plan[name] = {
                "enabled": bool(cfg.get("enabled", True)),
                "priority": int(cfg.get("priority", 3)),
                "params": cfg.get("params", {}),
            }
        else:
            plan[name] = {"enabled": True, "priority": 3, "params": {}}
    plan["skip_reasons"] = obj.get("skip_reasons", {})
    if not isinstance(plan["skip_reasons"], dict):
        plan["skip_reasons"] = {}
    return plan
