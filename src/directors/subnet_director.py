"""AI-directed subnet probing.

After passive sensors complete, asks the LLM which adjacent hosts to probe,
which ports to scan, and at what depth — replacing the fixed /24 sweep.

Fail-soft: returns default directive (/24 sweep, common ports).
"""

from __future__ import annotations

import json
import logging
from typing import Callable, Optional

log = logging.getLogger("netlogic.directors.subnet_director")

SYSTEM = (
    "You are a penetration testing coordinator. Given scan results for a "
    "target host, decide whether to probe adjacent hosts for lateral "
    "movement opportunities.\n\n"
    "Rules:\n"
    "  • Only recommend probing if the target is on a private subnet "
    "(10.x, 172.16-31.x, 192.168.x) — cloud public IPs are not adjacent.\n"
    "  • If probing is useful, specify specific target IPs and ports.\n"
    "  • Prefer targets that share the same service type (e.g., both run "
    "web servers) for lateral movement potential.\n"
    "  • Set depth to:\n"
    "      - 'skip': no subnet probe needed\n"
    "      - 'quick': sweep 4 common ports (22, 80, 443, 8080)\n"
    "      - 'standard': sweep 33 common ports on live hosts\n"
    "      - 'deep': sweep all top-1000 ports on live hosts\n\n"
    "Respond with a JSON object ONLY — no prose, no markdown fences:\n"
    '{"action": "skip|quick|standard|deep",\n'
    ' "targets": ["10.0.0.5", "10.0.0.10"],\n'
    ' "ports_per_target": {"10.0.0.5": [80, 443, 8080], "10.0.0.10": [22, 3306]},\n'
    ' "reason": "why these targets were chosen or why probing was skipped"}'
)


def build_subnet_directive(
    target_ip: str,
    open_ports: list[dict],
    tech_stack: Optional[list[dict]] = None,
    vuln_matches: Optional[list] = None,
    complete: Optional[Callable[[str, str], str]] = None,
) -> dict:
    """Return a subnet probe directive dict.

    Returned shape:
      {"action": "skip"|"quick"|"standard"|"deep",
       "targets": [str],
       "ports_per_target": {str: [int]},
       "reason": str}
    """
    default = {"action": "standard", "targets": [], "ports_per_target": {},
               "reason": "default /24 sweep"}

    if complete is None:
        return dict(default)

    ports_summary = []
    for p in open_ports:
        pnum = p.get("port", "")
        svc = p.get("service", "")
        if pnum:
            ports_summary.append(f"{pnum}/{svc}")

    tech_summary = []
    for t in (tech_stack or []):
        name = t.get("name", "")
        ver = t.get("version", "")
        if name:
            tech_summary.append(f"{name} {ver}".strip())

    cve_count = 0
    for vm in (vuln_matches or []):
        cve_count += len(vm.get("cves", []) or [])

    user = (
        f"Target IP: {target_ip}\n"
        f"  Open ports: {', '.join(ports_summary) or 'none'}\n"
        f"  Tech stack: {', '.join(tech_summary) or 'none'}\n"
        f"  CVE matches: {cve_count}\n\n"
        "Should we probe adjacent hosts, which ones, and at what depth?"
    )

    try:
        text = complete(SYSTEM, user).strip()
        return _parse_directive(text, default)
    except Exception as exc:
        log.warning("Subnet director failed (%s) — using default sweep", exc)
        return dict(default)


def _parse_directive(text: str, default: dict) -> dict:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[-1] if "\n" in cleaned else cleaned[3:]
        cleaned = cleaned.rsplit("```", 1)[0].strip()
    try:
        obj = json.loads(cleaned)
    except json.JSONDecodeError:
        log.warning("Could not parse subnet directive: %.200s", text)
        return dict(default)
    if not isinstance(obj, dict):
        return dict(default)

    action = str(obj.get("action", "standard")).strip().lower()
    if action not in ("skip", "quick", "standard", "deep"):
        action = "standard"

    targets = obj.get("targets") or []
    if not isinstance(targets, list):
        targets = []

    ports_pt = obj.get("ports_per_target") or {}
    if not isinstance(ports_pt, dict):
        ports_pt = {}

    reason = str(obj.get("reason", ""))[:200]

    return {
        "action": action,
        "targets": [str(t) for t in targets],
        "ports_per_target": {str(k): [int(p) for p in (v if isinstance(v, list) else [v])]
                             for k, v in ports_pt.items()},
        "reason": reason,
    }
