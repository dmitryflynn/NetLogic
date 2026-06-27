"""AI-driven Nuclei template selector.

Given the discovered tech stack and open ports, asks the LLM which Nuclei
template tags to include/exclude — reducing irrelevant template runs.

Fail-soft: returns default tags when AI is unavailable.
"""

from __future__ import annotations

import json
import logging
from typing import Callable, Optional

log = logging.getLogger("netlogic.directors.nuclei_selector")

SYSTEM = (
    "You are a penetration testing assistant. Given a target's open ports, "
    "services, and detected technology stack, select which Nuclei template "
    "categories to run.\n\n"
    "Available template tags: cve, tech, exposure, config, misconfig, "
    "wordpress, joomla, drupal, apache, nginx, iis, tomcat, network, ssl, "
    "cloud, os, default-login, dos, fuzz, brute-force, generic-detections\n\n"
    "RULES:\n"
    "  • Only include tags relevant to the detected tech stack and ports.\n"
    "  • Never exclude 'cve' if any software version is detected.\n"
    "  • Skip CMS-specific tags (wordpress, joomla, drupal) unless that CMS "
    "is confirmed in the tech stack.\n"
    "  • Skip 'fuzz' and 'dos' tags unless the target is explicitly being "
    "stress-tested.\n\n"
    "Respond with a JSON object ONLY — no prose, no markdown fences:\n"
    '{"include": ["tag1", "tag2"], "exclude": ["tag3"]}\n'
    "Include at minimum ['cve', 'exposure', 'config', 'misconfig']."
)

DEFAULT_TAGS = ["cve", "tech", "exposure", "config", "misconfig"]


def select_nuclei_tags(
    open_ports: list[dict],
    tech_stack: list[dict],
    vuln_matches: Optional[list] = None,
    complete: Optional[Callable[[str, str], str]] = None,
) -> list[str]:
    """Return the list of Nuclei template tags to run.

    Falls back to DEFAULT_TAGS if no AI completer is available or the AI
    call fails.
    """
    if complete is None:
        return list(DEFAULT_TAGS)

    tech_summary = []
    for t in tech_stack:
        name = t.get("name", "")
        ver = t.get("version", "")
        if name:
            tech_summary.append(f"{name} {ver}".strip())

    ports_summary = []
    for p in open_ports:
        pnum = p.get("port", "")
        svc = p.get("service", "")
        if pnum:
            ports_summary.append(f"{pnum}/{svc}")

    user = (
        "Target context:\n"
        f"  Open ports: {', '.join(ports_summary) or 'none reported'}\n"
        f"  Tech stack: {', '.join(tech_summary) or 'none detected'}\n"
        f"  CVE matches: {len(vuln_matches or [])}\n\n"
        "Select Nuclei template tags."
    )

    try:
        text = complete(SYSTEM, user).strip()
        return _parse_tags(text)
    except Exception as exc:
        log.warning("Nuclei tag selection failed (%s) — using defaults", exc)
        return list(DEFAULT_TAGS)


def _parse_tags(text: str) -> list[str]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[-1] if "\n" in cleaned else cleaned[3:]
        cleaned = cleaned.rsplit("```", 1)[0].strip()
    try:
        obj = json.loads(cleaned)
    except json.JSONDecodeError:
        log.warning("Could not parse nuclei tag selection: %.200s", text)
        return list(DEFAULT_TAGS)
    if not isinstance(obj, dict):
        return list(DEFAULT_TAGS)
    include = obj.get("include") or []
    if not isinstance(include, list):
        include = []
    return [str(t).strip().lower() for t in include if t]
