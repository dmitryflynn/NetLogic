"""
Nuclei runner — wraps the nuclei binary (MIT license) for accurate, template-based
vulnerability scanning and technology detection.

Replaces the custom banner-parsing and regex-based CVE correlation with community-
maintained templates (~13k+ templates covering CVEs, tech detection, misconfigs,
exposures, and default logins).

MIT-licensed tool, safe for commercial SaaS integration.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from typing import Optional


NUCLEI_BIN: str | None = None


def _which() -> str:
    global NUCLEI_BIN
    if NUCLEI_BIN is not None:
        return NUCLEI_BIN
    for candidate in ("nuclei", "nuclei.exe"):
        try:
            r = subprocess.run(
                [candidate, "-version"],
                capture_output=True, text=False, timeout=15,
            )
            out = (r.stdout or b"").decode("utf-8", errors="replace")
            err = (r.stderr or b"").decode("utf-8", errors="replace")
            if r.returncode == 0 or "Nuclei" in out + err:
                NUCLEI_BIN = candidate
                return candidate
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            continue
    NUCLEI_BIN = ""
    return ""


def available() -> bool:
    return bool(_which())


NucleiFinding = dict


def scan(
    target: str,
    tags: str = "cve,tech,exposure,config,misconfig,default-login",
    timeout: int = 300,
    max_host_error: int = 30,
) -> list[NucleiFinding]:
    """Run nuclei against a single target URL/host.

    Args:
        target: Host or URL to scan (e.g. ``example.com`` or ``https://example.com``).
        tags: Comma-separated nuclei template tags to include.
        timeout: Max seconds for the entire nuclei run.
        max_host_error: Max errors per host before nuclei stops trying.

    Returns:
        List of parsed finding dicts, each with keys:
            template_id, name, severity, type, host, matched_at, tags, matcher_name,
            extract_results, cve_id (optional), description (optional).
    """
    bin_path = _which()
    if not bin_path:
        return []

    fd, out_path = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)

    try:
        cmd = [
            bin_path,
            "-target", target,
            "-tags", tags,
            "-j",
            "-duc",
            "-silent",
            "-o", out_path,
            "-me", str(max_host_error),
        ]
        try:
            subprocess.run(
                cmd, timeout=timeout,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            pass

        if not os.path.exists(out_path) or os.path.getsize(out_path) == 0:
            return []

        findings: list[NucleiFinding] = []
        raw_bytes = open(out_path, "rb").read()
        text = raw_bytes.decode("utf-8", errors="replace")
        for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue

                info = raw.get("info") or {}
                classification = info.get("classification") or {}
                cve_list = classification.get("cve-id") or []
                cve_id = cve_list[0] if isinstance(cve_list, list) and cve_list else None
                if not cve_id:
                    cve_id = classification.get("cve")

                findings.append({
                    "template_id": raw.get("template-id"),
                    "name": info.get("name") or raw.get("name", ""),
                    "severity": info.get("severity", "unknown"),
                    "description": info.get("description", ""),
                    "type": raw.get("type", "http"),
                    "host": raw.get("host", target),
                    "matched_at": raw.get("matched-at", ""),
                    "tags": info.get("tags", []),
                    "matcher_name": raw.get("matcher-name", ""),
                    "extract_results": raw.get("extracted-results", []),
                    "cve_id": cve_id,
                    "port": raw.get("port"),
                    "scheme": raw.get("scheme"),
                })
        return findings
    finally:
        try:
            os.remove(out_path)
        except OSError:
            pass


def scan_tech_only(target: str, timeout: int = 120) -> list[NucleiFinding]:
    """Quick scan using only tech-detect templates (faster, for tech stack only)."""
    return scan(target, tags="tech-detect", timeout=timeout)


def scan_cve_only(target: str, timeout: int = 300) -> list[NucleiFinding]:
    """Scan using only CVE templates."""
    return scan(target, tags="cve", timeout=timeout)


def extract_technologies(findings: list[NucleiFinding]) -> list[dict]:
    """Extract unique technology entries from nuclei findings.

    Returns list of {name, version, certainty} dicts.
    """
    seen: set[str] = set()
    techs: list[dict] = []
    for f in findings:
        tags = f.get("tags") or []
        is_tech = "tech" in tags
        if not is_tech:
            continue
        name = f.get("name", "").replace(" Detection", "").replace(" Detect", "").strip()
        if not name:
            name = f.get("matcher_name", "")
        key = name.lower()
        if key and key not in seen:
            seen.add(key)
            techs.append({
                "name": name,
                "version": "",
                "certainty": 100,
                "source": "nuclei",
            })
    return techs


def extract_cves(findings: list[NucleiFinding]) -> list[dict]:
    """Extract CVE matches from nuclei findings.

    Returns list of {cve_id, severity, description, port, matched_at} dicts.
    """
    cves: list[dict] = []
    for f in findings:
        cve_id = f.get("cve_id")
        if not cve_id:
            continue
        cves.append({
            "cve_id": cve_id,
            "severity": f.get("severity", "unknown"),
            "description": f.get("description", ""),
            "port": f.get("port"),
            "matched_at": f.get("matched_at", ""),
            "name": f.get("name", ""),
        })
    return cves


def extract_exposures(findings: list[NucleiFinding]) -> list[dict]:
    """Extract exposure/misconfig findings (non-CVE, non-tech-detect)."""
    exposures: list[dict] = []
    for f in findings:
        tags = f.get("tags") or []
        cve_id = f.get("cve_id")
        is_tech = "tech-detect" in tags
        if cve_id or is_tech:
            continue
        exposures.append({
            "template_id": f.get("template_id"),
            "name": f.get("name", ""),
            "severity": f.get("severity", "unknown"),
            "description": f.get("description", ""),
            "matched_at": f.get("matched_at", ""),
            "port": f.get("port"),
        })
    return exposures
