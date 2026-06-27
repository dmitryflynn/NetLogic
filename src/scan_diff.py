"""
NetLogic - Change-Over-Time Diffing
===================================
A single scan is a snapshot; the SECURITY signal is in what changed. New services,
new versions, and newly-appeared CVEs are where fresh exposure lives — and a
disappeared service can mean a fix (or an outage worth noting). This compares the
current scan to the most recent prior JSON report for the same target.

Self-contained: reads NetLogic's own saved JSON reports. Auto-runs when a prior
report for the target exists in the output directory.
"""
from __future__ import annotations

import glob
import json
import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ScanDiff:
    target: str
    previous_file: str
    previous_time: str = ""
    ports_added: list[int] = field(default_factory=list)
    ports_removed: list[int] = field(default_factory=list)
    version_changes: list[dict] = field(default_factory=list)   # {port, product, old, new}
    cves_added: list[dict] = field(default_factory=list)        # {port, cve}
    cves_removed: list[dict] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.ports_added or self.ports_removed or self.version_changes
                    or self.cves_added or self.cves_removed)


def _summarize_current(host_result, vuln_matches) -> dict:
    """Reduce an in-memory scan to the comparable shape {ports, versions, cves}."""
    ports, versions, cves = {}, {}, {}
    for p in getattr(host_result, "ports", []) or []:
        banner = getattr(p, "banner", None)
        ports[p.port] = getattr(p, "service", "") or ""
        if banner and getattr(banner, "product", None):
            versions[p.port] = f"{banner.product} {banner.version or ''}".strip()
    for vm in (vuln_matches or []):
        ids = {c.id for c in getattr(vm, "cves", []) or []}
        if ids:
            cves[vm.port] = ids
        if vm.port not in versions and getattr(vm, "product", None):
            versions[vm.port] = f"{vm.product} {vm.version or ''}".strip()
    return {"ports": ports, "versions": versions, "cves": cves}


def _summarize_report(report: dict) -> dict:
    """Reduce a saved JSON report to the same comparable shape."""
    ports, versions, cves = {}, {}, {}
    host = report.get("host", {})
    for p in host.get("ports", []) or []:
        port = p.get("port")
        if port is None:
            continue
        ports[port] = p.get("service", "") or ""
        banner = p.get("banner") or {}
        if banner.get("product"):
            versions[port] = f"{banner['product']} {banner.get('version') or ''}".strip()
    for vm in report.get("vulnerabilities", []) or []:
        port = vm.get("port")
        ids = {c.get("id") for c in vm.get("cves", []) or [] if c.get("id")}
        if ids:
            cves[port] = ids
        if port not in versions and vm.get("product"):
            versions[port] = f"{vm['product']} {vm.get('version') or ''}".strip()
    return {"ports": ports, "versions": versions, "cves": cves}


def find_previous_report(out_dir: str, target: str, exclude: str = "") -> Optional[str]:
    """Return the newest prior NetLogic JSON report for this target, or None."""
    safe = target.replace("/", "_").replace(":", "_")
    pattern = os.path.join(out_dir, f"netlogic_{safe}_*.json")
    try:
        files = sorted((f for f in glob.glob(pattern) if os.path.abspath(f) != os.path.abspath(exclude or "")),
                       key=os.path.getmtime, reverse=True)
    except OSError:
        return None
    return files[0] if files else None


def diff_scans(target: str, prev_summary: dict, curr_summary: dict,
               previous_file: str, previous_time: str = "") -> ScanDiff:
    d = ScanDiff(target=target, previous_file=previous_file, previous_time=previous_time)
    prev_ports, curr_ports = set(prev_summary["ports"]), set(curr_summary["ports"])
    d.ports_added   = sorted(curr_ports - prev_ports)
    d.ports_removed = sorted(prev_ports - curr_ports)

    for port in sorted(curr_ports & prev_ports):
        old, new = prev_summary["versions"].get(port), curr_summary["versions"].get(port)
        if old and new and old != new:
            d.version_changes.append({"port": port, "old": old, "new": new})

    for port in curr_ports:
        new_cves = curr_summary["cves"].get(port, set()) - prev_summary["cves"].get(port, set())
        for cve in sorted(new_cves):
            d.cves_added.append({"port": port, "cve": cve})
    for port in prev_ports:
        gone = prev_summary["cves"].get(port, set()) - curr_summary["cves"].get(port, set())
        for cve in sorted(gone):
            d.cves_removed.append({"port": port, "cve": cve})
    return d


def diff_against_last(host_result, vuln_matches, out_dir: str,
                      target: str, exclude: str = "") -> Optional[ScanDiff]:
    """Find the prior report for target and diff the current scan against it."""
    prev_file = find_previous_report(out_dir, target, exclude)
    if not prev_file:
        return None
    try:
        with open(prev_file, "r", encoding="utf-8") as f:
            prev_report = json.load(f)
    except Exception:
        return None
    prev_summary = _summarize_report(prev_report)
    curr_summary = _summarize_current(host_result, vuln_matches)
    prev_time = (prev_report.get("meta", {}) or {}).get("generated", "")
    return diff_scans(target, prev_summary, curr_summary, prev_file, prev_time)
