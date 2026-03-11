"""
NetRecon - Report Generator
Produces machine-readable JSON reports and human-readable HTML/terminal output.
"""

import json
import html
import time
from dataclasses import asdict
from typing import Optional


# ─── ANSI Terminal Colors ────────────────────────────────────────────────────────

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    ORANGE  = "\033[38;5;208m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    DIM     = "\033[2m"
    WHITE   = "\033[97m"

SEV_COLOR = {
    "CRITICAL": C.RED,
    "HIGH":     C.ORANGE,
    "MEDIUM":   C.YELLOW,
    "LOW":      C.GREEN,
    "UNKNOWN":  C.DIM,
}

SEV_BADGE = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH":     "🟠 HIGH    ",
    "MEDIUM":   "🟡 MEDIUM  ",
    "LOW":      "🟢 LOW     ",
}


def _sev_color(severity: str, text: str) -> str:
    color = SEV_COLOR.get(severity.upper(), C.DIM)
    return f"{C.BOLD}{color}{text}{C.RESET}"


# ─── Terminal Report ─────────────────────────────────────────────────────────────

def print_terminal_report(host_result, vuln_matches, osint_result=None):
    """Rich terminal output with color-coded severity."""
    hr = "─" * 70

    print(f"\n{C.BOLD}{C.CYAN}{'═' * 70}")
    print(f"  NetRecon Scan Report")
    print(f"  Target : {host_result.target}")
    print(f"  IP     : {host_result.ip or 'unresolved'}")
    if host_result.hostname:
        print(f"  Host   : {host_result.hostname}")
    if host_result.os_guess:
        print(f"  OS Est.: {host_result.os_guess}")
    print(f"  Scanned: {host_result.timestamp}")
    print(f"  Runtime: {host_result.scan_duration_s}s")
    print(f"{'═' * 70}{C.RESET}\n")

    # Open Ports Table
    print(f"{C.BOLD}{C.WHITE}  OPEN PORTS{C.RESET}")
    print(f"  {hr}")
    if not host_result.ports:
        print(f"  {C.DIM}No open ports discovered.{C.RESET}")
    else:
        print(f"  {'PORT':<8} {'SERVICE':<16} {'PRODUCT/VERSION':<35} {'TLS'}")
        print(f"  {'-'*70}")
        for p in host_result.ports:
            tls_str = f"{C.GREEN}✓ TLS{C.RESET}" if p.tls else f"{C.DIM}─{C.RESET}"
            prod_ver = ""
            if p.banner:
                prod_ver = f"{p.banner.product or ''} {p.banner.version or ''}".strip()
            print(f"  {C.CYAN}{p.port:<8}{C.RESET} {p.service or 'unknown':<16} {prod_ver:<35} {tls_str}")
    print()

    # Vulnerabilities
    print(f"{C.BOLD}{C.WHITE}  VULNERABILITY FINDINGS{C.RESET}")
    print(f"  {hr}")
    if not vuln_matches:
        print(f"  {C.GREEN}No known vulnerabilities identified.{C.RESET}\n")
    else:
        for vm in sorted(vuln_matches, key=lambda x: x.risk_score, reverse=True):
            label = f"Port {vm.port}/{vm.service}"
            if vm.product:
                label += f" ({vm.product}"
                if vm.version:
                    label += f" {vm.version}"
                label += ")"
            print(f"\n  {C.BOLD}{C.WHITE}{label}{C.RESET}")
            print(f"  Risk Score: {_risk_color(vm.risk_score)}")

            if vm.notes:
                for note in vm.notes:
                    print(f"  {C.YELLOW}⚠  {note}{C.RESET}")

            for cve in sorted(vm.cves, key=lambda c: c.cvss_score, reverse=True):
                sev = cve.severity.upper()
                color = SEV_COLOR.get(sev, C.DIM)
                badge = SEV_BADGE.get(sev, sev)
                print(f"\n    {color}{C.BOLD}{badge}{C.RESET}  {C.BOLD}{cve.id}{C.RESET}  CVSS {cve.cvss_score}")
                print(f"    {C.DIM}{cve.description[:100]}{'…' if len(cve.description) > 100 else ''}{C.RESET}")
                if cve.exploit_available:
                    print(f"    {C.RED}⚡ Known exploit available{C.RESET}")

    # OSINT Summary
    if osint_result:
        print(f"\n{C.BOLD}{C.WHITE}  PASSIVE RECON / OSINT{C.RESET}")
        print(f"  {hr}")
        if osint_result.dns_records:
            print(f"  {C.BOLD}DNS Records:{C.RESET} {len(osint_result.dns_records)} found")
        if osint_result.subdomains:
            print(f"  {C.BOLD}Subdomains:{C.RESET}  {len(osint_result.subdomains)} discovered via CT logs")
            for s in osint_result.subdomains[:10]:
                ip_str = f"  → {s.ip}" if s.ip else ""
                print(f"    {C.CYAN}{s.subdomain}{C.RESET}{C.DIM}{ip_str}{C.RESET}")
            if len(osint_result.subdomains) > 10:
                print(f"    {C.DIM}... and {len(osint_result.subdomains) - 10} more{C.RESET}")
        if osint_result.technologies:
            print(f"  {C.BOLD}Technologies:{C.RESET} {', '.join(osint_result.technologies)}")
        if osint_result.emails:
            print(f"  {C.BOLD}Emails:{C.RESET}  {', '.join(osint_result.emails[:5])}")
        if osint_result.asn_info:
            a = osint_result.asn_info
            print(f"  {C.BOLD}ASN:{C.RESET}  {a.asn} {a.org} [{a.country}]")

    print(f"\n  {C.DIM}{'─' * 70}{C.RESET}")
    print(f"  {C.DIM}NetRecon — For authorized use only. Always obtain permission.{C.RESET}\n")


def _risk_color(score: float) -> str:
    if score >= 9.0:
        return f"{C.BOLD}{C.RED}{score:.1f}/10{C.RESET}"
    if score >= 7.0:
        return f"{C.BOLD}{C.ORANGE}{score:.1f}/10{C.RESET}"
    if score >= 4.0:
        return f"{C.BOLD}{C.YELLOW}{score:.1f}/10{C.RESET}"
    return f"{C.GREEN}{score:.1f}/10{C.RESET}"


# ─── JSON Report ─────────────────────────────────────────────────────────────────

def generate_json_report(host_result, vuln_matches, osint_result=None) -> dict:
    """Produce a structured JSON report suitable for SIEM ingestion."""
    report = {
        "meta": {
            "tool": "NetRecon",
            "version": "1.0.0",
            "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "host": asdict(host_result),
        "vulnerabilities": [],
        "osint": None,
    }

    for vm in vuln_matches:
        report["vulnerabilities"].append({
            "port":       vm.port,
            "service":    vm.service,
            "product":    vm.product,
            "version":    vm.version,
            "risk_score": vm.risk_score,
            "notes":      vm.notes,
            "cves": [
                {
                    "id":               c.id,
                    "description":      c.description,
                    "cvss_score":       c.cvss_score,
                    "severity":         c.severity,
                    "vector":           c.vector,
                    "published":        c.published,
                    "exploit_available": c.exploit_available,
                    "references":       c.references,
                }
                for c in c.cves
            ] if hasattr(vm, "cves") else [],
        })

    if osint_result:
        report["osint"] = {
            "dns_records":  [asdict(r) for r in osint_result.dns_records],
            "subdomains":   [asdict(s) for s in osint_result.subdomains],
            "asn_info":     asdict(osint_result.asn_info) if osint_result.asn_info else None,
            "technologies": osint_result.technologies,
            "emails":       osint_result.emails,
        }

    return report


def save_json_report(report: dict, path: str):
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] JSON report saved → {path}")


# ─── HTML Report ─────────────────────────────────────────────────────────────────

SEV_HTML_COLOR = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8c00",
    "MEDIUM":   "#ffd700",
    "LOW":      "#44ff88",
    "UNKNOWN":  "#888",
}

def generate_html_report(host_result, vuln_matches, osint_result=None) -> str:
    h = host_result
    total_vulns = sum(len(vm.cves) for vm in vuln_matches)
    critical = sum(1 for vm in vuln_matches for c in vm.cves if c.severity.upper() == "CRITICAL")
    high     = sum(1 for vm in vuln_matches for c in vm.cves if c.severity.upper() == "HIGH")

    def esc(s): return html.escape(str(s or ""))

    vuln_rows = ""
    for vm in sorted(vuln_matches, key=lambda x: x.risk_score, reverse=True):
        for cve in sorted(vm.cves, key=lambda c: c.cvss_score, reverse=True):
            sev = cve.severity.upper()
            color = SEV_HTML_COLOR.get(sev, "#888")
            vuln_rows += f"""
            <tr>
              <td><code>{esc(cve.id)}</code></td>
              <td><span style="color:{color};font-weight:700">{esc(sev)}</span></td>
              <td>{esc(cve.cvss_score)}</td>
              <td>{esc(vm.port)}/{esc(vm.service)}</td>
              <td>{esc(vm.product or "–")} {esc(vm.version or "")}</td>
              <td style="font-size:0.85em">{esc(cve.description[:120])}…</td>
              <td>{"⚡ Yes" if cve.exploit_available else "–"}</td>
            </tr>"""

    port_rows = ""
    for p in h.ports:
        pv = ""
        if p.banner:
            pv = f"{p.banner.product or ''} {p.banner.version or ''}".strip()
        tls = "✓" if p.tls else "–"
        port_rows += f"""
        <tr>
          <td>{esc(p.port)}</td>
          <td>{esc(p.service or "unknown")}</td>
          <td>{esc(pv)}</td>
          <td>{tls}</td>
          <td>{esc(round(p.response_time_ms, 1))} ms</td>
        </tr>"""

    osint_section = ""
    if osint_result and osint_result.subdomains:
        sub_items = "".join(
            f"<li><code>{esc(s.subdomain)}</code>{f' → {esc(s.ip)}' if s.ip else ''}</li>"
            for s in osint_result.subdomains[:20]
        )
        osint_section = f"""
        <section>
          <h2>Passive Recon</h2>
          <p><strong>Subdomains discovered:</strong> {len(osint_result.subdomains)}</p>
          <ul>{sub_items}</ul>
          <p><strong>Technologies:</strong> {esc(', '.join(osint_result.technologies) or 'None detected')}</p>
        </section>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NetRecon Report — {esc(h.target)}</title>
<style>
  :root {{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#e6edf3;--dim:#7d8590;--accent:#58a6ff;}}
  * {{box-sizing:border-box;margin:0;padding:0}}
  body {{font-family:"Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--text);padding:2rem;}}
  h1 {{font-size:1.8rem;color:var(--accent);margin-bottom:0.25rem}}
  h2 {{font-size:1.1rem;color:var(--dim);text-transform:uppercase;letter-spacing:.1em;margin:2rem 0 1rem}}
  .meta {{color:var(--dim);font-size:0.9rem;margin-bottom:2rem}}
  .stat-grid {{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:1rem;margin:1.5rem 0}}
  .stat {{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1rem;text-align:center}}
  .stat .num {{font-size:2rem;font-weight:700;color:var(--accent)}}
  .stat .label {{font-size:0.8rem;color:var(--dim);margin-top:4px}}
  section {{margin-bottom:2.5rem}}
  table {{width:100%;border-collapse:collapse;font-size:0.9rem}}
  th {{background:var(--surface);border-bottom:2px solid var(--border);padding:.6rem .8rem;text-align:left;color:var(--dim);font-weight:600;font-size:0.8rem;text-transform:uppercase}}
  td {{padding:.55rem .8rem;border-bottom:1px solid var(--border)}}
  tr:hover td {{background:rgba(255,255,255,.03)}}
  code {{font-family:monospace;color:#79c0ff;font-size:0.9em}}
  footer {{margin-top:3rem;color:var(--dim);font-size:0.8rem;border-top:1px solid var(--border);padding-top:1rem}}
</style>
</head>
<body>
<h1>NetRecon Security Report</h1>
<div class="meta">
  Target: <strong>{esc(h.target)}</strong> · IP: {esc(h.ip)} · OS Estimate: {esc(h.os_guess or "Unknown")} · Scanned: {esc(h.timestamp)} · Duration: {h.scan_duration_s}s
</div>

<div class="stat-grid">
  <div class="stat"><div class="num">{len(h.ports)}</div><div class="label">Open Ports</div></div>
  <div class="stat"><div class="num" style="color:#ff4444">{critical}</div><div class="label">Critical CVEs</div></div>
  <div class="stat"><div class="num" style="color:#ff8c00">{high}</div><div class="label">High CVEs</div></div>
  <div class="stat"><div class="num">{total_vulns}</div><div class="label">Total Findings</div></div>
</div>

<section>
  <h2>Open Ports</h2>
  <table>
    <thead><tr><th>Port</th><th>Service</th><th>Product / Version</th><th>TLS</th><th>RTT</th></tr></thead>
    <tbody>{port_rows or "<tr><td colspan='5' style='color:var(--dim)'>No open ports</td></tr>"}</tbody>
  </table>
</section>

<section>
  <h2>Vulnerability Findings</h2>
  <table>
    <thead><tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Port/Service</th><th>Product</th><th>Description</th><th>Exploit</th></tr></thead>
    <tbody>{vuln_rows or "<tr><td colspan='7' style='color:#44ff88'>No known vulnerabilities identified.</td></tr>"}</tbody>
  </table>
</section>

{osint_section}

<footer>Generated by NetRecon v1.0.0 — For authorized security assessments only.</footer>
</body>
</html>"""


def save_html_report(html_content: str, path: str):
    with open(path, "w") as f:
        f.write(html_content)
    print(f"[+] HTML report saved → {path}")
