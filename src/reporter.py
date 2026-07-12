"""
NetLogic - Report Generator
Produces machine-readable JSON reports and human-readable HTML/terminal output.
"""

import json
import html
import time
from dataclasses import asdict


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
    print(f"  NetLogic Scan Report")
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
            conf = getattr(vm, 'detection_confidence', 'LOW')
            print(f"  {_confidence_badge(conf)}")
            print(f"  Risk Score: {_risk_color(vm.risk_score)}")

            if vm.notes:
                for note in vm.notes:
                    print(f"  {C.YELLOW}⚠  {note}{C.RESET}")

            for cve in sorted(vm.cves, key=lambda c: (getattr(c, 'kev', False),
                                                       getattr(c, 'epss', 0.0),
                                                       c.cvss_score), reverse=True):
                sev = cve.severity.upper()
                color = SEV_COLOR.get(sev, C.DIM)
                badge = SEV_BADGE.get(sev, sev)
                # EPSS: probability of exploitation. Highlight high values — they
                # matter more than a high CVSS with near-zero exploitation odds.
                epss = getattr(cve, 'epss', 0.0) or 0.0
                if epss >= 0.5:    epss_str = f"  {C.RED}EPSS {epss*100:.0f}%{C.RESET}"
                elif epss >= 0.1:  epss_str = f"  {C.ORANGE}EPSS {epss*100:.0f}%{C.RESET}"
                elif epss > 0:     epss_str = f"  {C.DIM}EPSS {epss*100:.1f}%{C.RESET}"
                else:              epss_str = ""
                desc = (cve.description or "").strip()
                title = desc[:90] + ("…" if len(desc) > 90 else "") if desc else cve.id
                print(f"\n    {color}{C.BOLD}{badge}{C.RESET}  {C.BOLD}{title}{C.RESET}  CVSS {cve.cvss_score}{epss_str}")
                print(f"    {C.DIM}Related: {cve.id}{C.RESET}")
                has_msf = getattr(cve, 'has_metasploit', False)
                has_pub = getattr(cve, 'has_public_exploit', False)
                if has_msf:
                    print(f"    {C.RED}⚡ Metasploit module available{C.RESET}")
                elif has_pub:
                    print(f"    {C.ORANGE}⚡ Public exploit / PoC available{C.RESET}")
                elif cve.exploit_available:
                    print(f"    {C.RED}⚡ Actively exploited (CISA KEV){C.RESET}")
                refs = getattr(cve, 'exploit_refs', [])
                for ref in refs[:2]:
                    print(f"    {C.DIM}   → {ref}{C.RESET}")

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
    print(f"  {C.DIM}NetLogic — For authorized use only. Always obtain permission.{C.RESET}\n")


def print_service_probe_results(probe_result, no_color: bool = False):
    """Print service misconfiguration findings from service_prober."""
    if not probe_result or not probe_result.findings:
        return
    R  = C.RESET  if not no_color else ""
    Bo = C.BOLD   if not no_color else ""
    D  = C.DIM    if not no_color else ""
    Cy = C.CYAN   if not no_color else ""

    print(f"\n{'─'*70}")
    print(f"  SERVICE MISCONFIGURATION FINDINGS  "
          f"({len(probe_result.findings)} issue(s), {probe_result.probes_run} probes run)")
    print(f"{'─'*70}")

    for f in probe_result.findings:
        sev = f.severity.upper()
        color = SEV_COLOR.get(sev, C.DIM) if not no_color else ""
        badge = SEV_BADGE.get(sev, sev)
        print(f"\n  {color}{Bo}{badge}{R}  {Bo}{f.title}{R}")
        print(f"  {D}Port {f.port} / {f.service}{R}")
        print(f"  {f.detail[:130]}{'…' if len(f.detail)>130 else ''}")
        if f.evidence:
            print(f"  {D}Evidence   : {f.evidence[:100]}{R}")
        if f.remediation:
            print(f"  {Cy}Remediation: {f.remediation[:110]}{'…' if len(f.remediation)>110 else ''}{R}")


def print_vuln_probe_results(probe_result, no_color: bool = False):
    """Print CVE-specific active probe findings from vuln_prober."""
    if not probe_result or not probe_result.confirmed:
        return
    R  = C.RESET  if not no_color else ""
    Bo = C.BOLD   if not no_color else ""
    D  = C.DIM    if not no_color else ""
    Cy = C.CYAN   if not no_color else ""
    G  = C.GREEN  if not no_color else ""

    print(f"\n{'─'*70}")
    print(f"  ACTIVE VULNERABILITY PROBES  "
          f"({len(probe_result.confirmed)} confirmed, {probe_result.probes_run} probes run)")
    print(f"{'─'*70}")

    for f in probe_result.confirmed:
        sev = f.severity.upper()
        color = SEV_COLOR.get(sev, C.DIM) if not no_color else ""
        badge = SEV_BADGE.get(sev, sev)
        confirmed_str = f"{G}[CONFIRMED]{R}" if f.confirmed else f"{C.YELLOW if not no_color else ''}[POSSIBLE]{R}"
        print(f"\n  {color}{Bo}{badge}{R}  {Bo}{f.title}{R}  {confirmed_str}")
        print(f"  {D}{f.cve_id}{R}")
        print(f"  {f.detail[:130]}{'…' if len(f.detail)>130 else ''}")
        if f.evidence:
            print(f"  {D}Evidence   : {f.evidence[:100]}{R}")
        poc = getattr(f, "poc", None) or {}
        if isinstance(poc, dict) and poc.get("curl"):
            curl = str(poc["curl"])
            print(f"  {Cy}PoC / repro: {curl[:120]}{'…' if len(curl) > 120 else ''}{R}")
            if poc.get("expected"):
                print(f"  {D}Expect     : {str(poc['expected'])[:100]}{R}")
        if f.remediation:
            print(f"  {Cy}Remediation: {f.remediation[:110]}{'…' if len(f.remediation)>110 else ''}{R}")


def print_topology(topo, no_color: bool = False):
    """Print network topology context."""
    if not topo:
        return
    R = C.RESET if not no_color else ""
    Cy = C.CYAN if not no_color else ""
    D = C.DIM if not no_color else ""
    print(f"\n{'─'*70}")
    print(f"  NETWORK TOPOLOGY")
    print(f"{'─'*70}")
    if getattr(topo, "ptr", None):
        print(f"  Reverse DNS : {Cy}{topo.ptr}{R}")
    if getattr(topo, "asn", None):
        print(f"  ASN         : {topo.asn}  {D}({topo.asn_org or ''} · {topo.country or ''}){R}")
    if getattr(topo, "ipv6", None):
        print(f"  IPv6        : {Cy}{', '.join(topo.ipv6[:3])}{R}")
    if getattr(topo, "hop_count", None):
        print(f"  Hops        : {topo.hop_count}  {D}{' → '.join(topo.traceroute_hops[:8])}{R}")
    for n in getattr(topo, "notes", [])[:3]:
        print(f"  {D}• {n}{R}")


def print_auth_result(auth, no_color: bool = False):
    """Print authenticated (credentialed) scan results — installed package ground truth."""
    if not auth:
        return
    R = C.RESET if not no_color else ""
    Bo = C.BOLD if not no_color else ""
    Cy = C.CYAN if not no_color else ""
    G = C.GREEN if not no_color else ""
    Y = C.YELLOW if not no_color else ""
    print(f"\n{'─'*70}")
    print(f"  AUTHENTICATED SCAN  {G if auth.success else Y}{'(connected)' if auth.success else '(failed)'}{R}")
    print(f"{'─'*70}")
    if not auth.success:
        print(f"  {Y}{auth.error}{R}")
        return
    print(f"  OS          : {auth.os_name or '?'}   Kernel: {auth.kernel or '?'}")
    print(f"  Packages    : {len(auth.packages)} installed")
    if auth.product_versions:
        print(f"  {Bo}Installed versions (GROUND TRUTH){R}:")
        for prod, info in sorted(auth.product_versions.items()):
            bp = f"  {G}[backported — likely patched]{R}" if info.get("backported") else ""
            print(f"    {Cy}{prod:<12}{R} {info['upstream']:<12} {info['full']}{bp}")


def print_scan_diff(diff, no_color: bool = False):
    """Print what changed since the previous scan."""
    if not diff or not getattr(diff, "has_changes", False):
        return
    R = C.RESET if not no_color else ""
    Bo = C.BOLD if not no_color else ""
    G = C.GREEN if not no_color else ""
    Rd = C.RED if not no_color else ""
    Y = C.YELLOW if not no_color else ""
    D = C.DIM if not no_color else ""
    print(f"\n{'─'*70}")
    print(f"  CHANGES SINCE LAST SCAN  {D}(vs {diff.previous_time or 'previous report'}){R}")
    print(f"{'─'*70}")
    for p in diff.ports_added:
        print(f"  {G}+ port {p} now open{R}")
    for p in diff.ports_removed:
        print(f"  {D}- port {p} closed{R}")
    for ch in diff.version_changes:
        print(f"  {Y}~ port {ch['port']}: {ch['old']} → {ch['new']}{R}")
    for c in diff.cves_added:
        print(f"  {Rd}{Bo}+ NEW CVE {c['cve']} on port {c['port']}{R}")
    for c in diff.cves_removed[:10]:
        print(f"  {G}- resolved {c['cve']} on port {c['port']}{R}")


def print_web_fingerprint(fp, no_color: bool = False):
    """Print web application fingerprint (favicon hash, versions, exposed files, JS leaks)."""
    if not fp:
        return
    R  = C.RESET  if not no_color else ""
    Bo = C.BOLD   if not no_color else ""
    D  = C.DIM    if not no_color else ""
    Cy = C.CYAN   if not no_color else ""
    Y  = C.YELLOW if not no_color else ""
    Rd = C.RED    if not no_color else ""
    print(f"\n{'─'*70}")
    print(f"  WEB APPLICATION FINGERPRINT")
    print(f"{'─'*70}")
    if getattr(fp, "title", None):
        print(f"  Title       : {fp.title[:80]}")
    if getattr(fp, "generator", None):
        print(f"  Generator   : {Cy}{fp.generator}{R}")
    if getattr(fp, "favicon_mmh3", None) is not None:
        print(f"  Favicon hash: {fp.favicon_mmh3}  {D}(Shodan http.favicon.hash){R}")
    if getattr(fp, "version_markers", None):
        print(f"  Versions    : {Cy}{', '.join(fp.version_markers[:6])}{R}")
    if getattr(fp, "exposed_files", None):
        print(f"  {Y}Exposed     : {', '.join(fp.exposed_files)}{R}")
    if getattr(fp, "js_endpoints", None):
        print(f"  JS endpoints: {D}{', '.join(fp.js_endpoints[:8])}{R}")
    if getattr(fp, "js_secrets", None):
        print(f"  {Rd}{Bo}JS secrets  : {', '.join(fp.js_secrets[:5])}{R}")
    for n in getattr(fp, "notes", [])[:4]:
        print(f"  {Y}⚠ {n}{R}")


def print_service_enum(enum_result, no_color: bool = False):
    """Print protocol-level exploitability attributes (SMBv1, RDP NLA, SSH crypto, …)."""
    if not enum_result or not getattr(enum_result, "attributes", None):
        return
    R  = C.RESET  if not no_color else ""
    Bo = C.BOLD   if not no_color else ""
    D  = C.DIM    if not no_color else ""
    Cy = C.CYAN   if not no_color else ""
    print(f"\n{'─'*70}")
    print(f"  SERVICE EXPLOITABILITY ATTRIBUTES  ({len(enum_result.attributes)} detected)")
    print(f"{'─'*70}")
    for a in sorted(enum_result.attributes,
                    key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}.get(x.severity, 5)):
        sev = a.severity.upper()
        color = SEV_COLOR.get(sev, C.DIM) if not no_color else ""
        print(f"\n  {color}{Bo}{sev:<8}{R}  port {a.port}/{a.service}  {Bo}{a.attribute}={a.value}{R}")
        print(f"  {D}{a.detail[:140]}{'…' if len(a.detail)>140 else ''}{R}")
        if a.exploit_precondition_for:
            print(f"  {Cy}→ precondition for: {', '.join(a.exploit_precondition_for[:4])}{R}")


def print_detected_vulnerabilities(fusion: dict, no_color: bool = False):
    """Render the unified Detected Vulnerabilities panel from fusion output."""
    if not fusion:
        return
    vulns = fusion.get("detected_vulnerabilities")
    if not vulns:
        return
    R  = C.RESET  if not no_color else ""
    Bo = C.BOLD   if not no_color else ""
    Cy = C.CYAN   if not no_color else ""
    D  = C.DIM    if not no_color else ""
    Rd = C.RED    if not no_color else ""
    Or = C.ORANGE if not no_color else ""
    G  = C.GREEN  if not no_color else ""

    print(f"\n{Bo}{Cy}{'═'*70}{R}")
    print(f"{Bo}{Cy}  DETECTED VULNERABILITIES  "
          f"({fusion['summary']['confirmed']} confirmed, "
          f"{fusion['summary']['potential']} potential, "
          f"{fusion['summary']['ai_discovered']} ai-discovered, "
          f"{fusion['summary']['discarded']} discarded){R}")
    print(f"{Bo}{Cy}{'═'*70}{R}\n")

    impact_color = {"critical": Rd, "high": Or, "medium": C.YELLOW, "low": G}
    for v in vulns:
        c = impact_color.get(v["impact"], D)
        decision_badge = f"{G}[CONFIRMED]{R}" if v["decision"] == "confirmed" else f"{C.YELLOW}[POTENTIAL]{R}"
        print(f"  {c}{Bo}{v['impact'].upper():<10}{R}  {v['subject']:<48}  {decision_badge}")
        port_str = f"port {v['port']}" if v.get("port") else ""
        ai_str = f"AI: {v['ai']['verdict']} ({v['ai']['reason'][:60]})" if v.get("ai") else "gate: deterministic"
        print(f"  {D}  {port_str:<20}  {ai_str}{R}")
        print()


def print_ai_analysis(analysis, no_color: bool = False):
    """Render the LLM analyst's Markdown report to the terminal."""
    if not analysis:
        return
    R  = C.RESET  if not no_color else ""
    Bo = C.BOLD   if not no_color else ""
    Cy = C.CYAN   if not no_color else ""
    D  = C.DIM    if not no_color else ""
    Y  = C.YELLOW if not no_color else ""

    print(f"\n{Bo}{Cy}{'═'*70}{R}")
    print(f"{Bo}{Cy}  AI ANALYSIS{R}")
    if getattr(analysis, "model", ""):
        print(f"{D}  {analysis.provider} · {analysis.model}"
              f"{f' · {analysis.tokens} tokens' if getattr(analysis,'tokens',None) else ''}{R}")
    print(f"{Bo}{Cy}{'═'*70}{R}\n")

    if getattr(analysis, "error", None):
        print(f"  {Y}⚠ AI analysis unavailable: {analysis.error}{R}\n")
        return

    # Light Markdown styling for the terminal: bold headers, dim code fences.
    for line in (analysis.markdown or "").splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            print(f"  {Bo}{Cy}{stripped.lstrip('# ').strip()}{R}")
        elif stripped.startswith(("- ", "* ")):
            print(f"    {stripped}")
        elif stripped.startswith("```"):
            print(f"  {D}{stripped}{R}")
        else:
            print(f"  {line}")
    print()


def _risk_color(score: float) -> str:
    if score >= 9.0:
        return f"{C.BOLD}{C.RED}{score:.1f}/10{C.RESET}"
    if score >= 7.0:
        return f"{C.BOLD}{C.ORANGE}{score:.1f}/10{C.RESET}"
    if score >= 4.0:
        return f"{C.BOLD}{C.YELLOW}{score:.1f}/10{C.RESET}"
    return f"{C.GREEN}{score:.1f}/10{C.RESET}"


def _confidence_badge(conf: str) -> str:
    if conf == "HIGH":
        return f"{C.GREEN}[✓ version confirmed]{C.RESET}"
    if conf == "MEDIUM":
        return f"{C.YELLOW}[~ product detected, version unknown]{C.RESET}"
    if conf == "POTENTIAL":
        return f"{C.ORANGE}[⚠ POTENTIAL — patch level not verifiable from banner]{C.RESET}"
    return f"{C.DIM}[? port-based guess]{C.RESET}"


# ─── JSON Report ─────────────────────────────────────────────────────────────────

def generate_json_report(host_result, vuln_matches, osint_result=None) -> dict:
    """Produce a structured JSON report suitable for SIEM ingestion."""
    report = {
        "meta": {
            "tool": "NetLogic",
            "version": "2.0.0",
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
            "detection_confidence": vm.detection_confidence,
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
                    "epss":             getattr(c, 'epss', 0.0),
                    "epss_percentile":  getattr(c, 'epss_percentile', 0.0),
                    "references":       c.references,
                    "has_metasploit":   getattr(c, 'has_metasploit', False),
                    "has_public_exploit": getattr(c, 'has_public_exploit', False),
                    "exploit_refs":     getattr(c, 'exploit_refs', []),
                    "kev":              getattr(c, 'kev', False),
                    "cwe":              getattr(c, 'cwe', ""),
                }
                for c in vm.cves
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
    with open(path, "w", encoding="utf-8") as f:
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
            desc = (cve.description or "").strip()
            title = (desc[:120] + ("…" if len(desc) > 120 else "")) if desc else "Known issue"
            vuln_rows += f"""
            <tr>
              <td style="font-size:0.9em">{esc(title)}</td>
              <td><code>{esc(cve.id)}</code></td>
              <td><span style="color:{color};font-weight:700">{esc(sev)}</span></td>
              <td>{esc(cve.cvss_score)}</td>
              <td>{esc(vm.port)}/{esc(vm.service)}</td>
              <td>{esc(vm.product or "–")} {esc(vm.version or "")}</td>
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
<title>NetLogic Report — {esc(h.target)}</title>
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
<h1>NetLogic Security Report</h1>
<div class="meta">
  Target: <strong>{esc(h.target)}</strong> · IP: {esc(h.ip)} · OS Estimate: {esc(h.os_guess or "Unknown")} · Scanned: {esc(h.timestamp)} · Duration: {h.scan_duration_s}s
</div>

<div class="stat-grid">
  <div class="stat"><div class="num">{len(h.ports)}</div><div class="label">Open Ports</div></div>
  <div class="stat"><div class="num" style="color:#ff4444">{critical}</div><div class="label">Critical vulns</div></div>
  <div class="stat"><div class="num" style="color:#ff8c00">{high}</div><div class="label">High vulns</div></div>
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
    <thead><tr><th>Vulnerability</th><th>Related CVE</th><th>Severity</th><th>CVSS</th><th>Port/Service</th><th>Product</th><th>Exploit</th></tr></thead>
    <tbody>{vuln_rows or "<tr><td colspan='7' style='color:#44ff88'>No known vulnerabilities identified.</td></tr>"}</tbody>
  </table>
</section>

{osint_section}

<footer>Generated by NetLogic v2.0.0 — For authorized security assessments only.</footer>
</body>
</html>"""


def save_html_report(html_content: str, path: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[+] HTML report saved → {path}")
