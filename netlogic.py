#!/usr/bin/env python3
"""NetLogic v2.0 — Attack Surface Mapper & Vulnerability Correlator"""

import argparse
import sys
import os
import time
import concurrent.futures

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from src.scanner        import scan_host, scan_cidr, COMMON_PORTS, EXTENDED_PORTS
from src.cve_correlator import correlate
from src.osint          import run_osint
from src.reporter       import (
    print_terminal_report, generate_json_report,
    generate_html_report, save_json_report, save_html_report, C,
)

VERSION = "2.0.0"
BANNER = f"""
{C.CYAN}{C.BOLD}
  ███╗   ██╗███████╗████████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗  ██╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ██║
  ██╔██╗ ██║█████╗     ██║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗██║
  ██║╚██╗██║██╔══╝     ██║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚████║
  ██║ ╚████║███████╗   ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚███║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚══╝
{C.RESET}  {C.DIM}Attack Surface Mapper & Vulnerability Correlator  v{VERSION}{C.RESET}
  {C.DIM}For authorized security assessments only.{C.RESET}
"""


def parse_args():
    p = argparse.ArgumentParser(description="NetLogic — network recon and vulnerability correlation")
    p.add_argument("target", help="Host, IP, or CIDR range to scan")
    p.add_argument("--ports",     default="quick",
                   help="quick|full|custom=21,22,80,443  (default: quick)")
    p.add_argument("--tls",       action="store_true", help="Deep SSL/TLS analysis")
    p.add_argument("--headers",   action="store_true", help="HTTP security header audit")
    p.add_argument("--takeover",  action="store_true", help="Subdomain takeover detection")
    p.add_argument("--osint",     action="store_true", help="Run passive OSINT recon")
    p.add_argument("--stack",     action="store_true", help="Technology stack + WAF fingerprinting")
    p.add_argument("--dns",       action="store_true", help="DNS/email security (SPF, DKIM, DMARC, DNSSEC)")
    p.add_argument("--full",      action="store_true", help="Run ALL checks")
    p.add_argument("--report",    default="terminal",
                   choices=["terminal", "json", "html", "all"])
    p.add_argument("--out",       default=".", help="Output directory")
    p.add_argument("--cidr",      action="store_true", help="Scan CIDR block")
    p.add_argument("--timeout",   type=float, default=2.0)
    p.add_argument("--threads",   type=int,   default=100)
    p.add_argument("--json-stream", action="store_true",
                   help="Newline-delimited JSON stream (Electron GUI mode)")
    p.add_argument("--no-color",  action="store_true")
    p.add_argument("--min-cvss",  type=float, default=4.0,
                   help="Minimum CVSS score to report (default: 4.0)")
    p.add_argument("--nvd-key",   default="",
                   help="NVD API key for higher rate limits (or set NETLOGIC_NVD_KEY env var)")
    p.add_argument("--clear-cache", action="store_true", help="Clear NVD cache and exit")
    p.add_argument("--cache-stats", action="store_true", help="Show NVD cache stats and exit")
    p.add_argument("--preload-cache", action="store_true", help="Pre-populate NVD cache for common products")
    p.add_argument("--version",   action="version", version=f"NetLogic {VERSION}")
    return p.parse_args()


def resolve_ports(ports_arg):
    if ports_arg == "quick":  return COMMON_PORTS
    if ports_arg == "full":   return EXTENDED_PORTS
    if ports_arg.startswith("custom="):
        return [int(p) for p in ports_arg[7:].split(",") if p.strip().isdigit()]
    try:
        return [int(p) for p in ports_arg.split(",") if p.strip().isdigit()]
    except Exception:
        print(f"[!] Invalid --ports: {ports_arg}", file=sys.stderr)
        sys.exit(1)


# ─── TLS Report Printer ───────────────────────────────────────────────────────

def print_tls_results(tls_results, no_color=False):
    if not tls_results:
        return
    print(f"\n{'─'*70}")
    print(f"  SSL/TLS ANALYSIS")
    print(f"{'─'*70}")
    for r in tls_results:
        grade_color = {
            "A": C.GREEN, "B": C.GREEN, "C": C.YELLOW,
            "D": C.ORANGE, "F": C.RED
        }.get(r.grade, C.DIM) if not no_color else ""
        reset = C.RESET if not no_color else ""
        print(f"\n  Port {r.port} — Grade: {grade_color}{C.BOLD}{r.grade}{reset}")
        if r.protocols_supported:
            print(f"  Protocols : {', '.join(r.protocols_supported)}")
        if r.protocols_deprecated:
            dep_str = ', '.join(r.protocols_deprecated)
            print(f"  Deprecated: {C.YELLOW if not no_color else ''}{dep_str}{reset}")
        if r.cipher_suite:
            print(f"  Cipher    : {r.cipher_suite}")
        if r.cert:
            c = r.cert
            print(f"  Cert CN   : {c.subject_cn}  (issuer: {c.issuer_cn})")
            days = c.days_until_expiry
            exp_color = C.RED if (days and days < 0) else C.YELLOW if (days and days < 30) else C.GREEN
            exp_color = exp_color if not no_color else ""
            print(f"  Expiry    : {exp_color}{c.not_after}  ({days} days){reset}")
            if c.san_domains:
                print(f"  SANs      : {', '.join(c.san_domains[:5])}{'…' if len(c.san_domains)>5 else ''}")
        for f in sorted(r.findings, key=lambda x: x.cvss, reverse=True):
            sev_color = {
                "CRITICAL": C.RED, "HIGH": C.ORANGE,
                "MEDIUM": C.YELLOW, "LOW": C.GREEN, "INFO": C.DIM
            }.get(f.severity, C.DIM) if not no_color else ""
            print(f"\n    {sev_color}{C.BOLD if not no_color else ''}{f.severity:<10}{reset}  {f.title}")
            print(f"    {C.DIM if not no_color else ''}{f.detail[:120]}{'…' if len(f.detail)>120 else ''}{reset}")
            if f.cve:
                print(f"    CVE: {f.cve}")


# ─── Header Audit Printer ─────────────────────────────────────────────────────

def print_header_results(audit, no_color=False):
    if not audit:
        return
    reset = C.RESET if not no_color else ""
    grade_color = {
        "A": C.GREEN, "B": C.GREEN, "C": C.YELLOW, "D": C.ORANGE, "F": C.RED
    }.get(audit.grade, C.DIM) if not no_color else ""

    print(f"\n{'─'*70}")
    print(f"  HTTP SECURITY HEADERS  —  Score: {audit.score}/100  Grade: {grade_color}{C.BOLD if not no_color else ''}{audit.grade}{reset}")
    print(f"{'─'*70}")
    if audit.server_banner:
        print(f"  Server   : {audit.server_banner}")
    if audit.powered_by:
        print(f"  Powered-By: {audit.powered_by}")
    print(f"  Present  : {', '.join(audit.headers_present) or 'none'}")
    print(f"  Missing  : {(C.YELLOW if not no_color else '')}{', '.join(audit.headers_missing) or 'none'}{reset}")

    for f in sorted(audit.findings, key=lambda x: x.cvss, reverse=True):
        if f.severity == "INFO":
            continue
        sev_color = {
            "CRITICAL": C.RED, "HIGH": C.ORANGE,
            "MEDIUM": C.YELLOW, "LOW": C.GREEN
        }.get(f.severity, C.DIM) if not no_color else ""
        print(f"\n  {sev_color}{C.BOLD if not no_color else ''}{f.severity:<10}{reset}  {f.title}")
        print(f"  {C.DIM if not no_color else ''}{f.detail[:120]}{'…' if len(f.detail)>120 else ''}{reset}")
        print(f"  {C.CYAN if not no_color else ''}Fix: {f.recommendation[:100]}{reset}")


# ─── Takeover Printer ─────────────────────────────────────────────────────────

def print_takeover_results(result, no_color=False):
    if not result:
        return
    reset = C.RESET if not no_color else ""
    print(f"\n{'─'*70}")
    print(f"  SUBDOMAIN TAKEOVER  —  {result.subdomains_checked} checked, "
          f"{len(result.vulnerable)} vulnerable, {len(result.potential)} potential")
    print(f"{'─'*70}")

    for f in result.vulnerable:
        print(f"\n  {C.RED if not no_color else ''}{C.BOLD if not no_color else ''}VULNERABLE{reset}  {f.subdomain}")
        print(f"  Provider : {f.provider}")
        print(f"  CNAME    : {' → '.join(f.cname_chain)}")
        print(f"  {C.DIM if not no_color else ''}{f.detail}{reset}")

    for f in result.potential:
        print(f"\n  {C.YELLOW if not no_color else ''}POTENTIAL{reset}   {f.subdomain}")
        print(f"  Provider : {f.provider}")
        print(f"  CNAME    : {' → '.join(f.cname_chain)}")

    if not result.vulnerable and not result.potential:
        print(f"  {C.GREEN if not no_color else ''}No takeover vulnerabilities detected.{reset}")


# ─── Stack Fingerprint Printer ────────────────────────────────────────────────

def print_stack_results(stack, no_color=False):
    if not stack or not (stack.technologies or stack.waf.detected):
        return
    R = C.RESET if not no_color else ""
    D = C.DIM   if not no_color else ""
    W = C.WHITE if not no_color else ""
    Y = C.YELLOW if not no_color else ""
    G = C.GREEN  if not no_color else ""
    Rd = C.RED   if not no_color else ""
    Cy = C.CYAN  if not no_color else ""
    Bo = C.BOLD  if not no_color else ""

    print(f"\n{'─'*70}")
    print(f"  TECHNOLOGY STACK FINGERPRINT")
    print(f"{'─'*70}")

    if stack.cloud_provider:
        print(f"  Cloud    : {Cy}{stack.cloud_provider}{R}")
    if stack.cdn:
        print(f"  CDN      : {Cy}{stack.cdn}{R}")

    # WAF
    if stack.waf.detected:
        conf_color = Rd if stack.waf.confidence == "HIGH" else Y
        print(f"\n  {Bo}{Y}⛨  WAF DETECTED: {stack.waf.name}  [{stack.waf.confidence} confidence]{R}")
        print(f"  {D}Evidence : {stack.waf.evidence}{R}")
        if stack.waf.bypass_notes:
            print(f"  {D}Bypass   : {stack.waf.bypass_notes}{R}")
    else:
        print(f"\n  {G}⛨  No WAF detected — direct server access{R}")

    # Technologies grouped by category
    if stack.technologies:
        print()
        by_cat = {}
        for t in stack.technologies:
            by_cat.setdefault(t.category, []).append(t)

        cat_order = ["CMS", "Framework", "Language", "Server", "Cloud", "CDN",
                     "Cache", "Proxy", "Analytics", "Payment", "Hosting", "Finding"]
        for cat in cat_order:
            techs = by_cat.get(cat, [])
            if not techs:
                continue
            for t in techs:
                ver_str = f" {t.version}" if t.version else ""
                conf_d = f"{D}[{t.confidence}]{R}" if t.confidence != "HIGH" else ""
                flag = f"  {Rd}⚠ {t.notes}{R}" if t.notes else ""
                cve_str = f"  {Y}→ CVEs: {', '.join(t.cves[:3])}{R}" if t.cves else ""
                print(f"  {Bo}{cat:<12}{R}  {W}{t.name}{ver_str}{R} {conf_d}{flag}{cve_str}")
                if t.evidence:
                    print(f"  {' '*12}  {D}via: {t.evidence[:80]}{R}")


# ─── DNS Security Printer ─────────────────────────────────────────────────────

def print_dns_results(dns, no_color=False):
    if not dns:
        return
    R  = C.RESET  if not no_color else ""
    D  = C.DIM    if not no_color else ""
    Bo = C.BOLD   if not no_color else ""
    G  = C.GREEN  if not no_color else ""
    Y  = C.YELLOW if not no_color else ""
    Rd = C.RED    if not no_color else ""
    Or = C.ORANGE if not no_color else ""
    Cy = C.CYAN   if not no_color else ""

    spoof_color = Rd if dns.spoofability_score >= 7 else Or if dns.spoofability_score >= 4 else G
    print(f"\n{'─'*70}")
    print(f"  DNS & EMAIL SECURITY  —  Spoofability: {spoof_color}{Bo}{dns.spoofability_score}/10{R}  "
          f"{'(SPOOFABLE)' if dns.email_spoofable else '(Protected)'}")
    print(f"{'─'*70}")

    # SPF
    spf = dns.spf
    spf_ok = spf.present and spf.valid
    spf_icon = f"{G}✓{R}" if spf_ok else f"{Rd}✗{R}"
    print(f"\n  SPF    {spf_icon}  ", end="")
    if not spf.present:
        print(f"{Rd}MISSING — anyone can spoof this domain{R}")
    else:
        print(f"{spf.record[:70]}")
        print(f"  {'':9}all={spf.all_mechanism or 'none'}  lookups≈{spf.mechanism_count}")
        for issue in spf.issues:
            print(f"  {'':9}{Y}⚠ {issue}{R}")

    # DKIM
    dkim = dns.dkim
    dkim_ok = bool(dkim.found_selectors)
    dkim_icon = f"{G}✓{R}" if dkim_ok else f"{Rd}✗{R}"
    print(f"\n  DKIM   {dkim_icon}  ", end="")
    if dkim.found_selectors:
        print(f"Selectors found: {Cy}{', '.join(dkim.found_selectors)}{R}")
    else:
        print(f"{Rd}No selectors found (checked {len(dkim.checked_selectors)} common names){R}")
    for issue in dkim.issues:
        print(f"  {'':9}{Y}⚠ {issue}{R}")

    # DMARC
    dmarc = dns.dmarc
    policy_color = G if dmarc.policy == "reject" else Y if dmarc.policy == "quarantine" else Rd
    dmarc_ok = dmarc.present and dmarc.policy in ("quarantine", "reject")
    dmarc_icon = f"{G}✓{R}" if dmarc_ok else f"{Rd}✗{R}"
    print(f"\n  DMARC  {dmarc_icon}  ", end="")
    if not dmarc.present:
        print(f"{Rd}MISSING — no policy enforcement{R}")
    else:
        print(f"p={policy_color}{Bo}{dmarc.policy}{R}  pct={dmarc.pct}%  "
              f"sp={dmarc.subdomain_policy or 'inherit'}")
        if dmarc.rua:
            print(f"  {'':9}reports → {', '.join(dmarc.rua[:2])}")
        for issue in dmarc.issues:
            print(f"  {'':9}{Y}⚠ {issue}{R}")

    # DNSSEC
    dnssec_icon = f"{G}✓{R}" if dns.dnssec.enabled else f"{D}–{R}"
    print(f"\n  DNSSEC {dnssec_icon}  {'Enabled' if dns.dnssec.enabled else f'{D}Not configured{R}'}")

    # CAA
    caa_icon = f"{G}✓{R}" if dns.caa.present else f"{D}–{R}"
    print(f"  CAA    {caa_icon}  ", end="")
    if dns.caa.present:
        print(f"{', '.join(dns.caa.records[:3])}")
    else:
        print(f"{D}Not configured{R}")

    # MX
    if dns.mx_records:
        print(f"\n  MX Records:")
        for mx in dns.mx_records:
            provider_str = f"  [{mx.provider}]" if mx.provider else ""
            print(f"  {'':9}{mx.priority:>4}  {Cy}{mx.host}{R}{D}{provider_str}{R}")

    # Zone transfer
    if dns.zone_transfer_vulnerable:
        print(f"\n  {Bo}{Rd}⚠ ZONE TRANSFER VULNERABLE — full DNS records exposed!{R}")
        for rec in dns.zone_transfer_data[:5]:
            print(f"  {D}  {rec}{R}")

    # Wildcard
    if dns.wildcard_dns:
        print(f"\n  {Y}⚠ Wildcard DNS active (*.{dns.domain} resolves){R}")

    # Findings summary
    if dns.findings:
        print(f"\n  Findings:")
        for f in dns.findings:
            sev_color = Rd if f['severity']=="CRITICAL" else Or if f['severity']=="HIGH" else Y
            print(f"  {sev_color}{Bo}{f['severity']:<10}{R}  {f['title']}")
            print(f"  {'':12}{D}{f['detail'][:110]}{'…' if len(f['detail'])>110 else ''}{R}")
            if f.get('recommendation'):
                print(f"  {'':12}{Cy}Fix: {f['recommendation'][:90]}{R}")

# ─── Main Single-Host Runner ──────────────────────────────────────────────────

def run_single(target, args):
    do_tls      = args.tls      or args.full
    do_headers  = args.headers  or args.full
    do_takeover = args.takeover or args.full
    do_osint    = args.osint    or args.full
    no_color    = args.no_color

    ports = resolve_ports(args.ports)
    print(f"[*] Scanning {target} ({len(ports)} ports)…")
    host_result = scan_host(target, ports=ports, max_workers=args.threads, timeout=args.timeout)

    from src.nvd_lookup import cache_stats
    stats = cache_stats()
    cache_note = f"(cache: {stats['entries']} entries)" if stats['entries'] > 0 else "(live NVD queries — first run may be slow)"
    print(f"[*] Correlating CVEs via NVD API {cache_note}…")
    vuln_matches = correlate(host_result.ports, min_cvss=getattr(args, "min_cvss", 4.0), verbose=True)

    # ── TLS Analysis ──
    tls_results = []
    if do_tls:
        from src.tls_analyzer import analyze_tls_ports
        tls_ports = [p.port for p in host_result.ports if p.tls or p.port in (443,8443,993,995,465)]
        if not tls_ports:
            tls_ports = [443]
        print(f"[*] Running TLS analysis on ports {tls_ports}…")
        tls_results = analyze_tls_ports(target, tls_ports)

    # ── Header Audit ──
    header_audit = None
    if do_headers:
        from src.header_audit import audit_headers
        http_port = next((p.port for p in host_result.ports if p.service in ("http","https","http-alt","https-alt")), 443)
        print(f"[*] Auditing HTTP security headers (port {http_port})…")
        header_audit = audit_headers(target, http_port)

    # ── Takeover Detection ──
    takeover_result = None
    if do_takeover:
        from src.takeover import discover_and_check
        print(f"[*] Checking subdomains for takeover (CT log discovery)…")
        takeover_result = discover_and_check(target)

    # ── Stack Fingerprint ──
    stack_result = None
    do_stack = args.full or getattr(args, 'stack', False) or do_headers
    if do_stack or do_headers:
        from src.stack_fingerprint import fingerprint_stack
        http_port2 = next((p.port for p in host_result.ports
                          if p.service in ("http","https","http-alt","https-alt")), 443)
        print(f"[*] Fingerprinting technology stack…")
        stack_result = fingerprint_stack(target, http_port2)

    # ── DNS Security ──
    dns_result = None
    do_dns = args.full or getattr(args, 'dns', False)
    if do_dns:
        from src.dns_security import check_dns_security
        print(f"[*] Checking DNS/email security (SPF, DKIM, DMARC, DNSSEC)…")
        dns_result = check_dns_security(target)

    # ── OSINT ──
    osint_result = None
    if do_osint:
        print(f"[*] Running passive OSINT…")
        osint_result = run_osint(target, ip=host_result.ip)

    # ── Output ──
    if args.report in ("terminal", "all"):
        print_terminal_report(host_result, vuln_matches, osint_result)
        print_tls_results(tls_results, no_color)
        print_header_results(header_audit, no_color)
        print_stack_results(stack_result, no_color)
        print_dns_results(dns_result, no_color)
        print_takeover_results(takeover_result, no_color)

    safe_name = target.replace("/","_").replace(":","_")
    ts = time.strftime("%Y%m%d_%H%M%S")

    if args.report in ("json", "all"):
        os.makedirs(args.out, exist_ok=True)
        report = generate_json_report(host_result, vuln_matches, osint_result)
        # Embed new results in JSON
        if tls_results:
            from dataclasses import asdict
            report["tls"] = [asdict(r) for r in tls_results]
        if header_audit:
            from dataclasses import asdict
            report["headers"] = asdict(header_audit)
        if takeover_result:
            from dataclasses import asdict
            report["takeover"] = asdict(takeover_result)
        save_json_report(report, os.path.join(args.out, f"netlogic_{safe_name}_{ts}.json"))

    if args.report in ("html", "all"):
        os.makedirs(args.out, exist_ok=True)
        html_content = generate_html_report(host_result, vuln_matches, osint_result)
        save_html_report(html_content, os.path.join(args.out, f"netlogic_{safe_name}_{ts}.html"))


def run_cidr(cidr, args):
    ports = resolve_ports(args.ports)
    print(f"[*] CIDR scan: {cidr}…")
    results = scan_cidr(cidr, ports=ports, max_workers=args.threads, timeout=args.timeout)
    print(f"[+] {len(results)} live host(s) found.\n")
    for hr in results:
        vm = correlate(hr.ports)
        if args.report in ("terminal","all"):
            print_terminal_report(hr, vm)
        if args.report in ("json","all"):
            os.makedirs(args.out, exist_ok=True)
            ts = time.strftime("%Y%m%d_%H%M%S")
            save_json_report(generate_json_report(hr, vm),
                             os.path.join(args.out, f"netlogic_{hr.ip}_{ts}.json"))


def main():
    args = parse_args()

    if hasattr(args, 'json_stream') and args.json_stream:
        from src.json_bridge import run_streaming_scan, emit
        ports = resolve_ports(args.ports)
        try:
            run_streaming_scan(
                target=args.target, ports=ports, timeout=args.timeout,
                threads=args.threads, do_osint=(args.osint or args.full),
                cidr=args.cidr,
            )
        except Exception as e:
            emit("error", message=str(e))
        return

    if not args.no_color:
        print(BANNER)
    else:
        print(f"NetLogic v{VERSION}\n")
    print(f"  For authorized use only.\n")

    if args.cidr:
        run_cidr(args.target, args)
    else:
        run_single(args.target, args)

if __name__ == "__main__":
    main()