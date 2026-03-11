#!/usr/bin/env python3
"""NetRecon v2.0 — Attack Surface Mapper & Vulnerability Correlator"""

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
    p = argparse.ArgumentParser(description="NetRecon — network recon and vulnerability correlation")
    p.add_argument("target", help="Host, IP, or CIDR range to scan")
    p.add_argument("--ports",     default="quick",
                   help="quick|full|custom=21,22,80,443  (default: quick)")
    p.add_argument("--tls",       action="store_true", help="Deep SSL/TLS analysis")
    p.add_argument("--headers",   action="store_true", help="HTTP security header audit")
    p.add_argument("--takeover",  action="store_true", help="Subdomain takeover detection")
    p.add_argument("--osint",     action="store_true", help="Run passive OSINT recon")
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
    p.add_argument("--version",   action="version", version=f"NetRecon {VERSION}")
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

    print(f"[*] Correlating CVEs ({len(host_result.ports)} open ports)…")
    vuln_matches = correlate(host_result.ports)

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
        save_json_report(report, os.path.join(args.out, f"netrecon_{safe_name}_{ts}.json"))

    if args.report in ("html", "all"):
        os.makedirs(args.out, exist_ok=True)
        html_content = generate_html_report(host_result, vuln_matches, osint_result)
        save_html_report(html_content, os.path.join(args.out, f"netrecon_{safe_name}_{ts}.html"))


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
                             os.path.join(args.out, f"netrecon_{hr.ip}_{ts}.json"))


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
        print(f"NetRecon v{VERSION}\n")
    print(f"  For authorized use only.\n")

    if args.cidr:
        run_cidr(args.target, args)
    else:
        run_single(args.target, args)


if __name__ == "__main__":
    main()
