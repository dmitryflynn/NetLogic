#!/usr/bin/env python3
"""
NetRecon — Attack Surface Mapper & Vulnerability Correlator
─────────────────────────────────────────────────────────────
Usage:
  python netrecon.py <target> [options]

Examples:
  python netrecon.py scanme.nmap.org
  python netrecon.py 192.168.1.1 --ports full
  python netrecon.py example.com --osint --report html
  python netrecon.py 192.168.1.0/24 --cidr --out results/

Targets:
  domain, IPv4, or CIDR range (with --cidr)

Options:
  --ports   quick|full|custom=21,22,80,443   Port set to scan (default: quick)
  --osint                                    Run passive recon (DNS, CT logs, ASN)
  --report  terminal|json|html|all           Output format (default: terminal)
  --out     <directory>                      Save output files here
  --cidr                                     Treat target as CIDR block
  --timeout <seconds>                        Per-port timeout (default: 2)
  --threads <n>                              Max threads (default: 100)
  --no-color                                 Disable ANSI colors
  --version                                  Print version and exit
"""

import argparse
import sys
import os
import time

sys.path.insert(0, os.path.dirname(__file__))
from src.scanner       import scan_host, scan_cidr, COMMON_PORTS, EXTENDED_PORTS
from src.cve_correlator import correlate
from src.osint          import run_osint
from src.reporter       import (
    print_terminal_report,
    generate_json_report,
    generate_html_report,
    save_json_report,
    save_html_report,
    C,
)

VERSION = "1.0.0"
BANNER  = f"""
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
    p = argparse.ArgumentParser(
        description="NetRecon — network recon and vulnerability correlation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("target", help="Host, IP, or CIDR range to scan")
    p.add_argument("--ports",   default="quick",
                   help="quick|full|custom=21,22,80,443  (default: quick)")
    p.add_argument("--osint",   action="store_true", help="Run passive OSINT recon")
    p.add_argument("--report",  default="terminal",
                   choices=["terminal", "json", "html", "all"],
                   help="Output format (default: terminal)")
    p.add_argument("--out",     default=".", help="Output directory for saved reports")
    p.add_argument("--cidr",    action="store_true", help="Scan CIDR block")
    p.add_argument("--timeout", type=float, default=2.0,
                   help="Per-port TCP timeout in seconds (default: 2)")
    p.add_argument("--threads", type=int, default=100,
                   help="Maximum concurrent threads (default: 100)")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    p.add_argument("--version", action="version", version=f"NetRecon {VERSION}")
    return p.parse_args()


def resolve_ports(ports_arg: str) -> list[int]:
    if ports_arg == "quick":
        return COMMON_PORTS
    if ports_arg == "full":
        return EXTENDED_PORTS
    if ports_arg.startswith("custom="):
        return [int(p) for p in ports_arg[7:].split(",") if p.strip().isdigit()]
    # Bare comma-separated fallback
    try:
        return [int(p) for p in ports_arg.split(",") if p.strip().isdigit()]
    except Exception:
        print(f"[!] Invalid --ports argument: {ports_arg}", file=sys.stderr)
        sys.exit(1)


def run_single(target: str, args) -> None:
    ports = resolve_ports(args.ports)

    print(f"[*] Scanning {target} ({len(ports)} ports, timeout={args.timeout}s)…")
    host_result = scan_host(
        target,
        ports=ports,
        max_workers=args.threads,
        timeout=args.timeout,
    )

    print(f"[*] Correlating CVEs for {len(host_result.ports)} open port(s)…")
    vuln_matches = correlate(host_result.ports)

    osint_result = None
    if args.osint:
        print(f"[*] Running passive OSINT recon…")
        osint_result = run_osint(target, ip=host_result.ip)

    # Output
    safe_name = target.replace("/", "_").replace(":", "_")
    ts = time.strftime("%Y%m%d_%H%M%S")

    if args.report in ("terminal", "all"):
        print_terminal_report(host_result, vuln_matches, osint_result)

    if args.report in ("json", "all"):
        os.makedirs(args.out, exist_ok=True)
        report = generate_json_report(host_result, vuln_matches, osint_result)
        save_json_report(report, os.path.join(args.out, f"netrecon_{safe_name}_{ts}.json"))

    if args.report in ("html", "all"):
        os.makedirs(args.out, exist_ok=True)
        html_content = generate_html_report(host_result, vuln_matches, osint_result)
        save_html_report(html_content, os.path.join(args.out, f"netrecon_{safe_name}_{ts}.html"))


def run_cidr(cidr: str, args) -> None:
    ports = resolve_ports(args.ports)
    print(f"[*] CIDR scan: {cidr} ({len(ports)} ports per host)…")
    results = scan_cidr(cidr, ports=ports, max_workers=args.threads, timeout=args.timeout)
    print(f"[+] {len(results)} live host(s) found.\n")

    for host_result in results:
        vuln_matches = correlate(host_result.ports)
        if args.report in ("terminal", "all"):
            print_terminal_report(host_result, vuln_matches)

        if args.report in ("json", "all"):
            os.makedirs(args.out, exist_ok=True)
            report = generate_json_report(host_result, vuln_matches)
            ts = time.strftime("%Y%m%d_%H%M%S")
            save_json_report(report, os.path.join(
                args.out, f"netrecon_{host_result.ip}_{ts}.json"))


def main():
    args = parse_args()

    if not args.no_color:
        print(BANNER)
    else:
        print(f"NetRecon v{VERSION}\n")

    print(f"{C.DIM}[!] Ensure you have explicit permission to scan this target.{C.RESET}\n")

    if args.cidr:
        run_cidr(args.target, args)
    else:
        run_single(args.target, args)


if __name__ == "__main__":
    main()
