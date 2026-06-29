#!/usr/bin/env python3
"""NetLogic v2.0 — Attack Surface Mapper & Vulnerability Correlator"""

import argparse
import io
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

# Ensure UTF-8 output on Windows consoles to prevent UnicodeEncodeError for emojis/symbols.
# Prefer reconfigure(): it changes only the encoding and PRESERVES the stream's line
# buffering. Replacing stdout with a brand-new TextIOWrapper makes it block-buffered, so
# the GUI banner/URL printed before the (blocking) uvicorn.run never flushes to the
# console. Fall back to a *line-buffered* wrapper on older Pythons that lack reconfigure.
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", line_buffering=True)
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", line_buffering=True)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from src.scanner        import scan_host, scan_cidr, COMMON_PORTS, EXTENDED_PORTS
from src.cve_correlator import correlate
from src.osint          import run_osint
from src.nvd_lookup     import clear_cache, preload_cache, cache_stats
from src.reporter       import (
    print_terminal_report, generate_json_report,
    generate_html_report, save_json_report, save_html_report, C,
    print_service_probe_results, print_vuln_probe_results,
)

VERSION = "3.0.0"
BANNER = f"""
{C.CYAN}{C.BOLD}
  ███╗   ██╗███████╗████████╗██╗      ██████╗  ██████╗ ██╗ ██████╗
  ████╗  ██║██╔════╝╚══██╔══╝██║     ██╔═══██╗██╔════╝ ██║██╔════╝
  ██╔██╗ ██║█████╗     ██║   ██║     ██║   ██║██║  ███╗██║██║
  ██║╚██╗██║██╔══╝     ██║   ██║     ██║   ██║██║   ██║██║██║
  ██║ ╚████║███████╗   ██║   ███████╗╚██████╔╝╚██████╔╝██║╚██████╗
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝ ╚═════╝
{C.RESET}  {C.DIM}Attack Surface Mapper & Vulnerability Correlator  v{VERSION}{C.RESET}
  {C.DIM}For authorized security assessments only.{C.RESET}
"""


def parse_args():
    p = argparse.ArgumentParser(description="NetLogic — network recon and vulnerability correlation")
    p.add_argument("target", nargs="?", default=None, help="Host, IP, or CIDR range to scan")
    p.add_argument("--ports",     default="quick",
                   help="quick|full|custom=21,22,80,443  (default: quick)")
    p.add_argument("--tls",       action="store_true", help="Deep SSL/TLS analysis")
    p.add_argument("--headers",   action="store_true", help="HTTP security header audit")
    p.add_argument("--takeover",  action="store_true", help="Subdomain takeover detection")
    p.add_argument("--osint",     action="store_true", help="Run passive OSINT recon")
    p.add_argument("--stack",     action="store_true", help="Technology stack + WAF fingerprinting")
    p.add_argument("--dns",       action="store_true", help="DNS/email security (SPF, DKIM, DMARC, DNSSEC)")
    p.add_argument("--probe",     action="store_true",
                   help="Active service probing: unauthenticated access, default creds, CVE-specific checks")
    p.add_argument("--full",      action="store_true", help="Run ALL checks")
    p.add_argument("--reason",    action="store_true",
                   help="Enable the adaptive reasoning loop (observe→reason→act). Deterministic "
                        "by default; uses AI to augment when an API key is configured.")
    p.add_argument("--multi-host", action="store_true",
                   help="Enable multi-host world modeling: discover in-scope neighbors from "
                        "evidence and reason over each as its own host (requires --reason; "
                        "every probe stays scope-gated). Off by default.")
    p.add_argument("--since-last", action="store_true",
                   help="Change detection: diff this scan's observations against the prior "
                        "snapshot for the target and report what changed (new ports/CVEs/hosts, "
                        "version bumps). No-op on the first scan. Off by default.")
    # ── AI analysis ──
    p.add_argument("--ai",        action="store_true",
                   help="Run AI-powered analysis of findings (needs an API key)")
    p.add_argument("--ai-key",    default="",
                   help="AI API key (or set NETLOGIC_AI_API_KEY / OPENROUTER_API_KEY)")
    p.add_argument("--ai-provider", default="",
                   help="openrouter|openai|anthropic|kimi|qwen|groq|gemini|ollama|custom (default: openrouter)")
    p.add_argument("--ai-model",  default="", help="Model id (provider default if omitted)")
    p.add_argument("--ai-base-url", default="", help="Custom OpenAI-compatible base URL")
    # ── Authenticated scanning + topology + diffing (Tier 3) ──
    p.add_argument("--ssh-user",  default="", help="Username for authenticated (credentialed) SSH scanning — reads real installed package versions")
    p.add_argument("--ssh-key",   default="", help="SSH private key path for authenticated scanning")
    p.add_argument("--ssh-pass",  default="", help="SSH password (requires sshpass; prefer --ssh-key)")
    p.add_argument("--ssh-port",  type=int, default=22, help="SSH port for authenticated scanning (default: 22)")
    p.add_argument("--no-diff",   action="store_true", help="Disable change-diff against the previous saved report")
    p.add_argument("--no-traceroute", action="store_true", help="Skip traceroute in topology mapping")
    p.add_argument("--report",    default="terminal",
                   choices=["terminal", "json", "html", "all"])
    p.add_argument("--out",       default=".", help="Output directory")
    p.add_argument("--cidr",      action="store_true", help="Scan CIDR block")
    p.add_argument("--timeout",   type=float, default=2.0)
    p.add_argument("--threads",   type=int,   default=100)
    p.add_argument("--no-color",  action="store_true")
    p.add_argument("--min-cvss",  type=float, default=4.0,
                   help="Minimum CVSS score to report (default: 4.0)")
    p.add_argument("--deep-probe", action="store_true",
                   help="Use per-service agent architecture for deeper, "
                   "context-isolated probe execution")
    p.add_argument("--sensor-plan", default="",
                   help="Override sensor plan: 'show' to inspect AI plan, "
                   "or JSON (e.g. '{\"takeover\":{\"enabled\":false}}') to override")
    p.add_argument("--nvd-key",   default="",
                   help="NVD API key for higher rate limits (or set NETLOGIC_NVD_KEY env var)")
    p.add_argument("--clear-cache", action="store_true", help="Clear NVD cache and exit")
    p.add_argument("--cache-stats", action="store_true", help="Show NVD cache stats and exit")
    p.add_argument("--preload-cache", action="store_true", help="Pre-populate NVD cache for common products")
    p.add_argument("--vdb-sync", nargs="?", type=int, const=0, default=None, metavar="N",
                   help="Sync the local offline CVE database from NVD (optionally only the first N products), then exit")
    p.add_argument("--vdb-status", action="store_true",
                   help="Show local offline CVE database freshness/stats and exit")
    p.add_argument("--gui", "-gui", action="store_true",
                   help="Start the web dashboard (no other flags allowed)")
    # ── Fusion benchmark ──
    p.add_argument("--benchmark", action="store_true",
                   help="Run the fusion-pipeline benchmark against the labeled cassette corpus and exit")
    p.add_argument("--benchmark-export", default="",
                   help="Export the benchmark report to this file path (supports .md, .json)")
    p.add_argument("--benchmark-ai", action="store_true",
                   help="Use the configured AI model instead of the ground-truth oracle")
    p.add_argument("--benchmark-verbose", action="store_true",
                   help="Print per-subject decisions in benchmark output")
    p.add_argument("--version",   action="version", version=f"NetLogic {VERSION}")
    return p.parse_args()


def resolve_ports(ports_arg):
    if ports_arg == "quick":  return COMMON_PORTS
    if ports_arg == "full":   return EXTENDED_PORTS
    if ports_arg.startswith("custom="):
        port_list = [int(p) for p in ports_arg[7:].split(",") if p.strip().isdigit()]
        if not port_list:
            print(f"[!] No valid ports in --ports: {ports_arg}", file=sys.stderr)
            sys.exit(1)
        return port_list
    try:
        port_list = [int(p) for p in ports_arg.split(",") if p.strip().isdigit()]
        if not port_list:
            print(f"[!] No valid ports in --ports: {ports_arg}", file=sys.stderr)
            sys.exit(1)
        return port_list
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
        for finding in spf.findings:
            print(f"  {'':9}{Y}⚠ {finding.description}{R}")

    # DKIM
    dkim = dns.dkim
    dkim_ok = bool(dkim.found_selectors)
    dkim_icon = f"{G}✓{R}" if dkim_ok else f"{Rd}✗{R}"
    print(f"\n  DKIM   {dkim_icon}  ", end="")
    if dkim.found_selectors:
        print(f"Selectors found: {Cy}{', '.join(dkim.found_selectors)}{R}")
    else:
        print(f"{Rd}No selectors found (checked {len(dkim.checked_selectors)} common names){R}")
    for finding in dkim.findings:
        print(f"  {'':9}{Y}⚠ {finding.description}{R}")

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
        for finding in dmarc.findings:
            print(f"  {'':9}{Y}⚠ {finding.description}{R}")

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

def _write_reports(art: dict, target: str, args):
    """Render terminal report and write JSON/HTML files for a single host's scan."""
    host_result          = art["host_result"]
    vuln_matches         = art["vuln_matches"]
    osint_result         = art["osint_result"]
    tls_results          = art["tls_results"]
    header_audit         = art["header_audit"]
    stack_result         = art["stack_result"]
    dns_result           = art["dns_result"]
    takeover_result      = art["takeover_result"]
    service_probe_result = art["service_probe_result"]
    vuln_probe_result    = art["vuln_probe_result"]
    service_enum_result  = art["service_enum_result"]
    web_fingerprint      = art["web_fingerprint"]
    topology             = art["topology"]
    auth_result          = art["auth_result"]
    scan_diff            = art["scan_diff"]
    ai_analysis          = art["ai_analysis"]
    fusion_result        = art.get("fusion")
    no_color             = args.no_color

    # ── Terminal output ──
    if args.report in ("terminal", "all"):
        print_terminal_report(host_result, vuln_matches, osint_result)
        print_tls_results(tls_results, no_color)
        print_header_results(header_audit, no_color)
        print_stack_results(stack_result, no_color)
        print_dns_results(dns_result, no_color)
        print_takeover_results(takeover_result, no_color)
        print_service_probe_results(service_probe_result, no_color)
        print_vuln_probe_results(vuln_probe_result, no_color)
        if topology is not None:
            from src.reporter import print_topology
            print_topology(topology, no_color)
        if scan_diff is not None:
            from src.reporter import print_scan_diff
            print_scan_diff(scan_diff, no_color)
        if auth_result is not None:
            from src.reporter import print_auth_result
            print_auth_result(auth_result, no_color)
        if web_fingerprint is not None:
            from src.reporter import print_web_fingerprint
            print_web_fingerprint(web_fingerprint, no_color)
        if service_enum_result is not None:
            from src.reporter import print_service_enum
            print_service_enum(service_enum_result, no_color)
        if fusion_result is not None and ai_analysis is None:
            from src.reporter import print_detected_vulnerabilities
            print_detected_vulnerabilities(fusion_result, no_color)
        if ai_analysis is not None:
            from src.reporter import print_ai_analysis
            print_ai_analysis(ai_analysis, no_color)

    safe_name = target.replace("/","_").replace(":","_")
    ts = time.strftime("%Y%m%d_%H%M%S")

    # ── JSON report ──
    if args.report in ("json", "all"):
        os.makedirs(args.out, exist_ok=True)
        from src import engine
        report = engine.build_json_report(art)
        save_json_report(report, os.path.join(args.out, f"netlogic_{safe_name}_{ts}.json"))

    # ── HTML report ──
    if args.report in ("html", "all"):
        os.makedirs(args.out, exist_ok=True)
        html_content = generate_html_report(host_result, vuln_matches, osint_result)
        save_html_report(html_content, os.path.join(args.out, f"netlogic_{safe_name}_{ts}.html"))


def run_single(target, args):
    # ONE scan path: the engine does all gathering (and the GUI calls the same
    # engine). Here we just run it and render the human report from the artifacts.
    from src import engine
    ports = resolve_ports(args.ports)
    if args.deep_probe:
        from src.deep import run_deep_scan
        art = run_deep_scan(target, ports, args)        # emit=None → prints [*] progress
    else:
        art = engine.run_scan(target, ports, args)        # emit=None → prints [*] progress
    _write_reports(art, target, args)


def run_multi(targets, args):
    """Run full scans across multiple targets with cross-host analysis."""
    from src import orchestrator
    ports = resolve_ports(args.ports)
    scan_fn = None
    if getattr(args, "deep_probe", False):
        from src.deep import run_deep_scan as scan_fn
    result = orchestrator.run_multi_scan(targets, ports, args,
                                         scan_fn=scan_fn)

    # Per-host reports
    for art, target in zip(result["hosts"], targets):
        print()
        _write_reports(art, target, args)

    # Combined JSON report with cross-host context
    if args.report in ("json", "all"):
        ts = time.strftime("%Y%m%d_%H%M%S")
        combined = {
            "scan_type": "multi-host",
            "targets": targets,
            "host_count": result["host_count"],
            "cross_host_context": result["cross_host_context"],
            "errors": result["errors"],
        }
        safe_name = "_".join(t.replace("/","_").replace(":","_") for t in targets)
        if len(safe_name) > 100:
            safe_name = safe_name[:100]
        os.makedirs(args.out, exist_ok=True)
        path = os.path.join(args.out, f"netlogic_multi_{safe_name}_{ts}.json")
        with open(path, "w") as f:
            json.dump(combined, f, indent=2, default=str)
        print(f"[+] Combined multi-host report: {path}")

    if result["errors"]:
        print(f"[!] {len(result['errors'])} host(s) failed to scan:")
        for t, e in result["errors"]:
            print(f"    {t}: {e}")


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


def run_gui():
    """Start the web dashboard (blocking)."""
    CONFIG_DIR   = Path.home() / ".netlogic"
    SECRETS_FILE = CONFIG_DIR / "secrets.json"
    DIST_DIR     = Path(__file__).parent / "dashboard" / "dist"

    # ── Load or generate secrets ──
    if SECRETS_FILE.exists():
        try:
            data = json.loads(SECRETS_FILE.read_text())
        except Exception:
            data = {}
    else:
        data = {}

    changed = False
    for key in ("NETLOGIC_JWT_SECRET", "NETLOGIC_ADMIN_KEY", "NETLOGIC_API_KEY"):
        if not data.get(key):
            data[key] = secrets.token_hex(32) if key != "NETLOGIC_ADMIN_KEY" else secrets.token_urlsafe(32)
            changed = True
    if changed:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        SECRETS_FILE.write_text(json.dumps(data, indent=2))
        try:
            SECRETS_FILE.chmod(0o600)
        except Exception:
            pass

    for k, v in data.items():
        os.environ.setdefault(k, v)

    api_key = data["NETLOGIC_API_KEY"]
    os.environ["NETLOGIC_API_KEYS"] = f"{api_key}:default"
    os.environ.setdefault("NETLOGIC_VALID_LICENSES", "NL-LOCAL-DESKTOP")
    os.environ.setdefault("NETLOGIC_LICENSE_KEY", "NL-LOCAL-DESKTOP")
    # We open the browser ourselves (below) and the server starts its own built-in
    # in-process scan agent. Suppress the server's duplicate browser launch so the
    # dashboard opens in exactly ONE window, not two.
    os.environ["NETLOGIC_NO_BROWSER"] = "1"

    # ── Build dashboard if needed ──
    if not (DIST_DIR / "index.html").exists():
        dash_dir = Path(__file__).parent / "dashboard"
        if dash_dir.exists():
            print("[netlogic] Building dashboard for the first time (~30 s)...")
            try:
                subprocess.run("npm install", cwd=dash_dir, shell=True, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run("npm run build", cwd=dash_dir, shell=True, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print("[netlogic] Dashboard ready.")
            except subprocess.CalledProcessError:
                print("[netlogic] Warning: dashboard build failed — API-only mode.")
            except FileNotFoundError:
                print("[netlogic] Warning: npm not found — install Node.js for the dashboard.")

    port = int(os.environ.get("NETLOGIC_PORT", "8000"))
    host = os.environ.get("NETLOGIC_HOST", "0.0.0.0")
    url  = f"http://localhost:{port}"

    print()
    print("  ███╗   ██╗███████╗████████╗██╗      ██████╗  ██████╗ ██╗ ██████╗")
    print("  ████╗  ██║██╔════╝╚══██╔══╝██║     ██╔═══██╗██╔════╝ ██║██╔════╝")
    print("  ██╔██╗ ██║█████╗     ██║   ██║     ██║   ██║██║  ███╗██║██║")
    print("  ██║╚██╗██║██╔══╝     ██║   ██║     ██║   ██║██║   ██║██║██║")
    print("  ██║ ╚████║███████╗   ██║   ███████╗╚██████╔╝╚██████╔╝██║╚██████╗")
    print("  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝ ╚═════╝")
    print()
    print(f"  URL:       {url}")
    print(f"  Agent key: {api_key}")
    print()
    print("  Open the URL and sign in with your account to use the dashboard.")
    print("  The Agent key above is a MACHINE credential — use it only for remote")
    print("  agents (netlogic_agent.py) and programmatic API access, not to log in.")
    print("  Press Ctrl+C to stop.")
    print()
    # Flush now: uvicorn.run() blocks below, so anything still buffered would never
    # reach the console until shutdown.
    sys.stdout.flush()

    threading.Timer(1.5, webbrowser.open, args=(url,)).start()

    # NOTE: the API server starts its own built-in in-process scan agent on startup
    # (api/main.py lifespan → local_agent.start), which has all scan capabilities.
    # We deliberately do NOT spawn a second external netlogic_agent.py here — doing so
    # registered a duplicate "localhost" agent in the fleet. Remote/extra agents are
    # still added by running netlogic_agent.py manually against this controller.

    import uvicorn  # noqa: PLC0415
    uvicorn.run("api.main:app", host=host, port=port, log_level="warning")


def _load_dotenv() -> None:
    """Load KEY=VALUE pairs from a project-root .env into the environment.

    Stdlib-only, dependency-free. Existing env vars win (never override the real
    environment). Called at the START of main() — NOT at import — so importing this
    module (e.g. in tests, which also import api.main) never silently enables
    .env-driven features like OIDC.
    """
    env_path = Path(__file__).parent / ".env"
    if not env_path.exists():
        return
    try:
        for raw in env_path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val
    except OSError:
        pass


def _run_benchmark(args):
    """Run the fusion-pipeline benchmark against the labeled cassette corpus and exit."""
    print(f"{'='*70}")
    print(f"  NETLOGIC FUSION BENCHMARK")
    print(f"{'='*70}")

    from src.fusion.corpus import cases_from_cassettes, cassette_to_case
    from src.fusion.cassette import load_cassettes
    from src.fusion.benchmark import score_with_oracle, run_pipeline, oracle_complete, score, _score_precomputed, demo_corpus
    from src.fusion.gate import adjudicate

    cassettes = load_cassettes()
    cases = cases_from_cassettes()

    # Include the synthetic demo corpus too for broader coverage
    demo = demo_corpus()
    all_cases = cases + demo
    print(f"\n  Dataset: {len(cassettes)} real cassette recordings + {len(demo)} synthetic cases")
    print(f"           {len(all_cases)} total cases, {sum(len(c.truth) for c in all_cases)} labeled subjects")

    from src.fusion.ai import make_completer

    if args.benchmark_ai:
        from src import ai_analyst as aa
        cfg = aa.config_from_env()
        usable, reason = cfg.is_usable()
        if not usable:
            print(f"\n  ERROR: {reason}")
            print(f"  Set NETLOGIC_AI_API_KEY or paste a key in ~/.netlogic/secrets.json")
            sys.exit(1)
        print(f"\n  AI model: {cfg.provider} / {cfg.model}  @ {cfg.base_url}")
        completer = make_completer(cfg)
        r = score(all_cases, complete=completer)
        label = f"REAL MODEL ({cfg.provider}/{cfg.model})"
    else:
        r = score_with_oracle(all_cases)
        label = "ORACLE (perfect-AI upper bound)"

    print(f"\n  {label}")
    print(f"  {'─'*60}")
    print(f"  {'':>30} {'Raw scanner':>15} {'Pipeline':>15}")
    print(f"  {'':>30} {'─────────────':>15} {'────────':>15}")
    print(f"  {'Precision':>30} {r.raw_precision:>14.1%} {r.precision:>14.1%}")
    print(f"  {'Recall':>30} {'100.0%':>15} {r.recall:>14.1%}")
    print(f"  {'Critical recall':>30} {'100.0%':>15} {r.critical_recall:>14.1%}")
    print(f"  {'False positives':>30} {r.raw_fp:>15} {r.fp:>15}")
    print(f"  {'FP reduction':>30} {'—':>15} {r.fp_reduction:>13.1%}")
    print(f"  {'Critical FNs':>30} {0:>15} {r.critical_fn:>15}")
    print(f"  {'─'*60}")

    verdict = f"{'✅ PASS' if r.passed else '❌ FAIL'}"
    print(f"\n  Verdict: {verdict}")
    print(f"  Gate: FP reduction ≥ 80% AND critical recall = 100%")
    if r.passed:
        print(f"  Target: {r.fp_reduction:.1%} ≥ 80% ✓ | critical recall {r.critical_recall:.0%} = 100% ✓")
    else:
        if r.fp_reduction < 0.80:
            print(f"  ✗ FP reduction {r.fp_reduction:.1%} < 80%")
        if r.critical_recall < 1.0:
            print(f"  ✗ Critical recall {r.critical_recall:.0%} < 100% ({r.critical_fn} critical FNs)")

    if args.benchmark_verbose:
        print(f"\n  Per-subject decisions:")
        for c in all_cases:
            dec = run_pipeline(c, oracle_complete(c))
            for (host, port, claim), d in sorted(dec.items()):
                gt = c.truth_for(host, port, claim) or {}
                tag = "✓" if gt.get("is_real") else "✗"
                print(f"    {c.name:24} {host}:{port:<5} {claim:30} -> {d:12} (truth: {tag})")

    # Export report
    if args.benchmark_export:
        import json as _json
        path = args.benchmark_export.lower()
        if path.endswith(".json"):
            content = r.to_json()
        else:
            content = _yc_report_markdown(r, cassettes, all_cases, mode_label=label)
        with open(args.benchmark_export, "w", encoding="utf-8") as fh:
            fh.write(content + "\n" if not content.endswith("\n") else content)
        print(f"\n  Report exported → {args.benchmark_export}")


def _yc_report_markdown(r, cassettes, all_cases, mode_label: str = "") -> str:
    """YC-ready benchmark report."""
    from src.fusion.benchmark import MIN_FP_REDUCTION, REQUIRED_CRITICAL_RECALL
    is_oracle = "ORACLE" in (mode_label or "").upper()
    # Honest mode disclosure — the numbers mean very different things depending on
    # the adjudicator. The oracle is a PERFECT-AI UPPER BOUND (ceiling), not what a
    # real model achieves; never present it as measured product performance.
    mode_note = (
        "> **Measurement mode: ORACLE (perfect-AI upper bound).** These figures are the "
        "*theoretical ceiling* the pipeline reaches if the AI adjudicator is always correct — "
        "they are NOT real-model results. Run `--benchmark-ai` with a configured model for "
        "measured performance before citing these numbers externally."
        if is_oracle else
        f"> **Measurement mode: {mode_label or 'real model'}** — measured against the labeled corpus."
    )
    lines = [
        "# NetLogic Fusion-Pipeline Benchmark Report",
        "",
        f"**Date:** _auto_  ·  **Dataset:** {len(cassettes)} real HTTP cassettes (Vulhub) + {len(all_cases) - len(cassettes)} synthetic edge cases",
        "",
        mode_note,
        "",
        "> _Internal benchmark on a small labeled corpus — directional evidence, not "
        "production-scale or independent validation._",
        "",
        "---",
        "",
        "## Verdict",
        "",
        f"**{'✅ PASS' if r.passed else '❌ FAIL'}** — all gates satisfied" if r.passed else f"**❌ FAIL** — gates not met",
        "",
        f"| Gate | Threshold | Actual |",
        f"|---|---:|---:|",
        f"| False-positive reduction | ≥ {MIN_FP_REDUCTION:.0%} | **{r.fp_reduction:.1%}** {'✓' if r.fp_reduction >= MIN_FP_REDUCTION else '✗'} |",
        f"| Critical recall | = {REQUIRED_CRITICAL_RECALL:.0%} | **{r.critical_recall:.0%}** {'✓' if r.critical_recall >= REQUIRED_CRITICAL_RECALL else '✗'} |",
        "",
        "---",
        "",
        "## Aggregate Results",
        "",
        f"**{r.cases} cases, {r.subjects} labeled subjects**",
        "",
        "| Metric | Raw scanner | NetLogic pipeline | Improvement |",
        "|---|---:|---:|---:|",
        f"| Precision | {r.raw_precision:.1%} | **{r.precision:.1%}** | +{r.precision - r.raw_precision:.1%} |",
        f"| Recall | 100.0% | {r.recall:.1%} | — |",
        f"| Critical recall | 100.0% | **{r.critical_recall:.0%}** | — |",
        f"| False positives | {r.raw_fp} | **{r.fp}** | **-{r.fp_reduction:.1%}** |",
        f"| Critical false negatives | 0 | {r.critical_fn} | — |",
        "",
        "Confusion matrix: "
        f"TP={r.tp}, FP={r.fp}, FN={r.fn}, TN={r.tn}",
        "",
        "---",
        "",
        "## Dataset Details",
        "",
        "| Cassette | Label | Interactions | Truth subjects | Probes |",
        "|---|---:|---:|---:|---:|",
    ]
    for c in cassettes:
        n_int = len(getattr(c, 'interactions', []) or [])
        n_truth = len(getattr(c, 'truth', []) or [])
        n_probes = len(getattr(c, 'probes', []) or [])
        label = getattr(c, 'label_source', '?') or '?'
        lines.append(
            f"| {c.name:30} | {label:45} | {n_int} | {n_truth} | {n_probes} |"
        )

    lines += [
        "",
        "### Dataset Sources",
        "",
        "- **Vulhub cassettes:** Recorded HTTP interactions from real vulnerable Docker environments (Log4Shell, Struts2), captured via recording proxy with ground-truth labels.",
        "- **Clean cassettes:** Recordings from patched/current-version targets (nginx, WordPress) — these should produce NO real findings (all sensor output is noise).",
        "- **Synthetic cases:** Hand-authored edge cases exercising specific gate invariants (pinned KEV, auto-confirmed by corroboration, lone low-impact noise, safety-floor cost).",
        "",
        "### Methodology",
        "",
        "1. Each cassette contains raw HTTP request/response pairs replayed through the real sensor pipeline (NVD correlation, Wappalyzer fingerprinting, Nuclei templates).",
        "2. Sensors produce `Signal` objects — the same pipeline that runs in a live `netlogic --full` scan.",
        "3. The fusion gate (`adjudicate()`) deterministically classifies each signal as `confirmed`, `discarded`, or `gray` without spending an AI token.",
        "4. Gray-band items are handed to the AI adjudicator (or the ground-truth oracle in benchmark mode).",
        "5. The final verdict is scored against the ground truth: `confirmed` + `potential` = reported; `discarded` = suppressed.",
        "",
        "### Safety Guarantees (Architectural, not Prompt-Based)",
        "",
        "- KEV-listed and probe-confirmed findings are **structurally pinned** — the AI cannot drop them.",
        "- High/critical impact items in the gray band can be promoted or demoted to `potential` (report + verify) but the AI can **never** discard them.",
        "- AI failure (timeout, parse error, garbage output) defaults to `potential` — nothing real is ever silently dropped.",
        "- The benchmark harness **fails closed**: if critical recall drops below 100%, the pipeline gate returns FAIL.",
        "",
        "---",
        "",
        "## Key Design Decision: Why This Matters",
        "",
        "Most AI security tools feed raw scanner output directly into an LLM, burning tokens on every finding — "
        "including the 80-90% that are inventory noise. NetLogic's fusion layer uses a deterministic agreement "
        "gate to settle certain cases *before* the AI is ever called:",
        "",
        "- **KEV/probe-confirmed** → auto-confirmed (pinned, un-droppable)",
        "- **≥2 independent sensors + ≥1 high-reliability** → auto-confirmed (no AI token)",
        "- **Lone low-reliability low/medium impact** → auto-discarded (noise filter)",
        "- **Everything else (the gray band)** → AI adjudication (token cost ∝ ambiguity, not asset count)",
        "",
        f"This architecture delivers **{r.fp_reduction:.0%} fewer false positives** than a raw scanner while "
        f"guaranteeing **{r.critical_recall:.0%} critical recall** — no real critical vulnerability is ever dropped.",
        "",
    ]
    return "\n".join(lines)


def main():
    _load_dotenv()
    args = parse_args()

    # ── Fusion benchmark mode ──
    if args.benchmark:
        _run_benchmark(args)
        return

    # ── GUI mode ──
    if args.gui:
        # Reject any other flags when --gui is used
        # Only check boolean (store_true) flags — they default to False.
        # Flags with truthy defaults (--ports=quick, --report=terminal, etc.)
        # are harmless when left at their defaults.
        bool_flags = ["tls", "headers", "takeover", "osint", "stack", "dns",
                       "probe", "full", "ai", "deep_probe", "no_diff",
                       "no_traceroute", "cidr", "no_color", "clear_cache",
                       "preload_cache", "cache_stats", "vdb_status"]
        if any(getattr(args, f) for f in bool_flags):
            print("error: --gui cannot be combined with scan flags", file=sys.stderr)
            sys.exit(1)
        value_flags = ["ai_key", "ai_provider", "ai_model", "ai_base_url",
                       "ssh_user", "ssh_key", "ssh_pass", "ports", "report",
                       "out", "timeout", "threads", "min_cvss", "nvd_key",
                       "vdb_sync"]
        # For value flags, check they're different from their defaults
        defaults = {"ports": "quick", "timeout": 2.0, "threads": 100,
                    "min_cvss": 4.0, "report": "terminal", "out": ".",
                    "ssh_port": 22, "ai_key": "", "ai_provider": "",
                    "ai_model": "", "ai_base_url": "", "ssh_user": "",
                    "ssh_key": "", "ssh_pass": "", "nvd_key": ""}
        for f in value_flags:
            val = getattr(args, f, None)
            if val is not None and val != defaults.get(f):
                print(f"error: --gui cannot be combined with --{f.replace('_', '-')}", file=sys.stderr)
                sys.exit(1)
        if args.target:
            print("error: --gui does not take a target argument", file=sys.stderr)
            sys.exit(1)
        run_gui()
        return

    if args.clear_cache:
        clear_cache()
        if not args.target:
            return
    if args.preload_cache:
        preload_cache()
        if not args.target:
            return
    if args.cache_stats:
        stats = cache_stats()
        print(f"  NVD cache: {stats.get('entries', 0)} entries, "
              f"{stats.get('size_bytes', 0) // 1024} KB")
        if not args.target:
            return

    # ── Offline VDB management (sync/status) — run and exit ──
    if args.vdb_status:
        from src.vdb_syncer import print_status
        print_status()
        return
    if args.vdb_sync is not None:
        from src.vdb_syncer import run_vdb_sync, print_status
        print(f"[*] Syncing local offline CVE database from NVD"
              f"{f' (first {args.vdb_sync} products)' if args.vdb_sync else ''}…")
        run_vdb_sync(limit=args.vdb_sync)
        print()
        print_status()
        return

    if not args.target:
        print("error: target is required", file=sys.stderr)
        sys.exit(1)

    if not args.no_color:
        print(BANNER)
    else:
        print(f"NetLogic v{VERSION}\n")
    print(f"  For authorized use only.\n")

    # Detect comma-separated multi-target scans
    targets = [t.strip() for t in args.target.split(",")] if "," in args.target else [args.target]

    if args.deep_probe and args.cidr:
        print("[!] --deep-probe + --cidr: deep-probe mode not supported for CIDR scans; "
              "falling back to standard CIDR scan.", file=sys.stderr)
        args.deep_probe = False

    if args.deep_probe and len(targets) > 1:
        print("[!] --deep-probe with multi-target: each host is scanned independently "
              "via the deep-probe architecture.", file=sys.stderr)

    if args.cidr:
        run_cidr(args.target, args)
    elif len(targets) > 1:
        run_multi(targets, args)
    else:
        run_single(targets[0], args)


if __name__ == "__main__":
    main()
