"""
NetLogic - Scan Engine (single source of truth)
===============================================
ONE scan implementation, used by both the CLI (netlogic.py) and the GUI/API
streaming bridge (json_bridge.py). Previously these were two divergent code paths,
so features added to the CLI never reached the GUI. Now both call run_scan():

  • CLI  → run_scan(emit=None): prints "[*]" progress, then renders the report.
  • GUI  → run_scan(emit=cb):   every stage is streamed as a structured event.

run_scan gathers everything (scan, CVE correlation + EPSS, TLS, headers, stack,
DNS, OSINT, takeover, active probes, service exploitability, web fingerprint,
topology, authenticated SSH enum, change-diff, AI analysis) and returns an
artifacts dict. build_json_report() turns artifacts into the saved JSON report.
"""
from __future__ import annotations

from dataclasses import asdict

from src.scanner import scan_host
from src.cve_correlator import correlate
from src.osint import run_osint


def _g(args, name, default=None):
    return getattr(args, name, default)


def run_scan(target: str, ports: list, args, emit=None) -> dict:
    """Run a full scan and return an artifacts dict. Streams events via emit if given.

    emit(event_type: str, data: dict | None, message: str | None)
    """
    def _emit(etype, data=None, message=None):
        if emit is not None:
            emit(etype, data, message)
        elif message:                      # CLI: human progress only
            print(f"[*] {message}")

    streaming = emit is not None
    timeout = _g(args, "timeout", 2.0)
    threads = _g(args, "threads", 100)
    min_cvss = _g(args, "min_cvss", 4.0)
    full = _g(args, "full", False)
    ai_deep = _g(args, "ai", False)

    # Which deep modules to run. --ai implies the rich passive set; --full = all.
    do_tls      = _g(args, "tls", False)      or full or ai_deep
    do_headers  = _g(args, "headers", False)  or full or ai_deep
    do_takeover = _g(args, "takeover", False) or full or ai_deep
    do_osint    = _g(args, "osint", False)    or full or ai_deep
    do_stack    = _g(args, "stack", False)    or full or ai_deep
    do_dns      = _g(args, "dns", False)      or full or ai_deep
    do_probe    = _g(args, "probe", False)    or full
    # Fusion adjudication (sensors→gate→AI precision funnel). Opt-in; runs when --ai
    # is on (it uses the AI to judge the gray band) or when explicitly requested.
    do_fusion   = _g(args, "fusion", False)   or ai_deep

    # ── Port scan (streams ports live when emitting) ──
    _emit("progress", {"percent": 10, "status": f"Scanning {target} ({len(ports)} ports)…"},
          message=f"Scanning {target} ({len(ports)} ports)…")

    def _on_port(pr):
        _emit("port", {"target": target, **asdict(pr)})

    host_result = scan_host(target, ports=ports, max_workers=threads, timeout=timeout,
                            on_open_port=_on_port if streaming else None)
    _emit("host", {
        "target": host_result.target, "ip": host_result.ip, "hostname": host_result.hostname,
        "os_guess": host_result.os_guess, "ttl": host_result.ttl,
        "timestamp": host_result.timestamp, "scan_duration_s": host_result.scan_duration_s,
    })

    # ── CVE correlation (+ EPSS, done inside correlate) ──
    from src.nvd_lookup import cache_stats
    n = cache_stats().get("entries", 0)
    _emit("progress", {"percent": 60, "status": "Correlating CVEs…"},
          message=f"Correlating CVEs via NVD API ({'cache: %d entries' % n if n else 'live queries'})…")
    vuln_matches = correlate(host_result.ports, min_cvss=min_cvss, verbose=not streaming)
    for vm in vuln_matches:
        _emit("vuln", {"target": host_result.ip, **_vuln_to_dict(vm)})

    art: dict = {
        "host_result": host_result, "vuln_matches": vuln_matches,
        "tls_results": [], "header_audit": None, "stack_result": None, "dns_result": None,
        "takeover_result": None, "osint_result": None, "service_probe_result": None,
        "vuln_probe_result": None, "service_enum_result": None, "web_fingerprint": None,
        "topology": None, "auth_result": None, "scan_diff": None, "ai_analysis": None,
        "fusion": None,
    }
    ports_open = host_result.ports
    http_port = next((p.port for p in ports_open
                      if p.service in ("http", "https", "http-alt", "https-alt")), None)
    # Prefer a TLS/HTTPS port for the header & stack audits — HSTS and most
    # security headers are only meaningful over HTTPS, so auditing the plain-HTTP
    # port first (80 sorts before 443) would understate the real posture.
    https_port = next((p.port for p in ports_open
                       if getattr(p, "tls", False) or p.port in (443, 8443)
                       or p.service in ("https", "https-alt")), None)
    web_port = https_port or http_port or 443

    # ── TLS ──
    if do_tls:
        from src.tls_analyzer import analyze_tls_ports
        tls_ports = [p.port for p in ports_open if p.tls or p.port in (443, 8443, 993, 995, 465)] or [443]
        _emit("progress", {"percent": 78, "status": "TLS analysis…"}, message="Running TLS analysis…")
        art["tls_results"] = analyze_tls_ports(target, tls_ports)
        _emit("tls", {"results": [asdict(r) for r in art["tls_results"]]})

    # ── HTTP headers ──
    if do_headers:
        from src.header_audit import audit_headers
        _emit("progress", {"percent": 82, "status": "HTTP security headers…"}, message="Auditing HTTP security headers…")
        try:
            art["header_audit"] = audit_headers(target, web_port)
            _emit("headers", asdict(art["header_audit"]))
        except Exception as e:
            _emit("log", {"text": f"Header audit: {e}", "level": "warn"})

    # ── Tech stack ──
    if do_stack:
        from src.stack_fingerprint import fingerprint_stack
        _emit("progress", {"percent": 85, "status": "Technology stack…"}, message="Fingerprinting technology stack…")
        try:
            art["stack_result"] = fingerprint_stack(target, web_port)
            _emit("stack", asdict(art["stack_result"]))
        except Exception as e:
            _emit("log", {"text": f"Stack fingerprint: {e}", "level": "warn"})

    # ── DNS/email ──
    if do_dns:
        from src.dns_security import check_dns_security
        _emit("progress", {"percent": 88, "status": "DNS/email security…"}, message="Checking DNS/email security…")
        # Defense-in-depth: the module fails soft internally, but never let a DNS
        # hiccup abort the rest of the scan (mirrors the OSINT block below).
        try:
            art["dns_result"] = check_dns_security(target)
            _emit("dns", asdict(art["dns_result"]))
        except Exception as e:
            _emit("log", {"text": f"DNS/email: {e}", "level": "warn"})

    # ── OSINT ──
    if do_osint:
        _emit("progress", {"percent": 90, "status": "Passive OSINT…"}, message="Running passive OSINT…")
        try:
            o = run_osint(target, ip=host_result.ip)
            art["osint_result"] = o
            _emit("osint", {
                "dns_records": [asdict(r) for r in o.dns_records],
                "subdomains": [asdict(s) for s in o.subdomains],
                "technologies": o.technologies, "emails": o.emails,
                "asn_info": asdict(o.asn_info) if o.asn_info else None,
            })
        except Exception as e:
            _emit("log", {"text": f"OSINT: {e}", "level": "warn"})

    # ── Subdomain takeover ──
    if do_takeover:
        from src.takeover import discover_and_check
        _emit("progress", {"percent": 92, "status": "Subdomain takeover…"}, message="Checking subdomains for takeover…")
        try:
            art["takeover_result"] = discover_and_check(target)
            _emit("takeover", asdict(art["takeover_result"]))
        except Exception as e:
            _emit("log", {"text": f"Takeover: {e}", "level": "warn"})

    # ── Active probes ──
    if do_probe and ports_open:
        from src.service_prober import probe_services
        from src.vuln_prober import probe_web_vulnerabilities
        _emit("progress", {"percent": 94, "status": "Active probes…"}, message="Running active service/vuln probes…")
        # Each prober swallows its own per-check errors, but guard the orchestrators
        # too so an unexpected failure in one can't abort the rest of the scan.
        try:
            art["service_probe_result"] = probe_services(target, ports_open, timeout=timeout)
            _emit("service_probes", asdict(art["service_probe_result"]))
        except Exception as e:
            _emit("log", {"text": f"Service probes: {e}", "level": "warn"})
        try:
            art["vuln_probe_result"] = probe_web_vulnerabilities(target, ports_open, timeout=timeout)
            _emit("vuln_probes", asdict(art["vuln_probe_result"]))
        except Exception as e:
            _emit("log", {"text": f"Vuln probes: {e}", "level": "warn"})

    # ── Service exploitability enumeration ──
    if (ai_deep or full) and ports_open:
        from src.service_enum import enumerate_services
        _emit("progress", {"percent": 95, "status": "Service exploitability…"}, message="Enumerating service exploitability…")
        try:
            art["service_enum_result"] = enumerate_services(target, ports_open, timeout=timeout)
            _emit("service_exploitability", asdict(art["service_enum_result"]))
        except Exception as e:
            _emit("log", {"text": f"Service enum: {e}", "level": "warn"})

    # ── Web fingerprint ──
    if (ai_deep or full) and http_port is not None:
        from src.web_fingerprint import fingerprint_web
        wscheme = "https" if (http_port in (443, 8443) or
                              any(p.port == http_port and p.tls for p in ports_open)) else "http"
        _emit("progress", {"percent": 96, "status": "Web fingerprint…"}, message="Fingerprinting web application…")
        try:
            art["web_fingerprint"] = fingerprint_web(target, http_port, wscheme, timeout=max(timeout, 5.0))
            if art["web_fingerprint"]:
                _emit("web_fingerprint", asdict(art["web_fingerprint"]))
        except Exception as e:
            _emit("log", {"text": f"Web fingerprint: {e}", "level": "warn"})

    # ── Topology ──
    if ai_deep or full:
        from src.topology import map_topology
        _emit("progress", {"percent": 97, "status": "Network topology…"}, message="Mapping network topology…")
        try:
            art["topology"] = map_topology(target, host_result.ip,
                                           do_traceroute=not _g(args, "no_traceroute", False), timeout=timeout)
            _emit("topology", asdict(art["topology"]))
        except Exception as e:
            _emit("log", {"text": f"Topology: {e}", "level": "warn"})

    # ── Authenticated scan ──
    if _g(args, "ssh_user", ""):
        from src.authenticated import ssh_enumerate
        _emit("progress", {"percent": 98, "status": "Authenticated SSH enum…"},
              message=f"Authenticated scan: SSH {args.ssh_user}@{target}…")
        try:
            art["auth_result"] = ssh_enumerate(target, args.ssh_user, key_path=_g(args, "ssh_key") or None,
                                               password=_g(args, "ssh_pass") or None, port=_g(args, "ssh_port", 22))
            _emit("authenticated", asdict(art["auth_result"]))
        except Exception as e:
            _emit("log", {"text": f"Authenticated scan: {e}", "level": "warn"})

    # ── Change diff ──
    if not _g(args, "no_diff", False):
        from src.scan_diff import diff_against_last
        try:
            art["scan_diff"] = diff_against_last(host_result, vuln_matches, _g(args, "out", "."), target)
            if art["scan_diff"]:
                _emit("scan_diff", asdict(art["scan_diff"]))
        except Exception as e:
            _emit("log", {"text": f"Scan diff: {e}", "level": "warn"})

    # ── AI analysis ──
    if ai_deep:
        from src import ai_analyst
        cfg = ai_analyst.build_config(api_key=_g(args, "ai_key") or None, provider=_g(args, "ai_provider") or None,
                                      model=_g(args, "ai_model") or None, base_url=_g(args, "ai_base_url") or None)
        _emit("progress", {"percent": 99, "status": "AI analysis…"},
              message=f"Running AI analysis via {cfg.provider} ({cfg.model})…")
        try:
            art["ai_analysis"] = ai_analyst.analyze_scan(
                host_result, vuln_matches, cfg=cfg,
                tls_results=art["tls_results"], header_audit=art["header_audit"],
                stack_result=art["stack_result"], dns_result=art["dns_result"],
                takeover_result=art["takeover_result"], service_probe_result=art["service_probe_result"],
                vuln_probe_result=art["vuln_probe_result"], osint_result=art["osint_result"],
                service_enum_result=art["service_enum_result"], web_fingerprint=art["web_fingerprint"],
                topology=art["topology"], auth_result=art["auth_result"], scan_diff=art["scan_diff"])
            if art["ai_analysis"]:
                _emit("ai", {"markdown": art["ai_analysis"].markdown, "error": art["ai_analysis"].error,
                             "provider": art["ai_analysis"].provider, "model": art["ai_analysis"].model})
        except Exception as e:
            _emit("log", {"text": f"AI analysis: {e}", "level": "warn"})

    # ── Fusion adjudication (sensors → deterministic gate → AI gray-band judge) ──
    # Converts the findings above into Signals, runs the precision funnel, and adds a
    # structured confirmed/potential/discarded view. Guarded + fail-soft: it never
    # alters the existing findings and can never break a scan.
    if do_fusion:
        _emit("progress", {"percent": 99, "status": "Fusion adjudication…"},
              message="Fusion: gate + AI adjudication of findings…")
        try:
            from src.fusion.engine_bridge import run_fusion
            from src import ai_analyst
            # Fusion uses its OWN configured model (NETLOGIC_FUSION_*), falling back to
            # the AI-analyst config when no separate fusion key is set.
            fcfg = ai_analyst.fusion_config_from_env()
            art["fusion"] = run_fusion(art, cfg=fcfg)
            _emit("fusion", art["fusion"])
        except Exception as e:
            _emit("log", {"text": f"Fusion: {e}", "level": "warn"})

    _emit("progress", {"percent": 100, "status": "Scan complete."})
    _emit("done", {"ports": len(ports_open), "vulns": len(vuln_matches),
                   "duration": host_result.scan_duration_s})
    return art


def build_json_report(art: dict) -> dict:
    """Assemble the full JSON report from a run_scan() artifacts dict."""
    from src.reporter import generate_json_report
    report = generate_json_report(art["host_result"], art["vuln_matches"], art.get("osint_result"))
    sections = {
        "tls": art.get("tls_results"), "headers": art.get("header_audit"),
        "takeover": art.get("takeover_result"), "topology": art.get("topology"),
        "authenticated": art.get("auth_result"), "scan_diff": art.get("scan_diff"),
        "web_fingerprint": art.get("web_fingerprint"),
        "service_exploitability": art.get("service_enum_result"),
        "service_probes": art.get("service_probe_result"), "vuln_probes": art.get("vuln_probe_result"),
        "stack": art.get("stack_result"), "dns": art.get("dns_result"),
    }
    for key, val in sections.items():
        if not val:
            continue
        if key == "tls":
            report["tls"] = [asdict(r) for r in val]
        else:
            report[key] = asdict(val)
    ai = art.get("ai_analysis")
    if ai is not None:
        report["ai_analysis"] = {"markdown": ai.markdown, "error": ai.error,
                                 "provider": ai.provider, "model": ai.model, "tokens": ai.tokens}
    if art.get("fusion") is not None:
        report["fusion"] = art["fusion"]
    return report


def _vuln_to_dict(vm) -> dict:
    """Serialise a VulnMatch for the frontend (includes EPSS + confidence)."""
    return {
        "port": vm.port, "service": vm.service, "product": vm.product, "version": vm.version,
        "risk_score": vm.risk_score, "notes": vm.notes,
        "detection_confidence": getattr(vm, "detection_confidence", ""),
        "source": getattr(vm, "source", "nvd"),
        "cves": [{
            "id": c.id, "description": c.description, "cvss_score": c.cvss_score,
            "severity": c.severity, "vector": getattr(c, "vector", ""),
            "published": getattr(c, "published", ""), "exploit_available": c.exploit_available,
            "epss": getattr(c, "epss", 0.0), "epss_percentile": getattr(c, "epss_percentile", 0.0),
            "kev": getattr(c, "kev", False), "cwe": getattr(c, "cwe", ""),
            "has_metasploit": getattr(c, "has_metasploit", False),
            "has_public_exploit": getattr(c, "has_public_exploit", False),
            "version_range": getattr(c, "version_range", ""), "references": getattr(c, "references", []),
        } for c in vm.cves],
    }
