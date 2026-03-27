"""
NetLogic - JSON Stream Bridge
Wraps the scanner to emit newline-delimited JSON events for the Electron frontend.
Each line is a JSON object: {"type": "...", "data": {...}} or {"type": "error", "message": "..."}
"""

import sys
import json
import time
from dataclasses import asdict

from src.scanner import scan_host, scan_cidr, COMMON_PORTS, EXTENDED_PORTS
from src.cve_correlator import correlate
from src.osint import run_osint


def emit(event_type: str, data=None, message: str = None):
    """Write a single JSON event to stdout and flush immediately."""
    if message is not None:
        obj = {"type": event_type, "message": message}
    else:
        obj = {"type": event_type, "data": data}
    print(json.dumps(obj, default=str), flush=True)


def run_streaming_scan(target: str, ports: list, timeout: float,
                       threads: int, do_osint: bool, cidr: bool,
                       do_tls: bool = False, do_headers: bool = False,
                       do_stack: bool = False, do_dns: bool = False,
                       do_full: bool = False, do_probe: bool = False,
                       min_cvss: float = 4.0):
    """Execute a scan and stream results as JSON events."""

    emit("progress", {"percent": 5, "status": f"Resolving {target}..."})

    if cidr:
        hosts = scan_cidr(target, ports=ports, max_workers=threads, timeout=timeout)
        total_p = 0
        total_v = 0
        for hr in hosts:
            emit("host", asdict(hr))
            for p in hr.ports:
                total_p += 1
                emit("port", {"target": hr.ip, **asdict(p)})
            vuln_matches = correlate(hr.ports, min_cvss=min_cvss, verbose=False)
            for vm in vuln_matches:
                total_v += 1
                emit("vuln", {"target": hr.ip, **_vuln_to_dict(vm)})
        if do_osint or do_full:
            emit("progress", {"percent": 92, "status": "Running passive OSINT on base target..."})
            try:
                osint = run_osint(target, ip=hosts[0].ip if hosts else None)
                from dataclasses import asdict as _asdict
                emit("osint", {
                    "dns_records":  [_asdict(r) for r in osint.dns_records],
                    "subdomains":   [_asdict(s) for s in osint.subdomains],
                    "technologies": osint.technologies,
                    "emails":       osint.emails,
                    "asn_info":     _asdict(osint.asn_info) if osint.asn_info else None,
                })
            except Exception as e:
                emit("log", {"text": f"OSINT: {e}", "level": "warn"})

        emit("done", {
            "hosts": len(hosts),
            "ports": total_p,
            "vulns": total_v,
            "duration": getattr(hosts[-1], "scan_duration_s", 0) if hosts else 0
        })
        return

    emit("progress", {"percent": 10, "status": "Scanning ports..."})
    result = _scan_streaming(target, ports, threads, timeout)

    emit("host", {
        "target":         result.target,
        "ip":             result.ip,
        "hostname":       result.hostname,
        "os_guess":       result.os_guess,
        "timestamp":      result.timestamp,
        "scan_duration_s":result.scan_duration_s,
    })

    # Ports already streamed live inside _scan_streaming
    emit("progress", {"percent": 60, "status": f"Found {len(result.ports)} open ports, correlating CVEs..."})

    # CVE correlation
    vuln_matches = correlate(result.ports, min_cvss=min_cvss, verbose=False)
    emit("progress", {"percent": 75, "status": f"Found {len(vuln_matches)} vulnerability findings..."})
    for vm in vuln_matches:
        emit("vuln", {"target": result.ip, **_vuln_to_dict(vm)})

    from dataclasses import asdict as _asdict

    # TLS Analysis
    if do_tls or do_full:
        emit("progress", {"percent": 78, "status": "Running TLS analysis..."})
        try:
            from src.tls_analyzer import analyze_tls_ports
            tls_ports = [p.port for p in result.ports
                         if p.tls or p.port in (443, 8443, 993, 995, 465)]
            if not tls_ports:
                tls_ports = [443]
            tls_results = analyze_tls_ports(target, tls_ports)
            if tls_results:
                emit("tls", {"results": [_asdict(r) for r in tls_results]})
        except Exception as e:
            emit("log", {"text": f"TLS: {e}", "level": "warn"})

    # HTTP Header Audit
    if do_headers or do_full:
        emit("progress", {"percent": 82, "status": "Auditing HTTP security headers..."})
        try:
            from src.header_audit import audit_headers
            http_port = next(
                (p.port for p in result.ports if p.service in ("http", "https", "http-alt", "https-alt")),
                80
            )
            audit = audit_headers(target, http_port)
            emit("headers", _asdict(audit))
        except Exception as e:
            emit("log", {"text": f"Headers: {e}", "level": "warn"})

    # Technology Stack
    if do_stack or do_headers or do_full:
        emit("progress", {"percent": 85, "status": "Fingerprinting technology stack..."})
        try:
            from src.stack_fingerprint import fingerprint_stack
            http_port = next(
                (p.port for p in result.ports if p.service in ("http", "https", "http-alt", "https-alt")),
                80
            )
            stack = fingerprint_stack(target, http_port)
            emit("stack", _asdict(stack))
        except Exception as e:
            emit("log", {"text": f"Stack: {e}", "level": "warn"})

    # DNS Security
    if do_dns or do_full:
        emit("progress", {"percent": 88, "status": "Checking DNS/email security..."})
        try:
            from src.dns_security import check_dns_security
            dns_result = check_dns_security(target)
            emit("dns", _asdict(dns_result))
        except Exception as e:
            emit("log", {"text": f"DNS: {e}", "level": "warn"})

    # Passive OSINT
    if do_osint or do_full:
        emit("progress", {"percent": 92, "status": "Running passive OSINT..."})
        try:
            osint = run_osint(target, ip=result.ip)
            emit("osint", {
                "dns_records":  [_asdict(r) for r in osint.dns_records],
                "subdomains":   [_asdict(s) for s in osint.subdomains],
                "technologies": osint.technologies,
                "emails":       osint.emails,
                "asn_info":     _asdict(osint.asn_info) if osint.asn_info else None,
            })
        except Exception as e:
            emit("log", {"text": f"OSINT: {e}", "level": "warn"})

    # Active Service & Vulnerability Probing
    if (do_probe or do_full) and result.ports:
        emit("progress", {"percent": 94, "status": "Running active service and vulnerability probes..."})
        try:
            from src.service_prober import probe_services
            svc_result = probe_services(target, result.ports, timeout=timeout)
            emit("service_probes", _asdict(svc_result))
        except Exception as e:
            emit("log", {"text": f"ServiceProbe: {e}", "level": "warn"})
        try:
            from src.vuln_prober import probe_web_vulnerabilities
            vuln_p = probe_web_vulnerabilities(target, result.ports, timeout=timeout)
            emit("vuln_probes", _asdict(vuln_p))
        except Exception as e:
            emit("log", {"text": f"VulnProbe: {e}", "level": "warn"})

    emit("progress", {"percent": 100, "status": "Scan complete."})
    emit("done", {
        "ports":    len(result.ports),
        "vulns":    len(vuln_matches),
        "duration": result.scan_duration_s,
    })


def _scan_streaming(target, ports, threads, timeout):
    """Run scan but emit ports in real time as they are discovered."""
    import concurrent.futures
    from src.scanner import probe_port, resolve_target, guess_os_from_ttl, HostResult

    start = time.time()
    ip, hostname = resolve_target(target)

    result = HostResult(
        target=target,
        ip=ip,
        hostname=hostname,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(probe_port, ip, port, timeout): port
            for port in ports
        }
        completed = 0
        total = len(futures)
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            port_result = future.result()
            if port_result.state == "open":
                result.ports.append(port_result)
                emit("port", {"target": ip, **asdict(port_result)})

            if completed % max(1, total // 20) == 0:
                pct = 10 + int((completed / total) * 48)
                emit("progress", {
                    "percent": pct,
                    "status":  f"Scanned {completed}/{total} ports... ({len(result.ports)} open)",
                })

    result.ports.sort(key=lambda p: p.port)
    result.scan_duration_s = round(time.time() - start, 2)
    result.os_guess = guess_os_from_ttl(result.ttl)
    return result


def _vuln_to_dict(vm) -> dict:
    """Convert a VulnMatch to a JSON-serialisable dict for the frontend."""
    return {
        "port":       vm.port,
        "service":    vm.service,
        "product":    vm.product,
        "version":    vm.version,
        "risk_score": vm.risk_score,
        "notes":      vm.notes,
        "source":     getattr(vm, "source", "nvd"),
        "cves": [
            {
                "id":               c.id,
                "description":      c.description,
                "cvss_score":       c.cvss_score,
                "severity":         c.severity,
                "vector":           getattr(c, "vector", ""),
                "published":        getattr(c, "published", ""),
                "exploit_available":c.exploit_available,
                "kev":              getattr(c, "kev", False),
                "cwe":              getattr(c, "cwe", ""),
                "version_range":    getattr(c, "version_range", ""),
                "references":       getattr(c, "references", []),
            }
            for c in vm.cves
        ],
    }