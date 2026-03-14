"""
NetLogic - JSON Stream Bridge
Wraps the scanner to emit newline-delimited JSON events for the Electron frontend.
Each line is a JSON object: {"type": "...", "data": {...}} or {"type": "error", "message": "..."}
"""

import sys
import json
import time
from dataclasses import asdict

# Import core modules
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
                       threads: int, do_osint: bool, cidr: bool):
    """Execute a scan and stream results as JSON events."""

    # Emit host discovery start
    emit("progress", {"percent": 5, "status": f"Resolving {target}…"})

    if cidr:
        # CIDR sweep
        from src.scanner import scan_cidr
        hosts = scan_cidr(target, ports=ports, max_workers=threads, timeout=timeout)
        for hr in hosts:
            host_data = asdict(hr)
            emit("host", host_data)
            vuln_matches = correlate(hr.ports)
            for vm in vuln_matches:
                emit("vuln", _vuln_to_dict(vm))
        emit("done", {"hosts": len(hosts)})
        return

    # Single host scan — stream ports as they open
    # We need to modify scan_host to stream; for now, run normally and stream after
    emit("progress", {"percent": 10, "status": "Scanning ports…"})

    result = _scan_streaming(target, ports, threads, timeout)

    # Emit host info
    emit("host", {
        "target": result.target,
        "ip": result.ip,
        "hostname": result.hostname,
        "os_guess": result.os_guess,
        "timestamp": result.timestamp,
        "scan_duration_s": result.scan_duration_s,
    })

    # Emit each open port
    emit("progress", {"percent": 60, "status": f"Found {len(result.ports)} open ports, correlating CVEs…"})
    for p in result.ports:
        emit("port", asdict(p))

    # CVE correlation
    vuln_matches = correlate(result.ports)
    emit("progress", {"percent": 80, "status": f"Found {len(vuln_matches)} findings…"})
    for vm in vuln_matches:
        emit("vuln", _vuln_to_dict(vm))

    # OSINT
    if do_osint:
        emit("progress", {"percent": 85, "status": "Running passive OSINT…"})
        try:
            osint = run_osint(target, ip=result.ip)
            from dataclasses import asdict as _asdict
            emit("osint", {
                "dns_records":  [_asdict(r) for r in osint.dns_records],
                "subdomains":   [_asdict(s) for s in osint.subdomains],
                "technologies": osint.technologies,
                "emails":       osint.emails,
                "asn_info":     _asdict(osint.asn_info) if osint.asn_info else None,
            })
        except Exception as e:
            emit("error", message=f"OSINT failed: {e}")

    emit("progress", {"percent": 100, "status": "Scan complete."})
    emit("done", {
        "ports": len(result.ports),
        "vulns": len(vuln_matches),
        "duration": result.scan_duration_s,
    })


def _scan_streaming(target, ports, threads, timeout):
    """
    Run scan_host but emit ports as they are discovered.
    Uses a modified concurrent approach to stream results live.
    """
    import socket
    import concurrent.futures
    from src.scanner import (
        probe_port, resolve_target, guess_os_from_ttl, HostResult
    )

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
                # Stream this port immediately to the frontend
                emit("port", asdict(port_result))

            # Periodic progress updates
            if completed % max(1, total // 20) == 0:
                pct = 10 + int((completed / total) * 50)
                emit("progress", {
                    "percent": pct,
                    "status": f"Scanned {completed}/{total} ports…",
                    "open": len(result.ports),
                })

    result.ports.sort(key=lambda p: p.port)
    result.scan_duration_s = round(time.time() - start, 2)
    result.os_guess = guess_os_from_ttl(result.ttl)
    return result


def _vuln_to_dict(vm) -> dict:
    return {
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
                "exploit_available":c.exploit_available,
                "references":       c.references,
            }
            for c in vm.cves
        ],
    }
