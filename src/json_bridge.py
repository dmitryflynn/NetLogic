"""
NetLogic - JSON Stream Bridge (GUI / API)
=========================================
Thin adapter: turns the shared scan engine's events into newline-delimited JSON
for the Electron frontend / REST API. It does NOT contain its own scan logic —
single-host scans delegate to src.engine.run_scan(), the SAME path the CLI uses,
so every feature added to the engine reaches the GUI automatically.

Each emitted line: {"type": "...", "data": {...}} or {"type": "error", "message": "..."}

API mode: pass emit_callback to redirect events to a caller-supplied function
instead of stdout. Signature: callback(event_type, data|None, message|None).
Thread-local so concurrent scans don't interfere.
"""

import json
import threading
from dataclasses import asdict

from src.scanner import scan_cidr
from src.cve_correlator import correlate

_tls = threading.local()


def emit(event_type: str, data=None, message: str = None):
    """Write/route a single JSON event."""
    callback = getattr(_tls, "emit_callback", None)
    if callback is not None:
        callback(event_type, data, message)
    else:
        obj = {"type": event_type}
        if message is not None:
            obj["message"] = message
        if data is not None:
            obj["data"] = data
        print(json.dumps(obj, default=str), flush=True)


def run_streaming_scan(target: str, ports: list, timeout: float,
                       threads: int, do_osint: bool, cidr: bool,
                       do_tls: bool = False, do_headers: bool = False,
                       do_stack: bool = False, do_dns: bool = False,
                       do_full: bool = False, do_probe: bool = False,
                       do_takeover: bool = False,
                       min_cvss: float = 4.0,
                       do_ai: bool = False, ssh_user: str = "", ssh_key: str = "",
                       ssh_pass: str = "", ssh_port: int = 22,
                       ai_key: str = "", ai_provider: str = "", ai_model: str = "",
                       ai_base_url: str = "", org_id: str = "",
                       deep_probe: bool = False,
                       do_reason: bool = False, do_since_last: bool = False,
                       do_multi_host: bool = False, do_active_validate: bool = False,
                       do_ai_driven: bool = False,
                       do_ai_agent: bool = False,
                       agent_depth: bool = False,
                       allow_crash_probes: bool = False,
                       agent_max_steps: int = 12,
                       agent_max_requests: int = 40,
                       emit_callback=None,
                       **extra):
    """Execute a scan and stream results as JSON events via the shared engine.

    emit_callback: optional callable(event_type, data, message) used by the REST
    API layer; None for normal CLI/Electron usage (stdout).
    Accepts **extra for forward-compatibility with future scan options.
    """
    if emit_callback is not None:
        _tls.emit_callback = emit_callback
    try:
        if cidr:
            _run_cidr(target, ports, timeout, threads, do_osint, do_full, min_cvss)
        else:
            from types import SimpleNamespace
            from src.engine import run_scan
            # Build the same options object the CLI passes to the engine.
            args = SimpleNamespace(
                timeout=timeout, threads=threads, min_cvss=min_cvss,
                full=do_full, tls=do_tls, headers=do_headers, stack=do_stack,
                dns=do_dns, osint=do_osint, takeover=do_takeover, probe=do_probe,
                ai=do_ai, ssh_user=ssh_user, ssh_key=ssh_key, ssh_pass=ssh_pass, ssh_port=ssh_port,
                ai_key=ai_key, ai_provider=ai_provider, ai_model=ai_model, ai_base_url=ai_base_url,
                org_id=org_id,
                deep_probe=deep_probe,
                reason=do_reason, since_last=do_since_last, multi_host=do_multi_host,
                active_validate=do_active_validate, ai_driven=do_ai_driven,
                ai_agent=do_ai_agent or agent_depth,
                agent_depth=agent_depth,
                allow_crash_probes=allow_crash_probes,
                agent_max_steps=agent_max_steps, agent_max_requests=agent_max_requests,
                no_diff=False, no_traceroute=False, out=".",
            )
            if deep_probe:
                from src.deep import run_deep_scan
                run_deep_scan(target, ports, args, emit=emit)
            else:
                run_scan(target, ports, args, emit=emit)
    except Exception as e:
        # Cooperative cancel from the API layer (JobCancelled raised inside the
        # emit callback) must propagate — converting it to an "error" event would
        # re-enter the cancelled callback and double-raise / log a false failure.
        if type(e).__name__ == "JobCancelled":
            raise
        try:
            emit("error", message=str(e))
        except Exception:
            # Secondary failure while reporting the primary error (e.g. cancel
            # raced mid-emit). Don't mask the original exception.
            pass
    finally:
        _tls.emit_callback = None


def _run_cidr(target, ports, timeout, threads, do_osint, do_full, min_cvss):
    """Lightweight per-host streaming for CIDR sweeps (host + ports + vulns)."""
    from src.engine import _vuln_to_dict
    emit("progress", {"percent": 5, "status": f"CIDR scan {target}…"})
    hosts = scan_cidr(target, ports=ports, max_workers=threads, timeout=timeout)
    total_p = total_v = 0
    for hr in hosts:
        emit("host", asdict(hr))
        for p in hr.ports:
            total_p += 1
            emit("port", {"target": hr.ip, **asdict(p)})
        for vm in correlate(hr.ports, min_cvss=min_cvss, verbose=False):
            total_v += 1
            emit("vuln", {"target": hr.ip, **_vuln_to_dict(vm)})

    if do_osint or do_full:
        from src.osint import run_osint
        emit("progress", {"percent": 92, "status": "Passive OSINT on base target…"})
        try:
            o = run_osint(target, ip=hosts[0].ip if hosts else None)
            emit("osint", {
                "dns_records": [asdict(r) for r in o.dns_records],
                "subdomains": [asdict(s) for s in o.subdomains],
                "technologies": o.technologies, "emails": o.emails,
                "asn_info": asdict(o.asn_info) if o.asn_info else None,
            })
        except Exception as e:
            emit("log", {"text": f"OSINT: {e}", "level": "warn"})

    emit("done", {"hosts": len(hosts), "ports": total_p, "vulns": total_v,
                  "duration": getattr(hosts[-1], "scan_duration_s", 0) if hosts else 0})
