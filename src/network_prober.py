"""
NetLogic - Active Network Prober
Scans adjacent hosts on the same /24 subnet to discover reachable services
for cross-host attack graph edges. Pure Python sockets — no GPL dependencies.

Two-phase approach:
  1. Live-host sweep — TCP connect on a few common ports to find active hosts.
  2. Full port scan — scan all common ports on confirmed-live hosts.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional


# Ports for the live-host sweep (fast — just confirm host is reachable)
_SWEEP_PORTS = [22, 80, 443, 8080]

# Full common-port list for scanning confirmed-live hosts
_COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    389, 443, 445, 993, 995, 1433, 1521, 2049, 2375, 2379,
    3306, 3389, 5432, 5900, 6379, 6443, 8080, 8443, 9090,
    9200, 11211, 15672, 27017,
]


@dataclass
class ProbedHost:
    ip: str
    port: int


@dataclass
class SubnetProbeResult:
    target_ip: str
    subnet: str = ""
    hosts: list[ProbedHost] = field(default_factory=list)
    live_host_count: int = 0
    scan_duration_s: float = 0.0


_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

# Cap AI-directed cartesian products (hosts × ports) so a prompt cannot
# explode into tens of thousands of connect()s.
_MAX_PROBE_PAIRS = 256


def _is_rfc1918(ip: str) -> bool:
    """True only for RFC1918 — not loopback, link-local, or CGNAT."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _RFC1918)


def _subnet_of(target_ip: str, prefix: int = 24) -> Optional[str]:
    try:
        return str(ipaddress.ip_network(f"{target_ip}/{prefix}", strict=False))
    except ValueError:
        return None


def _tcp_connect(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _sweep_host(host: str, timeout: float) -> Optional[str]:
    """Return host if any sweep port is open, else None."""
    for port in _SWEEP_PORTS:
        if _tcp_connect(host, port, timeout):
            return host
    return None


def _probe_port(args: tuple[str, int, float]) -> Optional[ProbedHost]:
    host, port, timeout = args
    return ProbedHost(ip=host, port=port) if _tcp_connect(host, port, timeout) else None


def probe_subnet(target_ip: str, timeout: float = 1.0, max_workers: int = 100) -> SubnetProbeResult:
    """Scan the /24 subnet of *target_ip* for common open ports.

    Skips *target_ip* itself (already scanned by the main port scan).
    Returns only when all probes complete.
    """
    start = time.time()
    result = SubnetProbeResult(target_ip=target_ip)

    if not target_ip or not _is_rfc1918(target_ip):
        return result

    net_str = _subnet_of(target_ip)
    if not net_str:
        return result
    result.subnet = net_str

    net = ipaddress.ip_network(net_str, strict=False)
    remote_hosts = [str(h) for h in net.hosts() if str(h) != target_ip]
    if not remote_hosts:
        return result

    # Phase 1: live-host sweep
    sweep_pool = min(max_workers, 50)
    live_hosts: set[str] = set()
    with ThreadPoolExecutor(max_workers=sweep_pool) as pool:
        fut_map = {pool.submit(_sweep_host, h, timeout): h for h in remote_hosts}
        for fut in as_completed(fut_map):
            host = fut.result()
            if host:
                live_hosts.add(host)
    result.live_host_count = len(live_hosts)

    if live_hosts:
        # Phase 2: full port scan on live hosts
        all_args = [(h, p, timeout) for h in sorted(live_hosts) for p in _COMMON_PORTS]
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            fut_map2 = {pool.submit(_probe_port, a): a for a in all_args}
            for fut in as_completed(fut_map2):
                found = fut.result()
                if found:
                    result.hosts.append(found)

    result.scan_duration_s = time.time() - start
    return result


def probe_targets(targets: list[str], ports: list[int],
                  timeout: float = 1.0, max_workers: int = 100,
                  allowed_net: Optional[str] = None, threads: Optional[int] = None) -> list[ProbedHost]:
    """Probe specific *targets* on specific *ports* — used by AI-directed probing.

    Skips the live-host sweep; tests each target:port pair directly.
    Only RFC1918 (or *allowed_net*) addresses are probed, and the cartesian
    product is capped at ``_MAX_PROBE_PAIRS``.
    """
    if threads is not None:
        max_workers = threads
    if isinstance(targets, str):
        targets = [targets]
    if not targets or not ports:
        return []
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = list(_RFC1918)
    if allowed_net:
        try:
            nets = [ipaddress.ip_network(allowed_net, strict=False)]
        except ValueError:
            nets = list(_RFC1918)
    filtered: list[str] = []
    seen: set[str] = set()
    for h in targets:
        host = str(h or "").strip()
        if not host or host in seen:
            continue
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            continue
        if not any(addr in net for net in nets):
            continue
        seen.add(host)
        filtered.append(host)
    ports_clean: list[int] = []
    for p in ports:
        try:
            pi = int(p)
        except (TypeError, ValueError):
            continue
        if 1 <= pi <= 65535 and pi not in ports_clean:
            ports_clean.append(pi)
    all_args = [(h, p, timeout) for h in filtered for p in ports_clean][:_MAX_PROBE_PAIRS]
    if not all_args:
        return []
    found: list[ProbedHost] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        fut_map = {pool.submit(_probe_port, a): a for a in all_args}
        for fut in as_completed(fut_map):
            r = fut.result()
            if r:
                found.append(r)
    return found
