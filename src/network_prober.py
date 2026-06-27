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


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


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

    if not target_ip or not _is_private(target_ip):
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
                  timeout: float = 1.0, max_workers: int = 100) -> list[ProbedHost]:
    """Probe specific *targets* on specific *ports* — used by AI-directed probing.

    Skips the live-host sweep; tests each target:port pair directly.
    Returns all open (host, port) pairs discovered.
    """
    if not targets or not ports:
        return []
    all_args = [(h, p, timeout) for h in targets for p in ports]
    found: list[ProbedHost] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        fut_map = {pool.submit(_probe_port, a): a for a in all_args}
        for fut in as_completed(fut_map):
            r = fut.result()
            if r:
                found.append(r)
    return found
