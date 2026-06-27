"""
Reachability prober — determines post-compromise lateral movement potential.

After port discovery, this module builds a connectivity matrix between all
discovered (host, port) pairs. For single-target scans it's trivially same-host;
for CIDR sweeps across a private subnet it computes which services can likely
reach which other services post-compromise, enabling the fusion attack graph to
construct realistic multi-hop chains.

Logic:
  • Same-host post-exploitation is always assumed (compromising one service on
    a host grants access to its other ports).
  • Cross-host reachability is inferred from subnet position: if two hosts are
    on the same RFC 1918 private subnet (10.x, 172.16-31.x, 192.168.x), they
    can reach each other's services post-compromise.
  • Hosts on public IPs are treated as isolated (no lateral reachability) unless
    they share a subnet with other discovered hosts.
"""

from __future__ import annotations

import ipaddress
from typing import Optional


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _subnet_key(ip: str, mask: int = 24) -> Optional[str]:
    """Return the /mask network for an IP, or None if unparseable."""
    try:
        return str(ipaddress.ip_network(f"{ip}/{mask}", strict=False))
    except ValueError:
        return None


def build_reachability(hosts_ports: list[tuple[str, int]]) -> dict[str, set[str]]:
    """Given a list of (host, port) pairs discovered during scanning, return a dict
    mapping each ``"host:port"`` to the set of ``"other_host:other_port"`` strings
    it can reach post-compromise.

    The result is meant to populate ``exposure.reaches`` on fusion signals,
    enabling the attack graph to build cross-host edges.

    Rules:
      - Every entry on the same host reaches all other ports on that host.
      - If two hosts share a /24 private subnet, each of their ports reaches all
        ports on the other host.
      - Hosts on different public subnets or /24s have no cross-reachability.
    """
    if not hosts_ports:
        return {}

    # Group by host
    by_host: dict[str, set[int]] = {}
    for host, port in hosts_ports:
        by_host.setdefault(host, set()).add(port)

    # Pre-compute subnet keys
    host_subnets: dict[str, Optional[str]] = {h: _subnet_key(h) for h in by_host}

    result: dict[str, set[str]] = {}

    for host_a, ports_a in by_host.items():
        for pa in ports_a:
            key_a = f"{host_a}:{pa}"
            result.setdefault(key_a, set())

            # Same-host: all other ports on this host
            for pb in ports_a:
                if pb != pa:
                    result[key_a].add(f"{host_a}:{pb}")

            # Cross-host on same private subnet
            sub_a = host_subnets.get(host_a)
            if sub_a is None:
                continue
            for host_b, ports_b in by_host.items():
                if host_b == host_a:
                    continue
                sub_b = host_subnets.get(host_b)
                if sub_b is None:
                    continue
                if sub_a == sub_b and _is_private(host_a) and _is_private(host_b):
                    for pb in ports_b:
                        result[key_a].add(f"{host_b}:{pb}")

    return result


def hosts_ports_from_artifacts(art: dict) -> list[tuple[str, int]]:
    """Extract all discovered (host, port) pairs from scan artifacts.

    Handles both single-target scans (host_result) and CIDR sweeps (cidr_results).
    """
    pairs: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()

    def _add(host: str, port: int) -> None:
        k = (host, port)
        if k not in seen:
            seen.add(k)
            pairs.append(k)

    hr = art.get("host_result")
    if hr:
        host = hr.ip if hasattr(hr, "ip") and hr.ip else (hr.target if hasattr(hr, "target") else "")
        if host:
            ports = hr.ports if hasattr(hr, "ports") else []
            for p in ports:
                pnum = p.port if hasattr(p, "port") else (p if isinstance(p, int) else 0)
                if pnum:
                    _add(host, pnum)

    # CIDR results — list of HostResult tuples
    for r in (art.get("cidr_results") or []):
        host = r.ip if hasattr(r, "ip") and r.ip else (r.target if hasattr(r, "target") else "")
        if not host:
            host = getattr(r, "host", "")
            if not host:
                continue
        for p in (r.ports if hasattr(r, "ports") else []):
            pnum = p.port if hasattr(p, "port") else (p if isinstance(p, int) else 0)
            if pnum:
                _add(host, pnum)

    # Active subnet probe results (discovered adjacent hosts)
    for host, port in (art.get("probed_hosts") or []):
        if host and port:
            _add(host, port)

    return pairs
