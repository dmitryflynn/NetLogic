"""
NetLogic - Network Topology Context
===================================
Per-host findings tell you what's wrong with ONE box; topology tells you how a box
sits in a network — which is what lets an analyst (or the AI) reason about lateral
movement and blast radius, not just isolated CVEs.

Collects:
  • Reverse DNS (PTR) — the host's real name / role hints
  • IPv6 (AAAA) addresses — a second attack surface often left unfiltered
  • Traceroute — network path + hop count (proximity, intermediate devices, CDN edge)
  • ASN / org / country — hosting context (cloud vs on-prem vs ISP)

Stdlib + the system traceroute. Read-only, fails soft.
"""
from __future__ import annotations

import re
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Topology:
    target: str
    ip: Optional[str] = None
    ptr: Optional[str] = None                       # reverse-DNS hostname
    ipv6: list[str] = field(default_factory=list)
    traceroute_hops: list[str] = field(default_factory=list)   # hop IPs in order
    hop_count: Optional[int] = None
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    country: Optional[str] = None
    notes: list[str] = field(default_factory=list)


def _reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _resolve_ipv6(target: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_INET6)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []


# Both `tracert` (Windows) and `traceroute` (Unix) send this many probes per hop
# by default, and the per-probe wait (-w) applies to EACH probe. The overall
# subprocess timeout must therefore allow for max_hops × probes × per_hop, or a
# slow path can trip TimeoutExpired before the trace finishes and we lose the
# whole result.
_PROBES_PER_HOP = 3

_HOP_LINE_RE = re.compile(r"\s*\d+\s")
_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def _parse_traceroute(stdout: str) -> list[str]:
    """Parse tracert/traceroute stdout into an ordered list of hop IPs.

    Works for both Windows (`tracert -d`: ``  1   <1 ms  ...  10.0.0.1``) and
    Unix (`traceroute -n`: `` 1  10.0.0.1  0.4 ms ...``). A hop with no IP (a
    ``* * *`` / "Request timed out" line — the router didn't answer the probe)
    becomes ``"*"``. Trailing non-responding hops are trimmed so the returned
    list ends at the last hop that actually answered: that keeps ``hop_count``
    equal to the path depth at which we last had visibility, instead of padding
    it out to ``max_hops`` with placeholders the OS appended after giving up.
    """
    hops: list[str] = []
    for line in (stdout or "").splitlines():
        # A hop line starts with the hop number; header/summary lines don't.
        if not _HOP_LINE_RE.match(line):
            continue
        ips = _IP_RE.findall(line)
        # Take the last IP-looking token (latency columns never have 4 octets
        # under -d/-n, so the trailing token is the hop address).
        hops.append(ips[-1] if ips else "*")
    # Trim trailing "*" placeholders (path beyond last responder).
    while hops and hops[-1] == "*":
        hops.pop()
    return hops


def _traceroute(target: str, max_hops: int = 8, timeout_ms: int = 600) -> list[str]:
    """Run the system traceroute and return the ordered list of hop IPs.

    Fails soft to ``[]`` on any timeout / OS error / missing binary.
    """
    if sys.platform.startswith("win"):
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(timeout_ms), target]
    else:
        cmd = ["traceroute", "-n", "-m", str(max_hops),
               "-w", str(max(1, timeout_ms // 1000)), target]
    # max_hops × probes × per-hop wait, plus startup/DNS slack. Bounded so the
    # call can never hang the scan even if the binary stalls.
    overall = max_hops * _PROBES_PER_HOP * (timeout_ms / 1000.0) + 10
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=overall)
    except (subprocess.TimeoutExpired, OSError):
        return []
    except Exception:  # noqa: BLE001 — never let traceroute crash the scan
        return []
    return _parse_traceroute(proc.stdout or "")


def _asn_lookup(ip: str, timeout: float = 5.0) -> tuple:
    """Best-effort ASN/org/country via the free ip-api.com JSON endpoint (no key)."""
    if not ip:
        return None, None, None
    try:
        import json  # noqa: PLC0415
        import urllib.request  # noqa: PLC0415
        url = f"https://ip-api.com/json/{ip}?fields=status,country,isp,org,as"
        req = urllib.request.Request(url, headers={"User-Agent": "NetLogic/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            d = json.loads(resp.read().decode("utf-8"))
        if d.get("status") != "success":
            return None, None, None
        return d.get("as"), (d.get("org") or d.get("isp")), d.get("country")
    except Exception:
        return None, None, None


def map_topology(target: str, ip: Optional[str] = None, *,
                 do_traceroute: bool = True, timeout: float = 5.0) -> Topology:
    """Gather network context for a target. ip may be passed to avoid re-resolving."""
    if not ip:
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            ip = None
    topo = Topology(target=target, ip=ip)

    if ip:
        topo.ptr = _reverse_dns(ip)
        topo.asn, topo.asn_org, topo.country = _asn_lookup(ip, timeout)

    topo.ipv6 = _resolve_ipv6(target)
    if topo.ipv6:
        topo.notes.append(f"IPv6 reachable ({len(topo.ipv6)} address(es)) — a second "
                          "attack surface that is often firewalled separately from IPv4.")

    if do_traceroute and ip:
        hops = _traceroute(target)
        responded = [h for h in hops if h != "*"]
        if responded:
            # Classify hops: private/local addresses are the *scanner's* path
            # (home router, ISP CPE), not the target's infrastructure. Keep them
            # for diagnostics but annotate so reports don't look like the target
            # is dual-homed on 192.168.0.1.
            try:
                from src.ip_scope import is_private_or_local  # noqa: PLC0415
            except Exception:  # pragma: no cover
                def is_private_or_local(x: str) -> bool:  # type: ignore
                    return str(x).startswith(("10.", "192.168.", "172."))

            public_hops = [h for h in responded if not is_private_or_local(h)]
            private_hops = [h for h in responded if is_private_or_local(h)]
            topo.traceroute_hops = hops
            topo.hop_count = len(hops)
            if private_hops and public_hops:
                topo.notes.append(
                    f"Path: {len(private_hops)} local/scanner hop(s) then "
                    f"{len(public_hops)} public hop(s) toward target "
                    f"(private addresses are the probe path, not target LAN)."
                )
            elif private_hops and not public_hops:
                topo.notes.append(
                    f"{len(private_hops)} hop(s) answered but all are private/local "
                    f"(scanner network only — public path to target not visible)."
                )
            else:
                topo.notes.append(
                    f"{len(responded)} responding hop(s) over {len(hops)} "
                    "network hop(s) to target — network path mapped."
                )
        else:
            # No hop answered (all "*", or traceroute unavailable / failed).
            topo.notes.append("Traceroute path not traceable (ICMP/UDP probes filtered "
                              "or traceroute unavailable).")

    return topo
