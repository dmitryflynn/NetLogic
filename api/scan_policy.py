"""
NetLogic — SaaS scan target policy.

When the API runs in hosted / multi-tenant mode, block scan targets that would
turn the platform into an SSRF relay (cloud metadata, RFC1918, loopback, etc.).
Desktop and local CLI use remain unrestricted unless NETLOGIC_SAAS=1 is set.
"""
from __future__ import annotations

import ipaddress
import os
import socket

# Hostnames blocked in SaaS mode (loopback aliases + cloud metadata).
_BLOCKED_HOSTNAMES = frozenset({
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "instance-data",
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
})

# Supernets blocked in SaaS mode (IPv4 + IPv6 private/link-local/CGNAT/etc.).
_RESTRICTED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),   # IETF protocol assignments
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),  # benchmarking
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("100::/64"),       # discard
)


def saas_scan_restrictions_enabled() -> bool:
    """True when internal/metadata targets must be rejected at job submission."""
    flag = (os.environ.get("NETLOGIC_SAAS") or "").strip().lower()
    if flag in ("1", "true", "yes", "on"):
        return True
    if (os.environ.get("NETLOGIC_ENV") or "").strip().lower() in ("production", "prod"):
        return True
    from api import db  # noqa: PLC0415 — lazy; avoids import cycles at module load
    return db.is_enabled()


def _is_restricted_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    ):
        return True
    return any(
        addr in net for net in _RESTRICTED_NETWORKS if net.version == addr.version
    )


def _network_overlaps_restricted(
    net: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> bool:
    return any(net.overlaps(r) for r in _RESTRICTED_NETWORKS if r.version == net.version)


def _resolve_host_ips(host: str) -> set[str]:
    host = (host or "").strip().rstrip(".")
    if not host:
        return set()
    try:
        ipaddress.ip_address(host)
        return {host}
    except ValueError:
        pass
    ips: set[str] = set()
    try:
        for fam, _, _, _, sockaddr in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
            if fam in (socket.AF_INET, socket.AF_INET6) and sockaddr:
                ips.add(sockaddr[0])
    except OSError:
        pass
    return ips


def _check_literal_target(target: str) -> str | None:
    """Return an error message if *target* is blocked, else None."""
    target = target.strip()
    try:
        addr = ipaddress.ip_address(target)
        if _is_restricted_ip(addr):
            return (
                f"Scan target {target!r} is not permitted in hosted mode "
                "(private, loopback, link-local, or metadata-range addresses are blocked)."
            )
        return None
    except ValueError:
        pass

    try:
        net = ipaddress.ip_network(target, strict=False)
        if _network_overlaps_restricted(net):
            return (
                f"Scan target {target!r} overlaps a restricted network range and is "
                "not permitted in hosted mode."
            )
        return None
    except ValueError:
        pass

    labels = target.lower().rstrip(".").split(".")
    host_lower = target.lower().rstrip(".")
    if host_lower in _BLOCKED_HOSTNAMES:
        return f"Scan target {target!r} is not permitted in hosted mode."
    if labels and labels[0] in _BLOCKED_HOSTNAMES:
        return f"Scan target {target!r} is not permitted in hosted mode."

    return None


def validate_scan_target(target: str) -> None:
    """Raise ValueError if *target* violates SaaS scan policy."""
    if not saas_scan_restrictions_enabled():
        return

    err = _check_literal_target(target)
    if err:
        raise ValueError(err)

    # Hostname: reject if DNS fails (fail-closed) or resolves to restricted addresses.
    ips = _resolve_host_ips(target)
    if not ips:
        raise ValueError(
            f"Scan target {target!r} could not be resolved and is not permitted in hosted mode."
        )

    restricted = [ip for ip in ips if _is_restricted_ip(ipaddress.ip_address(ip))]
    if restricted:
        raise ValueError(
            f"Scan target {target!r} resolves to restricted address(es) "
            f"({', '.join(sorted(restricted)[:5])}) and is not permitted in hosted mode."
        )
