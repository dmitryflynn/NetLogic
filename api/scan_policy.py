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

_METADATA_HOSTNAMES = frozenset({
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "instance-data",
})

# AWS IMDSv2 IPv6 (not link-local; ULA).
_AWS_IMDS_V6 = ipaddress.ip_address("fd00:ec2::254")

# Hostnames blocked in SaaS mode (loopback aliases + cloud metadata).
_BLOCKED_HOSTNAMES = frozenset({
    *_METADATA_HOSTNAMES,
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


def _canonical_ip(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Treat IPv4-mapped IPv6 (:ffff:x.x.x.x) as the embedded IPv4 address."""
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _is_restricted_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    addr = _canonical_ip(addr)
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


def normalize_llm_base_url(url: str) -> str:
    """Validate a tenant-supplied LLM base URL and return it stripped.

    Desktop: HTTPS anywhere that is not link-local/metadata; HTTP only to
    loopback or RFC1918 (local Ollama) — never 169.254.x.x / cloud metadata.
    Hosted: HTTPS only, and the host must pass ``validate_scan_target`` so the
    API process cannot be used as an SSRF relay against IMDS or the VPC.
    """
    from urllib.parse import urlparse  # noqa: PLC0415

    url = (url or "").strip()
    if not url:
        return ""
    if not (url.startswith("https://") or url.startswith("http://")):
        raise ValueError("URL must start with http:// or https://")

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"URL scheme {parsed.scheme!r} is not permitted")
    host = (parsed.hostname or "").strip().strip("[]")
    if not host:
        raise ValueError("URL is missing a host")

    # Cloud metadata / link-local is never a legitimate LLM endpoint — block
    # even on desktop so a GUI running on a cloud VM cannot be pointed at IMDS.
    meta_err = _metadata_or_link_local_error(host)
    if meta_err:
        raise ValueError(meta_err)

    if saas_scan_restrictions_enabled():
        if parsed.scheme != "https":
            raise ValueError(
                "HTTP LLM base URLs are not permitted in hosted mode; use https://"
            )
        validate_scan_target(host)
        return url.rstrip("/")

    if parsed.scheme == "https":
        return url.rstrip("/")

    # Desktop HTTP: loopback and RFC1918 only (local/LAN Ollama). Hostnames
    # other than localhost must be an IP — no DNS-rebinding HTTP endpoints.
    if host not in ("localhost", "127.0.0.1", "::1"):
        try:
            addr = _canonical_ip(ipaddress.ip_address(host))
        except ValueError as exc:
            raise ValueError(
                "HTTP LLM base URL must be an IP address in a private range "
                "or localhost; use https:// for hostnames"
            ) from exc
        if not (addr.is_loopback or (addr.is_private and not addr.is_link_local)):
            raise ValueError(
                "HTTP LLM base URL must point to localhost, 127.0.0.1, "
                "or a private IP (e.g. 10.x.x.x, 172.16-31.x.x, 192.168.x.x)"
            )
    return url.rstrip("/")


def _metadata_or_link_local_error(host: str) -> str | None:
    """Return an error if *host* is cloud metadata or IPv4/IPv6 link-local."""
    host_lower = (host or "").strip().lower().rstrip(".")
    labels = host_lower.split(".")
    if host_lower in _METADATA_HOSTNAMES or (labels and labels[0] in _METADATA_HOSTNAMES):
        return f"LLM base URL host {host!r} is not permitted (cloud metadata)."
    addr = None
    try:
        addr = _canonical_ip(ipaddress.ip_address(host))
    except ValueError:
        # Decimal/hex IPv4 encodings (2852039166 → 169.254.169.254)
        if host_lower.isdigit():
            try:
                addr = _canonical_ip(ipaddress.ip_address(int(host_lower)))
            except (ValueError, OverflowError):
                addr = None
        elif host_lower.startswith("0x"):
            try:
                addr = _canonical_ip(ipaddress.ip_address(int(host_lower, 16)))
            except (ValueError, OverflowError):
                addr = None
    if addr is None:
        return None
    if addr == _AWS_IMDS_V6:
        return f"LLM base URL host {host!r} is not permitted (cloud metadata)."
    if addr.is_link_local or addr in ipaddress.ip_network("169.254.0.0/16"):
        return f"LLM base URL host {host!r} is not permitted (link-local / metadata range)."
    return None
