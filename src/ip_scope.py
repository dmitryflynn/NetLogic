"""IP / reply attribution helpers — keep remote scans from attributing LAN noise.

UDP tools (SSDP, generic udp_probe, scanner UDP fingerprinting) must only treat a
response as evidence about the *target* when the source address is the target (or
one of its resolved A/AAAA records). Accepting any datagram on the socket after a
unicast send is how 192.168.0.1 UPnP gateways get reported on Cloudflare edges.
"""
from __future__ import annotations

import ipaddress
import socket
from functools import lru_cache
from typing import Iterable


def is_private_or_local(ip: str) -> bool:
    """True for RFC1918, loopback, link-local, CGNAT, etc. — never the public target."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return True  # unparseable → treat as untrusted noise
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


@lru_cache(maxsize=256)
def resolve_host_ips(host: str) -> frozenset[str]:
    """Resolve host to IPv4/IPv6 address strings. Empty if resolution fails."""
    host = (host or "").strip()
    if not host:
        return frozenset()
    # Already an IP?
    try:
        ipaddress.ip_address(host)
        return frozenset({host})
    except ValueError:
        pass
    out: set[str] = set()
    try:
        for fam, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            if fam in (socket.AF_INET, socket.AF_INET6) and sockaddr:
                out.add(sockaddr[0])
    except OSError:
        pass
    return frozenset(out)


def target_ip_set(host: str, extra: Iterable[str] | None = None) -> set[str]:
    ips = set(resolve_host_ips(host))
    if extra:
        for x in extra:
            if x:
                ips.add(str(x).strip())
    # Literal host if it's an IP
    try:
        ipaddress.ip_address(host)
        ips.add(host)
    except ValueError:
        pass
    return ips


def reply_from_target(
    reply_ip: str,
    target_host: str,
    *,
    allowed_ips: Iterable[str] | None = None,
    allow_private_when_target_private: bool = True,
) -> bool:
    """Return True only if reply_ip is attributable to target_host.

    Rules:
      1. reply must parse as an IP.
      2. If target is a public host, private/local replies are ALWAYS rejected
         (the classic 192.168.0.1 UPnP false positive).
      3. reply must be in the resolved IP set for the target (or ``allowed_ips``).
    """
    reply = (reply_ip or "").strip()
    if not reply:
        return False
    try:
        ipaddress.ip_address(reply)
    except ValueError:
        return False

    allowed = set(target_ip_set(target_host, allowed_ips))
    if not allowed:
        # Unresolved public hostname: still reject private replies; accept
        # nothing else (fail closed) — better miss than invent remote UPnP.
        return False

    target_is_private = all(is_private_or_local(a) for a in allowed)
    if is_private_or_local(reply) and not (allow_private_when_target_private and target_is_private):
        return False

    return reply in allowed


def normalize_finding_id(raw_id: str, title: str = "") -> str:
    """Canonical agent finding id so free-form model labels collapse.

    Examples:
      ssdp-exposed / ssdp-exposure / upnp-exposed → ssdp_exposed
      tech:cloudflare / tech-cloudflare / cloudflare-protection → tech_cloudflare
      CVE-2021-31166 / cve-2021-31166-CONFIRMED → cve-2021-31166
    """
    import re

    s = (raw_id or title or "finding").strip().lower()
    s = s.replace(":", "_").replace("/", "_").replace(" ", "_")
    s = re.sub(r"[^a-z0-9_.-]+", "-", s)
    s = re.sub(r"[-_]+", "-", s).strip("-_")

    # CVE normalize
    m = re.search(r"(cve-?\d{4}-?\d+)", s)
    if m:
        cve = m.group(1).replace("cve", "cve-").replace("--", "-")
        cve = re.sub(r"cve-?(\d{4})-?(\d+)", r"cve-\1-\2", cve)
        return cve

    # SSDP / UPnP collapse
    if any(k in s for k in ("ssdp", "upnp")):
        return "ssdp_exposed"

    # Tech / WAF inventory — only when clearly inventory-shaped (not bare product ids like "iis")
    _CDN_WAF = ("cloudflare", "vercel", "akamai", "fastly", "cloudfront")
    _SERVER = ("nginx", "apache", "iis")
    if s.startswith("tech-") or s.startswith("tech_") or "protection" in s or "waf" in s:
        for tech in _CDN_WAF + _SERVER:
            if tech in s:
                return f"tech_{tech}"
    # Bare CDN/WAF product names (common free-form asserts)
    for tech in _CDN_WAF:
        if s == tech or s.startswith(tech + "-") or s.startswith(tech + "_"):
            return f"tech_{tech}"

    # Strip common noise suffixes (after tech detection so cloudflare-protection → tech_)
    for suf in ("-confirmed", "_confirmed", "-exposure", "_exposure", "-exposed", "_exposed",
                "-protection", "_protection", "-device", "_device", "-discovery", "_discovery"):
        if s.endswith(suf):
            s = s[: -len(suf)]
    return s[:80] or "finding"
