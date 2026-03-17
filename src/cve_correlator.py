"""
NetLogic - CVE Correlation Engine (NVD-powered)
=======================================================
Replaces hardcoded CVE signatures with live NVD API lookups.
Results are cached to disk (~/.netlogic/nvd_cache/) for 24 hours.

Flow:
  1. scan_host() discovers open ports with service banners
  2. correlate() extracts product/version from each banner
  3. nvd_lookup.lookup_cves_for_service() queries NVD (or cache)
  4. Results are version-filtered, CVSS-scored, and returned
"""

import re
import os
import sys
from dataclasses import dataclass, field
from typing import Optional

from src.nvd_lookup import (
    lookup_cves_for_service,
    NVDCve,
    cache_stats,
    PRODUCT_KEYWORD_MAP,
)


# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class CVE:
    """Unified CVE model — wraps NVDCve for reporter compatibility."""
    id: str
    description: str
    cvss_score: float
    severity: str
    vector: str
    published: str
    references: list[str] = field(default_factory=list)
    exploit_available: bool = False
    kev: bool = False
    cwe: str = ""
    version_range: str = ""


@dataclass
class VulnMatch:
    port: int
    service: str
    product: Optional[str]
    version: Optional[str]
    cves: list[CVE] = field(default_factory=list)
    risk_score: float = 0.0
    notes: list[str] = field(default_factory=list)
    source: str = "nvd"    # "nvd" | "cache" | "offline"


# ─── Banner → Product/Version Extraction ─────────────────────────────────────

# Regex patterns to extract clean product/version from raw banner strings
BANNER_PATTERNS = [
    # SSH: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    (r"openssh[_\s]+([\d.p]+)",         "openssh"),
    (r"SSH-[\d.]+-OpenSSH[_\s]+([\d.p]+)", "openssh"),

    # Apache: "Apache/2.4.51 (Ubuntu)" or "Apache/2.4.51"
    (r"Apache/([\d.]+)",                 "apache"),
    (r"apache.{0,10}?([\d]+\.[\d]+\.[\d]+)", "apache"),

    # nginx: "nginx/1.18.0"
    (r"nginx/([\d.]+)",                  "nginx"),

    # IIS: "Microsoft-IIS/10.0"
    (r"Microsoft-IIS/([\d.]+)",          "iis"),
    (r"IIS/([\d.]+)",                    "iis"),

    # PHP: "PHP/8.1.2"
    (r"PHP/([\d.]+)",                    "php"),
    (r"X-Powered-By: PHP/([\d.]+)",      "php"),

    # MySQL/MariaDB
    (r"([\d.]+)-MariaDB",                "mariadb"),
    (r"mysql.{0,20}?([\d]+\.[\d]+\.[\d]+)", "mysql"),

    # PostgreSQL
    (r"PostgreSQL ([\d.]+)",             "postgresql"),

    # Redis
    (r"redis_version:([\d.]+)",          "redis"),
    (r"Redis ([\d.]+)",                  "redis"),

    # MongoDB
    (r"\"version\":\"([\d.]+)\"",        "mongodb"),
    (r"MongoDB ([\d.]+)",                "mongodb"),

    # Elasticsearch
    (r"\"number\":\"([\d.]+)\"",         "elasticsearch"),

    # vsftpd
    (r"vsftpd ([\d.]+)",                 "vsftpd"),
    (r"vsFTPd ([\d.]+)",                 "vsftpd"),

    # ProFTPD
    (r"ProFTPD ([\d.]+)",                "proftpd"),

    # Tomcat
    (r"Apache Tomcat/([\d.]+)",          "tomcat"),
    (r"Tomcat/([\d.]+)",                 "tomcat"),

    # OpenSSL (from TLS banners)
    (r"OpenSSL/([\d.]+[a-z]?)",          "openssl"),

    # Exim
    (r"Exim ([\d.]+)",                   "exim"),

    # Postfix
    (r"Postfix ESMTP",                   "postfix"),

    # Dovecot
    (r"Dovecot",                         "dovecot"),

    # Samba
    (r"Samba ([\d.]+)",                  "samba"),

    # OpenVPN
    (r"OpenVPN ([\d.]+)",                "openvpn"),

    # WordPress
    (r"WordPress/([\d.]+)",              "wordpress"),
    (r"wp-content",                      "wordpress"),

    # Drupal
    (r"Drupal ([\d.]+)",                 "drupal"),
    (r"X-Generator: Drupal ([\d.]+)",    "drupal"),

    # Generic version extraction fallback — service name + nearby version
    (r"([\d]+\.[\d]+\.[\d]+)",           None),  # pure version, no product
]


def extract_product_version(banner_obj) -> tuple[Optional[str], Optional[str]]:
    """
    Extract (product, version) from a ServiceBanner or string.
    Tries structured fields first, falls back to regex on raw banner.
    """
    # Structured banner (from scanner.py ServiceBanner dataclass)
    if hasattr(banner_obj, 'product') and banner_obj.product:
        product = banner_obj.product.lower().strip()
        version = getattr(banner_obj, 'version', None)

        # Skip generic HTTP product info (e.g., "http 1.1") and instead
        # fall back to service+port inference.
        if product.startswith('http'):
            return None, None

        return product, version

    # Raw string banner
    raw = getattr(banner_obj, 'raw', '') or str(banner_obj) or ''
    if not raw:
        return None, None

    raw_lower = raw.lower()

    for pattern, product_name in BANNER_PATTERNS:
        m = re.search(pattern, raw, re.IGNORECASE)
        if m:
            version = m.group(1) if m.lastindex and m.lastindex >= 1 else None
            # If no product_name in pattern, try to infer from raw
            if product_name is None:
                # Try to match known products in the raw string (skip generic placeholders)
                for key, mapped in PRODUCT_KEYWORD_MAP.items():
                    if mapped is None:
                        continue
                    if key in raw_lower:
                        return key, version
                return None, version
            return product_name, version

    # Last resort: check if any known product name appears in the banner
    for key, mapped in PRODUCT_KEYWORD_MAP.items():
        if mapped is None:
            continue
        if len(key) > 3 and key in raw_lower:
            # Try to find a version number nearby
            vm = re.search(r'[\s/v]([\d]+\.[\d]+(?:\.[\d]+)?)', raw)
            version = vm.group(1) if vm else None
            return key, version

    return None, None


def infer_product_from_service(service: str, port: int) -> Optional[str]:
    """
    When no banner is available, infer likely product from service name and port.
    Used for CVE lookups when banner grabbing failed.
    """
    service_lower = (service or "").lower()
    port_map = {
        22:    "openssh",
        80:    "apache",
        443:   "apache",
        8080:  "tomcat",
        8443:  "tomcat",
        3306:  "mysql",
        5432:  "postgresql",
        6379:  "redis",
        27017: "mongodb",
        9200:  "elasticsearch",
        11211: "memcached",
        21:    "vsftpd",
        25:    "postfix",
        1433:  "mssql",
    }
    # Only return service name if it maps to a real product (not a generic placeholder)
    mapped = PRODUCT_KEYWORD_MAP.get(service_lower)
    if mapped:
        return service_lower
    return port_map.get(port)


# ─── Risk Scoring ─────────────────────────────────────────────────────────────

def calculate_risk(cves: list[CVE]) -> float:
    """
    Weighted risk score 0–10 based on:
    - Max CVSS score
    - Number of CRITICAL/HIGH CVEs
    - CISA KEV presence (actively exploited)
    """
    if not cves:
        return 0.0

    max_cvss = max(c.cvss_score for c in cves)
    kev_bonus = 1.5 if any(c.kev for c in cves) else 0.0
    critical_count = sum(1 for c in cves if c.severity == "CRITICAL")
    high_count = sum(1 for c in cves if c.severity == "HIGH")
    breadth_bonus = min(1.0, critical_count * 0.3 + high_count * 0.1)

    return min(10.0, max_cvss + kev_bonus + breadth_bonus)


# ─── NVD → CVE Model Conversion ──────────────────────────────────────────────

def _nvd_to_cve(nvd: NVDCve) -> CVE:
    ver_range = ""
    if nvd.version_start or nvd.version_end:
        parts = []
        if nvd.version_start:
            parts.append(f">= {nvd.version_start}")
        if nvd.version_end:
            op = "<=" if nvd.version_end_including else "<"
            parts.append(f"{op} {nvd.version_end}")
        ver_range = ", ".join(parts)

    return CVE(
        id=nvd.id,
        description=nvd.description,
        cvss_score=nvd.cvss_score,
        severity=nvd.severity,
        vector=nvd.vector,
        published=nvd.published,
        references=nvd.references,
        exploit_available=nvd.kev,
        kev=nvd.kev,
        cwe=nvd.cwe,
        version_range=ver_range,
    )


# ─── Main Correlator ──────────────────────────────────────────────────────────

def correlate(ports, min_cvss: float = 4.0, verbose: bool = False) -> list[VulnMatch]:
    """
    Main entry point. Takes list of PortResult objects, returns VulnMatch list.

    Args:
        ports:     List of PortResult objects from scanner.py
        min_cvss:  Minimum CVSS score to include (default 4.0 = MEDIUM+)
        verbose:   Print lookup status to stdout

    Returns:
        List of VulnMatch, one per port that has CVEs, sorted by risk score
    """
    results = []

    # Check NVD availability on first run
    from src.nvd_lookup import nvd_is_available, _nvd_unavailable
    if _nvd_unavailable or not nvd_is_available():
        print("  [!] NVD API unreachable — using built-in offline signatures", file=sys.stderr)
        if verbose:
            print("  [!] NVD API unreachable — using built-in offline signatures")
        return _offline_correlate(ports, min_cvss)

    for port_result in ports:
        port    = port_result.port
        service = getattr(port_result, 'service', '') or ''
        banner  = getattr(port_result, 'banner', None)

        # Extract product and version
        product, version = None, None
        if banner:
            product, version = extract_product_version(banner)

        # Treat generic HTTP/HTTPS banner values as unknown so we can infer from port
        if product and product.startswith('http'):
            product = None
            version = None

        if verbose and product:
            print(f"Correlating port {port}: product={product!r} version={version!r}", file=sys.stderr)

        # Fall back to service/port inference if no banner
        if not product:
            product = infer_product_from_service(service, port)
            if verbose and product:
                print(f"Inferred product from port {port}: {product!r}", file=sys.stderr)

        if not product:
            continue

        if verbose:
            ver_str = f" {version}" if version else " (version unknown)"
            print(f"  [NVD] {port}/{service} → {product}{ver_str}...", end=" ", flush=True)

        # Query NVD (or cache)
        nvd_cves = lookup_cves_for_service(product, version, min_cvss=min_cvss)

        if verbose:
            print(f"{len(nvd_cves)} CVEs")

        if not nvd_cves:
            continue

        cves = [_nvd_to_cve(c) for c in nvd_cves]
        risk = calculate_risk(cves)

        notes = []
        if not version:
            notes.append("Version unknown — showing all known CVEs for this product")
        if any(c.kev for c in cves):
            kev_ids = [c.id for c in cves if c.kev]
            notes.append(f"★ CISA KEV: {', '.join(kev_ids[:3])} — actively exploited in the wild")

        results.append(VulnMatch(
            port=port,
            service=service,
            product=product,
            version=version,
            cves=cves,
            risk_score=risk,
            notes=notes,
            source="nvd",
        ))

    # Sort by risk score descending
    results.sort(key=lambda m: m.risk_score, reverse=True)
    print(f"Total CVEs found: {len(results)}", file=sys.stderr)
    return results


# ─── Backward-compat helpers (used by reporter.py) ──────────────────────────

def _ver_lt(v: str, threshold: str) -> bool:
    """Legacy helper kept for any external callers."""
    from src.nvd_lookup import _parse_ver
    try:
        return _parse_ver(v) < _parse_ver(threshold)
    except Exception:
        return True


def _ver_in_range(v: str, low: str, high: str) -> bool:
    from src.nvd_lookup import _parse_ver
    try:
        return _parse_ver(low) <= _parse_ver(v) <= _parse_ver(high)
    except Exception:
        return True


# ─── Offline Fallback Signatures ─────────────────────────────────────────────
# Used when NVD API is unreachable. Kept lean — just the most critical/common.

OFFLINE_SIGS = [
    ("openssh", lambda v: _ver_lt(v, "9.3"),   "CVE-2023-38408", 9.8, "CRITICAL", "", "OpenSSH < 9.3p2 ssh-agent RCE via PKCS#11 — exploitable with agent forwarding."),
    ("openssh", lambda v: _ver_lt(v, "8.5"),   "CVE-2021-41617", 7.0, "HIGH",     "", "OpenSSH < 8.5 privilege escalation via supplemental group init in sshd."),
    ("openssh", lambda v: _ver_lt(v, "7.7"),   "CVE-2018-15473", 5.3, "MEDIUM",   "", "OpenSSH < 7.7 username enumeration via timing side-channel."),
    ("apache",  lambda v: _ver_lt(v, "2.4.55"),"CVE-2022-22720", 9.8, "CRITICAL", "", "Apache HTTP request smuggling via unclosed inbound connections."),
    ("apache",  lambda v: _ver_lt(v, "2.4.51"),"CVE-2021-40438", 9.0, "CRITICAL", "", "Apache mod_proxy SSRF via unix: URI scheme."),
    ("apache",  lambda v: v == "2.4.49",       "CVE-2021-41773", 9.8, "CRITICAL", "", "Apache 2.4.49 path traversal + RCE — massively exploited. Metasploit module."),
    ("nginx",   lambda v: _ver_lt(v, "1.25.3"),"CVE-2023-44487", 7.5, "HIGH",     "", "HTTP/2 Rapid Reset DoS — send+cancel streams to exhaust workers."),
    ("nginx",   lambda v: _ver_lt(v, "1.20.1"),"CVE-2021-23017", 7.7, "HIGH",     "", "nginx DNS resolver 1-byte heap overwrite."),
    ("php",     lambda v: _ver_lt(v, "7.4.0"), "CVE-2019-11043", 9.8, "CRITICAL", "", "PHP-FPM + nginx path_info buffer underflow — unauthenticated RCE."),
    ("php",     lambda v: _ver_lt(v, "8.1.0"), "CVE-2022-31626", 8.8, "HIGH",     "", "PHP < 8.1 password_verify() buffer overflow."),
    ("redis",   lambda v: _ver_lt(v, "6.2.0"), "CVE-2021-32625", 9.8, "CRITICAL", "", "Redis < 6.2 unauthenticated RCE via Lua integer overflow."),
    ("redis",   lambda v: _ver_lt(v, "5.0.14"),"CVE-2022-0543",  10.0,"CRITICAL", "", "Redis Lua sandbox escape — unauthenticated RCE (Debian/Ubuntu packages)."),
    ("vsftpd",  lambda v: v == "2.3.4",        "CVE-2011-2523",  10.0,"CRITICAL", "", "vsftpd 2.3.4 backdoor — username with :) opens root shell on port 6200."),
    ("tomcat",  lambda v: _ver_lt(v, "9.0.31"),"CVE-2020-1938",  9.8, "CRITICAL", "", "Ghostcat: Tomcat AJP file read/include — RCE if file upload possible."),
    ("iis",     lambda v: True,                "CVE-2022-21907",  9.8, "CRITICAL", "", "IIS HTTP Protocol Stack wormable pre-auth RCE (Windows Server 2022)."),
    ("drupal",  lambda v: _ver_lt(v, "8.9"),   "CVE-2018-7600",  9.8, "CRITICAL", "", "Drupalgeddon2 — unauthenticated RCE. Full Metasploit module, widely exploited."),
    ("wordpress",lambda v: _ver_lt(v, "6.4.2"),"CVE-2024-21726", 9.8, "CRITICAL", "", "WordPress < 6.4.2 PHP object injection in WP_HTML_Token — unauthenticated RCE."),
    ("proftpd", lambda v: _ver_lt(v, "1.3.6"), "CVE-2019-12815", 9.8, "CRITICAL", "", "ProFTPD mod_copy unauthenticated file copy via SITE CPFR/CPTO."),
    ("postgresql",lambda v: _ver_lt(v, "14.0"),"CVE-2022-1552",  8.8, "HIGH",     "", "PostgreSQL autovacuum, REINDEX, and other commands allow privilege escalation."),
    ("mysql",   lambda v: _ver_lt(v, "8.0.28"),"CVE-2022-21417", 6.5, "MEDIUM",   "", "MySQL < 8.0.28 InnoDB uncontrolled resource consumption DoS."),
    ("memcached",lambda v: True,               "CVE-2018-1000115",7.5,"HIGH",      "", "Memcached UDP amplification DDoS — 50,000x factor, used in 1.7Tbps attack."),
    ("openssl", lambda v: _ver_lt(v, "1.1.1u"),"CVE-2023-0286",  7.4, "HIGH",     "", "OpenSSL X.400 ASN.1 type confusion — potential RCE or DoS."),
    ("openssl", lambda v: _ver_lt(v, "1.0.2"),  "CVE-2014-0160", 7.5, "HIGH",     "", "Heartbleed — OpenSSL TLS heartbeat memory disclosure. Private key extraction possible."),
    ("samba",   lambda v: _ver_lt(v, "4.13.17"),"CVE-2021-44142",9.9, "CRITICAL", "", "Samba out-of-bounds heap write in VFS fruit module — pre-auth RCE."),
    ("exim",    lambda v: _ver_lt(v, "4.94.2"), "CVE-2021-27216",7.0, "HIGH",     "", "Exim local privilege escalation via race condition in /tmp handling."),
]


def _offline_correlate(ports, min_cvss: float = 4.0) -> list[VulnMatch]:
    """Fallback correlator using hardcoded signatures when NVD is offline."""
    results = []
    for port_result in ports:
        port    = port_result.port
        service = getattr(port_result, 'service', '') or ''
        banner  = getattr(port_result, 'banner', None)

        product, version = None, None
        if banner:
            product, version = extract_product_version(banner)
        if not product:
            product = infer_product_from_service(service, port)
        if not product:
            continue

        matched = []
        for prod_key, ver_fn, cve_id, cvss, sev, vec, desc in OFFLINE_SIGS:
            if prod_key not in (product or '').lower():
                continue
            if version and not ver_fn(version):
                continue
            if cvss < min_cvss:
                continue
            matched.append(CVE(
                id=cve_id, description=desc, cvss_score=cvss,
                severity=sev, vector=vec, published="",
                exploit_available=(cvss >= 9.0),
            ))

        if matched:
            matched.sort(key=lambda c: c.cvss_score, reverse=True)
            results.append(VulnMatch(
                port=port, service=service, product=product, version=version,
                cves=matched, risk_score=calculate_risk(matched),
                notes=["⚠ NVD offline — using built-in signatures (limited coverage)"],
                source="offline",
            ))
    results.sort(key=lambda m: m.risk_score, reverse=True)
    return results


# Backward compat alias
def _parse_ver(v):
    from src.nvd_lookup import _parse_ver as _pv
    return _pv(v)