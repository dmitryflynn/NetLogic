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
    has_metasploit: bool = False
    has_public_exploit: bool = False
    exploit_refs: list[str] = field(default_factory=list)


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
    detection_confidence: str = "LOW"   # HIGH = version from banner, MEDIUM = product only, LOW = port guess


# CVEs with confirmed public Metasploit modules
METASPLOIT_CVE_IDS: set[str] = {
    "CVE-2021-41773", "CVE-2021-44228", "CVE-2018-7600", "CVE-2014-3704",
    "CVE-2017-5638",  "CVE-2019-0708",  "CVE-2017-0144", "CVE-2020-1938",
    "CVE-2015-1427",  "CVE-2021-22205", "CVE-2011-2523", "CVE-2019-11510",
    "CVE-2021-26855", "CVE-2020-5902",  "CVE-2019-19781","CVE-2020-14882",
    "CVE-2007-2447",  "CVE-2017-7494",  "CVE-2022-26134","CVE-2019-11581",
    "CVE-2021-32625", "CVE-2021-40438", "CVE-2019-9193", "CVE-2021-21972",
    "CVE-2022-22965", "CVE-2021-44142", "CVE-2022-1388", "CVE-2022-36804",
    "CVE-2024-23897", "CVE-2014-0160",  "CVE-2019-15846","CVE-2019-10149",
    "CVE-2015-4852",  "CVE-2022-23131", "CVE-2022-27925","CVE-2012-1823",
    "CVE-2019-11043", "CVE-2015-1635",  "CVE-2015-3306", "CVE-2019-12815",
    "CVE-2012-2122",  "CVE-2021-22893", "CVE-2023-3519", "CVE-2021-21985",
    "CVE-2020-2021",  "CVE-2022-3602",  "CVE-2020-36239","CVE-2021-37219",
    "CVE-2024-3400",  "CVE-2023-20198", "CVE-2020-5135", "CVE-2021-20016",
}

# CVEs with confirmed public exploits on ExploitDB / GitHub / PacketStorm
PUBLIC_EXPLOIT_CVE_IDS: set[str] = METASPLOIT_CVE_IDS | {
    "CVE-2021-34473", "CVE-2024-21410", "CVE-2023-46214","CVE-2022-42475",
    "CVE-2023-27997", "CVE-2018-13379", "CVE-2019-1579", "CVE-2020-3118",
    "CVE-2018-0101",  "CVE-2023-4966",  "CVE-2020-15257","CVE-2019-5736",
    "CVE-2022-21907", "CVE-2021-31166", "CVE-2021-38554","CVE-2023-28432",
    "CVE-2019-20933", "CVE-2019-3826",  "CVE-2022-47966","CVE-2023-22515",
    "CVE-2021-26084", "CVE-2022-32158", "CVE-2001-0529", "CVE-2021-44141",
    "CVE-2020-13977", "CVE-2021-37344", "CVE-2019-0201", "CVE-2018-1002105",
    "CVE-2016-8704",  "CVE-2018-1000115","CVE-2019-9670","CVE-2022-31626",
    "CVE-2016-3115",  "CVE-2021-41617", "CVE-2018-15473","CVE-2014-0224",
}


# ─── Banner → Product/Version Extraction ─────────────────────────────────────

# Regex patterns to extract clean product/version from raw banner strings
BANNER_PATTERNS = [
    # Specific patterns first to avoid shadowing by generic ones
    (r"Apache Tomcat/([\d.]+)",          "tomcat"),
    (r"Tomcat/([\d.]+)",                 "tomcat"),
    (r"Apache-Coyote/([\d.]+)",                "tomcat"),

    (r"Apache/([\d.]+)",                 "apache"),
    (r"apache.{0,10}?([\d]+\.[\d]+\.[\d]+)", "apache"),

    # SSH
    (r"SSH-[\d.]+-OpenSSH[_\s]+([\d.p]+)", "openssh"),
    (r"openssh[_\s]+([\d.p]+)",         "openssh"),

    # nginx
    (r"nginx/([\d.]+)",                  "nginx"),

    # IIS
    (r"Microsoft-IIS/([\d.]+)",          "iis"),
    (r"IIS/([\d.]+)",                    "iis"),

    # PHP
    (r"X-Powered-By:\s*PHP/([\d.]+)",      "php"),
    (r"PHP/([\d.]+)",                    "php"),

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

    # Jenkins
    (r"X-Jenkins:\s*([\d.]+)",                "jenkins"),
    (r"Jenkins[/ ]([\d.]+)",                   "jenkins"),

    # GitLab
    (r"X-Gitlab-Meta",                         "gitlab"),
    (r"GitLab/([\d.]+)",                       "gitlab"),

    # Grafana
    (r"X-Grafana-Version:\s*([\d.]+)",         "grafana"),
    (r"Grafana/([\d.]+)",                      "grafana"),

    # Kibana
    (r'"number"\s*:\s*"([\d.]+)".*kibana',     "kibana"),
    (r"kbn-name.*kibana",                      "kibana"),

    # Drupal
    (r"X-Generator: Drupal ([\d.]+)",    "drupal"),
    (r"Drupal ([\d.]+)",                 "drupal"),
    (r'content="Drupal ([\d.]+)',              "drupal"),

    # WordPress
    (r"WordPress/([\d.]+)",              "wordpress"),
    (r'content="WordPress ([\d.]+)',           "wordpress"),
    (r"wp-content",                      "wordpress"),

    # Samba
    (r"Samba ([\d.]+)",                  "samba"),

    # OpenSSL (from TLS banners)
    (r"OpenSSL/([\d.]+[a-z]?)",          "openssl"),

    # Exim
    (r"Exim ([\d.]+)",                   "exim"),

    # Dovecot
    (r"Dovecot (?:ready|IMAP|POP3).{0,30}? ([\d.]+)", "dovecot"),
    (r"Dovecot",                         "dovecot"),

    # vsftpd
    (r"vsftpd ([\d.]+)",                 "vsftpd"),
    (r"vsFTPd ([\d.]+)",                 "vsftpd"),

    # ProFTPD
    (r"ProFTPD ([\d.]+)",                "proftpd"),

    # Confluence
    (r"Confluence/([\d.]+)",                   "confluence"),
    (r"X-Confluence-Request-Time",             "confluence"),

    # Jira
    (r"Jira/([\d.]+)",                         "jira"),
    (r"X-ASEN:\s*\S+",                         "jira"),

    # WebLogic
    (r"WebLogic Server ([\d.]+)",              "weblogic"),
    (r"BEA WebLogic/([\d.]+)",                 "weblogic"),

    # JBoss/WildFly
    (r"WildFly/([\d.]+)",                      "wildfly"),
    (r"JBoss[/ ]([\d.]+)",                     "jboss"),

    # HAProxy
    (r"via:.*haproxy[/ ]([\d.]+)",             "haproxy"),
    (r"HAProxy/([\d.]+)",                      "haproxy"),

    # Fallbacks and others
    (r"Postfix ESMTP",                   "postfix"),
    (r"ProFTPD ([\d.]+)",                "proftpd"),
    (r"OpenVPN ([\d.]+)",                "openvpn"),
    (r"X-Atlassian-Token",                     "bitbucket"),
    (r"Spring Boot[/ ]([\d.]+)",               "spring"),
    (r"^VERSION ([\d.]+)",                     "memcached"),
    (r'"Version"\s*:\s*"([\d.]+(?:-ce|-ee)?)"',"docker"),
    (r'"gitVersion"\s*:\s*"v([\d.]+)"',        "kubernetes"),
    (r'"etcdserver"\s*:\s*"([\d.]+)"',         "etcd"),
    (r'"version"\s*:\s*"([\d.]+)".*vault',     "vault"),
    (r"X-Vault-Request",                       "vault"),
    (r'"Config".*"Version"\s*:\s*"([\d.]+)"', "consul"),
    (r"X-Influxdb-Version:\s*([\d.]+)",        "influxdb"),
    (r'Server:\s*CouchDB/([\d.]+)',            "couchdb"),
    (r"RabbitMQ ([\d.]+)",                     "rabbitmq"),
    (r"lighttpd/([\d.]+)",                     "lighttpd"),
    (r"GlassFish(?:[^/]*)/([\d.]+)",           "glassfish"),
    (r"ColdFusion[/ ]([\d.]+)",                "coldfusion"),
    (r"X-Powered-By:.*ColdFusion",             "coldfusion"),
    (r'content="phpMyAdmin ([\d.]+)',           "phpmyadmin"),
    (r"X-OWA-Version:\s*([\d.]+)",             "exchange"),
    (r"X-FEServer:",                           "exchange"),
    (r"MicrosoftSharePointTeamServices:\s*([\d.]+)", "sharepoint"),
    (r"RFB (\d{3})\.(\d{3})",                  "vnc"),
    (r"OpenLDAP/([\d.]+)",                     "openldap"),
    (r'"solr-spec-version"\s*:\s*"([\d.]+)"',  "solr"),
    (r"MinIO Object Storage",                  "minio"),
    (r"X-Splunk-Request-Channel",              "splunk"),
    (r"Nagios/([\d.]+)",                       "nagios"),
    (r"Zabbix ([\d.]+)",                       "zabbix"),
    (r"Prometheus/([\d.]+)",                   "prometheus"),
    (r"Roundcube Webmail ([\d.]+)",            "roundcube"),
    (r"VMware vCenter Server ([\d.]+)",        "vcenter"),
    (r"Sendmail ([\d.]+)",                     "sendmail"),
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
        21:    "vsftpd",
        22:    "openssh",
        23:    "telnet",
        25:    "postfix",
        53:    "bind",
        80:    "apache",
        110:   "dovecot",
        111:   "rpcbind",
        139:   "samba",
        143:   "dovecot",
        161:   "snmpd",
        389:   "openldap",
        443:   "apache",
        445:   "samba",
        587:   "postfix",
        631:   "cups",
        993:   "dovecot",
        995:   "dovecot",
        1433:  "mssql",
        2049:  "nfs",
        3306:  "mysql",
        3389:  "rdp",
        5432:  "postgresql",
        5900:  "vnc",
        6379:  "redis",
        8080:  "tomcat",
        8443:  "tomcat",
        9200:  "elasticsearch",
        11211: "memcached",
        27017: "mongodb",
    }
    # If the service name itself maps to a known product, prefer that
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

    has_msf  = nvd.has_metasploit  or (nvd.id in METASPLOIT_CVE_IDS)
    has_pub  = nvd.has_public_exploit or (nvd.id in PUBLIC_EXPLOIT_CVE_IDS)

    return CVE(
        id=nvd.id,
        description=nvd.description,
        cvss_score=nvd.cvss_score,
        severity=nvd.severity,
        vector=nvd.vector,
        published=nvd.published,
        references=nvd.references,
        exploit_available=nvd.kev or has_msf,
        kev=nvd.kev,
        cwe=nvd.cwe,
        version_range=ver_range,
        has_metasploit=has_msf,
        has_public_exploit=has_pub,
        exploit_refs=nvd.exploit_refs,
    )


# ─── Main Correlator ──────────────────────────────────────────────────────────

def correlate(ports, min_cvss: float = 4.0, verbose: bool = False) -> list[VulnMatch]:
    """
    Main entry point. Takes list of PortResult objects, returns VulnMatch list.

    Strategy:
      1. Always run offline signatures first — guaranteed baseline coverage
         for the 25+ most critical/common CVEs regardless of NVD status.
      2. If NVD is reachable, query it per-port and MERGE into the results,
         deduplicating by CVE ID so offline + live results coexist cleanly.
      3. If NVD is unreachable, offline-only results are returned with a note.

    This means a scan of e.g. port 22/OpenSSH will ALWAYS show the offline
    critical CVEs even when NVD returns 0 (rate-limited, down, etc.).
    """
    results = []

    from src.nvd_lookup import nvd_is_available, _nvd_unavailable
    nvd_ok = not _nvd_unavailable and nvd_is_available()

    if not nvd_ok and verbose:
        print("  [!] NVD API unreachable — offline signatures only", file=sys.stderr)

    # ── Step 1: build a lookup map from offline signatures first ─────────────
    # keyed by port so we can merge NVD results into the same VulnMatch object
    offline_by_port: dict[int, VulnMatch] = {}

    for port_result in ports:
        if getattr(port_result, 'state', 'open') != 'open':
            continue
        port    = port_result.port
        service = getattr(port_result, 'service', '') or ''
        banner  = getattr(port_result, 'banner', None)

        product, version = None, None
        if banner:
            product, version = extract_product_version(banner)
        if product and product.startswith('http'):
            product = None
            version = None
        if not product:
            product = infer_product_from_service(service, port)

        if banner and product and version:
            _confidence = "HIGH"
        elif banner and product:
            _confidence = "MEDIUM"
        else:
            _confidence = "LOW"

        # If version is missing, we still want to flag critical misconfigurations
        # or at least return a result with a note if it's a high-risk service.
        if not product:
            continue

        if not version:
            if product == "redis":
                offline_by_port[port] = VulnMatch(
                    port=port, service=service, product=product, version=None,
                    cves=[], risk_score=5.0,
                    notes=["⚠ Redis instance appears to be unprotected (no authentication required)"],
                    source="misconfig", detection_confidence="MEDIUM",
                )
            elif product == "telnet":
                offline_by_port[port] = VulnMatch(
                    port=port, service=service, product=product, version=None,
                    cves=[], risk_score=4.0,
                    notes=["⚠ Telnet is an insecure protocol (unencrypted)"],
                    source="misconfig", detection_confidence="MEDIUM",
                )
            continue

        matched_offline = []
        for prod_key, ver_fn, cve_id, cvss, sev, vec, desc in OFFLINE_SIGS:
            if prod_key not in (product or '').lower():
                continue
            if version and not ver_fn(version):
                continue
            if cvss < min_cvss:
                continue
            matched_offline.append(CVE(
                id=cve_id, description=desc, cvss_score=cvss,
                severity=sev, vector=vec, published="",
                exploit_available=(cve_id in PUBLIC_EXPLOIT_CVE_IDS or cvss >= 9.0),
                has_metasploit=(cve_id in METASPLOIT_CVE_IDS),
                has_public_exploit=(cve_id in PUBLIC_EXPLOIT_CVE_IDS),
            ))

        if matched_offline:
            matched_offline.sort(key=lambda c: c.cvss_score, reverse=True)
            notes = []
            if not version:
                notes.append("Version unknown — showing CVEs that may apply to this product")
            offline_by_port[port] = VulnMatch(
                port=port, service=service, product=product, version=version,
                cves=matched_offline, risk_score=calculate_risk(matched_offline),
                notes=notes, source="offline", detection_confidence=_confidence,
            )

    # ── Step 2: if NVD is reachable, query and merge per port ────────────────
    if nvd_ok:
        for port_result in ports:
            port    = port_result.port
            service = getattr(port_result, 'service', '') or ''
            banner  = getattr(port_result, 'banner', None)

            product, version = None, None
            if banner:
                product, version = extract_product_version(banner)
            if product and product.startswith('http'):
                product = None
                version = None
            if not product:
                product = infer_product_from_service(service, port)

            if banner and product and version:
                _confidence = "HIGH"
            elif banner and product:
                _confidence = "MEDIUM"
            else:
                _confidence = "LOW"

            if not product or not version:
                if verbose and product:
                    print(f"  [NVD] {port}/{service} → {product} (version unknown)... skipping (no exact version)", file=sys.stderr)
                continue

            if verbose:
                print(f"  [NVD] {port}/{service} → {product} {version}...", end=" ", flush=True)

            nvd_cves = lookup_cves_for_service(product, version, min_cvss=min_cvss)

            if verbose:
                print(f"{len(nvd_cves)} CVEs")

            if not nvd_cves:
                continue  # Nothing from NVD — offline result (if any) stands

            nvd_converted = [_nvd_to_cve(c) for c in nvd_cves]

            # Merge: start from offline CVEs for this port, add NVD ones not already present
            existing = offline_by_port.get(port)
            if existing:
                seen_ids = {c.id for c in existing.cves}
                for c in nvd_converted:
                    if c.id not in seen_ids:
                        existing.cves.append(c)
                        seen_ids.add(c.id)
                existing.cves.sort(key=lambda c: c.cvss_score, reverse=True)
                existing.risk_score = calculate_risk(existing.cves)
                existing.source = "nvd+offline"
                if _confidence == "HIGH" and existing.detection_confidence != "HIGH":
                    existing.detection_confidence = _confidence
                if any(c.kev for c in existing.cves):
                    kev_ids = [c.id for c in existing.cves if c.kev]
                    kev_note = f"★ CISA KEV: {', '.join(kev_ids[:3])} — actively exploited in the wild"
                    if kev_note not in existing.notes:
                        existing.notes.append(kev_note)
            else:
                # No offline match — just use NVD result
                notes = []
                if not version:
                    notes.append("Version unknown — showing all known CVEs for this product")
                if any(c.kev for c in nvd_converted):
                    kev_ids = [c.id for c in nvd_converted if c.kev]
                    notes.append(f"★ CISA KEV: {', '.join(kev_ids[:3])} — actively exploited in the wild")
                offline_by_port[port] = VulnMatch(
                    port=port, service=service, product=product, version=version,
                    cves=nvd_converted, risk_score=calculate_risk(nvd_converted),
                    notes=notes, source="nvd", detection_confidence=_confidence,
                )

    results = list(offline_by_port.values())
    results.sort(key=lambda m: m.risk_score, reverse=True)

    total_cves = sum(len(m.cves) for m in results)
    source_tag = "nvd+offline" if nvd_ok else "offline"
    if verbose:
        print(f"Total CVEs found: {total_cves} ({len(results)} port(s), source: {source_tag})", file=sys.stderr)
    return results


# ─── Backward-compat helpers (used by reporter.py) ──────────────────────────

def _ver_lt(v: str, threshold: str) -> bool:
    """Legacy helper kept for any external callers."""
    from src.nvd_lookup import _ver_lt as _nvd_ver_lt
    return _nvd_ver_lt(v, threshold)


def _ver_in_range(v: str, low: str, high: str) -> bool:
    from src.nvd_lookup import _ver_lte
    return _ver_lte(low, v) and _ver_lte(v, high)


# ─── Offline Fallback Signatures ─────────────────────────────────────────────
# Used when NVD API is unreachable. Kept lean — just the most critical/common.

OFFLINE_SIGS = [
    ("openssh", lambda v: _ver_lt(v, "9.3"),   "CVE-2023-38408", 9.8, "CRITICAL", "", "OpenSSH < 9.3p2 ssh-agent RCE via PKCS#11 — exploitable with agent forwarding."),
    ("openssh", lambda v: _ver_lt(v, "8.5"),   "CVE-2021-41617", 7.0, "HIGH",     "", "OpenSSH < 8.5 privilege escalation via supplemental group init in sshd."),
    ("openssh", lambda v: _ver_lt(v, "7.7"),   "CVE-2018-15473", 5.3, "MEDIUM",   "", "OpenSSH < 7.7 username enumeration via timing side-channel."),
    ("openssh", lambda v: _ver_lt(v, "7.2"),   "CVE-2016-3115",  7.5, "HIGH",     "", "OpenSSH < 7.2p2 X11 Forwarding Bypass — possible bypass of restricted shells."),
    ("openssh", lambda v: _ver_lt(v, "2.9.9"), "CVE-2001-0529",  10.0,"CRITICAL", "", "OpenSSH < 2.9.9 Remote root compromise (channel code)."),
    ("apache",  lambda v: _ver_lt(v, "2.4.58"),"CVE-2023-45662", 7.5, "HIGH",     "", "Apache HTTP Request Smuggling DoS."),
    ("apache",  lambda v: _ver_lt(v, "2.4.55"),"CVE-2022-22720", 9.8, "CRITICAL", "", "Apache HTTP request smuggling via unclosed inbound connections."),
    ("apache",  lambda v: _ver_lt(v, "2.4.51"),"CVE-2021-40438", 9.0, "CRITICAL", "", "Apache mod_proxy SSRF via unix: URI scheme."),
    ("apache",  lambda v: v == "2.4.49",       "CVE-2021-41773", 9.8, "CRITICAL", "", "Apache 2.4.49 path traversal + RCE — massively exploited. Metasploit module."),
    ("apache",  lambda v: _ver_lt(v, "2.4.39"),"CVE-2019-0211",  9.8, "CRITICAL", "", "Apache CARPE DIEM — local privilege escalation to root."),
    ("apache",  lambda v: _ver_lt(v, "2.2.34"),"CVE-2017-9798",  7.5, "HIGH",     "", "Apache Optionsbleed — memory disclosure via OPTIONS request."),
    ("nginx",   lambda v: _ver_lt(v, "1.25.3"),"CVE-2023-44487", 7.5, "HIGH",     "", "HTTP/2 Rapid Reset DoS — send+cancel streams to exhaust workers."),
    ("nginx",   lambda v: _ver_lt(v, "1.20.1"),"CVE-2021-23017", 7.7, "HIGH",     "", "nginx DNS resolver 1-byte heap overwrite."),
    ("nginx",   lambda v: _ver_lt(v, "1.17.3"),"CVE-2019-9511",  7.5, "HIGH",     "", "HTTP/2 Data Dribble DoS."),
    ("php",     lambda v: _ver_lt(v, "8.1.0"), "CVE-2024-4577",  9.8, "CRITICAL", "", "PHP CGI RCE via argument injection on Windows."),
    ("php",     lambda v: _ver_lt(v, "7.4.0"), "CVE-2019-11043", 9.8, "CRITICAL", "", "PHP-FPM + nginx path_info buffer underflow — unauthenticated RCE."),
    ("php",     lambda v: _ver_lt(v, "8.1.0"), "CVE-2022-31626", 8.8, "HIGH",     "", "PHP < 8.1 password_verify() buffer overflow."),
    ("php",     lambda v: _ver_lt(v, "5.4.12"),"CVE-2012-1823",  10.0,"CRITICAL", "", "PHP CGI argument injection (RCE). widely used in botnets."),
    ("redis",   lambda v: _ver_lt(v, "6.2.0"), "CVE-2021-32625", 9.8, "CRITICAL", "", "Redis < 6.2 unauthenticated RCE via Lua integer overflow."),
    ("redis",   lambda v: _ver_lt(v, "5.0.14"),"CVE-2022-0543",  10.0,"CRITICAL", "", "Redis Lua sandbox escape — unauthenticated RCE (Debian/Ubuntu packages)."),
    ("redis",   lambda v: _ver_lt(v, "4.0.0"), "CVE-2018-8300",  8.8, "HIGH",     "", "Redis unprotected instance (No Auth) enabling system takeover via public SSH key drop."),
    ("vsftpd",  lambda v: v == "2.3.4",        "CVE-2011-2523",  10.0,"CRITICAL", "", "vsftpd 2.3.4 backdoor — username with :) opens root shell on port 6200."),
    ("tomcat",  lambda v: _ver_lt(v, "9.0.31"),"CVE-2020-1938",  9.8, "CRITICAL", "", "Ghostcat: Tomcat AJP file read/include — RCE if file upload possible."),
    ("tomcat",  lambda v: _ver_lt(v, "8.5.23"),"CVE-2017-12615", 9.8, "CRITICAL", "", "Tomcat JSP Upload Bypass RCE via HTTP PUT (Windows only)."),
    ("tomcat",  lambda v: _ver_lt(v, "7.0.100"),"CVE-2020-9484", 9.8, "CRITICAL", "", "Tomcat deserialization RCE via PersistentManager + FileStore."),
    ("iis",     lambda v: v and v.startswith("10."), "CVE-2022-21907", 9.8, "CRITICAL", "", "IIS HTTP Protocol Stack wormable pre-auth RCE (Windows Server 2019/2022)."),
    ("iis",     lambda v: _ver_lt(v, "8.6"),        "CVE-2015-1635",  10.0,"CRITICAL", "", "MS15-034: IIS HTTP.sys remote code execution via Range header (IIS ≤ 8.5)."),
    ("iis",     lambda v: v and v.startswith("10."), "CVE-2021-31166", 9.8, "CRITICAL", "", "IIS HTTP.sys UAF Remote Code Execution / Blue Screen DoS (IIS 10.0)."),
    ("drupal",  lambda v: _ver_lt(v, "8.9"),   "CVE-2018-7600",  9.8, "CRITICAL", "", "Drupalgeddon2 — unauthenticated RCE. Full Metasploit module, widely exploited."),
    ("drupal",  lambda v: _ver_lt(v, "7.32"),  "CVE-2014-3704",  9.8, "CRITICAL", "", "Drupalgeddon — SQL Injection via database abstraction API."),
    ("wordpress",lambda v: _ver_lt(v, "6.4.2"),"CVE-2024-21726", 9.8, "CRITICAL", "", "WordPress < 6.4.2 PHP object injection in WP_HTML_Token — unauthenticated RCE."),
    ("wordpress",lambda v: _ver_lt(v, "4.7.2"),"CVE-2017-1001000",9.8,"CRITICAL", "", "WordPress REST API unauthenticated privilege escalation/content injection."),
    ("wordpress",lambda v: _ver_lt(v, "5.1.1"),"CVE-2019-8942",  8.8, "HIGH",     "", "WordPress authenticatd RCE / Image upload path traversal."),
    ("joomla",  lambda v: _ver_lt(v, "3.4.6"), "CVE-2015-8562",  9.8, "CRITICAL", "", "Joomla Object Injection RCE via user-agent HTTP header."),
    ("proftpd", lambda v: _ver_lt(v, "1.3.6"), "CVE-2019-12815", 9.8, "CRITICAL", "", "ProFTPD mod_copy unauthenticated file copy via SITE CPFR/CPTO."),
    ("proftpd", lambda v: _ver_lt(v, "1.3.5"), "CVE-2015-3306",  10.0,"CRITICAL", "", "ProFTPD mod_copy unauthenticated RCE via SITE CPFR/CPTO."),
    ("proftpd", lambda v: _ver_lt(v, "1.3.3"), "CVE-2010-4221",  10.0,"CRITICAL", "", "ProFTPD TELNET IAC escape integer overflow (metasploit available)."),
    ("postgresql",lambda v: _ver_lt(v, "14.0"),"CVE-2022-1552",  8.8, "HIGH",     "", "PostgreSQL autovacuum, REINDEX, and other commands allow privilege escalation."),
    ("postgresql",lambda v: _ver_lt(v, "11.3"),"CVE-2019-9193",  9.0, "CRITICAL", "", "PostgreSQL authenticated RCE via COPY TO/FROM PROGRAM."),
    ("mysql",   lambda v: _ver_lt(v, "8.0.28"),"CVE-2022-21417", 6.5, "MEDIUM",   "", "MySQL < 8.0.28 InnoDB uncontrolled resource consumption DoS."),
    ("mysql",   lambda v: _ver_lt(v, "5.5.24"),"CVE-2012-2122",  7.5, "HIGH",     "", "MySQL authentication bypass probability bug in memcmp()."),
    ("memcached",lambda v: True,               "CVE-2018-1000115",7.5,"HIGH",     "", "Memcached UDP amplification DDoS — 50,000x factor, used in 1.7Tbps attack."),
    ("memcached",lambda v: _ver_lt(v, "1.4.33"),"CVE-2016-8704", 9.8, "CRITICAL", "", "Memcached SASL integer overflow leading to RCE."),
    ("openssl", lambda v: _ver_lt(v, "3.0.7"), "CVE-2022-3602",  9.8, "CRITICAL", "", "OpenSSL v3 Punycode vulnerability — stack buffer overflow."),
    ("openssl", lambda v: _ver_lt(v, "1.1.1u"),"CVE-2023-0286",  7.4, "HIGH",     "", "OpenSSL X.400 ASN.1 type confusion — potential RCE or DoS."),
    ("openssl", lambda v: _ver_lt(v, "1.0.2"),  "CVE-2014-0160", 7.5, "HIGH",     "", "Heartbleed — OpenSSL TLS heartbeat memory disclosure. Private key extraction possible."),
    ("openssl", lambda v: _ver_lt(v, "1.0.2"),  "CVE-2014-0224", 7.5, "HIGH",     "", "OpenSSL CCS Injection vulnerability (MiTM decryption)."),
    ("samba",   lambda v: _ver_lt(v, "4.15.5"),"CVE-2021-44142", 9.9, "CRITICAL", "", "Samba out-of-bounds heap write in VFS fruit module — pre-auth RCE."),
    ("samba",   lambda v: _ver_lt(v, "4.13.17"),"CVE-2021-44141",8.8, "HIGH",     "", "Samba information leak via SMB1 UNIX extensions."),
    ("samba",   lambda v: _ver_lt(v, "4.6.4"), "CVE-2017-7494",  10.0,"CRITICAL", "", "SambaCry — unauthenticated RCE via malicious shared library upload."),
    ("samba",   lambda v: _ver_lt(v, "3.0.25"),"CVE-2007-2447",  10.0,"CRITICAL", "", "Samba username map script injection RCE (widely exploited)."),
    ("exim",    lambda v: _ver_lt(v, "4.94.2"),"CVE-2021-27216", 7.0, "HIGH",     "", "Exim local privilege escalation via race condition in /tmp handling."),
    ("exim",    lambda v: _ver_lt(v, "4.92.2"),"CVE-2019-15846", 9.8, "CRITICAL", "", "Exim unauthenticated RCE via trailing backslash in SNI during TLS handshake."),
    ("exim",    lambda v: _ver_lt(v, "4.92"),  "CVE-2019-10149", 9.8, "CRITICAL", "", "Exim The Return of the WIZard — RCE via expand string rules."),
    ("smb",     lambda v: True,                "CVE-2017-0144",  10.0,"CRITICAL", "", "EternalBlue (MS17-010) — Windows SMBv1 pre-auth RCE. Widely exploited by WannaCry/NotPetya."),
    ("smb",     lambda v: True,                "CVE-2020-0796",  10.0,"CRITICAL", "", "SMBGhost — Windows 10/Server 2019 SMBv3.1.1 pre-auth RCE via malicious compression headers."),
    ("rdp",     lambda v: True,                "CVE-2019-0708",  9.8, "CRITICAL", "", "BlueKeep — Windows RDP pre-auth RCE. Wormable vulnerability in Remote Desktop Services."),
    ("elasticsearch", lambda v: _ver_lt(v, "1.4.3"), "CVE-2015-1427", 10.0, "CRITICAL", "", "Elasticsearch unauthenticated RCE via Groovy scripting engine sandbox bypass."),
    ("elasticsearch", lambda v: _ver_lt(v, "7.16.1"), "CVE-2021-44228", 10.0, "CRITICAL", "", "Log4Shell — Elasticsearch unauthenticated RCE via Log4j."),
    ("gitlab",  lambda v: _ver_lt(v, "13.10.3"), "CVE-2021-22205", 10.0, "CRITICAL", "", "GitLab unauthenticated RCE via ExifTool handling of uploaded image files."),
    ("gitlab",  lambda v: _ver_lt(v, "16.7.2"),  "CVE-2023-7028",  10.0, "CRITICAL", "", "GitLab account takeover via password reset to arbitrary email."),
    ("confluence", lambda v: _ver_lt(v, "7.18.1"), "CVE-2022-26134", 9.8, "CRITICAL", "", "Atlassian Confluence unauthenticated OGNL injection RCE."),
    ("confluence", lambda v: _ver_lt(v, "7.4.0"),  "CVE-2021-26084", 9.8, "CRITICAL", "", "Atlassian Confluence Server Webwork OGNL injection RCE."),
    ("confluence", lambda v: _ver_lt(v, "8.5.1"),  "CVE-2023-22515", 9.8, "CRITICAL", "", "Atlassian Confluence broken access control leading to RCE."),
    ("bind",    lambda v: _ver_lt(v, "9.10.2"), "CVE-2015-5477", 7.8, "HIGH",     "", "ISC BIND 9 TKEY query denial of service (DoS)."),
    ("fortigate", lambda v: _ver_lt(v, "7.2.5"), "CVE-2023-27997", 9.8, "CRITICAL", "", "FortiGate SSL VPN unauthenticated heap-based buffer overflow RCE."),
    ("fortigate", lambda v: _ver_lt(v, "7.0.6"), "CVE-2022-42475", 9.8, "CRITICAL", "", "FortiOS SSL-VPN heap-based buffer overflow RCE."),
    ("fortigate", lambda v: _ver_lt(v, "6.0.4"), "CVE-2018-13379", 9.8, "CRITICAL", "", "FortiOS SSL-VPN pre-auth path traversal (credentials leak)."),
    ("weblogic", lambda v: _ver_lt(v, "14.1.1.0"), "CVE-2020-14882", 9.8, "CRITICAL", "", "Oracle WebLogic Server unauthenticated RCE via Console HTTP interface."),
    ("weblogic", lambda v: _ver_lt(v, "12.1.3.0"), "CVE-2015-4852",  9.8, "CRITICAL", "", "Oracle WebLogic Server unauthenticated RCE via T3 protocol (Java Deserialization)."),
    ("exchange", lambda v: True,                "CVE-2021-26855", 9.8, "CRITICAL", "", "ProxyLogon — Microsoft Exchange Server pre-auth SSRF leading to RCE."),
    ("exchange", lambda v: True,                "CVE-2021-34473", 9.8, "CRITICAL", "", "ProxyShell — Microsoft Exchange Server pre-auth path confusion leading to RCE."),
    ("exchange", lambda v: True,                "CVE-2024-21410", 9.8, "CRITICAL", "", "Microsoft Exchange Server Elevation of Privilege (NTLM relay)."),
    ("vcenter",  lambda v: _ver_lt(v, "7.0.2"), "CVE-2021-21972", 9.8, "CRITICAL", "", "VMware vCenter Server unauthenticated file upload RCE in vROps plugin."),
    ("vcenter",  lambda v: _ver_lt(v, "7.0.2"), "CVE-2021-21985", 9.8, "CRITICAL", "", "VMware vCenter Server unauthenticated RCE in Virtual SAN Health Check plugin."),
    ("zabbix",   lambda v: _ver_lt(v, "5.0.22"),"CVE-2022-23131", 9.8, "CRITICAL", "", "Zabbix Frontend authentication bypass / SAML SSO injection."),
    ("spring",   lambda v: _ver_lt(v, "5.3.18"),"CVE-2022-22965", 9.8, "CRITICAL", "", "Spring4Shell — RCE via parameter binding on Spring MVC/WebFlux applications."),
    ("struts",   lambda v: _ver_lt(v, "2.5.13"),"CVE-2017-5638",  10.0,"CRITICAL", "", "Apache Struts 2 RCE via unescaped Content-Type parser (Equifax breach)."),
    ("struts",   lambda v: _ver_lt(v, "2.5.21"),"CVE-2020-17530", 9.8, "CRITICAL", "", "Apache Struts 2 double OGNL evaluation RCE."),
    ("log4j",    lambda v: _ver_lt(v, "2.15.0"),"CVE-2021-44228", 10.0,"CRITICAL", "", "Log4Shell — Apache Log4j2 unauthenticated JNDI lookup RCE."),
    ("citrix",   lambda v: _ver_lt(v, "13.0"),  "CVE-2023-3519",  9.8, "CRITICAL", "", "Citrix NetScaler ADC/Gateway unauthenticated code injection RCE."),
    ("citrix",   lambda v: _ver_lt(v, "12.1"),  "CVE-2019-19781", 9.8, "CRITICAL", "", "Citrix NetScaler directory traversal leading to RCE."),
    ("citrix",   lambda v: True,                "CVE-2023-4966",  7.5, "HIGH",     "", "Citrix NetScaler 'Citrix Bleed' information disclosure (session token theft)."),
    ("f5",       lambda v: _ver_lt(v, "16.1.2"),"CVE-2022-1388",  9.8, "CRITICAL", "", "F5 BIG-IP iControl REST unauthenticated RCE."),
    ("f5",       lambda v: _ver_lt(v, "15.1.0"),"CVE-2020-5902",  9.8, "CRITICAL", "", "F5 BIG-IP TMUI directory traversal RCE."),
    ("paloalto", lambda v: _ver_lt(v, "10.2"),  "CVE-2024-3400",  10.0,"CRITICAL", "", "Palo Alto PAN-OS GlobalProtect unauthenticated command injection RCE."),
    ("paloalto", lambda v: _ver_lt(v, "8.1.15"),"CVE-2020-2021",  10.0,"CRITICAL", "", "Palo Alto PAN-OS authentication bypass via SAML."),
    ("paloalto", lambda v: _ver_lt(v, "9.0.0"), "CVE-2019-1579",  9.8, "CRITICAL", "", "Palo Alto GlobalProtect pre-auth RCE."),
    ("pulse",    lambda v: _ver_lt(v, "9.0"),   "CVE-2019-11510", 10.0,"CRITICAL", "", "Pulse Secure Connect SSL VPN unauthenticated arbitrary file read."),
    ("pulse",    lambda v: _ver_lt(v, "9.1.5"), "CVE-2021-22893", 10.0,"CRITICAL", "", "Pulse Secure unauthenticated RCE via use-after-free."),
    ("sonicwall",lambda v: _ver_lt(v, "6.5.4"), "CVE-2020-5135",  9.4, "CRITICAL", "", "SonicWall SonicOS VPN stack buffer overflow RCE."),
    ("sonicwall",lambda v: True,                "CVE-2021-20016", 9.8, "CRITICAL", "", "SonicWall SMA 100 series pre-auth SQL injection."),
    ("zimbra",   lambda v: _ver_lt(v, "9.0.0"), "CVE-2022-27925", 9.8, "CRITICAL", "", "Zimbra Collaboration Suite unauthenticated RCE via mboximport zip extraction."),
    ("zimbra",   lambda v: _ver_lt(v, "8.8.11"),"CVE-2019-9670",  9.8, "CRITICAL", "", "Zimbra Autodiscover XXE to RCE."),
    ("manageengine", lambda v: _ver_lt(v, "10.0"), "CVE-2022-47966", 9.8, "CRITICAL", "", "ManageEngine unauthenticated RCE via outdated Apache Santuario SAML parser."),
    ("jira",     lambda v: _ver_lt(v, "8.4.0"), "CVE-2019-11581", 9.8, "CRITICAL", "", "Atlassian Jira Server template injection RCE."),
    ("jira",     lambda v: _ver_lt(v, "8.14.0"),"CVE-2020-36239", 7.5, "HIGH",     "", "Atlassian Jira missing authentication in Ehcache RMI interface."),
    ("bitbucket",lambda v: _ver_lt(v, "7.6.14"),"CVE-2022-36804", 9.9, "CRITICAL", "", "Atlassian Bitbucket Server command injection via crafted HTTP request."),
    ("jenkins",  lambda v: _ver_lt(v, "2.441"), "CVE-2024-23897", 9.8, "CRITICAL", "", "Jenkins CLI unauthenticated arbitrary file read leading to RCE."),
    ("jenkins",  lambda v: _ver_lt(v, "2.103"), "CVE-2017-1000353", 9.8, "CRITICAL", "", "Jenkins Java deserialization RCE via CLI transport."),
    ("cisco",    lambda v: True,                "CVE-2023-20198", 10.0,"CRITICAL", "", "Cisco IOS XE Web UI pre-auth command execution (0-day exploitation)."),
    ("cisco",    lambda v: True,                "CVE-2018-0101",  10.0,"CRITICAL", "", "Cisco ASA double free vulnerability in XML parser (RCE/DoS)."),
    ("cisco",    lambda v: True,                "CVE-2020-3118",  9.8, "CRITICAL", "", "Cisco IOS CDP protocol unauthenticated remote code execution."),
    ("ivanti",   lambda v: True,                "CVE-2023-46805", 8.2, "HIGH",     "", "Ivanti Connect Secure authentication bypass."),
    ("ivanti",   lambda v: True,                "CVE-2024-21887", 9.1, "CRITICAL", "", "Ivanti Connect Secure command injection RCE."),
    ("zscaler",  lambda v: True,                "CVE-2024-xxxxx", 9.8, "CRITICAL", "", "Check NVD for latest critical vulnerabilities on Zscaler / networking equipment."),
    ("squid",    lambda v: _ver_lt(v, "4.15"),  "CVE-2021-28651", 7.5, "HIGH",     "", "Squid Proxy URN processing buffer overflow / DoS."),
    ("haproxy",  lambda v: _ver_lt(v, "2.2.17"),"CVE-2021-40346", 8.6, "HIGH",     "", "HAProxy HTTP request smuggling vulnerability."),
    ("openvpn",  lambda v: _ver_lt(v, "2.4.9"), "CVE-2020-11810", 7.5, "HIGH",     "", "OpenVPN double free vulnerability leading to DoS/RCE."),
    ("cups",     lambda v: _ver_lt(v, "2.0"),   "CVE-2014-6271",  10.0,"CRITICAL", "", "Shellshock — Bash command injection via HTTP headers triggers via CGI in CUPS."),
    ("nfs",      lambda v: True,                "CVE-2022-4304",  7.5, "HIGH",     "", "NFSv4 multiple potential memory corruption issues."),
    ("rpcbind",  lambda v: True,                "CVE-2017-8779",  7.5, "HIGH",     "", "rpcbind UDP amplification attack and DoS via crafted requests."),
    ("snmp",     lambda v: True,                "CVE-2012-3268",  7.5, "HIGH",     "", "Default or easily guessable public/private SNMP community strings."),
    ("openldap", lambda v: _ver_lt(v, "2.4.58"),"CVE-2020-36221", 7.5, "HIGH",     "", "OpenLDAP saslAuthzTo configuration bypass."),
    ("dovecot",  lambda v: _ver_lt(v, "2.3.11"),"CVE-2020-12100", 7.5, "HIGH",     "", "Dovecot IMAP and POP3 unauthenticated DoS."),
    
    # --- New Expansion Pack ---
    ("grafana",  lambda v: _ver_lt(v, "8.3.1"), "CVE-2021-43798", 7.5, "HIGH",     "", "Grafana unauthenticated directory traversal (arbitrary file read)."),
    ("kibana",   lambda v: _ver_lt(v, "6.4.3"), "CVE-2018-17246", 9.8, "CRITICAL", "", "Kibana local file inclusion (LFI) leading to unauthenticated RCE."),
    ("splunk",   lambda v: _ver_lt(v, "8.2.3"), "CVE-2021-33904", 8.8, "HIGH",     "", "Splunk Enterprise deployment server timing side-channel."),
    ("splunk",   lambda v: _ver_lt(v, "9.0"),   "CVE-2022-32154", 8.1, "HIGH",     "", "Splunk Enterprise RCE via malicious deployment server component."),
    ("nexus",    lambda v: _ver_lt(v, "3.21.2"),"CVE-2020-10199", 9.8, "CRITICAL", "", "Sonatype Nexus Repository Manager RCE via EL injection."),
    ("nexus",    lambda v: _ver_lt(v, "3.15.0"),"CVE-2019-7238",  9.8, "CRITICAL", "", "Sonatype Nexus Repository unauthenticated RCE."),
    ("mongodb",  lambda v: _ver_lt(v, "4.4.8"), "CVE-2021-20336", 7.5, "HIGH",     "", "MongoDB configuration bypass leading to unauthenticated access."),
    ("rabbitmq", lambda v: _ver_lt(v, "3.4.0"), "CVE-2015-8786",  7.5, "HIGH",     "", "RabbitMQ management plugin CSRF vulnerability."),
    ("jupyter",  lambda v: _ver_lt(v, "5.7.3"), "CVE-2019-9644",  8.8, "HIGH",     "", "Jupyter Notebook DOM-based XSS enabling malicious terminal access."),
    ("kubernetes",lambda v: _ver_lt(v,"1.10.11"),"CVE-2018-1002105",9.8,"CRITICAL","", "Kubernetes API Server privilege escalation (Kubernetes-first 10.0 CVE)."),
    ("docker",   lambda v: _ver_lt(v, "18.09.2"),"CVE-2019-5736", 9.3, "CRITICAL", "", "Docker runC container breakout (RCE). widely used container escape."),
    
    # NAS & Network Appliances
    ("qnap",     lambda v: True,                "CVE-2021-28799", 9.8, "CRITICAL", "", "QNAP NAS unauthenticated remote code execution via HBS 3 (Qlocker ransomware vector)."),
    ("qnap",     lambda v: True,                "CVE-2022-27596", 9.8, "CRITICAL", "", "QNAP NAS SQL injection in QTS/QuTS hero (DeadBolt ransomware vector)."),
    ("synology", lambda v: _ver_lt(v, "6.2.3"), "CVE-2021-29085", 10.0,"CRITICAL", "", "Synology DiskStation Manager (DSM) unauthenticated pre-auth RCE."),
    ("synology", lambda v: True,                "CVE-2022-27615", 9.8, "CRITICAL", "", "Synology Router Manager network attack vulnerability."),
    
    # Home/SOHO Routers
    ("ubiquiti", lambda v: _ver_lt(v, "1.10"),  "CVE-2018-10562", 9.8, "CRITICAL", "", "Ubiquiti UniFi Video unauthenticated RCE."),
    ("ubiquiti", lambda v: _ver_lt(v, "6.1.71"),"CVE-2021-44228", 10.0,"CRITICAL", "", "Ubiquiti UniFi Network Application Log4Shell vulnerability."),
    ("hikvision",lambda v: True,                "CVE-2021-36260", 9.8, "CRITICAL", "", "Hikvision IP Camera unauthenticated RCE via crafted web requests."),
    ("dlink",    lambda v: True,                "CVE-2019-16920", 9.8, "CRITICAL", "", "D-Link DIR-series routers unauthenticated RCE."),
    ("dlink",    lambda v: True,                "CVE-2020-25506", 9.8, "CRITICAL", "", "D-Link DNS-320 firewall unauthenticated RCE."),
    ("netgear",  lambda v: True,                "CVE-2020-10987", 9.8, "CRITICAL", "", "Netgear router RCE via crafted HTTP request to UPnP endpoint."),
    ("netgear",  lambda v: True,                "CVE-2017-5521",  9.8, "CRITICAL", "", "Netgear authentication bypass leading to complete device takeover."),
    ("tplink",   lambda v: True,                "CVE-2023-1389",  9.8, "CRITICAL", "", "TP-Link Archer routers unauthenticated command injection (used by Mirai botnets)."),
    ("zyxel",    lambda v: True,                "CVE-2023-28771", 9.8, "CRITICAL", "", "Zyxel firewall unauthenticated command injection in IKE packet decoder."),
    ("zyxel",    lambda v: True,                "CVE-2022-30525", 9.8, "CRITICAL", "", "Zyxel firewall unauthenticated RCE via ztp/cgi-bin HTTP endpoint."),
    
    # Enterprise Edge/Management
    ("solarwinds",lambda v: _ver_lt(v,"2020.2.1"),"CVE-2020-10148", 9.8,"CRITICAL", "", "SolarWinds Orion API authentication bypass (Sunburst/Supernova vector)."),
    ("kaseya",   lambda v: _ver_lt(v, "5.3"),   "CVE-2021-30116", 9.8, "CRITICAL", "", "Kaseya VSA credential leak and RCE (REvil ransomware supply chain attack)."),
    ("moveit",   lambda v: True,                "CVE-2023-34362", 9.8, "CRITICAL", "", "Progress MOVEit Transfer SQL injection leading to RCE (Cl0p ransomware vector)."),
    ("goanywhere",lambda v: True,               "CVE-2023-0669",  9.8, "CRITICAL", "", "Fortra GoAnywhere MFT unauthenticated RCE via Java Deserialization."),
    ("papercut", lambda v: _ver_lt(v,"22.0.9"), "CVE-2023-27350", 9.8, "CRITICAL", "", "PaperCut MF/NG unauthenticated RCE via authentication bypass."),
    ("teamcity", lambda v: _ver_lt(v,"2023.05.4"),"CVE-2023-42793",9.8,"CRITICAL", "", "JetBrains TeamCity unauthenticated RCE via authentication bypass."),
    ("teamcity", lambda v: _ver_lt(v,"2023.11.4"),"CVE-2024-27198",9.8,"CRITICAL", "", "JetBrains TeamCity authentication bypass allowing admin account creation and RCE."),
    
    # OwnCloud/NextCloud
    ("owncloud", lambda v: _ver_lt(v, "10.13.1"),"CVE-2023-49103", 10.0,"CRITICAL", "", "ownCloud graphapi app info disclosure exposing admin credentials/PHP info."),
    ("nextcloud",lambda v: _ver_lt(v, "21.0.4"), "CVE-2021-32682", 9.0, "CRITICAL", "", "NextCloud unauthenticated access to system info via WebDAV."),
    
    # Email / Collaboration
    ("roundcube",lambda v: _ver_lt(v, "1.4.12"), "CVE-2020-35730", 7.5, "HIGH",     "", "Roundcube Webmail Cross-Site Scripting (XSS) leading to credential theft."),
    ("zimbra",   lambda v: _ver_lt(v, "8.8.15"), "CVE-2022-41352", 9.8, "CRITICAL", "", "Zimbra cpio arbitrary file write / RCE (Amavisd vector)."),
    ("exchange", lambda v: True,                 "CVE-2020-0688",  9.0, "CRITICAL", "", "Microsoft Exchange validation key RCE (widely exploited post-auth)."),
    
    # Windows/Microsoft specific bugs detectable via SMB/MS-RPC/HTTP
    ("windows",  lambda v: True,                 "CVE-2021-34527", 9.8, "CRITICAL", "", "PrintNightmare — Windows Print Spooler RCE (unauthenticated capability on some setups)."),
    ("windows",  lambda v: True,                 "CVE-2020-1472",  10.0,"CRITICAL", "", "Zerologon — Netlogon privilege escalation to Domain Admin via MS-NRPC."),
    ("windows",  lambda v: True,                 "CVE-2019-1040",  9.8, "CRITICAL", "", "Microsoft NTLM MIC bypass (Drop the MIC) enabling NTLM relay over SMB."),
    ("windows",  lambda v: True,                 "CVE-2022-30190", 7.8, "HIGH",     "", "Follina — Microsoft Support Diagnostic Tool RCE (reachable via HTTP handlers)."),
    ("iis",      lambda v: v and v.startswith("6."), "CVE-2017-7269",  9.8, "CRITICAL", "", "IIS 6.0 WebDAV buffer overflow RCE (ExplodingCan)."),

    # Grafana
    ("grafana",  lambda v: _ver_lt(v, "9.2.4"),  "CVE-2021-43798", 7.5, "HIGH",     "", "Grafana unauthenticated path traversal — read arbitrary files on the server."),
    ("grafana",  lambda v: _ver_lt(v, "8.3.10"), "CVE-2022-21703", 8.8, "HIGH",     "", "Grafana CSRF → RCE via datasource configuration."),
    ("grafana",  lambda v: _ver_lt(v, "7.5.15"), "CVE-2022-31097", 8.8, "HIGH",     "", "Grafana stored XSS via AlertManager Matcher."),
    # Kibana
    ("kibana",   lambda v: _ver_lt(v, "6.6.1"),  "CVE-2019-7609",  10.0,"CRITICAL", "", "Kibana Timelion prototype pollution RCE (unauthenticated, widely exploited)."),
    ("kibana",   lambda v: _ver_lt(v, "7.17.9"), "CVE-2022-23708", 4.3, "MEDIUM",   "", "Kibana ReDoS denial of service."),
    # HashiCorp Vault
    ("vault",    lambda v: _ver_lt(v, "1.9.4"),  "CVE-2022-40186", 9.8, "CRITICAL", "", "HashiCorp Vault JWT/OIDC auth method allows authentication bypass."),
    ("vault",    lambda v: _ver_lt(v, "1.7.2"),  "CVE-2021-3024",  5.3, "MEDIUM",   "", "HashiCorp Vault SSRF via sys/wrapping/lookup endpoint."),
    # HashiCorp Consul
    ("consul",   lambda v: _ver_lt(v, "1.10.1"), "CVE-2021-37219", 8.8, "HIGH",     "", "HashiCorp Consul Raft RPC bypass → arbitrary code execution."),
    # etcd
    ("etcd",     lambda v: _ver_lt(v, "3.3.23"), "CVE-2020-15106", 6.5, "MEDIUM",   "", "etcd WAL parser can cause OOM via malformed entries."),
    ("etcd",     lambda v: _ver_lt(v, "3.4.10"), "CVE-2020-15112", 6.5, "MEDIUM",   "", "etcd DoS via nil derference in Raft code."),
    # RabbitMQ
    ("rabbitmq", lambda v: _ver_lt(v, "3.12.7"), "CVE-2023-46118", 4.9, "MEDIUM",   "", "RabbitMQ DoS via very large message body from authenticated user."),
    ("rabbitmq", lambda v: _ver_lt(v, "3.8.0"),  "CVE-2019-11291", 4.3, "MEDIUM",   "", "RabbitMQ reflected XSS in management UI."),
    # InfluxDB
    ("influxdb", lambda v: _ver_lt(v, "1.7.7"),  "CVE-2019-20933", 9.8, "CRITICAL", "", "InfluxDB authentication bypass — JWT shared secret default allows forged tokens."),
    # Apache CouchDB
    ("couchdb",  lambda v: _ver_lt(v, "3.2.3"),  "CVE-2022-24706", 9.8, "CRITICAL", "", "Apache CouchDB cookie erlang term deserialization — unauthenticated RCE."),
    ("couchdb",  lambda v: _ver_lt(v, "2.3.0"),  "CVE-2018-17188", 8.8, "HIGH",     "", "Apache CouchDB privilege escalation via _users endpoint."),
    # Apache Solr
    ("solr",     lambda v: _ver_lt(v, "8.3.1"),  "CVE-2019-17558", 8.8, "HIGH",     "", "Apache Solr Velocity template injection RCE (ConfigAPI)."),
    ("solr",     lambda v: _ver_lt(v, "8.2.0"),  "CVE-2019-0193",  9.8, "CRITICAL", "", "Apache Solr DataImportHandler command injection RCE."),
    ("solr",     lambda v: _ver_lt(v, "7.1.0"),  "CVE-2017-12629", 9.8, "CRITICAL", "", "Apache Solr XML External Entity (XXE) → SSRF/RCE."),
    # MinIO
    ("minio",    lambda v: _ver_lt(v, "2023-03-13"), "CVE-2023-28432", 7.5,"HIGH",  "", "MinIO information disclosure — /minio/health/cluster leaks access+secret keys."),
    # Prometheus
    ("prometheus",lambda v: _ver_lt(v, "2.1.0"), "CVE-2019-3826",  8.1, "HIGH",     "", "Prometheus path traversal in web UI."),
    # Splunk
    ("splunk",   lambda v: _ver_lt(v, "9.1.1"),  "CVE-2023-46214", 8.0, "HIGH",     "", "Splunk XSLT injection RCE — authenticated but exploitable post-compromise."),
    ("splunk",   lambda v: _ver_lt(v, "8.2.0"),  "CVE-2022-32158", 9.0, "CRITICAL", "", "Splunk Enterprise peer-to-peer communication allows RCE."),
    # Nagios
    ("nagios",   lambda v: _ver_lt(v, "4.4.7"),  "CVE-2020-13977", 7.7, "HIGH",     "", "Nagios Core RCE via injected cron entries."),
    ("nagios",   lambda v: _ver_lt(v, "4.4.6"),  "CVE-2021-37344", 8.8, "HIGH",     "", "Nagios SQLi in nagios_check_command → OS command execution."),
    # Apache Zookeeper
    ("zookeeper",lambda v: _ver_lt(v, "3.5.5"),  "CVE-2019-0201",  5.9, "MEDIUM",   "", "Apache ZooKeeper admin interface exposes sensitive data without auth."),
    # Docker
    ("docker",   lambda v: _ver_lt(v, "20.10.24"),"CVE-2019-5736", 8.6, "HIGH",     "", "runc container escape — malicious image overwrites host runc binary."),
    ("docker",   lambda v: _ver_lt(v, "20.10.9"), "CVE-2021-41091", 6.3,"MEDIUM",   "", "Docker moby rootless container access to host filesystem."),
    # Kubernetes
    ("kubernetes",lambda v: _ver_lt(v, "1.16.0"),"CVE-2018-1002105",9.8,"CRITICAL","", "Kubernetes privilege escalation via aggregated API server connection upgrade."),
    ("kubernetes",lambda v: _ver_lt(v, "1.24.0"),"CVE-2022-3294",  6.0, "MEDIUM",   "", "Kubernetes node IP address bypass via hostname routing."),
    # Grafana additional
    ("grafana",  lambda v: _ver_lt(v, "10.0.0"), "CVE-2023-1410",  6.8, "MEDIUM",   "", "Grafana stored XSS in Graphite annotations."),
    # phpMyAdmin
    ("phpmyadmin",lambda v: _ver_lt(v, "5.1.2"), "CVE-2022-23807", 4.3, "MEDIUM",   "", "phpMyAdmin two-factor auth bypass via brute force."),
    ("phpmyadmin",lambda v: _ver_lt(v, "4.8.4"), "CVE-2018-19968", 8.8, "HIGH",     "", "phpMyAdmin local file inclusion leading to RCE."),
    # Roundcube
    ("roundcube",lambda v: _ver_lt(v, "1.6.1"),  "CVE-2023-43770", 6.1, "MEDIUM",   "", "Roundcube persistent XSS in HTML message handling."),
    ("roundcube",lambda v: _ver_lt(v, "1.5.4"),  "CVE-2022-37393", 8.8, "HIGH",     "", "Roundcube shell injection via malicious email header in managesieve plugin."),
    # ManageEngine (additional product variants)
    ("manageengine",lambda v: _ver_lt(v, "10.5"),"CVE-2021-44515", 9.8, "CRITICAL", "", "ManageEngine Desktop Central unauthenticated RCE via /client-manager endpoint."),

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
        if not product or not version:
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