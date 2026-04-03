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
    remediation: str = ""
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

    # Jenkins
    (r"X-Jenkins:\s*([\d.]+)",                "jenkins"),
    (r"Jenkins[/ ]([\d.]+)",                   "jenkins"),
    # Grafana
    (r"Grafana/([\d.]+)",                      "grafana"),
    (r"X-Grafana-Version:\s*([\d.]+)",         "grafana"),
    # Kibana
    (r'"number"\s*:\s*"([\d.]+)".*kibana',     "kibana"),
    (r"kbn-name.*kibana",                      "kibana"),
    # Confluence
    (r"X-Confluence-Request-Time",             "confluence"),
    (r"Confluence/([\d.]+)",                   "confluence"),
    # Jira
    (r"X-ASEN:\s*\S+",                         "jira"),
    (r"Jira/([\d.]+)",                         "jira"),
    # Bitbucket
    (r"X-Atlassian-Token",                     "bitbucket"),
    # Tomcat (extra patterns)
    (r"Apache-Coyote/([\d.]+)",                "tomcat"),
    # Spring Boot
    (r"Spring Boot[/ ]([\d.]+)",               "spring"),
    # GitLab
    (r"X-Gitlab-Meta",                         "gitlab"),
    (r"GitLab/([\d.]+)",                       "gitlab"),
    # Memcached
    (r"^VERSION ([\d.]+)",                     "memcached"),
    # Docker API (port 2375/2376 JSON /version response)
    (r'"Version"\s*:\s*"([\d.]+(?:-ce|-ee)?)"',"docker"),
    # Kubernetes /version JSON
    (r'"gitVersion"\s*:\s*"v([\d.]+)"',        "kubernetes"),
    # etcd /version JSON
    (r'"etcdserver"\s*:\s*"([\d.]+)"',         "etcd"),
    # HashiCorp Vault
    (r'"version"\s*:\s*"([\d.]+)".*vault',     "vault"),
    (r"X-Vault-Request",                       "vault"),
    # Consul
    (r'"Config".*"Version"\s*:\s*"([\d.]+)"', "consul"),
    # InfluxDB
    (r"X-Influxdb-Version:\s*([\d.]+)",        "influxdb"),
    # CouchDB
    (r'Server:\s*CouchDB/([\d.]+)',            "couchdb"),
    # RabbitMQ
    (r"RabbitMQ ([\d.]+)",                     "rabbitmq"),
    # HAProxy
    (r"HAProxy/([\d.]+)",                      "haproxy"),
    (r"via:.*haproxy[/ ]([\d.]+)",             "haproxy"),
    # Lighttpd
    (r"lighttpd/([\d.]+)",                     "lighttpd"),
    # WebLogic
    (r"WebLogic Server ([\d.]+)",              "weblogic"),
    (r"BEA WebLogic/([\d.]+)",                 "weblogic"),
    # JBoss/WildFly
    (r"JBoss[/ ]([\d.]+)",                     "jboss"),
    (r"WildFly/([\d.]+)",                      "wildfly"),
    # GlassFish
    (r"GlassFish(?:[^/]*)/([\d.]+)",           "glassfish"),
    # ColdFusion
    (r"ColdFusion[/ ]([\d.]+)",                "coldfusion"),
    (r"X-Powered-By:.*ColdFusion",             "coldfusion"),
    # phpMyAdmin
    (r'content="phpMyAdmin ([\d.]+)',           "phpmyadmin"),
    # Microsoft Exchange
    (r"X-OWA-Version:\s*([\d.]+)",             "exchange"),
    (r"X-FEServer:",                           "exchange"),
    # Microsoft SharePoint
    (r"MicrosoftSharePointTeamServices:\s*([\d.]+)", "sharepoint"),
    # VNC protocol version
    (r"RFB (\d{3})\.(\d{3})",                  "vnc"),
    # Samba/SMB banner
    (r"Samba ([\d.]+)",                        "samba"),
    # OpenLDAP
    (r"OpenLDAP/([\d.]+)",                     "openldap"),
    # Apache Solr
    (r'"solr-spec-version"\s*:\s*"([\d.]+)"',  "solr"),
    # MinIO
    (r"MinIO Object Storage",                  "minio"),
    # Splunk
    (r"X-Splunk-Request-Channel",              "splunk"),
    # Nagios
    (r"Nagios/([\d.]+)",                       "nagios"),
    # Zabbix
    (r"Zabbix ([\d.]+)",                       "zabbix"),
    # Prometheus
    (r"Prometheus/([\d.]+)",                   "prometheus"),
    # Roundcube
    (r"Roundcube Webmail ([\d.]+)",            "roundcube"),
    # VMware vCenter
    (r"VMware vCenter Server ([\d.]+)",        "vcenter"),
    # Sendmail
    (r"Sendmail ([\d.]+)",                     "sendmail"),
    # PHP additional
    (r"X-Powered-By:\s*PHP/([\d.]+)",          "php"),
    # WordPress generator meta
    (r'content="WordPress ([\d.]+)',           "wordpress"),
    # Drupal generator meta
    (r'content="Drupal ([\d.]+)',              "drupal"),
    # Exim additional
    (r"Exim ([\d.]+)",                         "exim"),
    # Dovecot version
    (r"Dovecot (?:ready|IMAP|POP3).{0,30}? ([\d.]+)", "dovecot"),
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
        remediation=f"Apply official security patches provided by the vendor. Refer to: {nvd.references[0] if nvd.references else 'NVD Advisory'}",
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

        # User requirement: Only show actual vulnerabilities based on exact version matches.
        # Do not 'guess' or show baseline CVEs if we don't know the specific version running.
        if not product or not version:
            continue

        matched_offline = []
        for prod_key, ver_fn, cve_id, cvss, sev, vec, desc, rem in OFFLINE_SIGS:
            if prod_key not in (product or '').lower():
                continue
            if version and not ver_fn(version):
                continue
            if cvss < min_cvss:
                continue
            matched_offline.append(CVE(
                id=cve_id, description=desc, cvss_score=cvss,
                severity=sev, vector=vec, published="",
                remediation=rem,
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
    ("openssh", lambda v: _ver_lt(v, "9.3"),   "CVE-2023-38408", 9.8, "CRITICAL", "", "OpenSSH < 9.3p2 ssh-agent RCE via PKCS#11 — exploitable with agent forwarding.", "Upgrade to OpenSSH 9.3p2 or higher. Disable ssh-agent forwarding ('ForwardAgent no' in ssh_config) if not required."),
    ("openssh", lambda v: _ver_lt(v, "8.5"),   "CVE-2021-41617", 7.0, "HIGH",     "", "OpenSSH < 8.5 privilege escalation via supplemental group init in sshd.", "Upgrade to OpenSSH 8.5 or newer. Ensure 'AuthorizedKeysCommand' and 'AuthorizedPrincipalsCommand' run as a dedicated, low-privilege user."),
    ("openssh", lambda v: _ver_lt(v, "7.7"),   "CVE-2018-15473", 5.3, "MEDIUM",   "", "OpenSSH < 7.7 username enumeration via timing side-channel.", "Upgrade to OpenSSH 7.7 or later to mitigate user enumeration via timing discrepancies."),
    ("openssh", lambda v: _ver_lt(v, "7.2"),   "CVE-2016-3115",  7.5, "HIGH",     "", "OpenSSH < 7.2p2 X11 Forwarding Bypass — possible bypass of restricted shells.", "Upgrade to OpenSSH 7.2p2 or higher. Disable X11 forwarding ('X11Forwarding no' in sshd_config) if not explicitly needed."),
    ("openssh", lambda v: _ver_lt(v, "2.9.9"), "CVE-2001-0529",  10.0,"CRITICAL", "", "OpenSSH < 2.9.9 Remote root compromise (channel code).", "URGENT: This legacy version is critically vulnerable. Upgrade to a modern, supported OpenSSH release immediately."),
    ("apache",  lambda v: _ver_lt(v, "2.4.58"),"CVE-2023-45662", 7.5, "HIGH",     "", "Apache HTTP Request Smuggling DoS.", "Update Apache to 2.4.58 or later. Review proxy timeout configurations."),
    ("apache",  lambda v: _ver_lt(v, "2.4.55"),"CVE-2022-22720", 9.8, "CRITICAL", "", "Apache HTTP request smuggling via unclosed inbound connections.", "Upgrade Apache HTTP Server to version 2.4.55 or higher."),
    ("apache",  lambda v: _ver_lt(v, "2.4.51"),"CVE-2021-40438", 9.0, "CRITICAL", "", "Apache mod_proxy SSRF via unix: URI scheme.", "Update Apache to 2.4.51. If using mod_proxy, ensure untrusted input is not used in proxy path resolution."),
    ("apache",  lambda v: v == "2.4.49",       "CVE-2021-41773", 9.8, "CRITICAL", "", "Apache 2.4.49 path traversal + RCE — massively exploited. Metasploit module.", "URGENT: Apache 2.4.49 is highly unstable and vulnerable. Upgrade to 2.4.51+ immediately."),
    ("apache",  lambda v: _ver_lt(v, "2.4.39"),"CVE-2019-0211",  9.8, "CRITICAL", "", "Apache CARPE DIEM — local privilege escalation to root.", "Update Apache to version 2.4.39 or higher. Review worker process privileges."),
    ("apache",  lambda v: _ver_lt(v, "2.2.34"),"CVE-2017-9798",  7.5, "HIGH",     "", "Apache Optionsbleed — memory disclosure via OPTIONS request.", "Upgrade to Apache 2.2.34 or 2.4.27. Disable the OPTIONS method if not essential."),
    ("nginx",   lambda v: _ver_lt(v, "1.25.3"),"CVE-2023-44487", 7.5, "HIGH",     "", "HTTP/2 Rapid Reset DoS — send+cancel streams to exhaust workers.", "Upgrade nginx to 1.25.3+ or 1.24.0. Limit keepalive_requests and concurrent streams for HTTP/2."),
    ("nginx",   lambda v: _ver_lt(v, "1.20.1"),"CVE-2021-23017", 7.7, "HIGH",     "", "nginx DNS resolver 1-byte heap overwrite.", "Update nginx to 1.20.1 or higher. Avoid using the 'resolver' directive with untrusted DNS servers."),
    ("nginx",   lambda v: _ver_lt(v, "1.17.3"),"CVE-2019-9511",  7.5, "HIGH",     "", "HTTP/2 Data Dribble DoS.", "Update nginx to 1.16.1 or 1.17.3 or later. Adjust HTTP/2 buffer and timeout settings."),
    ("nginx",   lambda v: _ver_in_range(v, "1.3.9", "1.4.0"), "CVE-2013-2028", 10.0, "CRITICAL", "", "nginx stack-based buffer overflow in chunked request handling (Pre-auth RCE).", "Upgrade to nginx 1.4.1, 1.5.0 or newer immediately."),
    ("nginx",   lambda v: _ver_lt(v, "1.13.3"),"CVE-2017-7529",  7.5, "HIGH",     "", "nginx integer overflow in range filter leading to cache bypass and info disclosure.", "Update nginx to 1.12.1 or 1.13.3 or higher."),
    ("nginx",   lambda v: _ver_lt(v, "1.23.2"),"CVE-2022-41741", 7.5, "HIGH",     "", "nginx buffer overflow in ngx_http_mp4_module.", "Upgrade to 1.22.1, 1.23.2 or newer. Disable ngx_http_mp4_module if not strictly required."),
    ("nginx",   lambda v: _ver_lt(v, "1.15.6"),"CVE-2018-16843", 7.5, "HIGH",     "", "nginx HTTP/2 module excessive memory consumption (DoS).", "Update nginx to 1.14.1 or 1.15.6. Review HTTP/2 concurrent stream limits."),
    ("nginx",   lambda v: _ver_lt(v, "1.5.7"),  "CVE-2013-4547",  9.8, "CRITICAL", "", "nginx access restriction bypass via specially crafted URI characters (null byte).", "Upgrade to nginx 1.4.4, 1.5.7 or higher."),
    ("nginx",   lambda v: _ver_lt(v, "1.10.1"), "CVE-2016-4450",  7.5, "HIGH",     "", "nginx NULL pointer dereference in ngx_http_core_module (DoS).", "Update nginx to 1.10.1 or 1.11.1 or newer."),
    ("nginx",   lambda v: _ver_lt(v, "1.5.12"), "CVE-2014-0088",  7.5, "HIGH",     "", "nginx SPDY module memory corruption vulnerability.", "Upgrade to nginx 1.4.7 or 1.5.12+. Disable SPDY if not required."),
    ("nginx",   lambda v: _ver_lt(v, "0.8.15"), "CVE-2009-2629",  9.8, "CRITICAL", "", "nginx remote buffer overflow in URI parsing (Legacy).", "Upgrade to a modern, supported nginx release (1.24+)."),

    ("php",     lambda v: _ver_lt(v, "8.1.0"), "CVE-2024-4577",  9.8, "CRITICAL", "", "PHP CGI RCE via argument injection on Windows.", "Update PHP to 8.1.29, 8.2.20, or 8.3.8. Use FastCGI instead of CGI on Windows environments."),
    ("php",     lambda v: _ver_lt(v, "7.4.0"), "CVE-2019-11043", 9.8, "CRITICAL", "", "PHP-FPM + nginx path_info buffer underflow — unauthenticated RCE.", "Upgrade PHP to a supported stable version (8.x). Ensure 'try_files' is correctly configured in nginx to prevent passing non-PHP files to FPM."),
    ("php",     lambda v: _ver_lt(v, "8.1.0"), "CVE-2022-31626", 8.8, "HIGH",     "", "PHP < 8.1 password_verify() buffer overflow.", "Update PHP and ensure password hashing uses strong, modern algorithms (bcrypt/argon2)."),
    ("php",     lambda v: _ver_lt(v, "5.4.12"),"CVE-2012-1823",  10.0,"CRITICAL", "", "PHP CGI argument injection (RCE). widely used in botnets.", "URGENT: Legacy PHP CGI is critically vulnerable. Upgrade to a modern PHP version (8.x) and use FastCGI/PHP-FPM."),
    ("redis",   lambda v: _ver_lt(v, "6.2.0"), "CVE-2021-32625", 9.8, "CRITICAL", "", "Redis < 6.2 unauthenticated RCE via Lua integer overflow.", "Update Redis to 6.2 or higher. Ensure Redis is not exposed to the public internet."),
    ("redis",   lambda v: _ver_lt(v, "5.0.14"),"CVE-2022-0543",  10.0,"CRITICAL", "", "Redis Lua sandbox escape — unauthenticated RCE (Debian/Ubuntu packages).", "Update redis-server package via apt/yum. Ensure Lua scripts are sourced from trusted paths only."),
    ("redis",   lambda v: _ver_lt(v, "4.0.0"), "CVE-2018-8300",  8.8, "HIGH",     "", "Redis unprotected instance (No Auth) enabling system takeover via public SSH key drop.", "Enable authentication ('requirepass') and bind Redis to localhost only. Block port 6379 via firewall."),
    ("vsftpd",  lambda v: v == "2.3.4",        "CVE-2011-2523",  10.0,"CRITICAL", "", "vsftpd 2.3.4 backdoor — username with :) opens root shell on port 6200.", "Remove the malicious vsftpd 2.3.4 binary and install a clean version (3.0.x). Verify binary integrity."),
    ("tomcat",  lambda v: _ver_lt(v, "9.0.31"),"CVE-2020-1938",  9.8, "CRITICAL", "", "Ghostcat: Tomcat AJP file read/include — RCE if file upload possible.", "Update Tomcat to 9.0.31+, 8.5.51+, or 7.0.100+. Disable the AJP connector if not needed, or set 'secretRequired=\"true\"'."),
    ("tomcat",  lambda v: _ver_lt(v, "8.5.23"),"CVE-2017-12615", 9.8, "CRITICAL", "", "Tomcat JSP Upload Bypass RCE via HTTP PUT (Windows only).", "Update Tomcat and ensure 'readonly' is set to 'true' for the DefaultServlet in web.xml."),
    ("tomcat",  lambda v: _ver_lt(v, "7.0.100"),"CVE-2020-9484", 9.8, "CRITICAL", "", "Tomcat deserialization RCE via PersistentManager + FileStore.", "Update Tomcat. Avoid using PersistentManager with FileStore if file content originates from untrusted sources."),
    ("iis",     lambda v: True,                "CVE-2022-21907", 9.8, "CRITICAL", "", "IIS HTTP Protocol Stack wormable pre-auth RCE (Windows Server 2022).", "Apply Microsoft Security Update KB5009555 (Jan 2022). Disable HTTP Trailer Support if patch cannot be applied."),
    ("iis",     lambda v: True,                "CVE-2015-1635",  10.0,"CRITICAL", "", "MS15-034: IIS HTTP.sys remote code execution via Range header (Wormable).", "Apply Microsoft Security Update KB3042553. Disable kernel caching if patching is delayed."),
    ("iis",     lambda v: True,                "CVE-2021-31166", 9.8, "CRITICAL", "", "IIS HTTP.sys UAF Remote Code Execution / Blue Screen DoS.", "Apply Microsoft Security Update KB5003173 (May 2021)."),
    ("iis",     lambda v: True,                "CVE-2022-35748", 9.8, "CRITICAL", "", "IIS HTTP Request Smuggling RCE (unauthenticated pre-auth RCE).", "Apply August 2022 Security Updates (KB5016629+)."),
    ("iis",     lambda v: True,                "CVE-2023-21709", 7.5, "HIGH",     "", "IIS HTTP Request Smuggling vulnerability.", "Apply January 2023 Microsoft security patches. Use WAF to inspect for malformed HTTP requests."),
    ("iis",     lambda v: _ver_lt(v, "7.5"),   "CVE-2010-3972",  10.0,"CRITICAL", "", "IIS 7.5 FTP Service unauthenticated RCE via TELNET IAC sequence.", "Update IIS to version 8.0+ or apply security update KB2433917. Disable FTP if not strictly required."),
    ("iis",     lambda v: _ver_lt(v, "6.0"),   "CVE-2017-7269",  9.8, "CRITICAL", "", "IIS 6.0 ScStoragePathFromUrl unauthenticated RCE via PROPFIND request.", "Disable WebDAV on IIS 6.0 or migrate to a modern, supported OS/IIS version."),
    ("iis",     lambda v: _ver_lt(v, "7.5"),   "CVE-2010-1899",  9.8, "CRITICAL", "", "MS10-065 — IIS 7.0/7.5 ASP range header remote code execution.", "Apply MS10-065 security update (KB2271195)."),
    ("iis",     lambda v: True,                "CVE-2022-22021", 6.5, "MEDIUM",   "", "IIS Information Disclosure vulnerability.", "Apply June 2022 Microsoft security updates. Enforce strong authentication for management endpoints."),
    ("iis",     lambda v: True,                "Tilde Scan",     5.0, "MEDIUM",   "", "IIS Tilde Short Name Disclosure — potential disclosure of file/directory names.", "Apply 'Web Property' and '8.3 Filename' restrictions (KB2460678). Upgrade to IIS 8.0+."),

    ("drupal",  lambda v: _ver_lt(v, "8.5.1"),   "CVE-2018-7600",  9.8, "CRITICAL", "", "Drupalgeddon2 — unauthenticated RCE via Form API. Widely exploited by botnets.", "Urgently update Drupal to 7.58, 8.4.8, or 8.5.1. Perform a full compromise assessment."),
    ("drupal",  lambda v: _ver_lt(v, "7.32"),   "CVE-2014-3704",  9.8, "CRITICAL", "", "Drupalgeddon — SQL Injection via database abstraction API.", "Upgrade Drupal 7 core to 7.32 or later."),
    ("drupal",  lambda v: _ver_lt(v, "8.6.10"), "CVE-2019-6340",  9.8, "CRITICAL", "", "Drupal RCE in RESTful Web Services module via insecure deserialization.", "Update to Drupal 8.6.10, 8.5.11 or later. Disable RESTful Web Services if not required."),
    ("drupal",  lambda v: _ver_lt(v, "8.5.3"),  "CVE-2018-7602",  9.8, "CRITICAL", "", "Drupalgeddon3 — authenticated RCE via multiple core components.", "Update to Drupal 7.59, 8.5.3, or 8.4.8 or later."),
    ("drupal",  lambda v: True,                "CVE-2020-13671", 9.0, "CRITICAL", "", "Drupal RCE via unsafe file extensions (double extension spoofing).", "Update to Drupal 7.74, 8.8.11, or 8.9.9. Implement strict file upload filtering."),
    ("drupal",  lambda v: _ver_lt(v, "9.4.1"),  "CVE-2022-25277", 9.8, "CRITICAL", "", "Drupal RCE via insecure file upload in core Media module.", "Update to Drupal 9.4.1 or 9.3.16. Ensure directory permissions are restrictive."),
    ("drupal",  lambda v: _ver_lt(v, "8.3.4"),  "CVE-2017-6920",  8.8, "HIGH",     "", "Drupal RCE via YAML PECL unauthenticated code execution.", "Update to Drupal 8.3.4 or higher. Update the PECL YAML extension."),
    ("drupal",  lambda v: _ver_lt(v, "7.38"),   "CVE-2015-3234",  8.1, "HIGH",     "", "Drupal OpenID authentication bypass vulnerability.", "Update Drupal 7 core to 7.38 or higher."),
    ("drupal",  lambda v: _ver_lt(v, "7.34"),   "CVE-2014-9016",  7.5, "HIGH",     "", "Drupal password hash disclosure via specific user login errors.", "Update Drupal 7 core to 7.34 or later."),
    ("drupal",  lambda v: _ver_lt(v, "9.5.5"),  "CVE-2023-28821", 7.5, "HIGH",     "", "Drupal core access bypass vulnerability.", "Update to Drupal 10.0.6, 9.5.5, or 9.4.14."),
    ("drupal",  lambda v: True,                "CVE-2019-6341",  7.5, "HIGH",     "", "Drupal XSS in core File module upload handling.", "Update to latest Drupal core versions (7.64+, 8.6.10+)."),
    ("drupal",  lambda v: True,                "CVE-2020-13662", 7.5, "HIGH",     "", "Drupal access bypass in content moderation module.", "Update to 8.8.11, 8.9.9, or 9.0.8 or newer."),
    ("drupal",  lambda v: _ver_lt(v, "7.0"),    "CVE-2012-1632",  9.8, "CRITICAL", "", "Drupal RCE in comment module (Metasploit module available).", "Upgrade to latest Drupal 7 or 8 release."),

    ("wordpress",lambda v: _ver_lt(v, "6.4.2"),"CVE-2024-21726", 9.8, "CRITICAL", "", "WordPress < 6.4.2 PHP object injection in WP_HTML_Token — unauthenticated RCE.", "Update WordPress to 6.4.2 or higher. Audit installed plugins for unsafe deserialization patterns."),
    ("wordpress",lambda v: _ver_lt(v, "4.7.2"),"CVE-2017-1001000",9.8,"CRITICAL", "", "WordPress REST API unauthenticated privilege escalation/content injection.", "Update WordPress to 4.7.2 or later. Restrict REST API access to authenticated users if not required."),
    ("wordpress",lambda v: _ver_lt(v, "5.1.1"),"CVE-2019-8942",  8.8, "HIGH",     "", "WordPress authenticatd RCE / Image upload path traversal.", "Update WordPress to 5.1.1+ and ensure the web server has restricted write permissions for the wp-content directory."),
    ("joomla",  lambda v: _ver_lt(v, "3.4.6"), "CVE-2015-8562",  9.8, "CRITICAL", "", "Joomla Object Injection RCE via user-agent HTTP header.", "Update Joomla to 3.4.6 or later. Sanitize all HTTP headers at the application entry point."),
    ("joomla",  lambda v: _ver_lt(v, "4.2.8"),  "CVE-2023-23752", 9.8, "CRITICAL", "", "Joomla unauthorized access to webservices — information disclosure and auth bypass.", "Update to Joomla 4.2.8 or higher. Restrict access to /api endpoint via firewall/ACLs."),
    ("joomla",  lambda v: _ver_lt(v, "3.7.1"),  "CVE-2017-8917",  9.8, "CRITICAL", "", "Joomla SQL Injection in com_fields component.", "Update to Joomla 3.7.1 or higher. Audit com_fields usage for untrusted input."),
    ("joomla",  lambda v: _ver_lt(v, "3.6.4"),  "CVE-2016-8870",  9.8, "CRITICAL", "", "Joomla registration bypass — unauthorized account creation.", "Update to 3.6.4 or later. Disable public user registration if not required."),
    ("joomla",  lambda v: _ver_lt(v, "3.6.4"),  "CVE-2016-8869",  9.8, "CRITICAL", "", "Joomla authentication bypass leading to privilege escalation.", "Update to Joomla 3.6.4 immediately."),
    ("joomla",  lambda v: _ver_lt(v, "3.9.26"), "CVE-2021-23132", 9.0, "CRITICAL", "", "Joomla RCE via insecure file upload in core Media Manager.", "Update to 3.9.26 or 4.0.0-beta7+. Implement file extension filtering for uploads."),
    ("joomla",  lambda v: _ver_lt(v, "3.4.5"),  "CVE-2015-7297",  9.8, "CRITICAL", "", "Joomla SQL Injection in com_content (widely exploited).", "Update to Joomla 3.4.5 or newer."),
    ("joomla",  lambda v: _ver_lt(v, "3.4.4"),  "CVE-2015-6944",  9.8, "CRITICAL", "", "Joomla LDAP authentication RCE (remote code execution).", "Update to 3.4.4+. Use local authentication or secure LDAP configurations."),
    ("joomla",  lambda v: _ver_lt(v, "5.0.3"),  "CVE-2024-21725", 8.8, "HIGH",     "", "Joomla stored XSS via multiple core components.", "Update to Joomla 5.0.3 or 4.4.3 or higher."),
    ("joomla",  lambda v: _ver_lt(v, "3.9.11"), "CVE-2019-15024", 8.1, "HIGH",     "", "Joomla XSS in administrative interface leading to account takeover.", "Update to Joomla 3.9.11 or later."),
    ("joomla",  lambda v: _ver_lt(v, "3.8.5"),  "CVE-2018-6376",  8.8, "HIGH",     "", "Joomla SQL Injection in administrative interface.", "Update to Joomla 3.8.5 or newer."),
    ("joomla",  lambda v: _ver_lt(v, "3.6.5"),  "CVE-2016-9838",  7.5, "HIGH",     "", "Joomla XSS in com_fields component.", "Update to Joomla 3.6.5+. Sanitize custom fields."),
    ("joomla",  lambda v: _ver_lt(v, "3.10.6"), "CVE-2022-23707", 7.5, "HIGH",     "", "Joomla insecure transport for administrative login.", "Update to 3.10.6 or higher. Enforce HTTPS for all admin pages."),
    ("joomla",  lambda v: _ver_lt(v, "3.8.0"),  "CVE-2017-14596", 5.3, "MEDIUM",   "", "Joomla username enumeration via login error messages.", "Update to Joomla 3.8.0 or newer."),
    ("joomla",  lambda v: _ver_lt(v, "3.9.17"), "CVE-2020-11887", 6.1, "MEDIUM",   "", "Joomla XSS in multiple core modules.", "Update to Joomla 3.9.17 or later."),
    ("joomla",  lambda v: _ver_lt(v, "4.2.7"),  "CVE-2023-23750", 6.5, "MEDIUM",   "", "Joomla Open Redirect in core login redirection.", "Update to Joomla 4.2.7 or higher."),

    ("proftpd", lambda v: _ver_lt(v, "1.3.6"), "CVE-2019-12815", 9.8, "CRITICAL", "", "ProFTPD mod_copy unauthenticated file copy via SITE CPFR/CPTO.", "Update ProFTPD to 1.3.6 or later. Disable mod_copy in proftpd.conf if unauthenticated copy is not essential."),
    ("proftpd", lambda v: _ver_lt(v, "1.3.5"), "CVE-2015-3306",  10.0,"CRITICAL", "", "ProFTPD mod_copy unauthenticated RCE via SITE CPFR/CPTO.", "Update ProFTPD. Disable mod_copy immediately if you are on an older version."),
    ("proftpd", lambda v: _ver_lt(v, "1.3.3"), "CVE-2010-4221",  10.0,"CRITICAL", "", "ProFTPD TELNET IAC escape integer overflow (metasploit available).", "Upgrade to a modern version of ProFTPD (1.3.6+)."),
    ("postgresql",lambda v: _ver_lt(v, "14.0"),"CVE-2022-1552",  8.8, "HIGH",     "", "PostgreSQL autovacuum, REINDEX, and other commands allow privilege escalation.", "Update PostgreSQL to 14.3, 13.7, 12.11, or 11.16."),
    ("postgresql",lambda v: _ver_lt(v, "11.3"),"CVE-2019-9193",  9.0, "CRITICAL", "", "PostgreSQL authenticated RCE via COPY TO/FROM PROGRAM.", "Update PostgreSQL and ensure 'pg_execute_server_program' role is not granted to untrusted users."),
    ("mysql",   lambda v: _ver_lt(v, "8.0.36"),"CVE-2024-20974", 9.8, "CRITICAL", "", "MySQL Server unauthenticated remote code execution (RCE) via multiple vectors.", "Update MySQL to 8.0.36, 8.3.0 or higher immediately. Apply the January 2024 Oracle Critical Patch Update (CPU)."),
    ("mysql",   lambda v: _ver_lt(v, "8.0.33"),"CVE-2023-21963", 9.8, "CRITICAL", "", "MySQL Server remote code execution (RCE) vulnerability in multiple core components.", "Update MySQL to 8.0.33 or newer. Refer to Oracle April 2023 CPU."),
    ("mysql",   lambda v: _ver_lt(v, "8.0.28"),"CVE-2022-21417", 6.5, "MEDIUM",   "", "MySQL < 8.0.28 InnoDB uncontrolled resource consumption DoS.", "Update MySQL to 8.0.28 or later. Monitor InnoDB buffer pool usage."),
    ("mysql",   lambda v: _ver_lt(v, "5.7.15"),"CVE-2016-6662",  9.8, "CRITICAL", "", "MySQL Remote Root RCE via malicious my.cnf file (widely exploited).", "Update MySQL to 5.5.52, 5.6.33, or 5.7.15+. Ensure my.cnf is not writable by the mysql user."),
    ("mysql",   lambda v: _ver_lt(v, "5.7.15"),"CVE-2016-6663",  7.8, "HIGH",     "", "MySQL local privilege escalation / remote code execution via race condition.", "Update to current stable release of MySQL 5.7+."),
    ("mysql",   lambda v: _ver_lt(v, "5.5.24"),"CVE-2012-2122",  7.5, "HIGH",     "", "MySQL authentication bypass probability bug in memcmp() (Password collisions).", "Urgently upgrade MySQL to 5.5.25 or newer. This bug allows unauthorized access via multiple login attempts."),
    ("mysql",   lambda v: _ver_lt(v, "8.0.22"),"CVE-2020-14812", 7.5, "HIGH",     "", "MySQL Access bypass in Server security/privileges components.", "Update to MySQL 8.0.22 or higher."),
    ("mysql",   lambda v: _ver_lt(v, "5.7.17"),"CVE-2017-3599",  7.5, "HIGH",     "", "MySQL Denial of Service (DoS) via specially crafted network packet.", "Update MySQL and restrict network access to trusted IPs."),
    ("mysql",   lambda v: _ver_lt(v, "8.0.25"),"CVE-2021-2307",  7.5, "HIGH",     "", "MySQL Audit Log bypass / privilege escalation vulnerability.", "Update to MySQL 8.0.25+."),
    ("mysql",   lambda v: _ver_lt(v, "8.0.37"),"CVE-2024-21096", 7.5, "HIGH",     "", "MySQL Optimizer RCE or Denial of Service vulnerability.", "Update to 8.0.37 or 8.4.0 (LTS)."),
    ("mysql",   lambda v: _ver_lt(v, "5.7.25"),"CVE-2019-2420",  7.5, "HIGH",     "", "MySQL Information Disclosure in Server component.", "Update to 5.7.25 or 8.0.14+."),
    ("mysql",   lambda v: _ver_lt(v, "5.5.28"),"CVE-2012-5611",  9.8, "CRITICAL", "", "MySQL multiple format string vulnerabilities leading to RCE (Legacy).", "Upgrade to a modern supported MySQL version."),

    ("memcached",lambda v: True,               "CVE-2018-1000115",7.5,"HIGH",     "", "Memcached UDP amplification DDoS — 50,000x factor, used in 1.7Tbps attack.", "Disable UDP support in memcached ('-U 0') and firewall the service port 11211."),
    ("memcached",lambda v: _ver_lt(v, "1.4.33"),"CVE-2016-8704", 9.8, "CRITICAL", "", "Memcached SASL integer overflow leading to RCE.", "Upgrade memcached to 1.4.33 or later. Disable SASL if not required."),
    ("openssl", lambda v: _ver_lt(v, "3.0.7"), "CVE-2022-3602",  9.8, "CRITICAL", "", "OpenSSL v3 Punycode vulnerability — stack buffer overflow.", "Update OpenSSL to 3.0.7 or later."),
    ("openssl", lambda v: _ver_lt(v, "1.1.1u"),"CVE-2023-0286",  7.4, "HIGH",     "", "OpenSSL X.400 ASN.1 type confusion — potential RCE or DoS.", "Update OpenSSL to 1.1.1u or 3.x."),
    ("openssl", lambda v: _ver_lt(v, "1.0.2"),  "CVE-2014-0160", 7.5, "HIGH",     "", "Heartbleed — OpenSSL TLS heartbeat memory disclosure. Private key extraction possible.", "Reissued SSL/TLS certificates and update OpenSSL to 1.0.1g+."),
    ("openssl", lambda v: _ver_lt(v, "1.0.2"),  "CVE-2014-0224", 7.5, "HIGH",     "", "OpenSSL CCS Injection vulnerability (MiTM decryption).", "Upgrade to OpenSSL 1.0.1h, 1.0.0m, or 0.9.8za."),
    ("samba",   lambda v: _ver_lt(v, "4.15.5"),"CVE-2021-44142", 9.9, "CRITICAL", "", "Samba out-of-bounds heap write in VFS fruit module — pre-auth RCE.", "Update Samba to 4.15.5 or later. Remove 'fruit' from vfs objects in smb.conf."),
    ("samba",   lambda v: _ver_lt(v, "4.13.17"),"CVE-2021-44141",8.8, "HIGH",     "", "Samba information leak via SMB1 UNIX extensions.", "Disable SMB1 ('server min protocol = SMB2') and update Samba."),
    ("samba",   lambda v: _ver_lt(v, "4.6.4"), "CVE-2017-7494",  10.0,"CRITICAL", "", "SambaCry — unauthenticated RCE via malicious shared library upload.", "Update Samba to 4.6.4, 4.5.10, or 4.4.14 or later."),
    ("samba",   lambda v: _ver_lt(v, "3.0.25"),"CVE-2007-2447",  10.0,"CRITICAL", "", "Samba username map script injection RCE (widely exploited).", "Urgently upgrade to a modern Samba version. Ensure 'username map script' is not using untrusted input."),
    ("exim",    lambda v: _ver_lt(v, "4.94.2"),"CVE-2021-27216", 7.0, "HIGH",     "", "Exim local privilege escalation via race condition in /tmp handling.", "Update Exim to 4.94.2 or later."),
    ("exim",    lambda v: _ver_lt(v, "4.92.2"),"CVE-2019-15846", 9.8, "CRITICAL", "", "Exim unauthenticated RCE via trailing backslash in SNI during TLS handshake.", "Update Exim to 4.92.2 or higher."),
    ("exim",    lambda v: _ver_lt(v, "4.92"),  "CVE-2019-10149", 9.8, "CRITICAL", "", "Exim The Return of the WIZard — RCE via expand string rules.", "Update Exim to 4.92 or higher."),
    ("smb",     lambda v: True,                "CVE-2017-0144",  10.0,"CRITICAL", "", "EternalBlue (MS17-010) — Windows SMBv1 pre-auth RCE. Widely exploited by WannaCry/NotPetya.", "Apply MS17-010 security update. Disable SMBv1 entirely on all systems."),
    ("smb",     lambda v: True,                "CVE-2020-0796",  10.0,"CRITICAL", "", "SMBGhost — Windows 10/Server 2019 SMBv3.1.1 pre-auth RCE via malicious compression headers.", "Apply patch CVE-2020-0796 (KB4551762). Disable SMBv3 compression as a workaround."),
    ("rdp",     lambda v: True,                "CVE-2019-0708",  9.8, "CRITICAL", "", "BlueKeep — Windows RDP pre-auth RCE. Wormable vulnerability in Remote Desktop Services.", "Apply security update KB4499175 (Windows 7) or KB4499180 (Server 2008). Enable Network Level Authentication (NLA)."),
    ("rdp",     lambda v: True,                "CVE-2019-1181",  9.8, "CRITICAL", "", "DejaBlue — Windows 10 / Server 2019 RDP pre-auth RCE (Wormable).", "Apply August 2019 Security Updates immediately. Enable NLA and restrict RDP access to VPN users."),
    ("rdp",     lambda v: True,                "CVE-2019-1182",  9.8, "CRITICAL", "", "DejaBlue — Windows Modern RDS pre-auth RCE. Similar to BlueKeep but affects later OS versions.", "Apply patches from Microsoft Security Update Guide (August 2019)."),
    ("rdp",     lambda v: True,                "CVE-2020-0609",  9.8, "CRITICAL", "", "RD Gateway RCE via specially crafted UDP requests (Pre-auth).", "Apply January 2020 Security Updates (KB4534273/KB4534306). Disable UDP transport in RDP Gateway settings if unpatched."),
    ("rdp",     lambda v: True,                "CVE-2020-0610",  9.8, "CRITICAL", "", "RD Gateway RDP pre-auth RCE via UDP data packets.", "Apply January 2020 Security Updates. Monitor UDP port 3391 for unusual traffic."),
    ("rdp",     lambda v: True,                "CVE-2021-34466", 9.8, "CRITICAL", "", "Remote Desktop Gateway unauthenticated remote code execution.", "Apply July 2021 Security Updates. Ensure 'Only allow connections from computers running Remote Desktop with Network Level Authentication' is checked."),
    ("rdp",     lambda v: True,                "CVE-2012-0002",  9.8, "CRITICAL", "", "MS12-020 — Windows RDP pre-auth RCE via malformed sequence of packets.", "Apply security update KB2671387. This is a legacy but common vulnerability in industrial/IoT environments."),
    ("rdp",     lambda v: True,                "CVE-2018-0886",  8.8, "HIGH",     "", "CredSSP RCE — Oracle Padding vulnerability in RDP authentication.", "Apply May 2018 Security Updates (KB4093492). Secure the 'Encryption Oracle Remediation' policy setting."),
    ("rdp",     lambda v: True,                "CVE-2022-21893", 8.8, "HIGH",     "", "Windows RDP authenticated RCE via low-privilege account.", "Apply January 2022 Security Updates. Follow the principle of least privilege for RDP users."),
    ("rdp",     lambda v: True,                "CVE-2024-21410", 9.8, "CRITICAL", "", "Microsoft Exchange/RDP NTLM Relay Elevation of Privilege.", "Enable Extended Protection for Authentication (EPA) and apply February 2024 Security Updates."),
    ("rdp",     lambda v: True,                "CVE-2021-26870", 8.8, "HIGH",     "", "Remote Desktop Services RCE vulnerability.", "Apply Microsoft security patches for March 2021. Enforce strong MFA for all remote access."),

    ("elasticsearch", lambda v: _ver_lt(v, "1.4.3"), "CVE-2015-1427", 10.0, "CRITICAL", "", "Elasticsearch unauthenticated RCE via Groovy scripting engine sandbox bypass.", "Update to Elasticsearch 1.4.3 or higher. Disable dynamic scripting."),
    ("elasticsearch", lambda v: _ver_lt(v, "7.16.1"), "CVE-2011-44228", 10.0, "CRITICAL", "", "Log4Shell — Elasticsearch unauthenticated RCE via Log4j.", "Update Elasticsearch to 7.16.1 or 6.8.21. Set -Dlog4j2.formatMsgNoLookups=true."),
    ("gitlab",  lambda v: _ver_lt(v, "13.10.3"), "CVE-2021-22205", 10.0, "CRITICAL", "", "GitLab unauthenticated RCE via ExifTool handling of uploaded image files.", "Update GitLab to 13.10.3, 13.9.6, or 13.8.8."),
    ("gitlab",  lambda v: _ver_lt(v, "16.7.2"),  "CVE-2023-7028",  10.0, "CRITICAL", "", "GitLab account takeover via password reset to arbitrary email. Massive 2024 campaign.", "Update GitLab to 16.7.2 or later to patch account takeover vulnerability."),
    ("gitlab",  lambda v: _ver_lt(v, "15.3.1"),  "CVE-2022-2884",  9.9, "CRITICAL", "", "GitLab RCE via GitHub Import feature (pre-auth code execution).", "Update to GitLab 15.3.1, 15.2.4 or 15.1.6 or newer."),
    ("gitlab",  lambda v: _ver_lt(v, "16.8.1"),  "CVE-2024-0402",  9.9, "CRITICAL", "", "GitLab arbitrary file write leading to remote code execution (RCE).", "Update to 16.8.1, 16.7.4, or 16.6.6 immediately."),
    ("gitlab",  lambda v: _ver_lt(v, "16.2.7"),  "CVE-2023-4998",  9.6, "CRITICAL", "", "GitLab RCE via malicious scheduled pipelines and user impersonation.", "Apply GitLab security update 16.2.7, 16.1.5 or newer."),
    ("gitlab",  lambda v: _ver_lt(v, "14.9.2"),  "CVE-2022-1162",  9.1, "CRITICAL", "", "GitLab hardcoded credentials vulnerability for OmniAuth-created users.", "Update to GitLab 14.9.2, 14.8.5, or 14.7.7 or newer."),
    ("gitlab",  lambda v: _ver_lt(v, "16.0.1"),  "CVE-2023-2825",  7.5, "HIGH",     "", "GitLab Path Traversal in core allowing unauthenticated arbitrary file read.", "Update to GitLab 16.0.1 or higher."),
    ("gitlab",  lambda v: _ver_lt(v, "17.1.1"),  "CVE-2024-5655",  9.6, "CRITICAL", "", "GitLab RCE via malicious GraphQL pipeline triggering.", "Update to 17.1.1, 17.0.3, or 16.11.5 or newer."),
    ("gitlab",  lambda v: _ver_lt(v, "15.11.0"), "CVE-2021-21415", 9.8, "CRITICAL", "", "GitLab SSRF in Slack integration leading to internal network exploitation.", "Update to GitLab 15.11.0 or higher. Use strict egress rules for your GitLab server."),
    ("gitlab",  lambda v: _ver_lt(v, "13.1.2"),  "CVE-2020-13271", 7.5, "HIGH",     "", "GitLab stored XSS in project settings leading to potential session theft.", "Update to 13.1.2 or later."),
    ("gitlab",  lambda v: _ver_lt(v, "15.3.3"),  "CVE-2022-2992",  9.9, "CRITICAL", "", "GitLab RCE via GitHub Import (secondary vulnerability found after 15.3.1).", "Update to 15.3.3 or latest stable release."),
    ("gitlab",  lambda v: True,                "Runners",        9.0, "CRITICAL", "", "GitLab Runner unauthenticated RCE via malicious docker images.", "Ensure GitLab Runner software is independently updated and isolation is enforced."),

    ("confluence", lambda v: _ver_lt(v, "7.18.1"), "CVE-2022-26134", 9.8, "CRITICAL", "", "Atlassian Confluence unauthenticated OGNL injection RCE.", "Update Confluence to 7.18.1, 7.17.4 or later."),
    ("confluence", lambda v: _ver_lt(v, "7.4.0"),  "CVE-2021-26084", 9.8, "CRITICAL", "", "Atlassian Confluence Server Webwork OGNL injection RCE.", "Update Confluence to 7.4.11, 7.12.5 or later."),
    ("confluence", lambda v: _ver_lt(v, "8.5.1"),  "CVE-2023-22515", 9.8, "CRITICAL", "", "Atlassian Confluence broken access control leading to RCE.", "Update Confluence to 8.5.2 or later. Implement restricting access to the setup wizard."),
    ("bind",    lambda v: _ver_lt(v, "9.10.2"), "CVE-2015-5477", 7.8, "HIGH",     "", "ISC BIND 9 TKEY query denial of service (DoS).", "Update BIND to latest stable release."),
    ("fortigate", lambda v: _ver_lt(v, "7.2.5"), "CVE-2023-27997", 9.8, "CRITICAL", "", "FortiGate SSL VPN unauthenticated heap-based buffer overflow RCE.", "Update FortiOS to 7.4.0, 7.2.5, 7.0.12 or newer. Disable SSL VPN if not used."),
    ("fortigate", lambda v: _ver_lt(v, "7.0.6"), "CVE-2022-42475", 9.8, "CRITICAL", "", "FortiOS SSL-VPN heap-based buffer overflow RCE.", "Update FortiOS immediately to the latest stable release."),
    ("fortigate", lambda v: _ver_lt(v, "6.0.4"), "CVE-2018-13379", 9.8, "CRITICAL", "", "FortiOS SSL-VPN pre-auth path traversal (credentials leak).", "Update FortiOS and change all administrative credentials."),
    ("weblogic", lambda v: _ver_lt(v, "14.1.1.0"), "CVE-2020-14882", 9.8, "CRITICAL", "", "Oracle WebLogic Server unauthenticated RCE via Console HTTP interface.", "Apply Oracle Security Alert patch for CVE-2020-14882. Restrict HTTP Console access."),
    ("weblogic", lambda v: _ver_lt(v, "12.1.3.0"), "CVE-2015-4852",  9.8, "CRITICAL", "", "Oracle WebLogic Server unauthenticated RCE via T3 protocol (Java Deserialization).", "Patch WebLogic and restrict T3/T3s protocols access to trusted IPs only."),
    ("exchange", lambda v: True,                "CVE-2021-26855", 9.8, "CRITICAL", "", "ProxyLogon — Microsoft Exchange Server pre-auth SSRF leading to RCE.", "Apply Microsoft security updates for ProxyLogon immediately."),
    ("exchange", lambda v: True,                "CVE-2021-34473", 9.8, "CRITICAL", "", "ProxyShell — Microsoft Exchange Server pre-auth path confusion leading to RCE.", "Apply cumulative security updates for Exchange Server."),
    ("exchange", lambda v: True,                "CVE-2024-21410", 9.8, "CRITICAL", "", "Microsoft Exchange Server Elevation of Privilege (NTLM relay).", "Enable Extended Protection for Authentication (EPA) and update Exchange."),
    ("vcenter",  lambda v: _ver_lt(v, "7.0.2"), "CVE-2021-21972", 9.8, "CRITICAL", "", "VMware vCenter Server unauthenticated file upload RCE in vROps plugin.", "Apply VMware security patch for CVE-2021-21972."),
    ("vcenter",  lambda v: _ver_lt(v, "7.0.2"), "CVE-2021-21985", 9.8, "CRITICAL", "", "VMware vCenter Server unauthenticated RCE in Virtual SAN Health Check plugin.", "Update vCenter Server or disable the vulnerable plugin."),
    ("zabbix",   lambda v: _ver_lt(v, "5.0.22"),"CVE-2022-23131", 9.8, "CRITICAL", "", "Zabbix Frontend authentication bypass / SAML SSO injection.", "Update Zabbix to 6.0.1, 5.4.10, or 5.0.21. Disable SAML auth if not required."),
    ("spring",   lambda v: _ver_lt(v, "5.3.18"),"CVE-2022-22965", 9.8, "CRITICAL", "", "Spring4Shell — RCE via parameter binding on Spring MVC/WebFlux applications.", "Update Spring Framework to 5.3.18 or 5.2.20. Update JDK if possible."),
    ("struts",   lambda v: _ver_lt(v, "2.5.13"),"CVE-2017-5638",  10.0,"CRITICAL", "", "Apache Struts 2 RCE via unescaped Content-Type parser (Equifax breach).", "Upgrade to Apache Struts 2.3.32 or 2.5.10.1."),
    ("struts",   lambda v: _ver_lt(v, "2.5.21"),"CVE-2020-17530", 9.8, "CRITICAL", "", "Apache Struts 2 double OGNL evaluation RCE.", "Upgrade to Apache Struts 2.5.26 or later."),
    ("log4j",    lambda v: _ver_lt(v, "2.15.0"),"CVE-2021-44228", 10.0,"CRITICAL", "", "Log4Shell — Apache Log4j2 unauthenticated JNDI lookup RCE.", "Update Log4j to 2.17.1 (for Java 8) or 2.12.4. Disable JNDI lookups."),
    ("citrix",   lambda v: _ver_lt(v, "13.0"),  "CVE-2023-3519",  9.8, "CRITICAL", "", "Citrix NetScaler ADC/Gateway unauthenticated code injection RCE.", "Apply Citrix security updates for CVE-2023-3519 immediately."),
    ("citrix",   lambda v: _ver_lt(v, "12.1"),  "CVE-2019-19781", 9.8, "CRITICAL", "", "Citrix NetScaler directory traversal leading to RCE.", "Update Citrix ADC/Gateway to latest patched versions."),
    ("citrix",   lambda v: True,                "CVE-2023-4966",  7.5, "HIGH",     "", "Citrix NetScaler 'Citrix Bleed' information disclosure (session token theft).", "Update Citrix appliances to KB5031439/KB5031440 or newer."),
    ("f5",       lambda v: _ver_lt(v, "16.1.2"),"CVE-2022-1388",  9.8, "CRITICAL", "", "F5 BIG-IP iControl REST unauthenticated RCE.", "Apply F5 security patches for CVE-2022-1388. Restrict access to management interface."),
    ("f5",       lambda v: _ver_lt(v, "15.1.0"),"CVE-2020-5902",  9.8, "CRITICAL", "", "F5 BIG-IP TMUI directory traversal RCE.", "Update BIG-IP software to latest version."),
    ("paloalto", lambda v: _ver_lt(v, "10.2"),  "CVE-2024-3400",  10.0,"CRITICAL", "", "Palo Alto PAN-OS GlobalProtect unauthenticated command injection RCE.", "Apply PAN-OS security updates (hotfixes) for CVE-2024-3400."),
    ("paloalto", lambda v: _ver_lt(v, "8.1.15"),"CVE-2020-2021",  10.0,"CRITICAL", "", "Palo Alto PAN-OS authentication bypass via SAML.", "Update PAN-OS and follow hardening guides for SAML auth."),
    ("paloalto", lambda v: _ver_lt(v, "9.0.0"), "CVE-2019-1579",  9.8, "CRITICAL", "", "Palo Alto GlobalProtect pre-auth RCE.", "Update GlobalProtect Gateway to latest patched firmware."),
    ("pulse",    lambda v: _ver_lt(v, "9.0"),   "CVE-2019-11510", 10.0,"CRITICAL", "", "Pulse Secure Connect SSL VPN unauthenticated arbitrary file read.", "Apply Pulse Secure security updates (SA44101). Change all passwords."),
    ("pulse",    lambda v: _ver_lt(v, "9.1.5"), "CVE-2021-22893", 10.0,"CRITICAL", "", "Pulse Secure unauthenticated RCE via use-after-free.", "Update Pulse Connect Secure to 9.1R11.4 or higher."),
    ("sonicwall",lambda v: _ver_lt(v, "6.5.4"), "CVE-2020-5135",  9.4, "CRITICAL", "", "SonicWall SonicOS VPN stack buffer overflow RCE.", "Update SonicOS to latest firmware release."),
    ("sonicwall",lambda v: True,                "CVE-2021-20016", 9.8, "CRITICAL", "", "SonicWall SMA 100 series pre-auth SQL injection.", "Update SMA 100 series firmware immediately."),
    ("zimbra",   lambda v: _ver_lt(v, "9.0.0"), "CVE-2022-27925", 9.8, "CRITICAL", "", "Zimbra Collaboration Suite unauthenticated RCE via mboximport zip extraction.", "Update Zimbra and apply latest security patches."),
    ("zimbra",   lambda v: _ver_lt(v, "8.8.11"),"CVE-2019-9670",  9.8, "CRITICAL", "", "Zimbra Autodiscover XXE to RCE.", "Upgrade Zimbra to latest stable version."),
    ("manageengine", lambda v: _ver_lt(v, "10.0"), "CVE-2022-47966", 9.8, "CRITICAL", "", "ManageEngine unauthenticated RCE via outdated Apache Santuario SAML parser.", "Update ManageEngine products to the latest available builds."),
    ("jira",     lambda v: _ver_lt(v, "8.4.0"), "CVE-2019-11581", 9.8, "CRITICAL", "", "Atlassian Jira Server template injection RCE.", "Update Jira Server/Data Center to 8.2.3, 8.3.2, 8.4.0 or later."),
    ("jira",     lambda v: _ver_lt(v, "8.14.0"),"CVE-2020-36239", 7.5, "HIGH",     "", "Atlassian Jira missing authentication in Ehcache RMI interface.", "Update Jira to 8.14.0 or later. Restrict network access to internal ports."),
    ("bitbucket",lambda v: _ver_lt(v, "7.6.14"),"CVE-2022-36804", 9.9, "CRITICAL", "", "Atlassian Bitbucket Server command injection via crafted HTTP request.", "Update Bitbucket Server to 7.21.4, 8.3.1 or newer."),
    ("jenkins",  lambda v: _ver_lt(v, "2.441"), "CVE-2024-23897", 9.8, "CRITICAL", "", "Jenkins CLI unauthenticated arbitrary file read leading to RCE.", "Update Jenkins to 2.442, LTS 2.426.3 or newer. Disable the CLI 'expand-at' feature."),
    ("jenkins",  lambda v: _ver_lt(v, "2.103"), "CVE-2017-1000353", 9.8, "CRITICAL", "", "Jenkins Java deserialization RCE via CLI transport.", "Update Jenkins to 2.103 or newer. Disable CLI over remoting."),
    ("cisco",    lambda v: True,                "CVE-2023-20198", 10.0,"CRITICAL", "", "Cisco IOS XE Web UI pre-auth command execution (0-day exploitation).", "Disable the HTTP Server feature or update to patched Cisco IOS XE software."),
    ("cisco",    lambda v: True,                "CVE-2018-0101",  10.0,"CRITICAL", "", "Cisco ASA double free vulnerability in XML parser (RCE/DoS).", "Update Cisco ASA software/firmware immediately."),
    ("cisco",    lambda v: True,                "CVE-2020-3118",  9.8, "CRITICAL", "", "Cisco IOS CDP protocol unauthenticated remote code execution.", "Update Cisco IOS or disable CDP on untrusted interfaces."),
    ("ivanti",   lambda v: True,                "CVE-2023-46805", 8.2, "HIGH",     "", "Ivanti Connect Secure authentication bypass.", "Apply latest Ivanti security patches and mitigation XML."),
    ("ivanti",   lambda v: True,                "CVE-2024-21887", 9.1, "CRITICAL", "", "Ivanti Connect Secure command injection RCE.", "Apply Ivanti security updates for CVE-2024-21887."),
    ("zscaler",  lambda v: True,                "CVE-2024-xxxxx", 9.8, "CRITICAL", "", "Check NVD for latest critical vulnerabilities on Zscaler / networking equipment.", "Refer to Zscaler security advisories for the latest patching instructions."),
    ("squid",    lambda v: _ver_lt(v, "4.15"),  "CVE-2021-28651", 7.5, "HIGH",     "", "Squid Proxy URN processing buffer overflow / DoS.", "Update Squid to version 4.15 or newer."),
    ("haproxy",  lambda v: _ver_lt(v, "2.2.17"),"CVE-2021-40346", 8.6, "HIGH",     "", "HAProxy HTTP request smuggling vulnerability.", "Update HAProxy to 2.4.4, 2.2.17, 2.0.25 or newer."),
    ("openvpn",  lambda v: _ver_lt(v, "2.4.9"), "CVE-2020-11810", 7.5, "HIGH",     "", "OpenVPN double free vulnerability leading to DoS/RCE.", "Update OpenVPN to 2.4.9 or 2.5.0."),
    ("cups",     lambda v: _ver_lt(v, "2.0"),   "CVE-2014-6271",  10.0,"CRITICAL", "", "Shellshock — Bash command injection via HTTP headers triggers via CGI in CUPS.", "Update Bash and CUPS to patched versions. Disable CGI in CUPS if not needed."),
    ("nfs",      lambda v: True,                "CVE-2022-4304",  7.5, "HIGH",     "", "NFSv4 multiple potential memory corruption issues.", "Update kernel/NFS server and restrict NFS access via export rules."),
    ("rpcbind",  lambda v: True,                "CVE-2017-8779",  7.5, "HIGH",     "", "rpcbind UDP amplification attack and DoS via crafted requests.", "Restrict rpcbind access via firewall/ACLs. Use TCP only if possible."),
    ("snmp",     lambda v: True,                "CVE-2012-3268",  7.5, "HIGH",     "", "Default or easily guessable public/private SNMP community strings.", "Change default SNMP community strings (public/private). Use SNMPv3 with auth/encryption."),
    ("openldap", lambda v: _ver_lt(v, "2.4.58"),"CVE-2020-36221", 7.5, "HIGH",     "", "OpenLDAP saslAuthzTo configuration bypass.", "Update OpenLDAP to 2.4.58 or newer."),
    ("dovecot",  lambda v: _ver_lt(v, "2.3.11"),"CVE-2020-12100", 7.5, "HIGH",     "", "Dovecot IMAP and POP3 unauthenticated DoS.", "Update Dovecot to 2.3.11.1 or 2.3.13."),

    # --- Expansion Pack (Modern Cloud & Infrastructure) ---
    ("kibana",   lambda v: _ver_lt(v, "6.4.3"), "CVE-2018-17246", 9.8, "CRITICAL", "", "Kibana local file inclusion (LFI) leading to unauthenticated RCE.", "Update Kibana to 6.4.3 or higher. Disable unused plugins."),
    ("splunk",   lambda v: _ver_lt(v, "8.2.3"), "CVE-2021-33904", 8.8, "HIGH",     "", "Splunk Enterprise deployment server timing side-channel.", "Update Splunk to 8.2.3 or later."),
    ("splunk",   lambda v: _ver_lt(v, "9.0"),   "CVE-2022-32154", 8.1, "HIGH",     "", "Splunk Enterprise RCE via malicious deployment server component.", "Update Splunk Enterprise to 9.0 or higher."),
    ("nexus",    lambda v: _ver_lt(v, "3.21.2"),"CVE-2020-10199", 9.8, "CRITICAL", "", "Sonatype Nexus Repository Manager RCE via EL injection.", "Update Nexus to 3.21.2 or later."),
    ("nexus",    lambda v: _ver_lt(v, "3.15.0"),"CVE-2019-7238",  9.8, "CRITICAL", "", "Sonatype Nexus Repository unauthenticated RCE.", "Update Nexus to 3.15.0 or newer."),
    ("mongodb",  lambda v: _ver_lt(v, "4.4.8"), "CVE-2021-20336", 7.5, "HIGH",     "", "MongoDB configuration bypass leading to unauthenticated access.", "Update MongoDB to 4.4.8 or 5.0.2. Enable authentication and authorization."),
    ("rabbitmq", lambda v: _ver_lt(v, "3.4.0"), "CVE-2015-8786",  7.5, "HIGH",     "", "RabbitMQ management plugin CSRF vulnerability.", "Update RabbitMQ or disable the management plugin if not required."),
    ("jupyter",  lambda v: _ver_lt(v, "5.7.3"), "CVE-2019-9644",  8.8, "HIGH",     "", "Jupyter Notebook DOM-based XSS enabling malicious terminal access.", "Update Jupyter Notebook to 5.7.3 or later."),
    ("kubernetes",lambda v: _ver_lt(v,"1.10.11"),"CVE-2018-1002105",9.8,"CRITICAL","", "Kubernetes API Server privilege escalation (Kubernetes-first 10.0 CVE).", "Update Kubernetes to 1.10.11, 1.11.5, or 1.12.3."),
    ("docker",   lambda v: _ver_lt(v, "18.09.2"),"CVE-2019-5736", 9.3, "CRITICAL", "", "Docker runC container breakout (RCE). widely used container escape.", "Update Docker to 18.09.2 or newer. Update runc on the host system."),
    ("qnap",     lambda v: True,                "CVE-2021-28799", 9.8, "CRITICAL", "", "QNAP NAS unauthenticated remote code execution via HBS 3 (Qlocker ransomware vector).", "Apply QNAP security updates for HBS 3. Disable HBS 3 if not needed."),
    ("qnap",     lambda v: True,                "CVE-2022-27596", 9.8, "CRITICAL", "", "QNAP NAS SQL injection in QTS/QuTS hero (DeadBolt ransomware vector).", "Update QTS/QuTS hero firmware immediately."),
    ("synology", lambda v: _ver_lt(v, "6.2.3"), "CVE-2021-29085", 10.0,"CRITICAL", "", "Synology DiskStation Manager (DSM) unauthenticated pre-auth RCE.", "Update Synology DSM to latest version."),
    ("hikvision",lambda v: True,                "CVE-2021-36260", 9.8, "CRITICAL", "", "Hikvision IP Camera unauthenticated RCE via crafted web requests.", "Update Hikvision firmware to latest available version."),
    ("papercut", lambda v: _ver_lt(v,"22.0.9"), "CVE-2023-27350", 9.8, "CRITICAL", "", "PaperCut MF/NG unauthenticated RCE via authentication bypass.", "Update PaperCut MF/NG to 22.0.9 or later."),
    
    # ─── Grafana Extensive Suite (15+ CVEs) ───
    ("grafana",  lambda v: _ver_lt(v, "11.4.0"), "CVE-2025-41115", 10.0,"CRITICAL", "", "SCIM provisioning privilege escalation (unauthorized user creation/impersonation).", "Update to Grafana 11.4.0, 10.4.11, or 11.3.2 immediately."),
    ("grafana",  lambda v: _ver_lt(v, "10.0.1"), "CVE-2023-3128",  9.4, "CRITICAL", "", "Azure AD OAuth authentication bypass via email claim spoofing.", "Update to 10.0.1+ or 9.5.5+. Ensure uniqueness of subject claims in Azure AD."),
    ("grafana",  lambda v: _ver_lt(v, "9.2.4"),  "CVE-2022-39328", 9.8, "CRITICAL", "", "Race condition in session middleware allowing admin auth bypass.", "Upgrade to Grafana 9.2.4 or 8.5.15."),
    ("grafana",  lambda v: _ver_lt(v, "8.1.5"),  "CVE-2021-39226", 9.8, "CRITICAL", "", "Snapshot authentication bypass (unauthenticated access to server snapshots).", "Upgrade to 8.1.5 or 7.5.11."),
    ("grafana",  lambda v: _ver_lt(v, "7.3.5"),  "CVE-2020-27846", 10.0,"CRITICAL", "", "SAML signature verification bypass leading to full authentication bypass.", "Update Grafana to 7.3.5 or newer."),
    ("grafana",  lambda v: _ver_lt(v, "10.3.1"), "CVE-2024-1313",  9.0, "CRITICAL", "", "Enterprise RCE via malicious plugin path manipulation.", "Update Grafana Enterprise to 10.3.1 or later."),
    ("grafana",  lambda v: _ver_lt(v, "11.2.1"), "CVE-2024-9456",  9.1, "CRITICAL", "", "RCE via malicious path in enterprise plugin system.", "Upgrade to 11.2.1 or higher."),
    ("grafana",  lambda v: _ver_lt(v, "6.3.4"),  "CVE-2019-15043", 9.8, "CRITICAL", "", "Prometheus SSRF leading to server takeover and RCE.", "Urgently upgrade to 6.3.4 or higher."),
    ("grafana",  lambda v: _ver_lt(v, "8.3.1"),  "CVE-2021-43798", 7.5, "HIGH",     "", "Directory traversal vulnerability allowing arbitrary file read via plugin URLs.", "Update Grafana to 8.3.1, 8.2.7, 8.1.8, or 8.0.7."),
    ("grafana",  lambda v: _ver_lt(v, "8.3.10"), "CVE-2022-21703", 8.8, "HIGH",     "", "CSRF bypass allowing account takeover and RCE via datasource config.", "Upgrade to 8.3.10 or 9.0.x."),
    ("grafana",  lambda v: _ver_lt(v, "10.1.5"), "CVE-2023-4414",  8.8, "HIGH",     "", "SQL injection in SQLite database handling.", "Update Grafana to 10.1.5 or newer."),
    ("grafana",  lambda v: _ver_lt(v, "9.0.3"),  "CVE-2022-31107", 8.3, "HIGH",     "", "OAuth account takeover via email address verification bypass.", "Upgrade to 9.0.3 or 8.5.9."),
    ("grafana",  lambda v: _ver_lt(v, "10.1.0"), "CVE-2023-5341",  8.1, "HIGH",     "", "Snapshot leakage via insecure default permissions.", "Upgrade to 10.1.0+ and audit existing public snapshots."),
    ("grafana",  lambda v: _ver_lt(v, "8.3.2"),  "CVE-2021-43813", 7.5, "HIGH",     "", "Path traversal in core 'alert-list' plugin.", "Update to 8.3.2 or 7.5.11."),
    ("grafana",  lambda v: _ver_lt(v, "8.5.15"), "CVE-2022-31097", 8.8, "HIGH",     "", "Stored XSS via AlertManager Matcher configuration.", "Update to 8.5.15 or 9.2.4."),
    ("grafana",  lambda v: _ver_lt(v, "9.3.4"),  "CVE-2023-22456", 6.5, "MEDIUM",   "", "LDAP authentication bypass via insecure search filters.", "Update Grafana to 9.3.4 or later."),
    ("grafana",  lambda v: _ver_lt(v, "10.4.0"), "CVE-2024-2509",  5.4, "MEDIUM",   "", "SSRF in Prometheus datasource via crafted metric names.", "Update to 10.4.0 or newer."),
    ("grafana",  lambda v: _ver_lt(v, "9.2.4"),  "CVE-2022-39307", 5.3, "MEDIUM",   "", "Username enumeration via API response discrepancies.", "Update to 9.2.4 or newer."),
    ("grafana",  lambda v: _ver_lt(v, "10.0.0"), "CVE-2023-1410",  6.8, "MEDIUM",   "", "Stored XSS in Graphite annotations.", "Update Grafana to 10.0.0 or higher."),
    
    # Other App stacks
    ("kibana",   lambda v: _ver_lt(v, "6.6.1"),  "CVE-2019-7609",  10.0,"CRITICAL", "", "Kibana Timelion prototype pollution RCE (unauthenticated).", "Update Kibana to 6.6.1 or later."),
    ("influxdb", lambda v: _ver_lt(v, "1.7.7"),  "CVE-2019-20933", 9.8, "CRITICAL", "", "InfluxDB authentication bypass — JWT shared secret default.", "Update InfluxDB to 1.7.7+. Change default JWT secret."),
    ("couchdb",  lambda v: _ver_lt(v, "3.2.3"),  "CVE-2022-24706", 9.8, "CRITICAL", "", "Apache CouchDB cookie erlang term deserialization RCE.", "Update CouchDB to 3.2.3 or 3.3.1."),
    ("solr",     lambda v: _ver_lt(v, "8.3.1"),  "CVE-2019-17558", 8.8, "HIGH",     "", "Apache Solr Velocity template injection RCE.", "Update Solr or disable VelocityResponseWriter."),
    ("minio",    lambda v: _ver_lt(v, "2023-03-13"), "CVE-2023-28432", 7.5,"HIGH",  "", "MinIO info disclosure — leaks cluster credentials.", "Update MinIO to RELEASE.2023-03-20T20-16-18Z."),
    ("vault",    lambda v: _ver_lt(v, "1.9.4"),  "CVE-2022-40186", 9.8, "CRITICAL", "", "HashiCorp Vault JWT/OIDC auth bypass.", "Update Vault to 1.9.4 or 1.10.x."),
    ("phpmyadmin",lambda v: _ver_lt(v, "4.8.4"), "CVE-2018-19968", 8.8, "HIGH",     "", "phpMyAdmin local file inclusion RCE.", "Update phpMyAdmin to 4.8.4 or higher."),
    ("phpmyadmin",lambda v: _ver_lt(v, "5.1.2"), "CVE-2022-23807", 4.3, "MEDIUM",   "", "phpMyAdmin two-factor auth bypass via brute force.", "Update phpMyAdmin to 5.1.2 or newer."),
    ("roundcube",lambda v: _ver_lt(v, "1.6.1"),  "CVE-2023-43770", 6.1, "MEDIUM",   "", "Roundcube persistent XSS in HTML message handling.", "Update Roundcube to 1.6.1 or later."),
    ("roundcube",lambda v: _ver_lt(v, "1.5.4"),  "CVE-2022-37393", 8.8, "HIGH",     "", "Roundcube shell injection via malicious email header in managesieve plugin.", "Update Roundcube to 1.5.4 or higher."),
    ("manageengine",lambda v: _ver_lt(v, "10.5"),"CVE-2021-44515", 9.8, "CRITICAL", "", "ManageEngine Desktop Central unauthenticated RCE via /client-manager endpoint.", "Update ManageEngine Desktop Central immediately."),
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
        for prod_key, ver_fn, cve_id, cvss, sev, vec, desc, rem in OFFLINE_SIGS:
            if prod_key not in (product or '').lower():
                continue
            if version and not ver_fn(version):
                continue
            if cvss < min_cvss:
                continue
            matched.append(CVE(
                id=cve_id, description=desc, cvss_score=cvss,
                severity=sev, vector=vec, published="",
                remediation=rem,
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