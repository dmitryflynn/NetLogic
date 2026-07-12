"""
NetLogic - CVE Correlation Engine (NVD-powered)
=======================================================
Live NVD API lookups for version→CVE correlation.
NVD responses may be cached briefly on disk for rate-limit friendliness.

Flow:
  1. scan_host() discovers open ports with service banners
  2. correlate() extracts product/version from each banner
  3. nvd_lookup.lookup_cves_for_service() queries NVD (or cache)
  4. Results are version-filtered, CVSS-scored, and returned
"""

import re
import sys
from dataclasses import dataclass, field
from typing import Optional

from src.nvd_lookup import (
    lookup_cves_for_service,
    NVDCve,
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
    epss: float = 0.0              # EPSS probability of exploitation (0–1)
    epss_percentile: float = 0.0   # EPSS percentile rank (0–1)


@dataclass
class VulnMatch:
    port: int
    service: str
    product: Optional[str]
    version: Optional[str]
    cves: list[CVE] = field(default_factory=list)
    risk_score: float = 0.0
    notes: list[str] = field(default_factory=list)
    source: str = "nvd"    # "nvd" | "cache" | "misconfig"
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

    # Pure-FTPd
    (r"Pure-FTPd",                       "pure-ftpd"),

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
    (r"ActiveMQ/([\d.]+)",                     "activemq"),
    (r"ActiveMQ ([\d.]+)",                     "activemq"),
    (r"MiniServ/([\d.]+)",                     "webmin"),    # Webmin's HTTP server
    (r"lighttpd/([\d.]+)",                     "lighttpd"),

    # ── Edge / VPN appliances — the most-exploited products in CISA KEV. Often
    # version-less in the banner (the appliance hides it), so these usually
    # identify the high-risk ASSET (product) for the AI/fusion layer; a version
    # is captured when the device leaks one. Markers are distinctive (cookies /
    # vendor paths / product strings) to keep false positives near zero.
    (r"Set-Cookie:\s*NSC_",                    "netscaler"),   # Citrix ADC/NetScaler (CVE-2023-3519)
    (r"Citrix(?:[^\n]{0,40}?)Gateway",         "netscaler"),
    (r"Set-Cookie:\s*SVPNCOOKIE",              "fortios"),     # Fortinet FortiGate SSL-VPN
    (r"FortiGate",                             "fortios"),
    (r"Set-Cookie:\s*BIGipServer",             "big-ip"),      # F5 BIG-IP (CVE-2022-1388)
    (r"Server:\s*BIG-IP",                      "big-ip"),
    (r"/dana-na/",                             "pulse-connect-secure"),  # Ivanti/Pulse (CVE-2024-21887)
    (r"GlobalProtect",                         "pan-os"),      # Palo Alto (CVE-2024-3400)
    (r"VMware vCenter(?:[^\n]{0,40}?)([\d.]+)", "vcenter"),    # CVE-2021-21972 / Log4j
    (r"X-Zimbra",                              "zimbra"),      # Zimbra (CVE-2022-27925)
    (r"Zimbra(?:\s+Collaboration)?",           "zimbra"),
    (r"SonicWALL|SonicWall",                   "sonicwall"),
    (r"GlassFish(?:[^/]*)/([\d.]+)",           "glassfish"),
    (r"ColdFusion[/ ]([\d.]+)",                "coldfusion"),
    (r"X-Powered-By:.*ColdFusion",             "coldfusion"),
    (r'content="phpMyAdmin ([\d.]+)',           "phpmyadmin"),
    (r"X-OWA-Version:\s*([\d.]+)",             "exchange"),
    (r"X-FEServer:",                           "exchange"),
    (r"MicrosoftSharePointTeamServices:\s*([\d.]+)", "sharepoint"),
    (r"RFB (\d{3}\.\d{3})",                    "vnc"),
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



# A CDN/WAF challenge or block page is NOT the origin service — fingerprinting it (and
# CVE-matching a token grabbed from it) manufactures false criticals. Detect the common ones
# and refuse to fingerprint. Markers are vendor-specific and near-zero false-positive.
_WAF_CHALLENGE = re.compile(
    r"(?i)(x-vercel-mitigated|vercel security checkpoint|"
    r"cf-mitigated|attention required.*cloudflare|__cf_chl|cf-chl|"
    r"just a moment|akamai.*reference\s*#|incapsula|imperva|"
    r"x-datadome|please enable (js|javascript) and cookies)")


def _is_challenge_banner(raw: str) -> bool:
    return bool(_WAF_CHALLENGE.search(raw or ""))


def _plausible_version(v: Optional[str]) -> Optional[str]:
    """Reject 'versions' that are actually tokens/timestamps — a real software version has no
    10-digit component (e.g. Vercel's challenge token '2.1783577134.60' is not F5 16.x)."""
    if not v:
        return v
    for part in str(v).split("."):
        if part.isdigit() and (len(part) >= 6 or int(part) > 65535):
            return None
    return v


def extract_product_version(banner_obj) -> tuple[Optional[str], Optional[str]]:
    """
    Extract (product, version) from a ServiceBanner or string.
    Tries structured fields first, falls back to regex on raw banner.
    """
    # Structured banner (from scanner.py ServiceBanner dataclass)
    if hasattr(banner_obj, 'product') and banner_obj.product:
        product = banner_obj.product.lower().strip()
        version = _plausible_version(getattr(banner_obj, 'version', None))

        # Skip generic HTTP product info (e.g., "http 1.1") and instead
        # fall back to service+port inference.
        if product.startswith('http'):
            return None, None
        # If a structured banner is itself a WAF challenge, don't trust its product.
        if _is_challenge_banner(getattr(banner_obj, 'raw', '') or ''):
            return None, None

        return product, version

    # Raw string banner
    raw = getattr(banner_obj, 'raw', '') or str(banner_obj) or ''
    # Coerce bytes → str: the regexes below are str patterns, so a bytes banner
    # (e.g. raw socket payload passed straight in) would raise TypeError.
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw).decode('utf-8', errors='replace')
    if not raw:
        return None, None

    # A WAF/CDN challenge or block page is not the origin service — never fingerprint it.
    if _is_challenge_banner(raw):
        return None, None

    raw_lower = raw.lower()

    for pattern, product_name in BANNER_PATTERNS:
        m = re.search(pattern, raw, re.IGNORECASE)
        if m:
            version = _plausible_version(m.group(1) if m.lastindex and m.lastindex >= 1 else None)
            # If no product_name in pattern, try to infer from raw
            if product_name is None:
                # A bare version number is NOT a product. Only accept a substring product match
                # when the keyword is specific (len > 3) — a 2-char token like "f5" trivially
                # appears inside base64/hex blobs and manufactured false F5-RCE findings.
                for key, mapped in PRODUCT_KEYWORD_MAP.items():
                    if mapped is None or len(key) <= 3:
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
            # Find a version number that appears AFTER the product name, and never
            # mistake the "HTTP/1.1" protocol token (which precedes the Server
            # header) for the product version — that fired CVEs on every
            # version-less HTTP banner.
            after = raw[raw_lower.find(key) + len(key):]
            after = re.sub(r'(?i)\bHTTP/\d(?:\.\d)?', ' ', after)
            vm = re.search(r'[\s/v_-]([\d]+\.[\d]+(?:\.[\d]+)?)', after)
            version = _plausible_version(vm.group(1) if vm else None)
            return key, version

    return None, None


# OS family that a port-inferred product implies. Used to avoid guessing an
# OS-incompatible daemon (e.g. a Linux FTP server on a Windows/IIS host).
_PORT_PRODUCT_OS = {
    "vsftpd": "unix", "apache": "unix", "openssh": "unix", "dovecot": "unix",
    "postfix": "unix", "bind": "unix", "samba": "unix", "cups": "unix",
    "nfs": "unix", "rpcbind": "unix", "proftpd": "unix", "openldap": "unix",
    "snmpd": "unix", "tomcat": "unix",
    "mssql": "windows", "rdp": "windows", "smb": "windows",
}


def infer_host_os(ports) -> Optional[str]:
    """Best-effort host OS family from confirmed banners across ALL open ports.

    A single strong signal (an IIS banner, an Ubuntu/Apache string) lets us avoid
    cross-OS misattribution when guessing products for ports that returned no
    banner. Returns 'windows', 'unix', or None when signals are absent/conflicting.
    """
    windows_signals = ("microsoft-iis", "microsoft", "win32", "win64", "windows",
                       "ms-wbt", "iis/")
    unix_signals = ("ubuntu", "debian", "unix", "linux", "apache", "openssh",
                    "nginx", "mod_", "centos", "red hat", "redhat", "freebsd", ".el")
    win = unix = 0
    for p in ports:
        b = getattr(p, 'banner', None)
        raw  = (getattr(b, 'raw', '') or '').lower() if b else ''
        prod = (getattr(b, 'product', '') or '').lower() if b else ''
        svc  = (getattr(p, 'service', '') or '').lower()
        hay = f"{raw} {prod} {svc}"
        if any(s in hay for s in windows_signals):
            win += 1
        if any(s in hay for s in unix_signals):
            unix += 1
    if win and not unix:
        return "windows"
    if unix and not win:
        return "unix"
    return None  # unknown or conflicting — don't claim


def infer_product_from_service(service: str, port: int,
                               host_os: Optional[str] = None) -> Optional[str]:
    """
    When no banner is available, infer likely product from service name and port.
    Used for CVE lookups when banner grabbing failed.

    ``host_os`` (from infer_host_os) suppresses OS-incompatible guesses — e.g. on a
    confirmed Windows/IIS host we won't claim port 21 is vsftpd or 443 is Apache.
    Suppressing a wrong guess is better than asserting one: a bad product name
    drives bad CVE correlation downstream.
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
    candidate = service_lower if mapped else port_map.get(port)
    # SMB ports are ambiguous: Windows runs SMB (EternalBlue/SMBGhost), Linux runs
    # Samba (SambaCry). Disambiguate by host OS so the right CVE family applies and
    # Linux Samba CVEs aren't attributed to a Windows host (or vice versa).
    if port in (139, 445) and not mapped:
        candidate = "smb" if host_os == "windows" else "samba"
    if not candidate:
        return None
    # Drop guesses that contradict the detected host OS.
    cand_os = _PORT_PRODUCT_OS.get(candidate)
    if host_os and cand_os and cand_os != host_os:
        return None
    return candidate


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

    Live NVD only (with normal on-disk NVD response cache for rate limits).
    No offline signature table and no local SQLite VDB path.
    """
    results: list[VulnMatch] = []

    from src.nvd_lookup import nvd_is_available, _nvd_unavailable
    nvd_ok = not _nvd_unavailable and nvd_is_available()

    if not nvd_ok:
        if verbose:
            print("  [!] NVD API unreachable — no version→CVE correlation this run",
                  file=sys.stderr)
        return results

    host_os = infer_host_os(ports)
    by_port: dict[int, VulnMatch] = {}

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
            product = infer_product_from_service(service, port, host_os)

        if banner and product and version:
            _confidence = "HIGH"
        elif banner and product:
            _confidence = "MEDIUM"
        else:
            _confidence = "LOW"

        # Misconfig notes without version (not CVE catalog matches)
        if product and not version:
            note = None
            if product == "redis":
                note = "⚠ Redis instance appears to be unprotected (no authentication required)"
            elif product == "telnet":
                note = "⚠ Telnet is an insecure protocol (unencrypted)"
            if note:
                by_port[port] = VulnMatch(
                    port=port, service=service, product=product, version=None,
                    cves=[], risk_score=(5.0 if product == "redis" else 4.0),
                    notes=[note], source="misconfig", detection_confidence="MEDIUM",
                )
            continue

        if not product or not version:
            continue

        if verbose:
            print(f"  [NVD] {port}/{service} → {product} {version}...", end=" ", flush=True)

        nvd_cves = lookup_cves_for_service(product, version, min_cvss=min_cvss)

        if verbose:
            print(f"{len(nvd_cves)} CVEs")

        if not nvd_cves:
            continue

        nvd_converted = [_nvd_to_cve(c) for c in nvd_cves]
        raw_banner = getattr(banner, 'raw', '') or str(banner) if banner else ''
        precision = _match_precision(product, version, raw_banner)
        notes: list[str] = []
        confidence = _confidence
        risk = calculate_risk(nvd_converted)
        has_kev = any(c.kev for c in nvd_converted)
        if precision == "potential" and not has_kev:
            confidence = "POTENTIAL"
            risk = min(risk, 5.9)
            notes.insert(0,
                "⚠ POTENTIAL (unverified): version/patch level can't be confirmed "
                "from the banner (coarse product version or a distro that backports "
                "fixes). These may already be patched — verify before reporting.")
        if has_kev:
            kev_ids = [c.id for c in nvd_converted if c.kev]
            notes.append(f"★ CISA KEV: {', '.join(kev_ids[:3])} — actively exploited in the wild")

        by_port[port] = VulnMatch(
            port=port, service=service, product=product, version=version,
            cves=nvd_converted, risk_score=risk,
            notes=notes, source="nvd", detection_confidence=confidence,
        )

    results = list(by_port.values())

    try:
        from src.epss import enrich_with_epss
        enrich_with_epss(results)
        for vm in results:
            vm.cves.sort(key=lambda c: (getattr(c, "kev", False),
                                        getattr(c, "epss", 0.0),
                                        c.cvss_score), reverse=True)
    except Exception:
        pass

    results.sort(key=lambda m: m.risk_score, reverse=True)

    total_cves = sum(len(m.cves) for m in results)
    if verbose:
        print(f"Total CVEs found: {total_cves} ({len(results)} port(s), source: nvd)",
              file=sys.stderr)
    return results


def _ver_lt(v: str, threshold: str) -> bool:
    """Legacy helper kept for any external callers."""
    from src.nvd_lookup import _ver_lt as _nvd_ver_lt
    return _nvd_ver_lt(v, threshold)


def _ver_in_range(v: str, low: str, high: str) -> bool:
    from src.nvd_lookup import _ver_lte
    return _ver_lte(low, v) and _ver_lte(v, high)


def _ver_lt_branch(v: str, branch_fixes: dict) -> bool:
    """Branch-aware vulnerability test for products with parallel release lines.

    A plain `_ver_lt(v, "9.0.31")` wrongly fires on a *patched* 8.5.51 (because
    8.5.51 < 9.0.31). This instead checks v against the fixed version of ITS OWN
    major.minor branch. Versions on a branch not listed return False — an unknown
    branch is never assumed vulnerable, which kills cross-branch over-firing.

    branch_fixes: {"9.0": "9.0.31", "8.5": "8.5.51", "7.0": "7.0.100"}
    """
    if not v:
        return False
    nums = [p for p in re.split(r'[^0-9]+', str(v).strip()) if p]
    if len(nums) < 2:
        return False
    for branch, fixed in branch_fixes.items():
        bparts = branch.split('.')
        if nums[:len(bparts)] == bparts:
            return _ver_lt(v, fixed)
    return False


# ─── Match Precision (false-positive suppression) ────────────────────────────
# A version pulled from a banner is only trustworthy enough to CONFIRM a CVE when
# that version number is actually patch-precise. Two common cases break that
# assumption and produce the bulk of false positives:
#
#   1. Coarse product versions — e.g. "Microsoft-IIS/10.0" is ONE banner value
#      for every Windows Server 2016/2019/2022 patch level. The http.sys CVEs
#      that "match" it are fixed by monthly Windows Updates, which the banner
#      cannot reveal. Matching them is a hint, never a confirmation.
#   2. Distro backports — Ubuntu/Debian/RHEL ship security fixes WITHOUT bumping
#      the upstream version ("OpenSSH 6.6.1p1 Ubuntu-2ubuntu2.13" is patched far
#      beyond what "6.6.1" implies). Treating the upstream number as the patch
#      level flags long-since-fixed CVEs on nearly every Linux host.
#
# When either holds, findings are tagged POTENTIAL (not CONFIRMED), de-ranked,
# and annotated so the operator verifies before reporting.

_COARSE_VERSION_PRODUCTS = {"iis"}

_BACKPORT_MARKERS = (
    "ubuntu", "debian", "raspbian", "red hat", "redhat", "rhel", "centos",
    ".el", "~deb", "+deb", "fips", "amzn", "amazon", "suse",
    "sles", "oracle linux", "rocky", "almalinux",
)


def _match_precision(product: str, version: str, raw_banner: str) -> str:
    """Classify how much trust a banner-version CVE match deserves.

    Returns "confirmed" only when the banner version is genuinely patch-precise.
    Returns "potential" for coarse product versions (e.g. IIS major version) or
    when the banner shows a distro that backports fixes without bumping the
    version — in those cases a version match is a lead, not proof.
    """
    p = (product or "").lower()
    raw = (raw_banner or "").lower()
    if p in _COARSE_VERSION_PRODUCTS:
        return "potential"
    if any(marker in raw for marker in _BACKPORT_MARKERS):
        return "potential"
    return "confirmed"


def _product_matches(prod_key: str, product: str) -> bool:
    """Whether an offline-signature product key applies to a detected product.

    Exact or whole-token match only. A naive substring check ('php' in 'phpmyadmin')
    fired PHP CVEs on phpMyAdmin, Tomcat keys on 'tomcat-foo', etc. — a real
    false-positive source.
    """
    p = (product or "").lower()
    if not p:
        return False
    if prod_key == p:
        return True
    return prod_key in re.split(r'[^a-z0-9]+', p)


def _is_version_independent(ver_fn) -> bool:
    """True if a version test ignores the version (lambda v: True).

    Probed by asking whether an impossibly-high version still 'matches'. A real
    threshold (`< x`, `== x`, `startswith`) returns False; an always-true test
    returns True.
    """
    try:
        return bool(ver_fn("999999.999.999"))
    except Exception:
        return False


# Backward-compat alias used by parser fuzz / legacy callers
def _parse_ver(v):
    from src.nvd_lookup import _parse_ver as _pv
    return _pv(v)
