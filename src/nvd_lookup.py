"""
NetLogic - NVD Live CVE Lookup Engine
======================================
Queries the NIST National Vulnerability Database API v2.0 for CVEs
matching discovered product/version combinations.

Features:
  - Live NVD API queries with smart keyword construction
  - Persistent disk cache (JSON) — avoids re-querying the same product/version
  - Cache TTL: 24 hours (CVEs don't change retroactively, new ones trickle in)
  - Version-range filtering: only returns CVEs that actually apply to the version found
  - CVSS v3.1 / v3.0 / v2.0 scoring with severity labels
  - Exploit awareness via CISA KEV (Known Exploited Vulnerabilities) catalog
  - No API key required (respects 5 req/30s public limit automatically)
  - Optional API key for 50 req/30s limit (set NETLOGIC_NVD_KEY env var)

Usage:
  from src.nvd_lookup import lookup_cves_for_service
  cves = lookup_cves_for_service("apache", "2.4.49")
"""
import urllib.parse
import urllib.request
import urllib.error
import os
import re
import json
import time
import hashlib
import sys
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional
import threading
import concurrent.futures


# ─── Constants ───────────────────────────────────────────────────────────────

NVD_API_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_DIR    = os.path.join(os.path.expanduser("~"), ".netlogic", "nvd_cache")
KEV_CACHE    = os.path.join(CACHE_DIR, "kev.json")
CACHE_TTL    = 86400        # 24 hours
MAX_RESULTS  = 50           # CVEs to fetch per product query
RATE_DELAY   = 6.1          # seconds between requests (public: 5 req/30s)
RATE_DELAY_KEYED = 0.7      # with API key: 50 req/30s

# Thread-local rate limiter
_last_request_time = 0.0
_rate_lock = threading.Lock()


# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class NVDCve:
    id: str
    description: str
    cvss_score: float
    severity: str
    vector: str
    published: str
    last_modified: str
    cwe: str
    references: list[str] = field(default_factory=list)
    affected_products: list[str] = field(default_factory=list)
    exploit_available: bool = False
    kev: bool = False            # In CISA Known Exploited Vulnerabilities catalog
    version_start: Optional[str] = None
    version_end: Optional[str] = None
    version_end_including: bool = False
    has_metasploit: bool = False
    has_public_exploit: bool = False
    exploit_refs: list[str] = field(default_factory=list)


# ─── Cache ───────────────────────────────────────────────────────────────────

def _cache_path(key: str) -> str:
    os.makedirs(CACHE_DIR, exist_ok=True)
    safe = hashlib.md5(key.encode()).hexdigest()
    return os.path.join(CACHE_DIR, f"{safe}.json")


def _cache_read(key: str) -> Optional[dict]:
    path = _cache_path(key)
    try:
        with open(path) as f:
            data = json.load(f)
        if time.time() - data.get("cached_at", 0) < CACHE_TTL:
            return data
    except Exception:
        pass
    return None


def _cache_write(key: str, data: dict):
    path = _cache_path(key)
    try:
        data["cached_at"] = time.time()
        with open(path, "w") as f:
            json.dump(data, f)
    except Exception:
        pass


# ─── CISA KEV Integration ─────────────────────────────────────────────────────

_kev_ids: set = set()
_kev_loaded = False
_kev_lock = threading.Lock()

def _load_kev():
    """Load CISA Known Exploited Vulnerabilities catalog."""
    global _kev_ids, _kev_loaded
    with _kev_lock:
        if _kev_loaded:
            return

        # Try disk cache first
        try:
            with open(KEV_CACHE) as f:
                data = json.load(f)
            if time.time() - data.get("cached_at", 0) < CACHE_TTL * 3:
                _kev_ids = set(data.get("ids", []))
                _kev_loaded = True
                return
        except Exception:
            pass

        # Fetch live
        try:
            req = urllib.request.Request(KEV_URL, headers={"User-Agent": "NetLogic/2.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = json.loads(resp.read())
            _kev_ids = {v["cveID"] for v in raw.get("vulnerabilities", [])}
            os.makedirs(CACHE_DIR, exist_ok=True)
            with open(KEV_CACHE, "w") as f:
                json.dump({"ids": list(_kev_ids), "cached_at": time.time()}, f)
            _kev_loaded = True
        except Exception:
            _kev_loaded = True   # Don't retry on failure


def is_kev(cve_id: str) -> bool:
    _load_kev()
    return cve_id in _kev_ids


# ─── Rate Limiter ─────────────────────────────────────────────────────────────

def _rate_limit():
    global _last_request_time
    api_key = os.environ.get("NETLOGIC_NVD_KEY", "")
    delay = RATE_DELAY_KEYED if api_key else RATE_DELAY
    with _rate_lock:
        now = time.time()
        wait = delay - (now - _last_request_time)
        if wait > 0:
            time.sleep(wait)
        _last_request_time = time.time()


# ─── NVD API Fetcher ──────────────────────────────────────────────────────────

_nvd_unavailable = False   # Set True after first connection failure

def _nvd_request(params: dict) -> Optional[dict]:
    """Make a single NVD API request with rate limiting."""
    global _nvd_unavailable
    if _nvd_unavailable:
        return None

    _rate_limit()
    api_key = os.environ.get("NETLOGIC_NVD_KEY", "")
    headers = {"User-Agent": "NetLogic/2.0"}
    if api_key:
        headers["apiKey"] = api_key

    url = NVD_API_URL + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw_body = resp.read()
            # print(f"DEBUG: NVD Response for {params.get('keywordSearch')}: {len(raw_body)} bytes", file=sys.stderr)
            return json.loads(raw_body)
    except urllib.error.HTTPError as e:
        if e.code == 429:
            # Rate limited — wait and retry once
            time.sleep(30)
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    return json.loads(resp.read())
            except Exception:
                return None
        return None
    except urllib.error.URLError:
        # Network unreachable / DNS failure — stop trying for this session
        _nvd_unavailable = True
        return None
    except Exception:
        return None


def nvd_is_available() -> bool:
    """Quick connectivity check."""
    try:
        req = urllib.request.Request(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1",
            headers={"User-Agent": "NetLogic/2.0"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False


# ─── CVE Parser ──────────────────────────────────────────────────────────────

def _parse_nvd_item(item: dict) -> NVDCve:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")

    # Description
    desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        ""
    )[:500]

    # Dates
    published = cve.get("published", "")[:10]
    modified  = cve.get("lastModified", "")[:10]

    # CVSS — prefer v3.1, then v3.0, then v2
    score, severity, vector = 0.0, "UNKNOWN", ""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            cd = m.get("cvssData", {})
            score    = float(cd.get("baseScore", 0))
            severity = (m.get("baseSeverity") or cd.get("baseSeverity", "UNKNOWN")).upper()
            vector   = cd.get("vectorString", "")
            break

    # CWE
    cwes = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("lang") == "en":
                cwes.append(d.get("value", ""))
    cwe = "; ".join(cwes[:3])

    # References
    refs = [r.get("url", "") for r in cve.get("references", [])[:5] if r.get("url")]

    # Exploit reference detection
    exploit_refs = []
    has_metasploit = False
    has_public_exploit = False
    for ref in cve.get("references", []):
        url = ref.get("url", "")
        if not url:
            continue
        url_lower = url.lower()
        if "rapid7.com/db" in url_lower or "metasploit" in url_lower:
            has_metasploit = True
            exploit_refs.append(url)
        elif ("exploit-db.com" in url_lower or "exploitdb.com" in url_lower or
              "packetstormsecurity.com" in url_lower or
              "github.com" in url_lower and any(k in url_lower for k in
                  ("exploit", "/poc", "proof-of-concept", "rce", "/lpe", "nuclei-templates"))):
            has_public_exploit = True
            exploit_refs.append(url)

    # Affected products (CPE) + version range extraction
    affected = []
    ver_start, ver_end = None, None
    ver_end_inc = False

    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    criteria = match.get("criteria", "")
                    affected.append(criteria)
                    # Extract version range
                    if match.get("versionStartIncluding"):
                        ver_start = match["versionStartIncluding"]
                    if match.get("versionEndExcluding"):
                        ver_end = match["versionEndExcluding"]
                        ver_end_inc = False
                    elif match.get("versionEndIncluding"):
                        ver_end = match["versionEndIncluding"]
                        ver_end_inc = True

    # KEV check
    kev = is_kev(cve_id)

    return NVDCve(
        id=cve_id,
        description=desc,
        cvss_score=score,
        severity=severity,
        vector=vector,
        published=published,
        last_modified=modified,
        cwe=cwe,
        references=refs,
        affected_products=affected[:10],
        exploit_available=kev,
        kev=kev,
        version_start=ver_start,
        version_end=ver_end,
        version_end_including=ver_end_inc,
        has_metasploit=has_metasploit,
        has_public_exploit=has_public_exploit,
        exploit_refs=exploit_refs[:5],
    )


# ─── Version Matching ─────────────────────────────────────────────────────────

try:
    from packaging.version import Version, InvalidVersion
except ImportError:
    Version = None
    class InvalidVersion(Exception): pass

def _parse_ver(v: str) -> tuple:
    """
    Parse version string into a comparable tuple.
    Extracts all numeric parts and normalizes suffixes.
    Used as a fallback for semantic versioning.
    """
    if not v:
        return (0,)
    
    v_str = str(v).strip().lower()
    
    # Fallback for non-standard versions (e.g., 1.10-patch2, 8.2p1)
    # Tokenize by splitting on non-alphanumeric boundaries
    parts = re.split(r"([.\-_])", v_str)
    result = []
    
    for p in parts:
        if not p or p in ".-_":
            continue
            
        # Try to find a leading number
        m = re.match(r"(\d+)(.*)", p)
        if m:
            num_part = int(m.group(1))
            suffix = m.group(2)
            result.append(num_part)
            
            if suffix:
                if suffix.startswith('p'): # patch
                    p_val = re.search(r"\d+", suffix)
                    result.append(100 + (int(p_val.group(0)) if p_val else 0))
                elif suffix.startswith('rc'):
                    result.append(-1)
                elif suffix.startswith('b'):
                    result.append(-2)
                elif suffix.startswith('a'):
                    result.append(-3)
        else:
            # Suffix-only part
            if 'rc' in p: result.append(-1)
            elif 'beta' in p or p.startswith('b'): result.append(-2)
            elif 'alpha' in p or p.startswith('a'): result.append(-3)
            elif 'patch' in p or p.startswith('p'):
                p_val = re.search(r"\d+", p)
                result.append(100 + (int(p_val.group(0)) if p_val else 0))
            else:
                result.append(0)
                
    return tuple(result)


def _ver_lte(a: str, b: str) -> bool:
    if not a or not b: return True
    try:
        v1, v2 = str(a).strip(), str(b).strip()
        try:
            if Version is None:
                raise TypeError("packaging not installed")
            return Version(v1) <= Version(v2)
        except (InvalidVersion, TypeError):
            return _parse_ver(v1) <= _parse_ver(v2)
    except Exception:
        return True

def _ver_lt(a: str, b: str) -> bool:
    if not a or not b: return True
    try:
        v1, v2 = str(a).strip(), str(b).strip()
        try:
            if Version is None:
                raise TypeError("packaging not installed")
            return Version(v1) < Version(v2)
        except (InvalidVersion, TypeError):
            return _parse_ver(v1) < _parse_ver(v2)
    except Exception:
        return True

def _ver_gte(a: str, b: str) -> bool:
    if not a or not b: return True
    try:
        v1, v2 = str(a).strip(), str(b).strip()
        try:
            if Version is None:
                raise TypeError("packaging not installed")
            return Version(v1) >= Version(v2)
        except (InvalidVersion, TypeError):
            return _parse_ver(v1) >= _parse_ver(v2)
    except Exception:
        return True


def version_is_affected(detected_version: str, cve: NVDCve) -> bool:
    """
    Check if detected_version falls within the CVE's affected version range.
    Returns True if:
      - No range info available (conservative: assume affected)
      - version >= ver_start AND version < ver_end (or <= if including)
    """
    if not detected_version:
        return True   # No version info — be conservative

    if not cve.version_end and not cve.version_start:
        return True   # No range data — assume affected

    start_ok = True
    end_ok   = True

    if cve.version_start:
        start_ok = _ver_gte(detected_version, cve.version_start)

    if cve.version_end:
        if cve.version_end_including:
            end_ok = _ver_lte(detected_version, cve.version_end)
        else:
            end_ok = _ver_lt(detected_version, cve.version_end)

    return start_ok and end_ok


# ─── Keyword Builder ──────────────────────────────────────────────────────────

# Maps internal service/product names → better NVD search terms
PRODUCT_KEYWORD_MAP = {
    "openssh":      "openssh",
    "ssh":          "openssh",
    "apache":       "apache server",
    "httpd":        "apache server",
    "nginx":        "nginx",
    "iis":          "internet information services",
    "tomcat":       "tomcat",
    "php":          "php",
    "mysql":        "mysql",
    "mariadb":      "mariadb",
    "postgresql":   "postgresql",
    "postgres":     "postgresql",
    "mssql":        "sql server",
    "redis":        "redis",
    "mongodb":      "mongodb",
    "elasticsearch":"elasticsearch",
    "memcached":    "memcached",
    "vsftpd":       "vsftpd",
    "proftpd":      "proftpd",
    "exim":         "exim",
    "postfix":      "postfix",
    "dovecot":      "dovecot",
    "samba":        "samba",
    "openssl":      "openssl",
    "wordpress":    "wordpress",
    "drupal":       "drupal",
    "joomla":       "joomla",
    "spring":       "spring framework",
    "log4j":        "log4j",
    "struts":       "struts",
    "jenkins":      "jenkins",
    "gitlab":       "gitlab",
    "grafana":      "grafana",
    "kibana":       "kibana",
    "docker":       "docker",
    "kubernetes":   "kubernetes",
    "openldap":     "openldap",
    "bind":         "bind",
    "unbound":      "unbound",
    "openvpn":      "openvpn",
    "libssl":       "openssl",
    "libcrypto":    "openssl",
    "smb":          "samba",
    "microsoft-ds": "samba",
    "netbios-ssn":  "samba",
    "rdp":          "remote desktop",
    "ms-wbt-server":"remote desktop",
    "telnet":       "telnet",
    "vnc":          "vnc",
    "snmpd":        "net-snmp",
    "snmp":         "net-snmp",
    "rpcbind":      "rpcbind",
    "nfs":          "nfs-utils",
    "cups":         "CUPS",
    "jboss":          "JBoss Application Server",
    "wildfly":        "WildFly",
    "weblogic":       "Oracle WebLogic Server",
    "websphere":      "IBM WebSphere Application Server",
    "glassfish":      "GlassFish",
    "coldfusion":     "Adobe ColdFusion",
    "exchange":       "Microsoft Exchange Server",
    "sharepoint":     "Microsoft SharePoint",
    "confluence":     "Atlassian Confluence",
    "jira":           "Atlassian Jira",
    "bitbucket":      "Atlassian Bitbucket",
    "haproxy":        "HAProxy",
    "lighttpd":       "lighttpd",
    "traefik":        "Traefik",
    "vault":          "HashiCorp Vault",
    "consul":         "HashiCorp Consul",
    "etcd":           "etcd",
    "rabbitmq":       "RabbitMQ",
    "influxdb":       "InfluxDB",
    "couchdb":        "Apache CouchDB",
    "solr":           "Apache Solr",
    "cassandra":      "Apache Cassandra",
    "neo4j":          "Neo4j",
    "minio":          "MinIO",
    "prometheus":     "Prometheus",
    "grafana":        "Grafana",
    "kibana":         "Kibana",
    "sendmail":       "Sendmail",
    "cups":           "CUPS",
    "nagios":         "Nagios",
    "splunk":         "Splunk",
    "zabbix":         "Zabbix",
    "roundcube":      "Roundcube",
    "phpmyadmin":     "phpMyAdmin",
    "manageengine":   "ManageEngine",
    "vcenter":        "VMware vCenter Server",
    "vmware":         "VMware",
    "paloalto":       "Palo Alto Networks PAN-OS",
    "fortigate":      "Fortinet FortiOS",
    "sonicwall":      "SonicWall",
    "citrix":         "Citrix NetScaler",
    "pulse":          "Ivanti Pulse Secure",
    "f5":             "F5 BIG-IP",
    "cisco":          "Cisco IOS",
    "zimbra":         "Zimbra Collaboration Suite",
    "http":         None,    # Too generic — skip
    "https":        None,
    "ftp":          None,
    "smtp":         None,
    "unknown":      None,
}


def _build_keyword(product: str, version: str = None) -> Optional[str]:
    """Build NVD search keyword from product name.

    Returns None for products explicitly suppressed in PRODUCT_KEYWORD_MAP
    (e.g. "http", "ftp") — callers must check for None and skip the query.
    """
    product_lower = (product or "").lower().strip()

    # Check the map first; use `is not None` so explicit None suppressions are honoured.
    if product_lower in PRODUCT_KEYWORD_MAP:
        return PRODUCT_KEYWORD_MAP[product_lower]  # may be None → caller skips

    # Unknown product — use as-is (best-effort)
    return product_lower or None


# ─── Main Lookup Function ─────────────────────────────────────────────────────

def query_nvd_for_product(product: str, version: str = None,
                           max_results: int = MAX_RESULTS) -> list[NVDCve]:
    """
    Query NVD for CVEs affecting a product, optionally filtered by version.
    Results are cached to disk for 24 hours.
    """
    product_clean = (product or "").strip().lower()
    keyword = _build_keyword(product_clean, version)
    if not keyword:  # None (suppressed) or empty string
        return []

    # Cache key includes product but NOT version (same CVEs apply)
    cache_key = f"product:{keyword.lower()}"
    cached = _cache_read(cache_key)
    if cached:
        raw_cves = [NVDCve(**c) for c in cached.get("cves", [])]
        # Still filter by version even from cache
        if version:
            return [c for c in raw_cves if version_is_affected(version, c)]
        return raw_cves

    # Fetch from NVD
    params = {
        "keywordSearch":    keyword,
        "keywordExactMatch": "false",
        "resultsPerPage":   min(max_results, 50),
        "startIndex":       0,
    }

    data = _nvd_request(params)
    if not data:
        return []

    vulns = data.get("vulnerabilities", [])
    cves = []
    for item in vulns:
        try:
            cve_obj = _parse_nvd_item(item)
            if cve_obj:
                cves.append(cve_obj)
        except Exception:
            continue

    # Sort by CVSS score descending
    cves.sort(key=lambda c: c.cvss_score, reverse=True)

    # Cache the results
    if cves:
        _cache_write(cache_key, {"cves": [asdict(c) for c in cves]})

    # Filter by version if provided
    if version:
        return [c for c in cves if version_is_affected(version, c)]

    return cves


def lookup_cves_for_service(product: str, version: str = None,
                             min_cvss: float = 0.0) -> list[NVDCve]:
    """
    Main entry point. Returns CVEs for a product/version, filtered by min CVSS.
    """
    cves = query_nvd_for_product(product, version)
    if min_cvss > 0:
        cves = [c for c in cves if c.cvss_score >= min_cvss]
    return cves


# ─── Batch Lookup (for scanning many ports at once) ───────────────────────────

def lookup_batch(services: list[dict], min_cvss: float = 4.0,
                 max_workers: int = 3) -> dict[str, list[NVDCve]]:
    """
    Lookup CVEs for multiple services concurrently (but rate-limited).
    services: list of {"product": "...", "version": "...", "port": N}
    Returns: dict keyed by "product:version"
    """
    results = {}
    seen_keys = set()

    # Deduplicate — no need to query the same product twice
    unique = []
    for s in services:
        prod = (s.get("product") or "").lower()
        ver  = s.get("version") or ""
        key  = f"{prod}:{ver}"
        if key not in seen_keys and prod:
            seen_keys.add(key)
            unique.append(s)

    # Sequential to respect rate limits (NVD is strict)
    for s in unique:
        prod = s.get("product") or s.get("service") or ""
        ver  = s.get("version") or ""
        key  = f"{prod.lower()}:{ver}"
        cves = lookup_cves_for_service(prod, ver or None, min_cvss=min_cvss)
        if cves:
            results[key] = cves

    return results


# ─── Cache Management ─────────────────────────────────────────────────────────

def cache_stats() -> dict:
    """Return cache statistics."""
    try:
        files = [f for f in os.listdir(CACHE_DIR) if f.endswith(".json")]
        total_size = sum(
            os.path.getsize(os.path.join(CACHE_DIR, f)) for f in files
        )
        return {
            "entries":    len(files),
            "size_kb":    round(total_size / 1024, 1),
            "cache_dir":  CACHE_DIR,
        }
    except Exception:
        return {"entries": 0, "size_kb": 0, "cache_dir": CACHE_DIR}


def clear_cache():
    """Delete all cached NVD responses."""
    try:
        import shutil
        shutil.rmtree(CACHE_DIR)
        os.makedirs(CACHE_DIR, exist_ok=True)
        print(f"[+] Cache cleared: {CACHE_DIR}")
    except Exception as e:
        print(f"[!] Cache clear failed: {e}")


def preload_cache(products: list[str] = None):
    """
    Pre-populate cache for common products.
    """
    common = products or list(set(PRODUCT_KEYWORD_MAP.values()) - {None})
    print(f"[*] Pre-loading NVD cache for {len(common)} products...")
    for i, product in enumerate(common):
        # Normalize keyword for consistent cache hits
        product_clean = product.strip().lower()
        print(f"  [{i+1}/{len(common)}] {product_clean}...", end=" ", flush=True)
        
        cves = query_nvd_for_product(product_clean)
        print(f"{len(cves)} CVEs")
    print("[+] Cache preload complete.")


if __name__ == "__main__":
    # Quick test
    import sys
    product = sys.argv[1] if len(sys.argv) > 1 else "OpenSSH"
    version = sys.argv[2] if len(sys.argv) > 2 else None
    print(f"\nQuerying NVD for: {product} {version or '(any version)'}")
    cves = lookup_cves_for_service(product, version)
    for c in cves:
        kev_flag = " ★ KEV" if c.kev else ""
        print(f"  {c.id}  CVSS {c.cvss_score}  [{c.severity}]{kev_flag}  {c.description[:80]}...")
    stats = cache_stats()
    print(f"\nCache: {stats['entries']} entries, {stats['size_kb']} KB at {stats['cache_dir']}")