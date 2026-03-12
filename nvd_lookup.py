"""
NetRecon - NVD Live CVE Lookup Engine
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
  - Optional API key for 50 req/30s limit (set NETRECON_NVD_KEY env var)

Usage:
  from src.nvd_lookup import lookup_cves_for_service
  cves = lookup_cves_for_service("apache", "2.4.49")
"""

import os
import re
import json
import time
import hashlib
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional
import threading
import concurrent.futures


# ─── Constants ───────────────────────────────────────────────────────────────

NVD_API_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_DIR    = os.path.join(os.path.expanduser("~"), ".netrecon", "nvd_cache")
KEV_CACHE    = os.path.join(CACHE_DIR, "kev.json")
CACHE_TTL    = 86400        # 24 hours
MAX_RESULTS  = 20           # CVEs to fetch per product query
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
            req = urllib.request.Request(KEV_URL, headers={"User-Agent": "NetRecon/2.0"})
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
    api_key = os.environ.get("NETRECON_NVD_KEY", "")
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
    api_key = os.environ.get("NETRECON_NVD_KEY", "")
    headers = {"User-Agent": "NetRecon/2.0"}
    if api_key:
        headers["apiKey"] = api_key

    url = NVD_API_URL + "?" + urllib.parse.urlencode(params)
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
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
    except OSError:
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
            headers={"User-Agent": "NetRecon/2.0"}
        )
        urllib.request.urlopen(req, timeout=5)
        return True
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
    )


# ─── Version Matching ─────────────────────────────────────────────────────────

def _parse_ver(v: str) -> tuple:
    """Parse version string into comparable tuple."""
    parts = re.split(r"[.\-_]", str(v).strip())
    result = []
    for p in parts:
        m = re.match(r"(\d+)", p)
        result.append(int(m.group(1)) if m else 0)
    return tuple(result)


def _ver_lte(a: str, b: str) -> bool:
    try: return _parse_ver(a) <= _parse_ver(b)
    except: return True

def _ver_lt(a: str, b: str) -> bool:
    try: return _parse_ver(a) < _parse_ver(b)
    except: return True

def _ver_gte(a: str, b: str) -> bool:
    try: return _parse_ver(a) >= _parse_ver(b)
    except: return True


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
    "openssh":      "OpenSSH",
    "ssh":          "OpenSSH",
    "apache":       "Apache HTTP Server",
    "httpd":        "Apache HTTP Server",
    "nginx":        "nginx",
    "iis":          "Microsoft IIS",
    "tomcat":       "Apache Tomcat",
    "php":          "PHP",
    "mysql":        "MySQL",
    "mariadb":      "MariaDB",
    "postgresql":   "PostgreSQL",
    "postgres":     "PostgreSQL",
    "mssql":        "Microsoft SQL Server",
    "redis":        "Redis",
    "mongodb":      "MongoDB",
    "elasticsearch":"Elasticsearch",
    "memcached":    "Memcached",
    "vsftpd":       "vsftpd",
    "proftpd":      "ProFTPD",
    "exim":         "Exim",
    "postfix":      "Postfix",
    "dovecot":      "Dovecot",
    "samba":        "Samba",
    "openssl":      "OpenSSL",
    "wordpress":    "WordPress",
    "drupal":       "Drupal",
    "joomla":       "Joomla",
    "spring":       "Spring Framework",
    "log4j":        "Apache Log4j",
    "struts":       "Apache Struts",
    "jenkins":      "Jenkins",
    "gitlab":       "GitLab",
    "grafana":      "Grafana",
    "kibana":       "Kibana",
    "docker":       "Docker",
    "kubernetes":   "Kubernetes",
    "openldap":     "OpenLDAP",
    "bind":         "ISC BIND",
    "unbound":      "Unbound DNS",
    "openvpn":      "OpenVPN",
    "libssl":       "OpenSSL",
    "libcrypto":    "OpenSSL",
    "http":         None,    # Too generic — skip
    "https":        None,
    "ftp":          None,
    "smtp":         None,
    "unknown":      None,
}


def _build_keyword(product: str, version: str = None) -> Optional[str]:
    """Build NVD search keyword from product name."""
    product_lower = (product or "").lower().strip()

    # Try direct map first
    mapped = PRODUCT_KEYWORD_MAP.get(product_lower)
    if mapped is None:
        return None   # Skip generic/unknown products
    if mapped:
        kw = mapped
    else:
        kw = product

    # Don't append version — NVD keyword search is for product name only
    # Version filtering is done on the results via CPE ranges
    return kw


# ─── Main Lookup Function ─────────────────────────────────────────────────────

def query_nvd_for_product(product: str, version: str = None,
                           max_results: int = MAX_RESULTS) -> list[NVDCve]:
    """
    Query NVD for CVEs affecting a product, optionally filtered by version.
    Results are cached to disk for 24 hours.
    """
    keyword = _build_keyword(product, version)
    if not keyword:
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
        "resultsPerPage":   min(max_results, 20),
        "startIndex":       0,
    }

    data = _nvd_request(params)
    if not data:
        return []

    cves = []
    for item in data.get("vulnerabilities", []):
        try:
            cves.append(_parse_nvd_item(item))
        except Exception:
            pass

    # Sort by CVSS score descending
    cves.sort(key=lambda c: c.cvss_score, reverse=True)

    # Cache the full product results (before version filtering)
    _cache_write(cache_key, {"cves": [asdict(c) for c in cves]})

    # Filter to version if provided
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


def preload_cache(products: list[str]):
    """
    Pre-populate cache for common products.
    Run once with: python -c "from src.nvd_lookup import preload_cache; preload_cache()"
    """
    common = products or list(set(PRODUCT_KEYWORD_MAP.values()) - {None})
    print(f"[*] Pre-loading NVD cache for {len(common)} products...")
    for i, product in enumerate(common):
        print(f"  [{i+1}/{len(common)}] {product}...", end=" ", flush=True)
        cves = query_nvd_for_product(product)
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