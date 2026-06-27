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
    version_ranges: list[dict] = field(default_factory=list)
    has_metasploit: bool = False
    has_public_exploit: bool = False
    exploit_refs: list[str] = field(default_factory=list)
    exploitability_score: float = 0.0  # CVSS Exploitability sub-score (E metric)

    def get_exploitability_severity(self) -> str:
        """
        Returns severity adjusted for exploitability.
        If a CVE has known exploits, Metasploit modules, or is in CISA KEV,
        the severity is bumped up to reflect real-world risk.
        """
        base_sev = self.severity.upper() if self.severity else "UNKNOWN"

        # Already critical, can't go higher
        if base_sev == "CRITICAL":
            return "CRITICAL"

        # Check for active exploitation indicators
        exploit_indicators = [
            self.kev,
            self.has_metasploit,
            self.has_public_exploit,
            self.exploitability_score >= 8.0,
        ]

        if any(exploit_indicators):
            # Bump severity by one level
            severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            try:
                current_idx = severity_order.index(base_sev)
                if current_idx < 3:  # Not already critical
                    return severity_order[current_idx + 1]
            except ValueError:
                return "HIGH"

        return base_sev


# ─── Cache ───────────────────────────────────────────────────────────────────

def _cache_path(key: str) -> str:
    os.makedirs(CACHE_DIR, exist_ok=True)
    # MD5 here only derives a deterministic cache FILENAME from the key — not a
    # security primitive. usedforsecurity=False is required so this doesn't raise
    # on FIPS-mode enterprise hosts (where unflagged md5() is disabled).
    safe = hashlib.md5(key.encode(), usedforsecurity=False).hexdigest()
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


# Detected product (banner/inferred name) → the set of CPE *product* tokens that
# legitimately belong to it. NVD CPE product fields use underscores and canonical
# vendor names ("http_server", "internet_information_services", "sql_server"),
# which a naive substring check can't align — and worse, a substring check
# cross-matches unrelated products ("ftp" in "tftp", "sql" in "postgresql").
# When a detected product is in this table we match ONLY against its CPE tokens,
# eliminating that whole class of false positives. Products absent from the table
# fall back to a token-boundary match (still far tighter than substring).
_CPE_PRODUCT_ALIASES: dict[str, set[str]] = {
    "apache":        {"http_server"},
    "httpd":         {"http_server"},
    "apache httpd":  {"http_server"},
    "nginx":         {"nginx"},
    "iis":           {"internet_information_services", "iis"},
    "microsoft-iis": {"internet_information_services", "iis"},
    "openssh":       {"openssh"},
    "ssh":           {"openssh"},
    "openssl":       {"openssl"},
    "libssl":        {"openssl"},
    "libcrypto":     {"openssl"},
    "tomcat":        {"tomcat"},
    "php":           {"php"},
    "mysql":         {"mysql"},
    "mariadb":       {"mariadb"},
    "postgresql":    {"postgresql"},
    "postgres":      {"postgresql"},
    "mssql":         {"sql_server"},
    "redis":         {"redis"},
    "mongodb":       {"mongodb", "mongodb_server"},
    "elasticsearch": {"elasticsearch"},
    "memcached":     {"memcached"},
    "vsftpd":        {"vsftpd"},
    "proftpd":       {"proftpd"},
    "pure-ftpd":     {"pure-ftpd", "pure_ftpd"},
    "exim":          {"exim"},
    "postfix":       {"postfix"},
    "dovecot":       {"dovecot"},
    "sendmail":      {"sendmail"},
    "samba":         {"samba"},
    "smb":           {"samba"},
    "wordpress":     {"wordpress"},
    "drupal":        {"drupal"},
    "joomla":        {"joomla", "joomla\\!"},
    "jenkins":       {"jenkins"},
    "gitlab":        {"gitlab"},
    "grafana":       {"grafana"},
    "kibana":        {"kibana"},
    "haproxy":       {"haproxy"},
    "lighttpd":      {"lighttpd"},
    "squid":         {"squid"},
    "bind":          {"bind"},
    "named":         {"bind"},
    "openvpn":       {"openvpn"},
    "openldap":      {"openldap"},
    "vnc":           {"vnc", "realvnc", "tightvnc", "ultravnc"},
    "telnet":        {"telnetd", "telnet"},
    "rabbitmq":      {"rabbitmq"},
    "couchdb":       {"couchdb"},
    "solr":          {"solr"},
    "cassandra":     {"cassandra"},
    "jboss":         {"jboss", "jboss_application_server", "jboss_enterprise_application_platform"},
    "weblogic":      {"weblogic_server"},
    "websphere":     {"websphere_application_server"},
    "confluence":    {"confluence"},
    "jira":          {"jira"},
    "exchange":      {"exchange_server"},
}

# CPE product tokens whose presence in a range is only meaningful for the matching
# detected product — never matched via the token fallback because they collide
# with many products (e.g. "server" appears in dozens of CPE product strings).
_AMBIGUOUS_CPE_TOKENS = {"server", "http", "ftp", "sql", "db", "ssl", "core", "framework", "api"}


def _cpe_aliases_for(detected_product_l: str) -> Optional[set[str]]:
    """Return the known CPE product tokens for a detected product, or None.

    Falls back to a normalized form of the human keyword map (spaces → underscores)
    when no explicit alias is registered, so e.g. 'apache solr' → 'apache_solr'.
    """
    if detected_product_l in _CPE_PRODUCT_ALIASES:
        return _CPE_PRODUCT_ALIASES[detected_product_l]
    mapped = PRODUCT_KEYWORD_MAP.get(detected_product_l)
    if mapped:
        return {mapped.lower().replace(" ", "_")}
    return None


def _range_product_matches(range_product: Optional[str], detected_product: Optional[str]) -> bool:
    """Whether a CVE range's CPE product applies to the detected product.

    Strategy (precision-first):
      1. Exact match → yes.
      2. Known product → match ONLY against its registered CPE tokens. No loose
         fallback, so a Postgres host never inherits MySQL/MSSQL CVEs.
      3. Unknown product → token-boundary match on distinctive (≥4-char,
         non-ambiguous) tokens, never an arbitrary substring.
    Empty/missing values stay permissive (can't disprove → don't drop).
    """
    if not range_product or not detected_product:
        return True

    rp = range_product.lower()
    dp = detected_product.lower()
    if rp == dp:
        return True

    aliases = _cpe_aliases_for(dp)
    if aliases is not None:
        return rp in aliases

    # Unknown product: require a shared distinctive token, not a substring.
    rp_tokens = {t for t in re.split(r"[^a-z0-9]+", rp) if t}
    dp_tokens = {t for t in re.split(r"[^a-z0-9]+", dp) if t}
    shared = {
        t for t in (rp_tokens & dp_tokens)
        if len(t) >= 4 and t not in _AMBIGUOUS_CPE_TOKENS
    }
    return bool(shared)


def _version_in_range(detected_version: str, start: Optional[str], end: Optional[str], end_including: bool, start_including: bool = True) -> bool:
    start_ok = True
    end_ok = True

    if start:
        start_ok = _ver_gte(detected_version, start) if start_including else _ver_gt(detected_version, start)

    if end:
        end_ok = _ver_lte(detected_version, end) if end_including else _ver_lt(detected_version, end)

    return start_ok and end_ok


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

def _safe_float(v, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _as_dicts(seq):
    """Yield only the dict items of a value that *should* be a list of dicts.
    NVD responses can be partial/malformed (null, a bare string, mixed items);
    this keeps the per-item loops from crashing on them."""
    if isinstance(seq, list):
        for x in seq:
            if isinstance(x, dict):
                yield x


def _parse_nvd_item(item: dict) -> NVDCve:
    # Defensive against unexpected NVD responses (schema change, partial/error
    # payload, null fields): a malformed item must never crash CVE correlation.
    cve = item.get("cve") if isinstance(item, dict) else None
    if not isinstance(cve, dict):
        cve = {}
    cve_id = cve.get("id", "UNKNOWN") or "UNKNOWN"

    # Description (skip non-dict description entries)
    desc = next(
        (d.get("value", "") for d in cve.get("descriptions", [])
         if isinstance(d, dict) and d.get("lang") == "en"),
        ""
    )
    desc = str(desc)[:500]

    # Dates — coerce to str before slicing (an int/None field would otherwise raise)
    published = str(cve.get("published", "") or "")[:10]
    modified  = str(cve.get("lastModified", "") or "")[:10]

    # CVSS — prefer v3.1, then v3.0, then v2
    score, severity, vector = 0.0, "UNKNOWN", ""
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        metrics = {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if isinstance(entries, list) and entries and isinstance(entries[0], dict):
            m = entries[0]
            cd = m.get("cvssData") if isinstance(m.get("cvssData"), dict) else {}
            score    = _safe_float(cd.get("baseScore", 0))
            severity = str(m.get("baseSeverity") or cd.get("baseSeverity") or "UNKNOWN").upper()
            vector   = str(cd.get("vectorString", "") or "")
            break

    # CWE
    cwes = []
    for w in _as_dicts(cve.get("weaknesses")):
        for d in _as_dicts(w.get("description")):
            if d.get("lang") == "en":
                cwes.append(str(d.get("value", "")))
    cwe = "; ".join(cwes[:3])

    # Extract exploitability score from CVSS vector
    exploitability_score = 0.0
    if vector:
        # CVSS v3.x format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:X/...
        # E values: X=0.0, U=0.85, P=0.94, F=0.97, H=1.0
        e_match = re.search(r'/E:([XUPFH])/', vector)
        if e_match:
            e_val = e_match.group(1)
            exploitability_score = {"X": 0.0, "U": 0.85, "P": 0.94, "F": 0.97, "H": 1.0}.get(e_val, 0.0)

    # References
    _ref_dicts = list(_as_dicts(cve.get("references")))
    refs = [str(r.get("url", "")) for r in _ref_dicts[:5] if r.get("url")]

    # Exploit reference detection
    exploit_refs = []
    has_metasploit = False
    has_public_exploit = False
    for ref in _ref_dicts:
        url = str(ref.get("url", "") or "")
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
    version_ranges = []

    for config in _as_dicts(cve.get("configurations")):
        for node in _as_dicts(config.get("nodes")):
            for match in _as_dicts(node.get("cpeMatch")):
                if match.get("vulnerable"):
                    criteria = str(match.get("criteria", "") or "")
                    affected.append(criteria)
                    cpe_parts = criteria.split(":")
                    cpe_product = cpe_parts[4].lower() if len(cpe_parts) >= 5 else ""
                    # CPE 2.3 version field (index 5). "*"/"-" mean "any/NA"; a
                    # concrete value pins the CVE to exactly that version.
                    cpe_version = cpe_parts[5].lower() if len(cpe_parts) >= 6 else ""
                    r_start_inc = "versionStartIncluding" in match
                    r_start = match.get("versionStartIncluding") or match.get("versionStartExcluding")
                    r_end = match.get("versionEndExcluding") or match.get("versionEndIncluding")
                    r_end_inc = bool(match.get("versionEndIncluding"))
                    if r_start or r_end:
                        version_ranges.append({
                            "start": r_start,
                            "start_including": r_start_inc,
                            "end": r_end,
                            "end_including": r_end_inc,
                            "cpe_product": cpe_product,
                        })
                        if ver_start is None:
                            ver_start = r_start
                        if ver_end is None:
                            ver_end = r_end
                            ver_end_inc = r_end_inc
                    elif cpe_version and cpe_version not in ("*", "-"):
                        # Exact-version pin (e.g. Apache 2.4.49 path traversal RCE).
                        # Recorded as a closed [v, v] range so it matches ONLY that
                        # version — recovers single-version CVEs the range-only parser
                        # dropped, with zero added false-positive surface.
                        version_ranges.append({
                            "start": cpe_version,
                            "end": cpe_version,
                            "end_including": True,
                            "cpe_product": cpe_product,
                            "exact": True,
                        })
                        if ver_start is None and ver_end is None:
                            ver_start = ver_end = cpe_version
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
        version_ranges=version_ranges,
        has_metasploit=has_metasploit,
        has_public_exploit=has_public_exploit,
        exploit_refs=exploit_refs[:5],
        exploitability_score=exploitability_score,
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

    # Cap length: a real version is never this long, and an attacker-controlled
    # banner with a 5000-digit "version" would otherwise blow up int() (Python's
    # 4300-digit integer-string-conversion guard) and crash CVE correlation.
    v_str = str(v).strip().lower()[:64]

    # Strip any prefix that doesn't contain a number
    m_start = re.search(r'(\d.*)', v_str)
    if not m_start:
        return (0,)
    v_str = m_start.group(1)
    
    parts = re.split(r"([.\-_])", v_str)
    result = []
    
    for p in parts:
        if not p or p in ".-_":
            continue
            
        m = re.match(r"^(\d+)(.*)", p)
        if m:
            result.append(int(m.group(1)))
            suffix = m.group(2)
        else:
            suffix = p
            
        if suffix:
            s = suffix.lower()
            # Order matters: match multi-letter pre-release WORDS before single
            # letters, so OpenSSL patch letters (1.0.1f) aren't mistaken for
            # alpha/beta. Pre-releases sort BEFORE the base release (negative);
            # patch letters/levels sort AFTER it (positive).
            if s.startswith('rc'):
                result.append(-1)
            elif s.startswith('beta'):
                result.append(-2)
            elif s.startswith('alpha'):
                result.append(-3)
            elif s.startswith('pre') or s.startswith('dev') or s.startswith('snapshot'):
                result.append(-4)
            elif re.fullmatch(r'p\d+', s):
                # OpenSSH portable patch: 9.3p2 → patch level 2
                result.append(100 + int(s[1:]))
            elif 'patch' in s:
                p_val = re.search(r"\d+", s)
                result.append(100 + (int(p_val.group(0)) if p_val else 0))
            elif len(s) == 1 and 'a' <= s <= 'z':
                # OpenSSL-style patch letter: 1.0.1f → 6, 1.0.1g → 7 (a=1).
                # Sorts AFTER the base (1.0.1 < 1.0.1a) and orders f < g, fixing
                # the inability to tell vulnerable 1.0.1f from patched 1.0.1g.
                result.append(ord(s) - ord('a') + 1)
            elif not m:
                # pure text chunk that didn't match anything known
                result.append(0)
                
    # Remove trailing zeroes for clean comparison
    while len(result) > 1 and result[-1] == 0:
        result.pop()
        
    return tuple(result) if result else (0,)



# OpenSSL-style "patch letter" versions (1.0.1f). packaging.Version misreads the
# trailing a/b/c as PEP 440 alpha/beta/rc pre-releases (sorting them BEFORE the
# base), so such versions must be compared with our own parser instead.
_LETTER_VERSION = re.compile(r'\d[a-z]$')

def _letterish(v: str) -> bool:
    return bool(_LETTER_VERSION.search(str(v).strip().lower()))

def _ver_lte(a: str, b: str) -> bool:
    if not a or not b: return True
    try:
        v1, v2 = str(a).strip(), str(b).strip()
        if _letterish(v1) or _letterish(v2):
            return _parse_ver(v1) <= _parse_ver(v2)
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
        if _letterish(v1) or _letterish(v2):
            return _parse_ver(v1) < _parse_ver(v2)
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
        if _letterish(v1) or _letterish(v2):
            return _parse_ver(v1) >= _parse_ver(v2)
        try:
            if Version is None:
                raise TypeError("packaging not installed")
            return Version(v1) >= Version(v2)
        except (InvalidVersion, TypeError):
            return _parse_ver(v1) >= _parse_ver(v2)
    except Exception:
        return True

def _ver_gt(a: str, b: str) -> bool:
    if not a or not b: return True
    try:
        v1, v2 = str(a).strip(), str(b).strip()
        if _letterish(v1) or _letterish(v2):
            return _parse_ver(v1) > _parse_ver(v2)
        try:
            if Version is None:
                raise TypeError("packaging not installed")
            return Version(v1) > Version(v2)
        except (InvalidVersion, TypeError):
            return _parse_ver(v1) > _parse_ver(v2)
    except Exception:
        return True

def version_is_affected(detected_version: str, cve: NVDCve, detected_product: Optional[str] = None) -> bool:
    """
    Check if detected_version falls within the CVE's affected version range.
    Returns True if:
      - No detected version is available (conservative: assume affected)
      - Any matching range confirms the version is affected
    """
    if not detected_version:
        return True   # No version info — be conservative

    if cve.version_ranges:
        matching_ranges = [
            r for r in cve.version_ranges
            if _range_product_matches(r.get("cpe_product"), detected_product)
        ]
        if not matching_ranges and detected_product:
            return False
        for version_range in matching_ranges or cve.version_ranges:
            if _version_in_range(
                detected_version,
                version_range.get("start"),
                version_range.get("end"),
                bool(version_range.get("end_including")),
                bool(version_range.get("start_including", True)),
            ):
                return True
        return False

    if cve.version_start or cve.version_end:
        return _version_in_range(
            detected_version,
            cve.version_start,
            cve.version_end,
            cve.version_end_including,
        )

    return False


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
    "sendmail":       "Sendmail",
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

    target_results = max(1, int(max_results or MAX_RESULTS))

    # Cache key includes product but NOT version (same CVEs apply)
    cache_key = f"product:{keyword.lower()}"
    cached = _cache_read(cache_key)
    if cached:
        raw_cves = [NVDCve(**c) for c in cached.get("cves", [])]
        cached_complete = bool(cached.get("complete"))
        if cached_complete or len(raw_cves) >= target_results:
            if version:
                return [
                    c for c in raw_cves
                    if version_is_affected(version, c, detected_product=product_clean)
                ]
            return raw_cves

    # Fetch from NVD, paginating when the caller needs more than one page.
    cves = []
    start_index = 0
    total_results = None

    while start_index < target_results and (total_results is None or start_index < total_results):
        # NOTE: do NOT send keywordExactMatch. It is a VALUELESS flag in the NVD
        # 2.0 API — its mere presence forces exact-match, and sending it with a
        # value (e.g. "false") makes NVD return HTTP 404 for the whole request.
        # Omitting it gives the partial keyword matching we want.
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(50, target_results - start_index),
            "startIndex": start_index,
        }
        data = _nvd_request(params)
        if not data:
            break

        vulns = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", total_results)
        if not vulns:
            break

        for item in vulns:
            try:
                cve_obj = _parse_nvd_item(item)
                if cve_obj:
                    cves.append(cve_obj)
            except Exception:
                continue

        start_index += len(vulns)
        if len(vulns) < params["resultsPerPage"]:
            break

    # Sort by CVSS score descending
    cves.sort(key=lambda c: c.cvss_score, reverse=True)

    # Cache the results
    if cves:
        _cache_write(cache_key, {
            "cves": [asdict(c) for c in cves],
            "complete": bool(total_results is not None and len(cves) >= total_results),
        })

    # Filter by version if provided
    if version:
        return [
            c for c in cves
            if version_is_affected(version, c, detected_product=product_clean)
        ]

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
