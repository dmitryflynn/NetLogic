"""
NetLogic - OSINT / Passive Reconnaissance Module
Aggregates public intelligence without touching the target directly:
  - DNS enumeration (A, MX, TXT, NS, CNAME, SOA, SRV)
  - Subdomain discovery via Certificate Transparency logs (crt.sh)
  - WHOIS data parsing
  - Shodan-style header fingerprinting (no key required via public API)
  - ASN / CIDR range lookup via BGP.tools
"""

import socket
import json
import urllib.request
import urllib.parse
import re
import concurrent.futures
from dataclasses import dataclass, field
from typing import Optional


# ─── Data Models ────────────────────────────────────────────────────────────────

@dataclass
class DNSRecord:
    record_type: str
    value: str
    ttl: Optional[int] = None

@dataclass
class SubdomainEntry:
    subdomain: str
    ip: Optional[str] = None
    source: str = "ct_logs"

@dataclass
class ASNInfo:
    asn: str
    org: str
    country: str
    cidr: str

@dataclass
class OSINTResult:
    target: str
    dns_records: list[DNSRecord] = field(default_factory=list)
    subdomains: list[SubdomainEntry] = field(default_factory=list)
    asn_info: Optional[ASNInfo] = None
    whois_raw: str = ""
    technologies: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    certificate_names: list[str] = field(default_factory=list)


# ─── DNS Enumeration ────────────────────────────────────────────────────────────

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "SRV"]

def query_dns_doh(name: str, record_type: str) -> list[str]:
    """
    DNS-over-HTTPS query via Cloudflare (1.1.1.1) — avoids local resolver quirks.
    Returns list of answer strings.
    """
    url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(name)}&type={record_type}"
    try:
        req = urllib.request.Request(url, headers={
            "Accept": "application/dns-json",
            "User-Agent": "NetLogic/2.0",
        })
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        answers = data.get("Answer", [])
        return [a.get("data", "") for a in answers]
    except Exception:
        return []


def _clean_dns_value(rtype: str, value: str) -> str:
    """Normalise a DoH answer string: strip trailing root dot and TXT quoting."""
    value = value.strip()
    # TXT/SOA answers from DoH are wrapped in double quotes (possibly chunked).
    if rtype in ("TXT", "SOA") and value.startswith('"') and value.endswith('"'):
        # Join chunked quoted segments: "abc" "def" -> abcdef
        value = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', value))
    return value.rstrip(".")


def enumerate_dns(domain: str) -> list[DNSRecord]:
    """Query all common DNS record types for a domain (de-duplicated)."""
    records = []
    seen = set()

    def fetch(rtype):
        answers = query_dns_doh(domain, rtype)
        return [(rtype, a) for a in answers if a]

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as exe:
        futures = [exe.submit(fetch, rt) for rt in DNS_RECORD_TYPES]
        for f in concurrent.futures.as_completed(futures):
            for rtype, value in f.result():
                cleaned = _clean_dns_value(rtype, value)
                if not cleaned:
                    continue
                key = (rtype, cleaned)
                if key in seen:
                    continue
                seen.add(key)
                records.append(DNSRecord(record_type=rtype, value=cleaned))

    return records


# ─── Certificate Transparency (crt.sh) ──────────────────────────────────────────

_RESOLVE_TIMEOUT = 3.0  # seconds, per-name DNS resolution


def _resolve_host(name: str, timeout: float = _RESOLVE_TIMEOUT) -> Optional[str]:
    """
    Bounded forward DNS resolution. socket.gethostbyname() ignores the
    per-call timeout and the default socket timeout is None, so a slow or
    unresponsive resolver could hang the whole scan. We run it in a thread
    with a hard deadline and return None on timeout/failure.
    """
    def _do():
        try:
            return socket.gethostbyname(name)
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as exe:
        fut = exe.submit(_do)
        try:
            return fut.result(timeout=timeout)
        except Exception:
            return None


def _belongs_to_domain(name: str, domain: str) -> bool:
    """
    True only if `name` is the apex domain or a real subdomain of it.
    Guards against substring false positives like 'notexample.com' or
    'example.com.evil.org' matching target 'example.com'.
    """
    name = name.lower().rstrip(".")
    domain = domain.lower().rstrip(".")
    return name == domain or name.endswith("." + domain)


def _detect_wildcard_ip(domain: str) -> Optional[str]:
    """
    Detect wildcard DNS: resolve a random, almost-certainly-nonexistent label.
    If it resolves, the zone answers everything; that IP is the wildcard sink
    and subdomains resolving ONLY to it must not be reported as real.
    """
    probe = "netlogic-wildcard-probe-zzq7x9k2." + domain
    return _resolve_host(probe)


def fetch_ct_subdomains(domain: str) -> list[SubdomainEntry]:
    """
    Pull subdomains from crt.sh Certificate Transparency logs.
    No API key needed — public service.

    Precision rules (false data is the cardinal sin):
      * Names must be a true suffix-match of the target domain.
      * CT logs contain historical/expired certs, so a name appearing there
        does NOT mean the host currently exists. We only report names that
        resolve right now.
      * If the zone uses wildcard DNS, a name resolving solely to the wildcard
        sink IP is NOT evidence the host exists, so it is dropped.
    """
    url = f"https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetLogic/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
    except Exception:
        return []

    if not isinstance(data, list):
        return []

    # Collect unique candidate names first (cheap), then resolve a bounded set.
    candidates = []
    seen = set()
    for entry in data:
        if not isinstance(entry, dict):
            continue
        name_value = entry.get("name_value", "") or ""
        for name in str(name_value).split("\n"):
            name = name.strip().lower().lstrip("*.").rstrip(".")
            if not name or name in seen:
                continue
            if not _belongs_to_domain(name, domain):
                continue
            seen.add(name)
            candidates.append(name)

    if not candidates:
        return []

    wildcard_ip = _detect_wildcard_ip(domain)

    entries = []
    # Resolve candidates concurrently with a bounded pool; only keep live names.
    candidates = candidates[:200]
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as exe:
        future_map = {exe.submit(_resolve_host, n): n for n in candidates}
        for fut in concurrent.futures.as_completed(future_map):
            name = future_map[fut]
            try:
                ip = fut.result()
            except Exception:
                ip = None
            if ip is None:
                # Does not currently resolve -> do not report as a live subdomain.
                continue
            if wildcard_ip is not None and ip == wildcard_ip:
                # Resolves only to the wildcard sink -> not real evidence.
                continue
            entries.append(SubdomainEntry(subdomain=name, ip=ip, source="ct_logs"))

    entries.sort(key=lambda e: e.subdomain)
    return entries[:100]   # cap at 100


# ─── ASN / BGP Lookup ───────────────────────────────────────────────────────────

_ASN_RE = re.compile(r"^AS\d+$", re.IGNORECASE)


def _parse_asn_org(data: dict) -> ASNInfo:
    """
    Parse an ipinfo.io-style JSON blob into an ASNInfo, tolerant of missing or
    malformed fields. ipinfo's `org` field is "AS13335 Cloudflare, Inc." — but
    the ASN prefix is not guaranteed, so only treat the first token as the ASN
    when it actually looks like one (ASxxxx); otherwise leave asn empty rather
    than mislabel an org name as an ASN.
    """
    # The ASN lookup is external API JSON — a malformed/error response (null, a
    # list, an HTML error body decoded as something non-dict) must not crash OSINT.
    if not isinstance(data, dict):
        return ASNInfo(asn="", org="", country="", cidr="")
    org_field = data.get("org") or ""
    if not isinstance(org_field, str):
        org_field = str(org_field)
    org_field = org_field.strip()

    asn = ""
    org = org_field
    if org_field:
        first, _, rest = org_field.partition(" ")
        if _ASN_RE.match(first):
            asn = first.upper()
            org = rest.strip()

    # ipinfo also sometimes exposes a dedicated "asn" object.
    asn_obj = data.get("asn")
    if isinstance(asn_obj, dict):
        if isinstance(asn_obj.get("asn"), str) and _ASN_RE.match(asn_obj["asn"]):
            asn = asn_obj["asn"].upper()
        if not org and isinstance(asn_obj.get("name"), str):
            org = asn_obj["name"].strip()

    country = data.get("country") or ""
    if not isinstance(country, str):
        country = str(country)

    cidr = ""
    route = data.get("route")  # not in free tier, but parse if present
    if isinstance(route, str):
        cidr = route.strip()
    elif isinstance(asn_obj, dict) and isinstance(asn_obj.get("route"), str):
        cidr = asn_obj["route"].strip()

    return ASNInfo(asn=asn, org=org.strip(), country=country.strip(), cidr=cidr)


def lookup_asn(ip: str) -> Optional[ASNInfo]:
    """
    Resolve IP → ASN + org via ipinfo.io (no key needed).
    Returns None on any failure so the caller falls back to an empty result.
    """
    if not ip:
        return None
    try:
        url = f"https://ipinfo.io/{urllib.parse.quote(ip)}/json"
        req = urllib.request.Request(url, headers={"User-Agent": "NetLogic/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        if not isinstance(data, dict):
            return None
        return _parse_asn_org(data)
    except Exception:
        return None


# ─── Email Harvesting from TXT/MX ───────────────────────────────────────────────

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

# SPF/DKIM/DMARC mechanism tokens that produce '@'-free but look-alike noise,
# plus mechanism prefixes whose argument is an address that is NOT a real
# mailbox harvested from the target (e.g. third-party report sinks).
_NON_EMAIL_LOCALPARTS = {"include", "redirect", "exp", "a", "mx", "ptr", "ip4", "ip6"}


def _normalise_candidate_email(raw: str) -> Optional[str]:
    """Strip RFC822/DMARC wrappers (mailto:, ruf=, rua=) and lowercase."""
    e = raw.strip().strip(",;").lower()
    for prefix in ("mailto:", "rua=", "ruf="):
        if e.startswith(prefix):
            e = e[len(prefix):]
    e = e.strip()
    if "@" not in e:
        return None
    local = e.split("@", 1)[0]
    if not local or local in _NON_EMAIL_LOCALPARTS:
        return None
    return e


def extract_emails_from_records(records: list[DNSRecord], domain: Optional[str] = None) -> list[str]:
    """
    Pull email addresses embedded in TXT/SOA records.

    Precision: emails are scoped to the target domain (or its subdomains) when a
    domain is supplied, so third-party report sinks (e.g. a DMARC rua pointing at
    a vendor) and SPF include targets are not falsely attributed to the target.
    """
    emails = set()
    for r in records:
        for match in EMAIL_RE.findall(r.value):
            email = _normalise_candidate_email(match)
            if email is None:
                continue
            if domain is not None:
                mail_domain = email.split("@", 1)[1]
                if not _belongs_to_domain(mail_domain, domain):
                    continue
            emails.add(email)
    return sorted(emails)


# ─── Technology Fingerprinting from HTTP Headers ─────────────────────────────────

TECH_SIGNATURES = {
    "WordPress":    r"wp-content|wp-includes",
    "Drupal":       r"Drupal",
    "Joomla":       r"Joomla",
    "PHP":          r"X-Powered-By: PHP",
    "ASP.NET":      r"X-AspNet-Version|X-Powered-By: ASP",
    "Django":       r"csrftoken|Django",
    "Ruby on Rails":r"X-Runtime.*\d+ms",
    "nginx":        r"Server: nginx",
    "Apache":       r"Server: Apache",
    "IIS":          r"Server: Microsoft-IIS",
    "Cloudflare":   r"cf-ray|cloudflare",
    "AWS":          r"x-amz-|AmazonS3",
    "Docker":       r"Docker",
}

def fingerprint_http(target: str, port: int = 80) -> list[str]:
    """Make HTTP HEAD request and fingerprint technologies from headers."""
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{target}:{port}/"
    detected = []
    try:
        req = urllib.request.Request(url, method="HEAD", headers={
            "User-Agent": "Mozilla/5.0 (compatible; NetLogic/1.0)",
        })
        # We deliberately ignore cert verification errors for recon
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        import urllib.error
        try:
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                header_str = str(dict(resp.headers))
        except urllib.error.HTTPError as e:
            header_str = str(dict(e.headers))

        for tech, pattern in TECH_SIGNATURES.items():
            if re.search(pattern, header_str, re.IGNORECASE):
                detected.append(tech)
    except Exception:
        pass
    return detected


# ─── Full OSINT Orchestrator ─────────────────────────────────────────────────────

def run_osint(target: str, ip: Optional[str] = None) -> OSINTResult:
    """
    Run all passive recon tasks against a domain/IP.
    Designed to be non-intrusive — uses only public APIs and DNS.
    """
    result = OSINTResult(target=target)

    # Resolve if needed (bounded — never hang the scan on a slow resolver).
    if ip is None:
        ip = _resolve_host(target) or target

    # Run tasks concurrently. Each source fails independently and returns its
    # empty/neutral value on error, so a total failure still yields a valid
    # (empty) OSINTResult rather than a crash or misleading data.
    def _safe(fn, *args, default):
        try:
            return fn(*args)
        except Exception:
            return default

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as exe:
        f_dns = exe.submit(_safe, enumerate_dns, target, default=[])
        f_subs = exe.submit(_safe, fetch_ct_subdomains, target, default=[])
        f_asn = exe.submit(_safe, lookup_asn, ip, default=None)
        f_tech = exe.submit(_safe, fingerprint_http, target, default=[])

        result.dns_records = f_dns.result()
        result.subdomains = f_subs.result()
        result.asn_info = f_asn.result()
        # De-duplicate technologies while preserving detection order.
        result.technologies = list(dict.fromkeys(f_tech.result()))

    result.emails = extract_emails_from_records(result.dns_records, domain=target)
    result.certificate_names = sorted({s.subdomain for s in result.subdomains})

    return result
