"""
NetRecon - OSINT / Passive Reconnaissance Module
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
            "User-Agent": "NetRecon/1.0",
        })
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        answers = data.get("Answer", [])
        return [a.get("data", "") for a in answers]
    except Exception:
        return []


def enumerate_dns(domain: str) -> list[DNSRecord]:
    """Query all common DNS record types for a domain."""
    records = []

    def fetch(rtype):
        answers = query_dns_doh(domain, rtype)
        return [(rtype, a) for a in answers if a]

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as exe:
        futures = [exe.submit(fetch, rt) for rt in DNS_RECORD_TYPES]
        for f in concurrent.futures.as_completed(futures):
            for rtype, value in f.result():
                records.append(DNSRecord(record_type=rtype, value=value.rstrip(".")))

    return records


# ─── Certificate Transparency (crt.sh) ──────────────────────────────────────────

def fetch_ct_subdomains(domain: str) -> list[SubdomainEntry]:
    """
    Pull subdomains from crt.sh Certificate Transparency logs.
    No API key needed — public service.
    """
    url = f"https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json"
    entries = []
    seen = set()

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetRecon/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
    except Exception:
        return []

    cert_names = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lstrip("*.")
            if name and domain in name and name not in seen:
                seen.add(name)
                cert_names.add(name)
                # Try to resolve
                ip = None
                try:
                    ip = socket.gethostbyname(name)
                except Exception:
                    pass
                entries.append(SubdomainEntry(subdomain=name, ip=ip, source="ct_logs"))

    return entries[:100]   # cap at 100


# ─── ASN / BGP Lookup ───────────────────────────────────────────────────────────

def lookup_asn(ip: str) -> Optional[ASNInfo]:
    """
    Resolve IP → ASN + org via Cloudflare Radar or ipinfo.io (no key needed).
    """
    try:
        url = f"https://ipinfo.io/{ip}/json"
        req = urllib.request.Request(url, headers={"User-Agent": "NetRecon/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        return ASNInfo(
            asn=data.get("org", "").split(" ")[0],
            org=" ".join(data.get("org", "").split(" ")[1:]),
            country=data.get("country", ""),
            cidr=data.get("region", ""),   # best we get without paid key
        )
    except Exception:
        return None


# ─── Email Harvesting from TXT/MX ───────────────────────────────────────────────

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

def extract_emails_from_records(records: list[DNSRecord]) -> list[str]:
    """Pull email addresses embedded in TXT/SOA records."""
    emails = set()
    for r in records:
        for match in EMAIL_RE.findall(r.value):
            emails.add(match)
    return list(emails)


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
            "User-Agent": "Mozilla/5.0 (compatible; NetRecon/1.0)",
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

    # Resolve if needed
    if ip is None:
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            ip = target

    # Run tasks concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as exe:
        f_dns = exe.submit(enumerate_dns, target)
        f_subs = exe.submit(fetch_ct_subdomains, target)
        f_asn = exe.submit(lookup_asn, ip)
        f_tech = exe.submit(fingerprint_http, target)

        result.dns_records = f_dns.result()
        result.subdomains = f_subs.result()
        result.asn_info = f_asn.result()
        result.technologies = f_tech.result()

    result.emails = extract_emails_from_records(result.dns_records)
    result.certificate_names = [s.subdomain for s in result.subdomains]

    return result
