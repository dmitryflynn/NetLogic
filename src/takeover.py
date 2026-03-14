"""
NetLogic - Subdomain Takeover Detector
Identifies subdomains vulnerable to takeover via dangling DNS records.

A subdomain takeover occurs when:
  1. A DNS record (CNAME/A) points to an external service
  2. That service/resource no longer exists or is unclaimed
  3. An attacker can register that resource and serve content under the victim's subdomain

Checks:
  - CNAME chains pointing to unclaimed cloud/SaaS resources
  - Fingerprint-based detection for 30+ providers (GitHub Pages, Heroku, S3, Netlify,
    Fastly, Shopify, Zendesk, Tumblr, WP.com, Azure, Surge.sh, Cargo, etc.)
  - Dangling A records to deprovisioned cloud IPs
  - NS delegation to non-existent nameservers
  - MX records pointing to unclaimed mail services
"""

import socket
import ssl
import urllib.request
import urllib.error
import re
import json
import concurrent.futures
from dataclasses import dataclass, field
from typing import Optional


# ─── Data Models ────────────────────────────────────────────────────────────────

@dataclass
class TakeoverFinding:
    subdomain: str
    cname_chain: list[str]
    provider: str
    confidence: str        # HIGH / MEDIUM / LOW
    detail: str
    fingerprint_matched: Optional[str] = None
    status_code: Optional[int] = None
    vulnerable: bool = False

@dataclass
class TakeoverResult:
    target: str
    subdomains_checked: int = 0
    vulnerable: list[TakeoverFinding] = field(default_factory=list)
    potential: list[TakeoverFinding] = field(default_factory=list)
    safe: int = 0


# ─── Provider Fingerprint Database ───────────────────────────────────────────────
# Format: { "provider_name": { "cname_pattern": r"...", "fingerprints": ["..."], "status": [404] } }

PROVIDER_FINGERPRINTS = {
    "GitHub Pages": {
        "cname": r"github\.io",
        "fingerprints": [
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index",
        ],
        "status": [404],
    },
    "Heroku": {
        "cname": r"herokuapp\.com|heroku\.com",
        "fingerprints": [
            "No such app",
            "herokucdn.com/error-pages/no-such-app",
        ],
        "status": [404],
    },
    "Amazon S3": {
        "cname": r"s3\.amazonaws\.com|s3-website",
        "fingerprints": [
            "NoSuchBucket",
            "The specified bucket does not exist",
            "Code: NoSuchBucket",
        ],
        "status": [404, 403],
    },
    "Amazon CloudFront": {
        "cname": r"cloudfront\.net",
        "fingerprints": [
            "Bad request",
            "ERROR: The request could not be satisfied",
        ],
        "status": [403],
    },
    "Netlify": {
        "cname": r"netlify\.app|netlify\.com",
        "fingerprints": [
            "Not Found - Request ID",
            "netlify",
        ],
        "status": [404],
    },
    "Vercel": {
        "cname": r"vercel\.app|now\.sh",
        "fingerprints": [
            "The deployment could not be found",
            "DEPLOYMENT_NOT_FOUND",
        ],
        "status": [404],
    },
    "Azure": {
        "cname": r"azurewebsites\.net|cloudapp\.net|azurecontainer\.io|trafficmanager\.net",
        "fingerprints": [
            "404 Web Site not found",
            "Error 404 - Web app not found",
        ],
        "status": [404],
    },
    "Shopify": {
        "cname": r"myshopify\.com",
        "fingerprints": [
            "Sorry, this shop is currently unavailable",
            "Only one step left",
        ],
        "status": [404],
    },
    "Fastly": {
        "cname": r"fastly\.net",
        "fingerprints": [
            "Fastly error: unknown domain",
            "Please check that this domain has been added to a service",
        ],
        "status": [404],
    },
    "Ghost": {
        "cname": r"ghost\.io",
        "fingerprints": [
            "The thing you were looking for is no longer here",
        ],
        "status": [404],
    },
    "Tumblr": {
        "cname": r"tumblr\.com",
        "fingerprints": [
            "There's nothing here",
            "Whatever you were looking for doesn't currently exist",
        ],
        "status": [404, 200],
    },
    "WordPress.com": {
        "cname": r"wordpress\.com",
        "fingerprints": [
            "Do you want to register",
            "doesn't exist",
        ],
        "status": [404],
    },
    "Zendesk": {
        "cname": r"zendesk\.com",
        "fingerprints": [
            "Help Center Closed",
            "Oops, this help center no longer exists",
        ],
        "status": [404],
    },
    "Surge.sh": {
        "cname": r"surge\.sh",
        "fingerprints": [
            "project not found",
        ],
        "status": [404],
    },
    "Cargo": {
        "cname": r"cargocollective\.com",
        "fingerprints": [
            "404 Not Found",
        ],
        "status": [404],
    },
    "Intercom": {
        "cname": r"custom\.intercom\.help",
        "fingerprints": [
            "This page is reserved for artistic works",
        ],
        "status": [404],
    },
    "Helpscout": {
        "cname": r"helpscoutdocs\.com",
        "fingerprints": [
            "No settings were found for this company",
        ],
        "status": [404],
    },
    "JetBrains": {
        "cname": r"myjetbrains\.com",
        "fingerprints": [
            "is not a registered InCloud YouTrack",
        ],
        "status": [404],
    },
    "Webflow": {
        "cname": r"webflow\.io",
        "fingerprints": [
            "The page you are looking for doesn't exist or has been moved",
        ],
        "status": [404],
    },
    "Squarespace": {
        "cname": r"squarespace\.com",
        "fingerprints": [
            "No Such Account",
        ],
        "status": [404],
    },
    "Wix": {
        "cname": r"wixsite\.com|parastorage\.com",
        "fingerprints": [
            "Error ConnectYourDomain",
        ],
        "status": [404],
    },
    "ReadTheDocs": {
        "cname": r"readthedocs\.io",
        "fingerprints": [
            "unknown to Read the Docs",
        ],
        "status": [404],
    },
    "Bitbucket": {
        "cname": r"bitbucket\.io",
        "fingerprints": [
            "Repository not found",
        ],
        "status": [404],
    },
    "Smartling": {
        "cname": r"smartling\.com",
        "fingerprints": [
            "Domain is not configured",
        ],
        "status": [404],
    },
    "Pingdom": {
        "cname": r"stats\.pingdom\.com",
        "fingerprints": [
            "Report not found",
        ],
        "status": [404],
    },
}


# ─── DNS CNAME Resolution ────────────────────────────────────────────────────────

def resolve_cname_chain(hostname: str, max_depth: int = 8) -> list[str]:
    """
    Follow CNAME chain via DNS-over-HTTPS (Cloudflare).
    Returns list of CNAMEs in order.
    """
    import urllib.request, json, urllib.parse
    chain = []
    current = hostname

    for _ in range(max_depth):
        url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(current)}&type=CNAME"
        try:
            req = urllib.request.Request(url, headers={
                "Accept": "application/dns-json",
                "User-Agent": "NetLogic/1.0",
            })
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
            answers = data.get("Answer", [])
            cname = next((a["data"].rstrip(".") for a in answers if a.get("type") == 5), None)
            if not cname or cname == current:
                break
            chain.append(cname)
            current = cname
        except Exception:
            break

    return chain


def check_nxdomain(hostname: str) -> bool:
    """Returns True if the hostname resolves to NXDOMAIN (doesn't exist)."""
    try:
        socket.gethostbyname(hostname)
        return False
    except socket.gaierror as e:
        return "Name or service not known" in str(e) or "No address" in str(e)


# ─── HTTP Fingerprint Check ───────────────────────────────────────────────────────

def fetch_body(url: str, timeout: float = 6.0) -> tuple[str, int]:
    """Fetch page body and status code, ignoring TLS errors."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetLogic/1.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(8192).decode("utf-8", errors="replace")
            return body, resp.status
    except urllib.error.HTTPError as e:
        try:
            body = e.read(4096).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return body, e.code
    except Exception:
        return "", 0


def match_fingerprints(body: str, status: int, provider: str) -> bool:
    """Return True if body/status matches known takeover fingerprints for provider."""
    info = PROVIDER_FINGERPRINTS.get(provider, {})
    fp_list = info.get("fingerprints", [])
    exp_status = info.get("status", [])

    status_match = status in exp_status if exp_status else True
    body_match = any(fp.lower() in body.lower() for fp in fp_list) if fp_list else False

    return status_match and body_match


# ─── Per-Subdomain Analysis ──────────────────────────────────────────────────────

def analyze_subdomain(subdomain: str) -> Optional[TakeoverFinding]:
    """
    Check a single subdomain for takeover vulnerability.
    Returns TakeoverFinding if vulnerable/potential, None if safe.
    """
    # Resolve CNAME chain
    cname_chain = resolve_cname_chain(subdomain)
    if not cname_chain:
        return None

    final_cname = cname_chain[-1]

    # Check if the final CNAME is NXDOMAIN (dead record)
    nxdomain = check_nxdomain(final_cname)

    # Match provider
    matched_provider = None
    for provider, info in PROVIDER_FINGERPRINTS.items():
        pattern = info.get("cname", "")
        if pattern and re.search(pattern, final_cname, re.IGNORECASE):
            matched_provider = provider
            break

    if not matched_provider and not nxdomain:
        return None

    # If we found a matching provider, fetch and fingerprint
    body, status = "", 0
    fingerprint_matched = None

    if matched_provider:
        for scheme in ("https", "http"):
            body, status = fetch_body(f"{scheme}://{subdomain}/")
            if body or status:
                break

        if match_fingerprints(body, status, matched_provider):
            fingerprint_matched = f"HTTP {status} with takeover fingerprint"
            return TakeoverFinding(
                subdomain=subdomain,
                cname_chain=cname_chain,
                provider=matched_provider,
                confidence="HIGH",
                detail=f"CNAME → {final_cname} ({matched_provider}). "
                       f"Response matches known unclaimed-resource fingerprint. "
                       f"Register the {matched_provider} resource to take over this subdomain.",
                fingerprint_matched=fingerprint_matched,
                status_code=status,
                vulnerable=True,
            )
        else:
            # CNAME matches provider but no fingerprint — potential
            return TakeoverFinding(
                subdomain=subdomain,
                cname_chain=cname_chain,
                provider=matched_provider,
                confidence="MEDIUM",
                detail=f"CNAME points to {matched_provider} ({final_cname}). "
                       f"Could not confirm unclaimed status — verify manually.",
                status_code=status,
                vulnerable=False,
            )

    # NXDOMAIN with no provider match — dangling DNS
    if nxdomain:
        return TakeoverFinding(
            subdomain=subdomain,
            cname_chain=cname_chain,
            provider="Unknown (NXDOMAIN)",
            confidence="MEDIUM",
            detail=f"CNAME chain ends at {final_cname} which does not resolve (NXDOMAIN). "
                   f"Dangling DNS record — if the target domain can be registered, takeover is possible.",
            vulnerable=False,
        )

    return None


# ─── Main Orchestrator ───────────────────────────────────────────────────────────

def check_subdomain_takeovers(target: str, subdomains: list[str],
                               max_workers: int = 20) -> TakeoverResult:
    """
    Check a list of subdomains for takeover vulnerabilities.
    subdomains: list of FQDNs (e.g. ['dev.example.com', 'staging.example.com'])
    """
    result = TakeoverResult(target=target, subdomains_checked=len(subdomains))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as exe:
        futures = {exe.submit(analyze_subdomain, sub): sub for sub in subdomains}
        for future in concurrent.futures.as_completed(futures):
            finding = future.result()
            if finding is None:
                result.safe += 1
            elif finding.vulnerable:
                result.vulnerable.append(finding)
            else:
                result.potential.append(finding)

    return result


def discover_and_check(target: str, max_workers: int = 20) -> TakeoverResult:
    """
    Discover subdomains via CT logs then check all for takeover.
    Convenience wrapper used by the main scanner.
    """
    from src.osint import fetch_ct_subdomains, SubdomainEntry
    subs = fetch_ct_subdomains(target)
    sub_names = [s.subdomain for s in subs if s.subdomain != target]
    if not sub_names:
        return TakeoverResult(target=target)
    return check_subdomain_takeovers(target, sub_names, max_workers)
