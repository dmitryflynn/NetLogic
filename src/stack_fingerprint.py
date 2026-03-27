"""
NetLogic - Technology Stack Fingerprinter
Identifies CMS, frameworks, cloud providers, CDNs, and WAFs from HTTP responses.

Detection methods:
  - HTTP response headers (Server, X-Powered-By, X-Generator, Via, CF-Ray, etc.)
  - HTML meta tags and comments
  - Cookie names and patterns
  - URL patterns and resource paths
  - Error page fingerprints
  - WAF detection via anomalous request probing
  - DNS-based cloud/CDN identification
  - JavaScript library detection
"""

import ssl
import socket
import urllib.request
import urllib.error
import urllib.parse
import re
import json
from dataclasses import dataclass, field
from typing import Optional
import concurrent.futures


# ─── Data Models ────────────────────────────────────────────────────────────────

@dataclass
class TechFinding:
    category: str        # CMS / Framework / Language / Cloud / CDN / WAF / Server / Analytics
    name: str
    version: Optional[str] = None
    confidence: str = "HIGH"   # HIGH / MEDIUM / LOW
    evidence: str = ""
    cves: list[str] = field(default_factory=list)
    notes: str = ""

@dataclass
class WAFDetection:
    detected: bool = False
    name: Optional[str] = None
    confidence: str = "LOW"
    evidence: str = ""
    bypass_notes: str = ""

@dataclass
class StackResult:
    target: str
    technologies: list[TechFinding] = field(default_factory=list)
    waf: WAFDetection = field(default_factory=WAFDetection)
    cloud_provider: Optional[str] = None
    cdn: Optional[str] = None
    hosting: Optional[str] = None
    ip_ranges: list[str] = field(default_factory=list)


# ─── Signature Databases ─────────────────────────────────────────────────────

# Headers → Technology
HEADER_SIGNATURES = {
    # Server software
    "server": [
        (r"Apache/([\d.]+)",        "Server",    "Apache HTTPD",      ["CVE-2021-41773", "CVE-2022-22720"]),
        (r"nginx/([\d.]+)",         "Server",    "nginx",             ["CVE-2022-41741"]),
        (r"Microsoft-IIS/([\d.]+)", "Server",    "Microsoft IIS",     ["CVE-2022-21907"]),
        (r"LiteSpeed",              "Server",    "LiteSpeed",         []),
        (r"cloudflare",             "CDN",       "Cloudflare",        []),
        (r"openresty/([\d.]+)",     "Server",    "OpenResty",         []),
        (r"Caddy",                  "Server",    "Caddy",             []),
        (r"gunicorn/([\d.]+)",      "Server",    "Gunicorn",          []),
        (r"Jetty",                  "Server",    "Eclipse Jetty",     []),
        (r"Tomcat/([\d.]+)",        "Server",    "Apache Tomcat",     ["CVE-2020-1938", "CVE-2022-34305"]),
    ],
    "x-powered-by": [
        (r"PHP/([\d.]+)",           "Language",  "PHP",               ["CVE-2022-31626"]),
        (r"ASP\.NET",               "Framework", "ASP.NET",           []),
        (r"Express",                "Framework", "Express.js",        []),
        (r"Next\.js",               "Framework", "Next.js",           []),
        (r"Laravel",                "Framework", "Laravel",           []),
        (r"Django",                 "Framework", "Django",            []),
        (r"Ruby on Rails",          "Framework", "Ruby on Rails",     []),
        (r"Phusion Passenger",      "Server",    "Phusion Passenger", []),
    ],
    "x-generator": [
        (r"WordPress ([\d.]+)",     "CMS",       "WordPress",         []),
        (r"Drupal ([\d.]+)",        "CMS",       "Drupal",            ["CVE-2018-7600"]),
        (r"Joomla",                 "CMS",       "Joomla",            ["CVE-2023-23752"]),
    ],
    "x-drupal-cache":     [(r".*", "CMS", "Drupal", ["CVE-2018-7600", "CVE-2019-6340"])],
    "x-wordpress-cache":  [(r".*", "CMS", "WordPress", [])],
    "cf-ray":             [(r".*", "CDN", "Cloudflare", [])],
    "x-vercel-id":        [(r".*", "Cloud", "Vercel", [])],
    "x-amz-cf-id":        [(r".*", "CDN", "Amazon CloudFront", [])],
    "x-amz-request-id":   [(r".*", "Cloud", "Amazon AWS", [])],
    "x-azure-ref":        [(r".*", "Cloud", "Microsoft Azure", [])],
    "x-goog-backend-server": [(r".*", "Cloud", "Google Cloud", [])],
    "x-fastly-request-id":   [(r".*", "CDN", "Fastly", [])],
    "x-cache":            [
        (r"HIT|MISS",    "CDN",   "Generic CDN/Cache", []),
        (r"cloudfront",  "CDN",   "Amazon CloudFront", []),
        (r"varnish",     "Cache", "Varnish Cache", []),
    ],
    "via": [
        (r"cloudfront",   "CDN", "Amazon CloudFront", []),
        (r"varnish",      "Cache","Varnish Cache", []),
        (r"squid",        "Proxy","Squid Proxy", []),
    ],
    "x-shopify-stage":    [(r".*", "CMS", "Shopify", [])],
    "x-wix-request-id":   [(r".*", "CMS", "Wix", [])],
    "x-squarespace-site": [(r".*", "CMS", "Squarespace", [])],
    "x-ghost-cache-status":[(r".*","CMS", "Ghost CMS", [])],
}

# HTML body → Technology
BODY_SIGNATURES = [
    # CMS
    (r"/wp-content/|/wp-includes/|wp-json",    "CMS",       "WordPress",     []),
    (r"Drupal\.settings|drupal\.js|/sites/default/files", "CMS", "Drupal", ["CVE-2018-7600"]),
    (r'content="Joomla',                        "CMS",       "Joomla",        ["CVE-2023-23752"]),
    (r"Powered by <a[^>]+>Shopify",             "CMS",       "Shopify",       []),
    (r'class="ghost-|ghost-theme',              "CMS",       "Ghost CMS",     []),
    (r"squarespace\.com/static",                "CMS",       "Squarespace",   []),
    (r"static\.wixstatic\.com|wix\.com",        "CMS",       "Wix",           []),
    (r"cdn\.webflow\.com|webflow\.js",          "CMS",       "Webflow",       []),

    # JS Frameworks
    (r"__NEXT_DATA__|_next/static",             "Framework", "Next.js",       []),
    (r"__nuxt__|_nuxt/",                        "Framework", "Nuxt.js",       []),
    (r'ng-version="|angular\.min\.js',          "Framework", "Angular",       []),
    (r"__react_fiber_|react\.development\.js",  "Framework", "React",         []),
    (r"vue\.runtime|__vue_store__",             "Framework", "Vue.js",        []),
    (r"ember\.js|Ember\.VERSION",               "Framework", "Ember.js",      []),

    # Backend frameworks
    (r"Laravel\b|laravel_session",              "Framework", "Laravel/PHP",   []),
    (r"csrfmiddlewaretoken|Django",             "Framework", "Django",        []),
    (r"authenticity_token.*Rails|rails\.js",    "Framework", "Ruby on Rails", []),
    (r"__FLASK_|flask_wtf",                     "Framework", "Flask",         []),

    # Analytics / tracking
    (r"google-analytics\.com/ga\.js|gtag\(",    "Analytics", "Google Analytics", []),
    (r"static\.hotjar\.com",                    "Analytics", "Hotjar",        []),
    (r"connect\.facebook\.net",                 "Analytics", "Facebook Pixel",[]),
    (r"cdn\.segment\.com",                      "Analytics", "Segment",       []),

    # Cloud / hosting
    (r"amazonaws\.com",                         "Cloud",     "Amazon AWS S3/CloudFront", []),
    (r"azurewebsites\.net|azure\.com",          "Cloud",     "Microsoft Azure",[]),
    (r"googleusercontent\.com",                 "Cloud",     "Google Cloud",  []),
    (r"pages\.github\.io|github\.io",           "Hosting",   "GitHub Pages",  []),
    (r"netlify\.app",                           "Hosting",   "Netlify",       []),

    # Security issues in HTML
    (r"<!--.*password|<!--.*secret|<!--.*api.?key", "Finding", "Sensitive Data in HTML Comments", []),
    (r"\.env\b",                                "Finding",   "Possible .env Reference", []),
]

# Cookie name patterns → Technology
COOKIE_SIGNATURES = [
    (r"PHPSESSID",              "Language",  "PHP"),
    (r"JSESSIONID",             "Framework", "Java/Tomcat"),
    (r"ASP\.NET_SessionId|\.ASPXAUTH", "Framework", "ASP.NET"),
    (r"laravel_session",        "Framework", "Laravel"),
    (r"django_language|csrftoken", "Framework", "Django"),
    (r"_rails_session",         "Framework", "Ruby on Rails"),
    (r"wordpress_logged_in|wp-settings", "CMS", "WordPress"),
    (r"shopify_session",        "CMS",       "Shopify"),
    (r"_ga\b|_gid\b",           "Analytics", "Google Analytics"),
    (r"__stripe",               "Payment",   "Stripe"),
]

# WAF signatures — detected via headers and error responses
WAF_SIGNATURES = {
    "Cloudflare WAF": {
        "headers": {"server": r"cloudflare", "cf-ray": r".*"},
        "body":    r"Attention Required!.*Cloudflare|cloudflare-nginx|Ray ID:",
        "status":  [403, 503],
    },
    "AWS WAF": {
        "headers": {"x-amzn-requestid": r".*", "x-amzn-trace-id": r".*"},
        "body":    r"<\?xml.*RequestId|AWS WAF",
        "status":  [403],
    },
    "Imperva / Incapsula": {
        "headers": {"x-iinfo": r".*", "x-cdn": r"Imperva"},
        "body":    r"incapsula incident id|_Incapsula_Resource",
        "status":  [403],
    },
    "Akamai": {
        "headers": {"x-akamai-transformed": r".*", "x-check-cacheable": r".*"},
        "body":    r"Reference #\d+\.\d+\.\d+|AkamaiGHost",
        "status":  [403],
    },
    "Sucuri": {
        "headers": {"x-sucuri-id": r".*", "x-sucuri-cache": r".*"},
        "body":    r"Sucuri Website Firewall|Access Denied - Sucuri",
        "status":  [403],
    },
    "ModSecurity": {
        "headers": {"server": r"mod_security|ModSecurity"},
        "body":    r"ModSecurity|This error was generated by Mod_Security",
        "status":  [403, 406],
    },
    "F5 BIG-IP ASM": {
        "headers": {"x-cnection": r".*", "server": r"BigIP"},
        "body":    r"The requested URL was rejected|F5 Networks",
        "status":  [403],
    },
    "Barracuda WAF": {
        "headers": {"server": r"BarracudaHTTP"},
        "body":    r"barracuda|You have been blocked",
        "status":  [403],
    },
    "Fastly WAF": {
        "headers": {"x-fastly-request-id": r".*"},
        "body":    r"Fastly error: unknown domain",
        "status":  [403],
    },
    "Wordfence": {
        "headers": {},
        "body":    r"generated by Wordfence|wordfence",
        "status":  [403],
    },
}

# WAF bypass notes per product
WAF_BYPASS_NOTES = {
    "Cloudflare WAF":    "Try: case variation, Unicode encoding, chunked transfer encoding",
    "ModSecurity":       "Try: HPP, multipart bypass, comment injection in SQL",
    "AWS WAF":           "Try: JSON unicode escapes, unusual Content-Type headers",
    "Imperva / Incapsula":"Try: IP rotation, slow POST, HTTP/2 smuggling",
    "Wordfence":         "WordPress-specific — try xmlrpc.php brute force bypass",
}


# ─── HTTP Fetcher ────────────────────────────────────────────────────────────

def _fetch(url: str, payload: str = None, timeout: float = 8.0) -> tuple[dict, str, int]:
    """Returns (headers, body, status_code)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    data = payload.encode() if payload else None
    req = urllib.request.Request(url, data=data, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
        "Accept-Language": "en-US,en;q=0.5",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(65536).decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in dict(resp.headers).items()}
            return headers, body, resp.status
    except urllib.error.HTTPError as e:
        try:
            body = e.read(16384).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        headers = {k.lower(): v for k, v in dict(e.headers).items()} if e.headers else {}
        return headers, body, e.code
    except Exception:
        return {}, "", 0


# ─── WAF Detection ────────────────────────────────────────────────────────────

def detect_waf(target: str, headers: dict, body: str, status: int, scheme: str = "https") -> WAFDetection:
    """
    First check normal response headers/body, then probe with a
    malicious-looking payload to trigger WAF block pages.
    """
    result = WAFDetection()

    # Phase 1: passive detection from normal response
    for waf_name, sig in WAF_SIGNATURES.items():
        matched = []
        for hdr, pattern in sig.get("headers", {}).items():
            if hdr in headers and re.search(pattern, headers[hdr], re.IGNORECASE):
                matched.append(f"header {hdr}")
        if sig.get("body") and re.search(sig["body"], body, re.IGNORECASE):
            matched.append("body fingerprint")
        if matched:
            result.detected = True
            result.name = waf_name
            result.confidence = "HIGH"
            result.evidence = "Passive: " + ", ".join(matched)
            result.bypass_notes = WAF_BYPASS_NOTES.get(waf_name, "")
            return result

    # Phase 2: active probe — send XSS/SQLi payload, check for block
    probe_url = f"{scheme}://{target}/?id=1'%20OR%20'1'='1&q=<script>alert(1)</script>"
    ph, pb, ps = _fetch(probe_url, timeout=5)
    all_headers = {**headers, **ph}
    combined_body = body + pb

    for waf_name, sig in WAF_SIGNATURES.items():
        matched = []
        for hdr, pattern in sig.get("headers", {}).items():
            if hdr in all_headers and re.search(pattern, all_headers[hdr], re.IGNORECASE):
                matched.append(f"header {hdr}")
        if sig.get("body") and re.search(sig["body"], combined_body, re.IGNORECASE):
            matched.append("block page fingerprint")
        if ps in sig.get("status", []) and matched:
            result.detected = True
            result.name = waf_name
            result.confidence = "MEDIUM"
            result.evidence = "Active probe: " + ", ".join(matched)
            result.bypass_notes = WAF_BYPASS_NOTES.get(waf_name, "")
            return result

    # Generic WAF detection heuristics
    if ps in (403, 406, 429, 503) and ps != status:
        result.detected = True
        result.name = "Unknown WAF"
        result.confidence = "LOW"
        result.evidence = f"Malicious probe returned HTTP {ps} (normal: {status})"
        return result

    return result


# ─── Technology Detection ─────────────────────────────────────────────────────

def detect_from_headers(headers: dict) -> list[TechFinding]:
    findings = []
    seen = set()

    for header_name, sigs in HEADER_SIGNATURES.items():
        val = headers.get(header_name, "")
        if not val:
            continue
        for pattern, category, name, cves in sigs:
            m = re.search(pattern, val, re.IGNORECASE)
            if m:
                version = m.group(1) if m.lastindex and m.lastindex >= 1 else None
                key = (category, name)
                if key not in seen:
                    seen.add(key)
                    findings.append(TechFinding(
                        category=category, name=name, version=version,
                        confidence="HIGH",
                        evidence=f"{header_name}: {val[:80]}",
                        cves=cves,
                    ))
    return findings


def detect_from_body(body: str) -> list[TechFinding]:
    findings = []
    seen = set()
    for pattern, category, name, cves in BODY_SIGNATURES:
        m = re.search(pattern, body, re.IGNORECASE)
        if m:
            key = (category, name)
            if key not in seen:
                seen.add(key)
                # Try to extract version from nearby text
                version = None
                ver_match = re.search(
                    pattern.split(r"|")[0].rstrip(r"\/\|") + r'[^\d]*([\d]+\.[\d]+(?:\.[\d]+)?)',
                    body, re.IGNORECASE
                )
                if ver_match:
                    try: version = ver_match.group(1)
                    except: pass
                findings.append(TechFinding(
                    category=category, name=name, version=version,
                    confidence="MEDIUM",
                    evidence=f"Body match: {m.group(0)[:60]}",
                    cves=cves,
                    notes="⚠ Sensitive data exposed" if category == "Finding" else "",
                ))
    return findings


def detect_from_cookies(headers: dict) -> list[TechFinding]:
    findings = []
    seen = set()
    cookies = headers.get("set-cookie", "")
    if not cookies:
        return findings
    for pattern, category, name in COOKIE_SIGNATURES:
        if re.search(pattern, cookies, re.IGNORECASE):
            key = (category, name)
            if key not in seen:
                seen.add(key)
                m = re.search(pattern, cookies, re.IGNORECASE)
                findings.append(TechFinding(
                    category=category, name=name,
                    confidence="HIGH",
                    evidence=f"Cookie: {m.group(0) if m else pattern}",
                ))
    return findings


def detect_cdn_cloud(headers: dict, body: str) -> tuple[Optional[str], Optional[str]]:
    """Return (cdn_name, cloud_provider)."""
    cdn = None
    cloud = None

    cdn_patterns = {
        "Cloudflare":        r"cloudflare|cf-ray",
        "Amazon CloudFront": r"cloudfront|x-amz-cf",
        "Fastly":            r"fastly",
        "Akamai":            r"akamai|x-akamai",
        "Varnish":           r"varnish",
        "Sucuri":            r"sucuri",
    }
    cloud_patterns = {
        "Amazon AWS":        r"amazonaws|aws-",
        "Microsoft Azure":   r"azure|x-ms-",
        "Google Cloud":      r"google|x-goog",
        "Vercel":            r"vercel",
        "Netlify":           r"netlify",
        "Heroku":            r"heroku",
    }

    all_text = " ".join(headers.values()) + " " + body[:4096]
    for name, pattern in cdn_patterns.items():
        if re.search(pattern, all_text, re.IGNORECASE):
            cdn = name
            break
    for name, pattern in cloud_patterns.items():
        if re.search(pattern, all_text, re.IGNORECASE):
            cloud = name
            break

    return cdn, cloud


# ─── WordPress Deep Scan ─────────────────────────────────────────────────────

def wordpress_deep_scan(target: str) -> list[TechFinding]:
    """Extra checks specifically for WordPress sites."""
    findings = []
    checks = [
        ("/wp-login.php",         "WordPress login page exposed"),
        ("/wp-json/wp/v2/users",  "WordPress REST API user enumeration"),
        ("/xmlrpc.php",           "WordPress XML-RPC enabled (brute force vector)"),
        ("/.env",                 "Environment file exposed"),
        ("/wp-config.php.bak",    "WordPress config backup exposed"),
        ("/readme.html",          "WordPress readme.html exposes version"),
    ]
    for path, description in checks:
        url = f"https://{target}{path}"
        _, body, status = _fetch(url, timeout=5)
        if status in (200, 301, 302):
            sev_note = "⚠ HIGH RISK" if "config" in path or ".env" in path else "ℹ INFO"
            findings.append(TechFinding(
                category="CMS",
                name=f"WordPress: {description}",
                confidence="HIGH" if status == 200 else "MEDIUM",
                evidence=f"HTTP {status} at {path}",
                notes=sev_note,
                cves=["CVE-2017-5487"] if "users" in path else [],
            ))
    return findings


# ─── Main Fingerprinter ──────────────────────────────────────────────────────

def fingerprint_stack(target: str, port: int = 443) -> StackResult:
    result = StackResult(target=target)
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{target}/"
    actual_scheme = scheme

    # Fetch main page
    headers, body, status = _fetch(url)
    if not headers and scheme == "https":
        headers, body, status = _fetch(f"http://{target}/")
        actual_scheme = "http"

    if not headers:
        return result

    # Detect technologies
    techs = []
    techs.extend(detect_from_headers(headers))
    techs.extend(detect_from_body(body))
    techs.extend(detect_from_cookies(headers))

    # Deduplicate
    seen = set()
    for t in techs:
        key = (t.category, t.name)
        if key not in seen:
            seen.add(key)
            result.technologies.append(t)

    # CDN / Cloud
    result.cdn, result.cloud_provider = detect_cdn_cloud(headers, body)

    # WAF
    result.waf = detect_waf(target, headers, body, status, actual_scheme)

    # WordPress extra checks
    is_wp = any(t.name == "WordPress" for t in result.technologies)
    if is_wp:
        result.technologies.extend(wordpress_deep_scan(target))

    return result