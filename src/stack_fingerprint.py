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
import urllib.request
import urllib.error
import re
from dataclasses import dataclass, field
from typing import Optional


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
        (r"cloudfront",  "CDN",   "Amazon CloudFront", []),
        (r"varnish",     "Cache", "Varnish Cache", []),
        # NOTE: bare "HIT"/"MISS" is emitted by many origin-side caches and is
        # NOT proof of a CDN, so it is intentionally not matched here to avoid
        # a "Generic CDN/Cache" false positive on every cached page.
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

# WAF signatures — detected via headers and error responses.
#
# PRECISION: each signature distinguishes *strong* headers (genuinely
# WAF/product-specific — their mere presence is real evidence the security
# product is in path) from *weak* headers listed in "routing_headers". Weak
# headers are generic routing/caching IDs that ride on EVERY response from the
# underlying CDN/cloud regardless of whether a WAF is enabled (e.g.
# x-amzn-requestid on any AWS response, x-fastly-request-id on any Fastly
# response, cf-ray on any Cloudflare-fronted page, x-akamai-transformed /
# x-check-cacheable caching hints). A WAF must NEVER be named from
# routing-header evidence alone — that wrongly flags every CDN-fronted site.
# Naming a WAF requires a body block-page fingerprint OR a strong header.
WAF_SIGNATURES = {
    "Cloudflare WAF": {
        "headers": {"server": r"cloudflare", "cf-ray": r".*"},
        "routing_headers": {"server", "cf-ray"},  # both are plain CDN routing
        "body":    r"Attention Required!.*Cloudflare|cloudflare-nginx|Ray ID:",
        "status":  [403, 503],
    },
    "AWS WAF": {
        "headers": {"x-amzn-requestid": r".*", "x-amzn-trace-id": r".*"},
        "routing_headers": {"x-amzn-requestid", "x-amzn-trace-id"},  # normal AWS IDs
        "body":    r"<\?xml.*RequestId|AWS WAF",
        "status":  [403],
    },
    "Imperva / Incapsula": {
        "headers": {"x-iinfo": r".*", "x-cdn": r"Imperva"},
        "routing_headers": set(),  # x-iinfo / x-cdn:Imperva are Imperva-specific
        "body":    r"incapsula incident id|_Incapsula_Resource",
        "status":  [403],
    },
    "Akamai": {
        "headers": {"x-akamai-transformed": r".*", "x-check-cacheable": r".*"},
        "routing_headers": {"x-akamai-transformed", "x-check-cacheable"},  # caching hints
        "body":    r"Reference #\d+\.\d+\.\d+|AkamaiGHost",
        "status":  [403],
    },
    "Sucuri": {
        "headers": {"x-sucuri-id": r".*", "x-sucuri-cache": r".*"},
        "routing_headers": set(),  # both headers are Sucuri-product-specific
        "body":    r"Sucuri Website Firewall|Access Denied - Sucuri",
        "status":  [403],
    },
    "ModSecurity": {
        "headers": {"server": r"mod_security|ModSecurity"},
        "routing_headers": set(),  # server token explicitly names ModSecurity
        "body":    r"ModSecurity|This error was generated by Mod_Security",
        "status":  [403, 406],
    },
    "F5 BIG-IP ASM": {
        "headers": {"x-cnection": r".*", "server": r"BigIP"},
        "routing_headers": {"x-cnection"},  # x-cnection is a generic F5 quirk
        "body":    r"The requested URL was rejected|F5 Networks",
        "status":  [403],
    },
    "Barracuda WAF": {
        "headers": {"server": r"BarracudaHTTP"},
        "routing_headers": set(),  # server token names Barracuda
        "body":    r"barracuda|You have been blocked",
        "status":  [403],
    },
    "Fastly WAF": {
        "headers": {"x-fastly-request-id": r".*"},
        "routing_headers": {"x-fastly-request-id"},  # present on every Fastly resp
        "body":    r"Fastly error: unknown domain",
        "status":  [403],
    },
    "Wordfence": {
        "headers": {},
        "routing_headers": set(),
        "body":    r"generated by Wordfence|wordfence",
        "status":  [403],
    },
    # Vercel bot protection / attack challenge — product-specific headers.
    # x-vercel-id alone is routing (CDN); x-vercel-mitigated=challenge proves
    # the bot/WAF layer is actively intercepting the request.
    "Vercel Bot Protection": {
        "headers": {
            "x-vercel-mitigated": r"challenge",
            "x-vercel-challenge-token": r".+",
            "x-vercel-id": r".+",
        },
        "routing_headers": {"x-vercel-id"},
        "body":    r"vercel.*challenge|Security Checkpoint|_vercel_challenge",
        "status":  [401, 403],
    },
}

# WAF bypass notes per product
WAF_BYPASS_NOTES = {
    "Vercel Bot Protection": "JS challenge blocks non-browser clients; allowlist scanner IPs "
                             "in Vercel firewall or supply a browser session for app analysis",
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
            headers = _flatten_headers(resp.headers)
            return headers, body, resp.status
    except urllib.error.HTTPError as e:
        try:
            body = e.read(16384).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        headers = _flatten_headers(e.headers) if e.headers else {}
        return headers, body, e.code
    except Exception:
        return {}, "", 0


def _host_for_url(target: str) -> str:
    """Bracket a bare IPv6 literal so it is a valid URL authority.
    A hostname or IPv4 address is returned unchanged; an already-bracketed
    address is left as-is."""
    if ":" in target and not target.startswith("["):
        return f"[{target}]"
    return target


def _flatten_headers(msg) -> dict:
    """Lower-case header dict. Multi-valued headers (notably Set-Cookie, which
    arrives as several distinct header lines) are joined so none are lost — a
    plain dict() over the message would keep only the first occurrence."""
    out: dict[str, str] = {}
    try:
        items = msg.items()
    except Exception:
        return {k.lower(): v for k, v in dict(msg).items()}
    for k, v in items:
        kl = k.lower()
        if kl in out:
            out[kl] = out[kl] + "\n" + v
        else:
            out[kl] = v
    return out


# ─── WAF Detection ────────────────────────────────────────────────────────────

def detect_waf(target: str, headers: dict, body: str, status: int, scheme: str = "https", port: int = 443) -> WAFDetection:
    """
    First check normal response headers/body, then probe with a
    malicious-looking payload to trigger WAF block pages.
    """
    result = WAFDetection()

    # Phase 1: passive detection from normal response.
    #
    # PRECISION: the mere presence of a CDN/edge routing header (cf-ray,
    # x-fastly-request-id, x-check-cacheable, server: cloudflare, ...) only
    # proves the site sits *behind* that provider — it does NOT prove a WAF is
    # active. A huge fraction of the web is fronted by Cloudflare/Fastly/Akamai
    # without their WAF product enabled. To avoid asserting "WAF detected" on
    # every CDN-fronted site, a passive HIGH-confidence match requires a WAF
    # block-page *body* fingerprint. Header-only signals are reported at MEDIUM
    # and only when at least two independent product headers are present (a
    # single generic caching header is not enough).
    for waf_name, sig in WAF_SIGNATURES.items():
        routing = sig.get("routing_headers", set())
        header_hits = []        # all matching headers (for evidence text)
        strong_hits = []        # matching headers that are NOT mere routing IDs
        for hdr, pattern in sig.get("headers", {}).items():
            if hdr in headers and re.search(pattern, headers[hdr], re.IGNORECASE):
                header_hits.append(f"header {hdr}")
                if hdr not in routing:
                    strong_hits.append(f"header {hdr}")
        body_hit = bool(sig.get("body")) and bool(re.search(sig["body"], body, re.IGNORECASE))

        if body_hit:
            # A block-page fingerprint in the body is strong, specific evidence.
            ev = ["body fingerprint"] + header_hits
            result.detected = True
            result.name = waf_name
            result.confidence = "HIGH"
            result.evidence = "Passive: " + ", ".join(ev)
            result.bypass_notes = WAF_BYPASS_NOTES.get(waf_name, "")
            return result
        # A WAF may only be NAMED passively when there is at least one
        # product-specific (strong) header. Routing/caching IDs (cf-ray,
        # x-amzn-requestid, x-fastly-request-id, x-akamai-* ...) are NOT WAF
        # evidence — they ride on every CDN-fronted response. Requiring a strong
        # header here stops "AWS WAF"/"Akamai"/"Fastly WAF"/"Cloudflare WAF"
        # being asserted on plain CDN-fronted sites with no WAF enabled.
        if strong_hits and not result.detected:
            # Product-specific header(s) present, but without a block page we
            # can't be certain the WAF is actively filtering. Report at MEDIUM
            # and keep scanning for a stronger (body) match on another product.
            result.detected = True
            result.name = waf_name
            result.confidence = "MEDIUM"
            result.evidence = "Passive (headers only): " + ", ".join(header_hits)
            result.bypass_notes = WAF_BYPASS_NOTES.get(waf_name, "")

    if result.detected:
        return result

    # Phase 2: active probe — send XSS/SQLi payload, check for block
    _t = _host_for_url(target)
    probe_url = _make_url(scheme, _t, port, "/?id=1'%20OR%20'1'='1&q=<script>alert(1)</script>")
    ph, pb, ps = _fetch(probe_url, timeout=5)
    all_headers = {**headers, **ph}
    combined_body = body + pb

    for waf_name, sig in WAF_SIGNATURES.items():
        routing = sig.get("routing_headers", set())
        matched = []
        strong = []   # evidence that genuinely fingerprints THIS WAF product
        for hdr, pattern in sig.get("headers", {}).items():
            if hdr in all_headers and re.search(pattern, all_headers[hdr], re.IGNORECASE):
                matched.append(f"header {hdr}")
                if hdr not in routing:
                    strong.append(f"header {hdr}")
        if sig.get("body") and re.search(sig["body"], combined_body, re.IGNORECASE):
            matched.append("block page fingerprint")
            strong.append("block page fingerprint")
        # A block status alone is not enough to NAME a product: a generic 403 on
        # a CDN-fronted site carries that CDN's routing headers, which would
        # otherwise mis-name e.g. "Fastly WAF" or "AWS WAF". Require a strong
        # (product-specific) signal in addition to the block status. Weak
        # routing-only matches fall through to the generic "Unknown WAF" path.
        if ps in sig.get("status", []) and strong:
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
                # PRECISION: only report a version when the signature pattern
                # itself captured one (a real parsed group). The previous
                # heuristic synthesised a throw-away regex from the signature
                # and scanned for any "N.N" nearby, which fabricated bogus
                # versions from unrelated numbers on the page.
                version = m.group(1) if (m.lastindex and m.lastindex >= 1) else None
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

    # PRECISION: CDN/cloud attribution is driven by *headers*, which are
    # authoritative routing evidence, plus a small set of unambiguous header
    # *names* that only a given provider emits. We deliberately do NOT scan the
    # HTML body for words like "google", "azure" or "vercel": a page that merely
    # links to Google Fonts, an Azure blob, or embeds a Vercel-hosted widget
    # must not be reported as *hosted on* that provider. Bare-substring body
    # matching here was a major false-positive source.

    # Provider-exclusive header names (presence alone is strong evidence).
    cdn_header_names = {
        "Cloudflare":        ("cf-ray", "cf-cache-status"),
        "Amazon CloudFront": ("x-amz-cf-id", "x-amz-cf-pop"),
        "Fastly":            ("x-fastly-request-id", "fastly-debug-digest"),
        "Akamai":            ("x-akamai-transformed", "akamai-grn"),
        "Sucuri":            ("x-sucuri-id", "x-sucuri-cache"),
    }
    cloud_header_names = {
        "Microsoft Azure":   ("x-azure-ref", "x-msedge-ref"),
        "Google Cloud":      ("x-goog-backend-server", "x-goog-generation"),
        "Vercel":            ("x-vercel-id", "x-vercel-cache"),
    }

    # Header *value* patterns, matched only against the relevant header values
    # (not the whole page), with anchored/specific tokens.
    server_val = headers.get("server", "")
    via_val = headers.get("via", "")
    xcache_val = headers.get("x-cache", "")
    powered = headers.get("x-powered-by", "")
    routing_text = " ".join([server_val, via_val, xcache_val,
                             headers.get("x-cdn", ""), headers.get("x-served-by", "")])

    cdn_val_patterns = {
        "Cloudflare":        r"\bcloudflare\b",
        "Amazon CloudFront": r"\bcloudfront\b",
        "Fastly":            r"\bfastly\b",
        "Akamai":            r"akamaighost|\bakamai\b",
        "Varnish":           r"\bvarnish\b",
        "Sucuri":            r"\bsucuri\b",
    }
    cloud_val_patterns = {
        "Amazon AWS":        r"\bamaz[ao]ws?\b|\baws\b",
        "Microsoft Azure":   r"\bazure\b",
        "Heroku":            r"\bheroku\b",
        "Vercel":            r"\bvercel\b",
        "Netlify":           r"\bnetlify\b",
    }

    for name, hdr_names in cdn_header_names.items():
        if any(h in headers for h in hdr_names):
            cdn = name
            break
    if cdn is None:
        for name, pattern in cdn_val_patterns.items():
            if routing_text and re.search(pattern, routing_text, re.IGNORECASE):
                cdn = name
                break

    for name, hdr_names in cloud_header_names.items():
        if any(h in headers for h in hdr_names):
            cloud = name
            break
    if cloud is None:
        cloud_text = " ".join([server_val, via_val, powered,
                               headers.get("x-served-by", "")])
        for name, pattern in cloud_val_patterns.items():
            if cloud_text and re.search(pattern, cloud_text, re.IGNORECASE):
                cloud = name
                break

    return cdn, cloud


# ─── WordPress Deep Scan ─────────────────────────────────────────────────────

def wordpress_deep_scan(target: str, scheme: str = "https", port: int = 443) -> list[TechFinding]:
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
    host = _host_for_url(target)
    for path, description in checks:
        url = _make_url(scheme, host, port, path)
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


# ─── URL Builder ─────────────────────────────────────────────────────────────

def _make_url(scheme: str, host: str, port: int, path: str = "/") -> str:
    """Build a URL, only including port when it is non-default."""
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        return f"{scheme}://{host}{path}"
    return f"{scheme}://{host}:{port}{path}"


# ─── Main Fingerprinter ──────────────────────────────────────────────────────

def fingerprint_stack(target: str, port: int = 443) -> StackResult:
    result = StackResult(target=target)
    scheme = "https" if port in (443, 8443) else "http"
    host = _host_for_url(target)
    url = _make_url(scheme, host, port)
    actual_scheme = scheme

    # Fetch main page
    headers, body, status = _fetch(url)
    if not headers and scheme == "https":
        headers, body, status = _fetch(_make_url("http", host, port))
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
    result.waf = detect_waf(target, headers, body, status, actual_scheme, port)

    # WordPress extra checks
    is_wp = any(t.name == "WordPress" for t in result.technologies)
    if is_wp:
        result.technologies.extend(wordpress_deep_scan(target, scheme=actual_scheme, port=port))

    return result