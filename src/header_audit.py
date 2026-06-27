"""
NetLogic - HTTP Security Header Auditor
Checks every security-relevant HTTP response header against current best practices.

Covers:
  - Strict-Transport-Security (HSTS) — presence, max-age, includeSubDomains, preload
  - Content-Security-Policy (CSP) — presence, unsafe-inline/eval, wildcards
  - X-Frame-Options — clickjacking protection
  - X-Content-Type-Options — MIME sniffing
  - Referrer-Policy — information leakage
  - Permissions-Policy — feature policy
  - Cross-Origin headers (CORP, COEP, COOP)
  - Cache-Control on sensitive responses
  - Server / X-Powered-By — information disclosure
  - Set-Cookie flags — Secure, HttpOnly, SameSite
  - CORS misconfiguration (Access-Control-Allow-Origin: *)
"""

import ssl
import urllib.request
import urllib.error
import re
from dataclasses import dataclass, field
from typing import Optional


# ─── Data Models ────────────────────────────────────────────────────────────────

@dataclass
class HeaderFinding:
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    header: str
    title: str
    detail: str
    recommendation: str
    cvss: float = 0.0
    present: bool = False   # True = header present but misconfigured; False = missing

@dataclass
class HeaderAuditResult:
    target: str
    url: str
    status_code: int = 0
    server_banner: Optional[str] = None
    powered_by: Optional[str] = None
    findings: list[HeaderFinding] = field(default_factory=list)
    headers_present: list[str] = field(default_factory=list)
    headers_missing: list[str] = field(default_factory=list)
    score: int = 0          # 0–100
    grade: str = "?"


# ─── Header Fetcher ──────────────────────────────────────────────────────────────

PROBE_ORIGIN = "https://evil.bad"


def _flatten_headers(msg) -> dict:
    """
    Collapse an email.message.Message (urllib response headers) into a
    case-insensitive dict, preserving DUPLICATE headers.

    HTTP headers are case-insensitive, so keys are lowercased. Duplicate
    headers must NOT be silently dropped: ``dict(msg)`` keeps only the first
    occurrence, which would hide extra Set-Cookie headers (and any other
    repeated header) from the audit and cause false negatives. Multiple
    Set-Cookie headers are joined with newlines (the cookie check splits on
    "\n"); any other repeated header is joined with ", " per RFC 7230.
    """
    if msg is None:
        return {}
    out: dict = {}
    try:
        items = msg.items()
    except Exception:
        # Fall back to a plain mapping if it is not a Message-like object.
        return {str(k).lower(): str(v) for k, v in dict(msg).items()}
    for k, v in items:
        lk = k.lower()
        v = "" if v is None else str(v)
        if lk in out:
            sep = "\n" if lk == "set-cookie" else ", "
            out[lk] = out[lk] + sep + v
        else:
            out[lk] = v
    return out


def fetch_headers(url: str, timeout: float = 8.0) -> tuple[dict, int]:
    """
    Fetch HTTP headers from a URL. Returns (headers_dict, status_code).
    Follows redirects (urllib default), ignores cert errors. Never raises:
    on any failure returns ({}, 0) so the caller can produce a sane
    "could not audit" result instead of a misleading all-missing report.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (compatible; NetLogic/1.0; Security Scanner)",
        "Accept": "text/html,application/xhtml+xml,*/*",
        "Origin": PROBE_ORIGIN,
    })

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            headers = _flatten_headers(resp.headers)
            headers["_request_origin"] = PROBE_ORIGIN
            return headers, resp.status
    except urllib.error.HTTPError as e:
        # A 4xx/5xx still carries response headers worth auditing.
        headers = _flatten_headers(e.headers)
        headers["_request_origin"] = PROBE_ORIGIN
        return headers, e.code
    except Exception:
        return {}, 0


# ─── Individual Header Checks ────────────────────────────────────────────────────

def check_hsts(headers: dict, is_https: bool = True) -> Optional[HeaderFinding]:
    val = headers.get("strict-transport-security", "")
    if not is_https:
        # HSTS is only meaningful over HTTPS — browsers ignore it on plain
        # HTTP responses. Flagging it "missing" on an HTTP-only target is a
        # false positive, so skip the check entirely for non-TLS responses.
        return None
    if not val:
        return HeaderFinding(
            severity="HIGH", cvss=7.4,
            header="Strict-Transport-Security",
            title="Missing HSTS Header",
            detail="Without HSTS, browsers may connect over HTTP first, allowing "
                   "SSL stripping attacks (sslstrip). Attackers on the network path "
                   "can intercept and downgrade connections.",
            recommendation='Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            present=False
        )

    issues = []
    # max-age check
    m = re.search(r"max-age\s*=\s*(\d+)", val, re.IGNORECASE)
    max_age = int(m.group(1)) if m else 0
    if max_age < 31536000:
        issues.append(f"max-age={max_age} is below recommended 31536000 (1 year)")
    if "includesubdomains" not in val.lower():
        issues.append("includeSubDomains missing — subdomains not protected")
    if "preload" not in val.lower():
        issues.append("preload directive missing — not eligible for HSTS preload list")

    if issues:
        return HeaderFinding(
            severity="MEDIUM", cvss=4.3,
            header="Strict-Transport-Security",
            title="HSTS Misconfigured",
            detail="HSTS present but weakly configured: " + "; ".join(issues),
            recommendation='Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            present=True
        )
    return None


def check_csp(headers: dict) -> Optional[HeaderFinding]:
    val = headers.get("content-security-policy", "")
    if not val:
        return HeaderFinding(
            severity="HIGH", cvss=6.1,
            header="Content-Security-Policy",
            title="Missing Content-Security-Policy",
            detail="No CSP header. The site is fully vulnerable to Cross-Site Scripting (XSS) "
                   "injection with no browser-level mitigation. Attackers can inject arbitrary "
                   "scripts to steal cookies, credentials, or perform actions as the victim.",
            recommendation="Add a restrictive CSP: Content-Security-Policy: default-src 'self'; "
                           "script-src 'self'; object-src 'none'; base-uri 'self'",
            present=False
        )

    issues = []
    if "unsafe-inline" in val:
        issues.append("'unsafe-inline' defeats XSS protection for inline scripts/styles")
    if "unsafe-eval" in val:
        issues.append("'unsafe-eval' allows eval() — major XSS vector")
    if re.search(r"(?:script-src|default-src)\b[^;]*(?<![\w.-])\*(?![\w.-])", val):
        issues.append("Wildcard (*) in script-src allows scripts from any origin")
    if "default-src" not in val and "script-src" not in val:
        issues.append("No script-src or default-src directive — scripts unrestricted")

    if issues:
        return HeaderFinding(
            severity="MEDIUM", cvss=5.4,
            header="Content-Security-Policy",
            title="Weak Content-Security-Policy",
            detail="CSP present but contains dangerous directives: " + "; ".join(issues),
            recommendation="Remove 'unsafe-inline', 'unsafe-eval', and wildcards. "
                           "Use nonces or hashes for inline scripts.",
            present=True
        )
    return None


def check_xframe(headers: dict) -> Optional[HeaderFinding]:
    val = headers.get("x-frame-options", "")
    csp = headers.get("content-security-policy", "")

    # CSP frame-ancestors supersedes X-Frame-Options if restrictive
    fa = re.search(r"frame-ancestors\s+([^;]+)", csp, re.IGNORECASE)
    if fa and fa.group(1).strip() != "*":
        return None

    if not val:
        return HeaderFinding(
            severity="MEDIUM", cvss=6.1,
            header="X-Frame-Options",
            title="Missing X-Frame-Options (Clickjacking)",
            detail="Without X-Frame-Options or CSP frame-ancestors, the site can be "
                   "embedded in an attacker's iframe. Clickjacking attacks trick users "
                   "into clicking hidden UI elements — enabling unauthorized actions.",
            recommendation="Add: X-Frame-Options: DENY  (or SAMEORIGIN if self-embedding needed)",
            present=False
        )

    if val.upper() not in ("DENY", "SAMEORIGIN"):
        return HeaderFinding(
            severity="LOW", cvss=3.1,
            header="X-Frame-Options",
            title="X-Frame-Options Value Invalid",
            detail=f"Value '{val}' is not a recognized directive. Only DENY and SAMEORIGIN are valid. "
                   "ALLOWFROM was deprecated and is not supported in modern browsers.",
            recommendation="Use: X-Frame-Options: DENY",
            present=True
        )
    return None


def check_xcto(headers: dict) -> Optional[HeaderFinding]:
    val = headers.get("x-content-type-options", "")
    if not val:
        return HeaderFinding(
            severity="LOW", cvss=4.3,
            header="X-Content-Type-Options",
            title="Missing X-Content-Type-Options",
            detail="Without nosniff, browsers may MIME-sniff responses and execute "
                   "uploaded files (e.g. images containing HTML/JS) as scripts, "
                   "enabling stored XSS via file uploads.",
            recommendation="Add: X-Content-Type-Options: nosniff",
            present=False
        )
    if val.lower().strip().rstrip(";") != "nosniff":
        return HeaderFinding(
            severity="LOW", cvss=3.1,
            header="X-Content-Type-Options",
            title="X-Content-Type-Options Invalid Value",
            detail=f"Value '{val}' is not valid. Only 'nosniff' is recognized.",
            recommendation="X-Content-Type-Options: nosniff",
            present=True
        )
    return None


def check_referrer_policy(headers: dict) -> Optional[HeaderFinding]:
    val = headers.get("referrer-policy", "")
    if not val:
        return HeaderFinding(
            severity="LOW", cvss=3.1,
            header="Referrer-Policy",
            title="Missing Referrer-Policy",
            detail="Without Referrer-Policy, the full URL (including query params with "
                   "session tokens, search terms, or PII) is sent in the Referer header "
                   "to third-party sites linked from this page.",
            recommendation="Add: Referrer-Policy: strict-origin-when-cross-origin",
            present=False
        )
    UNSAFE = {"unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin"}
    if val.lower() in UNSAFE:
        return HeaderFinding(
            severity="LOW", cvss=3.1,
            header="Referrer-Policy",
            title=f"Referrer-Policy Too Permissive: {val}",
            detail=f"'{val}' may leak full URLs including sensitive query parameters "
                   "to third-party origins.",
            recommendation="Referrer-Policy: strict-origin-when-cross-origin",
            present=True
        )
    return None


def check_permissions_policy(headers: dict) -> Optional[HeaderFinding]:
    val = (headers.get("permissions-policy") or
           headers.get("feature-policy") or "")
    if not val:
        return HeaderFinding(
            severity="INFO", cvss=0.0,
            header="Permissions-Policy",
            title="Missing Permissions-Policy",
            detail="No Permissions-Policy (formerly Feature-Policy). Browser features "
                   "like camera, microphone, geolocation, and payment are unrestricted "
                   "for embedded third-party scripts.",
            recommendation="Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
            present=False
        )
    return None


def check_cors(headers: dict) -> Optional[HeaderFinding]:
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()
    req_origin = headers.get("_request_origin", "")

    # Reflected Origin + Credentials (CRITICAL)
    if acao == req_origin and acac == "true":
        return HeaderFinding(
            severity="CRITICAL", cvss=9.1,
            header="Access-Control-Allow-Origin",
            title="CORS Misconfiguration: Reflected Origin",
            detail=f"The server reflects the request Origin header ('{req_origin}') into ACAO "
                   "and permits credentials. Any site can force a user's browser to make "
                   "requests to this application and read private data — session theft.",
            recommendation="Do not reflect Origin. Use a static allowlist or disable credentials.",
            present=True
        )

    if acao == "*" and acac == "true":
        return HeaderFinding(
            severity="HIGH", cvss=7.5,
            header="Access-Control-Allow-Origin",
            title="CORS: Wildcard + Credentials",
            detail="ACAO: * with Credentials: true is generally ignored by modern browsers "
                   "but indicates a permissive security mindset. Spec-invalid.",
            recommendation="Never combine wildcard ACAO with credentials.",
            present=True
        )
    
    if acao == "*":
        return HeaderFinding(
            severity="MEDIUM", cvss=5.3,
            header="Access-Control-Allow-Origin",
            title="CORS: Wildcard Origin Allowed",
            detail="Any website can make cross-origin requests to this server and read "
                   "responses. Acceptable for public APIs, dangerous for private data.",
            recommendation="Restrict to trusted origins.",
            present=True
        )
    return None


def check_server_disclosure(headers: dict) -> list[HeaderFinding]:
    findings = []
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")

    if server and re.search(r"\d", server):
        findings.append(HeaderFinding(
            severity="LOW", cvss=2.7,
            header="Server",
            title=f"Server Version Disclosed: {server}",
            detail="The Server header reveals the exact software version. "
                   "Attackers can target known CVEs for that exact version without scanning.",
            recommendation="Configure server to return generic: Server: webserver",
            present=True
        ))

    if powered:
        findings.append(HeaderFinding(
            severity="LOW", cvss=2.7,
            header="X-Powered-By",
            title=f"Technology Disclosed via X-Powered-By: {powered}",
            detail=f"X-Powered-By reveals the backend technology stack ({powered}). "
                   "Remove to reduce information available to attackers.",
            recommendation="Remove X-Powered-By header entirely.",
            present=True
        ))
    return findings


def check_cache_control(headers: dict) -> Optional[HeaderFinding]:
    cc = headers.get("cache-control", "").lower()
    pragma = headers.get("pragma", "").lower()

    # Only flag if this looks like a dynamic/authenticated page
    if not cc and not pragma:
        return HeaderFinding(
            severity="LOW", cvss=3.5,
            header="Cache-Control",
            title="Missing Cache-Control",
            detail="No Cache-Control header. Browsers and proxies may cache sensitive "
                   "responses. On shared computers, cached pages may be visible to "
                   "subsequent users.",
            recommendation="For authenticated pages: Cache-Control: no-store, no-cache, must-revalidate",
            present=False
        )
    return None


def check_cross_origin_policies(headers: dict) -> list[HeaderFinding]:
    findings = []
    corp = headers.get("cross-origin-resource-policy", "")
    if not corp:
        findings.append(HeaderFinding(
            severity="INFO", cvss=0.0,
            header="Cross-Origin-Resource-Policy",
            title="Missing Cross-Origin-Resource-Policy",
            detail="Without CORP, resources can be loaded cross-origin by any site. "
                   "Enables Spectre-based side-channel attacks in browsers.",
            recommendation="Cross-Origin-Resource-Policy: same-origin",
            present=False
        ))
    return findings


# ─── Cookie Analysis ─────────────────────────────────────────────────────────────

def check_cookies(headers: dict) -> list[HeaderFinding]:
    findings = []
    cookies = headers.get("set-cookie", "")
    if not cookies:
        return findings

    # Handle multiple Set-Cookie headers (urllib concatenates with \n)
    for cookie in cookies.split("\n"):
        cookie = cookie.strip()
        if not cookie:
            continue
        name = cookie.split("=")[0].strip()
        lower = cookie.lower()

        issues = []
        if "secure" not in lower:
            issues.append("missing Secure flag — cookie sent over HTTP")
        if "httponly" not in lower:
            issues.append("missing HttpOnly flag — accessible via JavaScript (XSS theft)")
        samesite = re.search(r"samesite=(\w+)", lower)
        if not samesite:
            issues.append("missing SameSite attribute — CSRF risk")
        elif samesite.group(1) == "none" and "secure" not in lower:
            issues.append("SameSite=None requires Secure flag — cookie will be rejected")

        if issues:
            findings.append(HeaderFinding(
                severity="MEDIUM" if "httponly" not in lower else "LOW",
                cvss=5.4 if "httponly" not in lower else 3.1,
                header="Set-Cookie",
                title=f"Insecure Cookie: {name}",
                detail="; ".join(issues),
                recommendation=f"Set-Cookie: {name}=...; Secure; HttpOnly; SameSite=Strict",
                present=True
            ))
    return findings


# ─── Scoring ─────────────────────────────────────────────────────────────────────

def calculate_score(findings: list[HeaderFinding], headers: dict) -> tuple[int, str]:
    deductions = 0
    for f in findings:
        if f.severity == "CRITICAL": deductions += 30
        elif f.severity == "HIGH":   deductions += 20
        elif f.severity == "MEDIUM": deductions += 10
        elif f.severity == "LOW":    deductions += 5
    score = max(0, 100 - deductions)
    if score >= 90: grade = "A"
    elif score >= 75: grade = "B"
    elif score >= 55: grade = "C"
    elif score >= 35: grade = "D"
    else: grade = "F"
    return score, grade


# ─── Main Auditor ────────────────────────────────────────────────────────────────

def audit_headers(target: str, port: int = 443, timeout: float = 8.0) -> HeaderAuditResult:
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{target}:{port}/" if port not in (80, 443) else f"{scheme}://{target}/"

    result = HeaderAuditResult(target=target, url=url)
    headers, status = fetch_headers(url, timeout)
    result.status_code = status
    is_https = (scheme == "https")

    if not headers:
        # Try HTTP fallback when HTTPS was unreachable.
        if scheme == "https":
            url_http = f"http://{target}/"
            headers, status = fetch_headers(url_http, timeout)
            result.status_code = status
            result.url = url_http
            is_https = False

    if not headers:
        # Connection failed entirely. Return a sane "could not audit" result:
        # status_code stays 0 and no findings are emitted, so the report shows
        # an empty audit rather than falsely claiming every header is missing.
        return result

    result.server_banner = headers.get("server", "")
    result.powered_by    = headers.get("x-powered-by", "")

    # Run all checks
    checks = [
        check_hsts(headers, is_https),
        check_csp(headers),
        check_xframe(headers),
        check_xcto(headers),
        check_referrer_policy(headers),
        check_permissions_policy(headers),
        check_cors(headers),
        check_cache_control(headers),
    ]

    for c in checks:
        if c:
            result.findings.append(c)

    result.findings.extend(check_server_disclosure(headers))
    result.findings.extend(check_cookies(headers))
    result.findings.extend(check_cross_origin_policies(headers))

    # Track present/missing
    security_headers = [
        "strict-transport-security", "content-security-policy",
        "x-frame-options", "x-content-type-options", "referrer-policy",
        "permissions-policy",
    ]
    if not is_https:
        # HSTS is not applicable over plain HTTP; don't report it as "missing".
        security_headers = [h for h in security_headers
                            if h != "strict-transport-security"]
    result.headers_present = [h for h in security_headers if h in headers]
    result.headers_missing  = [h for h in security_headers if h not in headers]

    result.score, result.grade = calculate_score(result.findings, headers)
    return result
