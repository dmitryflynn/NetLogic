"""
NetLogic - Web Content / Application Fingerprinting
===================================================
Narrows a coarse banner ("Apache 2.4.x") to the actual application and build by
looking at CONTENT, not just headers — the difference between a version guess and
a precise identification:

  • Favicon hash (Shodan-compatible MurmurHash3) — identifies the exact app/appliance
  • <meta generator> / application-name — CMS + version straight from the page
  • Version files — CHANGELOG.txt, package.json, composer.json, readme.html, /wp-json
  • JavaScript analysis — embedded versions, API endpoints, and leaked secrets in
    served JS bundles (the same recon that maps an auth surface)

Stdlib only, read-only GETs, fails soft. Feeds the AI so it can reason about a
specific application rather than a generic server banner.
"""
from __future__ import annotations

import base64
import hashlib
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SaaSHit:
    """A third-party backend/SaaS the app depends on, found in its own bundle/HTML.

    The whole point is CORRECT severity: a publishable/anon key is public BY DESIGN
    (INFO) — flagging it CRITICAL is crying wolf; a *secret* key (sk_, service_role,
    private key) is a real leak (CRITICAL). This nuance is the quality edge."""
    service: str        # "Clerk", "Supabase", "Stripe", ...
    category: str       # "auth" | "backend" | "payments" | "analytics" | "monitoring" | "cloud"
    evidence: str       # short/masked evidence string
    severity: str       # INFO | LOW | MEDIUM | HIGH | CRITICAL
    detail: str         # plain-English why-it-matters / remediation

    def to_dict(self) -> dict:
        return {"service": self.service, "category": self.category, "evidence": self.evidence,
                "severity": self.severity, "detail": self.detail}


@dataclass
class WebFingerprint:
    host: str
    port: int
    scheme: str
    favicon_mmh3: Optional[int] = None       # Shodan http.favicon.hash
    favicon_sha256: Optional[str] = None
    generator: Optional[str] = None          # <meta name="generator">
    app_name: Optional[str] = None           # <meta name="application-name">
    title: Optional[str] = None
    version_markers: list[str] = field(default_factory=list)   # "WordPress 6.4.1", ...
    exposed_files: list[str] = field(default_factory=list)     # paths that returned content
    js_endpoints: list[str] = field(default_factory=list)      # API paths found in JS
    js_secrets: list[str] = field(default_factory=list)        # masked secret hits
    saas: list = field(default_factory=list)                   # SaaSHit — third-party backends
    is_spa: bool = False                                       # soft-404 catch-all (client-routed SPA)
    frontend: Optional[str] = None                             # "React SPA", "Next.js", "Vue", ...
    waf: Optional[str] = None                                  # WAF/challenge that blocked deep analysis
    notes: list[str] = field(default_factory=list)


# ─── MurmurHash3 (Shodan favicon hash) ──────────────────────────────────────────

def _murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32, signed — matches Shodan's http.favicon.hash."""
    c1, c2 = 0xcc9e2d51, 0x1b873593
    length = len(data)
    h1 = seed
    rounded_end = length & 0xfffffffc
    for i in range(0, rounded_end, 4):
        k1 = ((data[i] & 0xff) | ((data[i + 1] & 0xff) << 8)
              | ((data[i + 2] & 0xff) << 16) | (data[i + 3] << 24))
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff
    k1 = 0
    tail = length & 0x03
    if tail == 3:
        k1 = (data[rounded_end + 2] & 0xff) << 16
    if tail >= 2:
        k1 |= (data[rounded_end + 1] & 0xff) << 8
    if tail >= 1:
        k1 |= (data[rounded_end] & 0xff)
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= (h1 >> 16)
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


# ─── HTTP helper ─────────────────────────────────────────────────────────────

# A realistic desktop-Chrome UA (+ Accept). A bot UA like "NetLogic/2.0" gets challenged/403'd by
# modern edge WAFs (Vercel/Cloudflare), which blocks the very bundle analysis we need — a browser UA
# reads the real page. This is fingerprinting the app the way a browser would, not evasion.
_BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")


def _get(url: str, timeout: float, binary: bool = False, max_bytes: int = 262144):
    """GET a URL → (status, bytes|str) or (None, None). Read-only, fail-soft."""
    req = urllib.request.Request(url, headers={
        "User-Agent": _BROWSER_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(max_bytes)
            return resp.status, (raw if binary else raw.decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        # Read the error body too — a WAF JS-challenge (Vercel/Cloudflare) serves its markers in the
        # 403/503 body, and we need to inspect it to report the block honestly. Callers gate on
        # status == 200, so handing back a non-200 body changes nothing for them.
        try:
            raw = e.read(max_bytes)
            return e.code, (raw if binary else raw.decode("utf-8", errors="replace"))
        except Exception:
            return e.code, None
    except Exception:
        return None, None


def _same_origin(src: str, host: str) -> bool:
    """True only if an absolute script URL's HOST equals the target host.

    A substring test (``host in src``) is unsafe: an off-origin URL can embed the
    host in a subdomain prefix, path, or query (e.g. ``evil-example.com`` or
    ``cdn.other.com/x.js?ref=example.com``) and would be fetched as if same-origin.
    """
    try:
        netloc = urllib.parse.urlsplit(src).netloc
    except Exception:
        return False
    # Strip any userinfo and port → compare bare hostnames, case-insensitively.
    netloc = netloc.rsplit("@", 1)[-1]
    if netloc.startswith("["):            # IPv6 literal: [::1]:8080
        hostname = netloc[1:netloc.find("]")] if "]" in netloc else netloc
    else:
        hostname = netloc.split(":", 1)[0]
    return hostname.lower() == host.lower()


# ─── Secret / endpoint / version patterns ───────────────────────────────────────

_SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Slack token",    re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("Stripe key",     re.compile(r"sk_live_[0-9A-Za-z]{24,}")),
    ("Generic secret", re.compile(r"""(?i)(?:api[_-]?key|secret|access[_-]?token|auth[_-]?token)["']?\s*[:=]\s*["']([0-9A-Za-z._\-]{16,})["']""")),
    ("JWT",            re.compile(r"eyJ[0-9A-Za-z_\-]{8,}\.[0-9A-Za-z_\-]{8,}\.[0-9A-Za-z_\-]{8,}")),
    ("Private key",    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]
_ENDPOINT_RE = re.compile(r"""["'`](/(?:api|v\d|rest|graphql|admin|internal)/[A-Za-z0-9_\-/.{}]{1,60})["'`]""")
_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)
_GENERATOR_RE = re.compile(r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']""", re.I)
_APPNAME_RE = re.compile(r"""<meta[^>]+name=["']application-name["'][^>]+content=["']([^"']+)["']""", re.I)
_TITLE_RE = re.compile(r"<title[^>]*>([^<]{1,120})</title>", re.I)


def _mask(s: str) -> str:
    s = s.strip()
    return (s[:6] + "…" + s[-2:]) if len(s) > 10 else (s[:3] + "…")


# Version files worth probing, with how to read a version out of them.
_VERSION_FILES = [
    ("/CHANGELOG.txt", re.compile(r"(?i)(?:drupal\s+|^)(\d+\.\d+(?:\.\d+)?)", re.M)),
    ("/package.json",  re.compile(r'"version"\s*:\s*"([^"]+)"')),
    ("/composer.json", re.compile(r'"version"\s*:\s*"([^"]+)"')),
    ("/readme.html",   re.compile(r"(?i)version\s+(\d+\.\d+(?:\.\d+)?)")),
    ("/CHANGELOG.md",  re.compile(r"(\d+\.\d+\.\d+)")),
]
# Sensitive paths → a validator that proves the response is REALLY that file
# (not a soft-404 / SPA catch-all that returns 200 + HTML for everything).
def _is_html(c: str) -> bool:
    cl = c[:200].lstrip().lower()
    return cl.startswith("<!doctype html") or cl.startswith("<html") or "<head" in cl


def _is_soft_404_body(content: str, soft_404: bool, baseline: Optional[str]) -> bool:
    """On a soft-404 host, reject bodies that match the known 200-for-everything page.

    Compares the leading window of the candidate against the baseline body captured
    from a guaranteed-nonexistent path. Returns False when the host is not a soft-404
    host (no gating needed) or no baseline was captured.
    """
    if not soft_404 or not baseline:
        return False
    return content[:512].strip() == baseline[:512].strip()

_SENSITIVE_PATHS = [
    ("/.git/HEAD",     lambda c: c.strip().startswith("ref:") or "refs/" in c[:100]),
    ("/.env",          lambda c: not _is_html(c) and re.search(r"(?m)^[A-Z][A-Z0-9_]+=", c) is not None),
    ("/wp-json",       lambda c: not _is_html(c) and ('"namespaces"' in c or "wp/v2" in c)),
    ("/server-status", lambda c: "Apache Server Status" in c or "Server uptime" in c),
    ("/.svn/entries",  lambda c: not _is_html(c) and (c[:20].strip().isdigit() or "dir" in c[:20])),
]


# ─── SaaS / third-party backend detection (the modern-web attack surface) ────────
# Modern serverless apps (Vercel/Netlify + React/Next SPA) expose almost nothing over
# the network — the real surface is the third-party SaaS wired into the JS bundle. We
# detect the service AND classify severity correctly: publishable/anon keys are PUBLIC
# by design (INFO); *secret* keys are real leaks (CRITICAL). Being smarter than a naive
# "any pk_ key = HIGH" scanner is the whole point.

_B64 = re.compile(r"^[A-Za-z0-9+/=_\-]+$")


def _clerk_instance(pk: str) -> str:
    """Clerk publishable keys are `pk_(test|live)_<base64(instance$)>`; decode the instance."""
    try:
        tail = pk.split("_", 2)[2]
        dec = base64.b64decode(tail + "=" * (-len(tail) % 4)).decode("utf-8", "replace")
        return dec.rstrip("$")
    except Exception:
        return ""


_WAF_CHALLENGE_RE = re.compile(
    r"(?i)(vercel security checkpoint|x-vercel-mitigated|attention required.*cloudflare|"
    r"__cf_chl|cf-mitigated|just a moment|checking your browser|akamai.*reference\s*#|"
    r"incapsula|imperva|datadome)")


def _waf_vendor(html: str) -> str:
    low = (html or "").lower()
    if "vercel" in low:
        return "Vercel"
    if "cloudflare" in low or "__cf_chl" in low or "cf-mitigated" in low:
        return "Cloudflare"
    if "akamai" in low:
        return "Akamai"
    if "incapsula" in low or "imperva" in low:
        return "Imperva"
    if "datadome" in low:
        return "DataDome"
    return "WAF"


def detect_frontend(html: str, js: str = "") -> Optional[str]:
    """Best-effort frontend framework/SPA identification from the HTML shell + bundle."""
    html = html or ""
    low = (html + " " + (js or "")).lower()
    spa = 'id="root"' in html or "id='root'" in html or 'id="app"' in html
    if "__next_data__" in low or "/_next/" in low:
        return "Next.js"
    if "__nuxt__" in low or "/_nuxt/" in low:
        return "Nuxt"
    if "ng-version" in low or "ng-app" in low:
        return "Angular"
    if "__sveltekit" in low or "svelte-announcer" in low or "/_app/immutable/" in low:
        return "SvelteKit"
    if "__vue__" in low or "vue.createapp" in low or "data-v-" in html:
        return "Vue SPA" if spa else "Vue"
    react = "react" in low or "reactdom" in low or "_reactroot" in low or "__react" in low
    if react:
        return "React SPA" if spa else "React"
    if spa and 'type="module"' in html:
        return "single-page application (bundled)"
    return None


def detect_saas(text: str) -> list[SaaSHit]:
    """Scan a blob (HTML or JS bundle) for third-party backends, with correct severity.
    Pure + deterministic — the deterministic floor the AI later reasons over."""
    hits: list[SaaSHit] = []
    seen: set[tuple] = set()

    def add(service, category, evidence, severity, detail):
        key = (service, severity, evidence)
        if key not in seen:
            seen.add(key)
            hits.append(SaaSHit(service, category, evidence, severity, detail))

    # ── Clerk (auth) ── publishable key is public; a TEST instance in prod is the finding
    for pk in set(re.findall(r"pk_(?:test|live)_[A-Za-z0-9+/=_\-]{16,}", text)):
        inst = _clerk_instance(pk)
        if pk.startswith("pk_test_"):
            add("Clerk", "auth", (inst or _mask(pk)),
                "MEDIUM",
                "Clerk DEVELOPMENT instance key served in production. Dev instances are "
                "shared/rate-limited and not hardened — switch to a pk_live_ production instance.")
        else:
            add("Clerk", "auth", (inst or _mask(pk)), "INFO",
                "Clerk publishable key — public by design; not a leak.")
    if "clerk.accounts.dev" in text or ".clerk.com" in text:
        add("Clerk", "auth", "clerk.accounts.dev", "INFO", "Clerk authentication in use.")

    # ── Supabase (backend/db) ── project ref public; service_role JWT is a CRITICAL leak
    for ref in set(re.findall(r"([a-z0-9]{20})\.supabase\.(?:co|in|red)", text)):
        add("Supabase", "backend", f"{ref}.supabase.co", "LOW",
            "Supabase project reference (public). The real risk is Row-Level Security: "
            "confirm RLS is enabled on every table so the anon key can't read others' data.")
    for jwt in set(re.findall(r"eyJ[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{6,}", text)):
        try:
            body = base64.b64decode(jwt.split(".")[1] + "===").decode("utf-8", "replace")
        except Exception:
            body = ""
        if "service_role" in body:
            add("Supabase", "backend", _mask(jwt), "CRITICAL",
                "Supabase SERVICE_ROLE key leaked in the client bundle — it BYPASSES Row-Level "
                "Security and grants full database read/write. Rotate immediately.")

    # ── Stripe (payments) ── publishable is public; SECRET key is critical
    if re.search(r"pk_live_[0-9A-Za-z]{20,}", text) and "stripe" in text.lower():
        add("Stripe", "payments", "pk_live_…", "INFO", "Stripe publishable key — public by design.")
    for sk in set(re.findall(r"sk_(?:live|test)_[0-9A-Za-z]{20,}", text)):
        add("Stripe", "payments", _mask(sk), "CRITICAL",
            "Stripe SECRET key leaked in the client bundle — full API access to charges/customers. "
            "Rotate immediately; secret keys must never ship to the browser.")

    # ── Firebase (backend) ── API key public by design; rules are the gate
    if re.search(r"AIza[0-9A-Za-z_\-]{35}", text) and ("firebase" in text.lower() or "firebaseio" in text):
        add("Firebase", "backend", "AIza…", "INFO",
            "Firebase API key — public by design. The real control is Firebase Security Rules; "
            "confirm they restrict reads/writes.")
    for dom in set(re.findall(r"([a-z0-9-]+)\.firebaseio\.com", text)):
        add("Firebase", "backend", f"{dom}.firebaseio.com", "LOW", "Firebase Realtime Database in use.")

    # ── Auth0 (auth) ──
    for dom in set(re.findall(r"([a-z0-9-]+)\.(?:us|eu|au)?\.?auth0\.com", text)):
        if dom not in ("cdn", "www"):
            add("Auth0", "auth", f"{dom}.auth0.com", "LOW", "Auth0 tenant in use.")

    # ── Monitoring / analytics (low-risk, but map the surface) ──
    for dsn in set(re.findall(r"https://[a-f0-9]{16,}@[a-z0-9.]+\.ingest\.sentry\.io/\d+", text)):
        add("Sentry", "monitoring", dsn.split("@")[-1], "INFO", "Sentry error monitoring (DSN is semi-public).")

    # ── Hard secrets that aren't SaaS-scoped ──
    if re.search(r"AKIA[0-9A-Z]{16}", text):
        add("AWS", "cloud", "AKIA…", "HIGH", "AWS access key ID exposed in the client bundle.")
    if "-----BEGIN" in text and "PRIVATE KEY-----" in text:
        add("Private key", "cloud", "-----BEGIN … PRIVATE KEY-----", "CRITICAL",
            "A private key is embedded in the client bundle. Rotate and remove immediately.")

    return hits


def fingerprint_web(host: str, port: int, scheme: str = "http",
                    timeout: float = 5.0) -> Optional[WebFingerprint]:
    fp = WebFingerprint(host=host, port=port, scheme=scheme)
    base = f"{scheme}://{host}:{port}"

    # ── Favicon hash ──
    status, body = _get(f"{base}/favicon.ico", timeout, binary=True, max_bytes=131072)
    if status == 200 and body:
        fp.favicon_mmh3 = _murmur3_32(base64.b64encode(body))
        fp.favicon_sha256 = hashlib.sha256(body).hexdigest()[:16]

    # ── Homepage: generator / app-name / title / script srcs ──
    status, html = _get(base + "/", timeout)
    # A JS-challenge WAF (Vercel/Cloudflare/Akamai) 403/503s non-browser clients — NO passive HTTP
    # scanner (nuclei, curl, us) can read the app through it. Surface it honestly instead of returning
    # an empty result: tell the operator WHY analysis is blocked and how to unblock it.
    if status in (403, 503) and html and _WAF_CHALLENGE_RE.search(html):
        fp.waf = _waf_vendor(html)
        fp.notes.append(
            f"Behind a {fp.waf} JS-challenge WAF — passive page/bundle analysis is blocked (this blocks "
            "every HTTP scanner, including nuclei). Allowlist the scanner IP or supply an authenticated "
            "session to analyze the application surface.")
        return fp
    script_srcs: list[str] = []
    if html:
        m = _GENERATOR_RE.search(html)
        if m:
            fp.generator = m.group(1).strip()
            fp.version_markers.append(fp.generator)
        m = _APPNAME_RE.search(html)
        if m:
            fp.app_name = m.group(1).strip()
        m = _TITLE_RE.search(html)
        if m:
            fp.title = m.group(1).strip()
        script_srcs = _SCRIPT_SRC_RE.findall(html)[:6]

    # ── Soft-404 baseline ──
    # Many sites (SPAs, custom error pages) return HTTP 200 for EVERY path. Probe a
    # random path; if it 200s with HTML, treat path-presence as untrustworthy and
    # require strict content validation before claiming a file is "exposed".
    rnd_status, rnd_body = _get(base + "/netlogic-404-probe-zzx9.html", timeout, max_bytes=2048)
    soft_404 = (rnd_status == 200)
    fp.is_spa = soft_404
    if soft_404:
        fp.notes.append("Client-routed SPA: returns HTTP 200 for nonexistent paths (soft-404). "
                        "Path-based file checks are content-validated, so /.git, /.env, /admin etc. "
                        "are NOT flagged from a bare 200 — no false positives.")

    # ── SaaS / third-party backend detection (over the HTML itself) ──
    saas: list = []
    seen_saas: set[tuple] = set()

    def _add_saas(hits):
        for h in hits:
            k = (h.service, h.severity, h.evidence)
            if k not in seen_saas:
                seen_saas.add(k)
                saas.append(h)

    if html:
        _add_saas(detect_saas(html))

    # ── Version files (only count when the version actually parses out) ──
    for path, ver_re in _VERSION_FILES:
        status, content = _get(base + path, timeout, max_bytes=8192)
        if status == 200 and content and not _is_html(content) \
                and not _is_soft_404_body(content, soft_404, rnd_body):
            vm = ver_re.search(content)
            if vm:
                fp.exposed_files.append(path)
                fp.version_markers.append(f"{path.lstrip('/').split('.')[0]} {vm.group(1)}")

    # ── Sensitive paths (content-validated, never bare 200) ──
    # The validators are the primary defence against soft-404 catch-alls (they reject
    # HTML shells and demand file-specific markers); we additionally reject any body
    # identical to the known soft-404 baseline.
    for path, validator in _SENSITIVE_PATHS:
        status, content = _get(base + path, timeout, max_bytes=4096)
        if status == 200 and content and not _is_soft_404_body(content, soft_404, rnd_body):
            try:
                ok = validator(content)
            except Exception:
                ok = False
            if ok:
                fp.exposed_files.append(path)
                fp.notes.append(f"Sensitive path {path} is publicly accessible and contains expected content.")

    # ── JavaScript analysis (same-origin scripts) ──
    endpoints: set[str] = set()
    secrets: list[str] = []
    frontend_js = ""                       # first bundle sample, for framework detection
    for src in script_srcs:
        if src.startswith("//"):
            if not _same_origin(f"{scheme}:{src}", host):   # protocol-relative, off-origin
                continue
            js_url = f"{scheme}:{src}"
        elif src.startswith("http"):
            if not _same_origin(src, host):                 # only fetch same-origin scripts
                continue
            js_url = src
        else:
            js_url = base + "/" + src.lstrip("/")
        # 2 MB cap: modern SPA bundles routinely exceed the old 512 KB limit (e.g. a
        # 611 KB Vite bundle), and truncation drops the very SaaS refs we're after.
        status, js = _get(js_url, timeout, max_bytes=2_000_000)
        # Require a real 200 with a body, and reject soft-404 HTML shells / baseline
        # pages so we never mine "secrets" or endpoints out of an error page.
        if status != 200 or not js or _is_html(js) \
                or _is_soft_404_body(js, soft_404, rnd_body):
            continue
        for ep in _ENDPOINT_RE.findall(js):
            endpoints.add(ep)
        for label, pat in _SECRET_PATTERNS:
            for hit in pat.findall(js):
                val = hit if isinstance(hit, str) else (hit[0] if hit else "")
                secrets.append(f"{label}: {_mask(val)}")
        _add_saas(detect_saas(js))            # third-party backends, correctly severity-rated
        if not frontend_js:
            frontend_js = js[:200000]
    fp.frontend = detect_frontend(html or "", frontend_js)
    fp.js_endpoints = sorted(endpoints)[:20]
    fp.js_secrets = secrets[:10]
    # Severity-sorted SaaS surface (worst first), stored as plain dicts for the report.
    _SEV = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    saas.sort(key=lambda h: _SEV.get(h.severity, 5))
    fp.saas = [h.to_dict() for h in saas[:20]]
    crit = [h for h in saas if h.severity in ("CRITICAL", "HIGH")]
    if crit:
        fp.notes.append(f"{len(crit)} high-risk third-party exposure(s): "
                        + ", ".join(f"{h.service} ({h.severity})" for h in crit[:5]))

    # De-dup version markers
    fp.version_markers = list(dict.fromkeys(fp.version_markers))

    # Nothing useful found → return None so callers can skip.
    if not any([fp.favicon_mmh3, fp.generator, fp.app_name, fp.version_markers,
                fp.exposed_files, fp.js_endpoints, fp.js_secrets, fp.saas]):
        return None
    return fp
