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

def _get(url: str, timeout: float, binary: bool = False, max_bytes: int = 262144):
    """GET a URL → (status, bytes|str) or (None, None). Read-only, fail-soft."""
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (NetLogic/2.0)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(max_bytes)
            return resp.status, (raw if binary else raw.decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
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
_VERSION_RE = re.compile(r"""(?i)["']?version["']?\s*[:=]\s*["']?v?(\d+\.\d+(?:\.\d+)?)""")
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
    if soft_404:
        fp.notes.append("Host returns HTTP 200 for nonexistent paths (soft-404) — "
                        "file-presence checks validated by content only.")

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
        status, js = _get(js_url, timeout, max_bytes=524288)
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
        vm = _VERSION_RE.search(js)
        if vm and len(fp.version_markers) < 8:
            fp.version_markers.append(f"js:{vm.group(1)}")
    fp.js_endpoints = sorted(endpoints)[:20]
    fp.js_secrets = secrets[:10]
    if fp.js_secrets:
        fp.notes.append(f"{len(fp.js_secrets)} possible secret(s) found in served JavaScript.")

    # De-dup version markers
    fp.version_markers = list(dict.fromkeys(fp.version_markers))

    # Nothing useful found → return None so callers can skip.
    if not any([fp.favicon_mmh3, fp.generator, fp.app_name, fp.version_markers,
                fp.exposed_files, fp.js_endpoints, fp.js_secrets]):
        return None
    return fp
