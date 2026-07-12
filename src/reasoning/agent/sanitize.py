"""Sanitize AI-proposed tool arguments — SSRF/path/body bounds (total gate)."""
from __future__ import annotations

import re
from typing import Any

_MAX_PATH = 256
_MAX_HEADER_KEY = 64
_MAX_HEADER_VAL = 512
_MAX_HEADERS = 20
_MAX_BODY = 4096
_MAX_RAW = 2048
_MAX_TIMEOUT = 15.0

# Agent probes are read-only by default: no methods that create/update/delete app data.
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# Tier C freeform proof: GET/HEAD/OPTIONS always; POST only on allowlisted paths.
_PROOF_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST"})
_HEADER_KEY_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
_MAX_COOKIE_NAME = 64
_MAX_COOKIE_VAL = 512
_MAX_COOKIES = 24
_MAX_PROOF_BODY = 2048

# Fail-closed: if any of these appear in path/query/headers/body, refuse to send.
_DESTRUCTIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\b(DROP|TRUNCATE)\s+(TABLE|DATABASE|SCHEMA|INDEX)\b"),
    re.compile(r"(?i)\bDELETE\s+FROM\b"),
    re.compile(r"(?i)\bUPDATE\s+\w[\w.]*\s+SET\b"),
    re.compile(r"(?i)\b(INSERT\s+INTO|ALTER\s+TABLE|CREATE\s+(TABLE|USER|DATABASE))\b"),
    re.compile(r"(?i)\b(GRANT|REVOKE)\s+\w"),
    re.compile(r"(?i)\brm\s+(-[a-zA-Z]*f|-[a-zA-Z]*r|/)|rmdir\b"),
    re.compile(r"(?i)\b(unlink|shutil\.rmtree|os\.(remove|unlink|rmdir)|pathlib\.Path\.unlink)\b"),
    re.compile(r"(?i)\b(powershell\s+(-enc|-e\b)|Invoke-Expression|\bIEX\s*\()"),
    re.compile(r"(?i);\s*(drop|delete|truncate|shutdown)\b"),
    re.compile(r"(?i)\b(mkfs\.|format\s+[a-z]:|dd\s+if=)"),
    re.compile(r"(?i)\b(userdel|deluser|passwd\s|chpasswd|net\s+user\s+\w+\s+/delete)\b"),
    re.compile(r"(?i)(/|%2f)(admin|api|users?|accounts?)(/|%2f).*(delete|destroy|purge|wipe|erase|drop)"),
    re.compile(r"(?i)[?&](_method|method|http_method)=(DELETE|PUT|PATCH)\b"),
    re.compile(r"(?i)<\?php\s+(system|exec|shell_exec|passthru|eval)\s*\("),
    re.compile(r"(?i)\b(eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)|Runtime\.getRuntime\(\)\.exec)"),
    re.compile(r"(?i)\b(wp_delete_user|destroy_user|force_delete|hard_delete)\b"),
    re.compile(r"(?i)\b(FLUSHALL|FLUSHDB|CONFIG\s+SET|SLAVEOF\s+NO\s+ONE)\b"),
    re.compile(r"(?i)\b(mongodb\.drop|dropDatabase\s*\(|db\.drop\()"),
)

# Freeform POST only to read-like / auth-probe surfaces (never admin CRUD / uploads).
_PROOF_POST_PATH_RE: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)^/(search|query|find|filter|echo|reflect|ping|health|status)(/|$)"),
    re.compile(r"(?i)^/(api|v\d+|graphql|gql)(/|$)"),
    re.compile(r"(?i)^/(api/)?(v\d+/)?(search|query|echo|reflect|ping|health|graphql|gql|login|auth|token|session)(/|$)"),
    re.compile(r"(?i)^/(login|signin|sign-in|auth|oauth)(/|$)"),
    re.compile(r"(?i)^/(wp-login\.php|user/login|accounts/login|session/new)(/|$)"),
)

_PROOF_POST_PATH_DENY_RE: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)/(delete|destroy|purge|wipe|erase|remove|drop|upload|import|admin/users)"),
    re.compile(r"(?i)/(password/reset|forgot-password|change-password)"),
)


def is_destructive_payload(*parts: str | None) -> tuple[bool, str]:
    """Return (True, reason) if any fragment looks state-destroying / weaponized.

    Used by Tier C freeform proof to fail closed — better to skip a check than
    risk wiping application data. Checks raw text and URL-decoded variants.
    """
    from urllib.parse import unquote_plus  # noqa: PLC0415

    chunks: list[str] = []
    for p in parts:
        if p is None:
            continue
        s = str(p)
        if s:
            chunks.append(s)
    if not chunks:
        return False, ""
    blob = "\n".join(chunks)
    # Cap scan cost
    if len(blob) > 16_000:
        blob = blob[:16_000]
    # Also scan URL-decoded form so DROP%20TABLE is caught
    try:
        decoded = unquote_plus(blob)
    except Exception:  # noqa: BLE001
        decoded = blob
    for candidate in (blob, decoded):
        for pat in _DESTRUCTIVE_PATTERNS:
            m = pat.search(candidate)
            if m:
                return True, f"destructive pattern blocked: {m.group(0)[:80]!r}"
    return False, ""


def is_proof_post_path_allowed(path: str) -> bool:
    """True if freeform POST may target this path (allowlist − denylist)."""
    p = (path or "/").strip() or "/"
    if not p.startswith("/"):
        p = "/" + p
    # Path only for matching (ignore query)
    path_only = p.split("?", 1)[0]
    for deny in _PROOF_POST_PATH_DENY_RE:
        if deny.search(path_only):
            return False
    for allow in _PROOF_POST_PATH_RE:
        if allow.search(path_only):
            return True
    return False


def safe_proof_method(method: Any) -> str | None:
    """Methods permitted for http_proof when freeform is enabled."""
    if not isinstance(method, str):
        return None
    m = method.strip().upper()
    return m if m in _PROOF_METHODS else None


def safe_proof_body(body: Any) -> str | None:
    """Bounded body for freeform proof POST (stricter than generic safe_body)."""
    if body is None:
        return None
    if not isinstance(body, str):
        return None
    if len(body) > _MAX_PROOF_BODY:
        return body[:_MAX_PROOF_BODY]
    return body


def safe_path(path: Any) -> str | None:
    """Relative URL path (+ optional query). Rejects absolute/protocol-relative paths.

    Query strings may contain ``https://…`` (needed for open-redirect probes). The
    path segment *before* ``?`` must not contain ``://`` or ``@``.
    """
    if not isinstance(path, str):
        return None
    p = path.strip()
    if not p:
        p = "/"
    if not p.startswith("/") or p.startswith("//"):
        return None
    path_only, sep, query = p.partition("?")
    if "://" in path_only or "@" in path_only or "\\" in path_only:
        return None
    if "@" in query or "\\" in query:
        return None
    if any(ord(c) < 0x20 or c == " " for c in p):
        return None
    # Proof redirects need longer queries; keep total bounded
    if len(p) > max(_MAX_PATH, 512):
        return None
    return p


def safe_method(method: Any) -> str | None:
    if not isinstance(method, str):
        return None
    m = method.strip().upper()
    return m if m in _SAFE_METHODS else None


def safe_headers(raw: Any) -> dict[str, str] | None:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        return None
    out: dict[str, str] = {}
    for i, (k, v) in enumerate(raw.items()):
        if i >= _MAX_HEADERS:
            break
        if not isinstance(k, str) or not isinstance(v, str):
            continue
        key = k.strip()[:_MAX_HEADER_KEY]
        if not key or not _HEADER_KEY_RE.match(key):
            continue
        # Block Host override / hop-by-hop smuggling helpers as free-form control
        if key.lower() in ("host", "content-length", "transfer-encoding"):
            continue
        out[key] = v.strip()[:_MAX_HEADER_VAL]
    return out


def safe_body(body: Any) -> str | None:
    if body is None:
        return None
    if not isinstance(body, str):
        return None
    if len(body) > _MAX_BODY:
        return body[:_MAX_BODY]
    return body


def safe_timeout(t: Any, default: float = 5.0) -> float:
    try:
        f = float(t)
    except (TypeError, ValueError):
        return default
    if f != f or f <= 0:  # NaN / non-positive
        return default
    return min(f, _MAX_TIMEOUT)


def safe_raw_payload(data: Any) -> bytes | None:
    """Bounded raw TCP payload. Accepts str (utf-8) or list of ints (0-255)."""
    if isinstance(data, str):
        b = data.encode("utf-8", errors="replace")
        return b[:_MAX_RAW] if b else None
    if isinstance(data, (bytes, bytearray)):
        return bytes(data[:_MAX_RAW]) if data else None
    if isinstance(data, list):
        try:
            b = bytes(int(x) & 0xFF for x in data[:_MAX_RAW])
            return b or None
        except (TypeError, ValueError):
            return None
    return None


def safe_port(port: Any, default: int = 80) -> int:
    try:
        p = int(port)
    except (TypeError, ValueError):
        return default
    return p if 1 <= p <= 65535 else default


def safe_tech_slug(name: Any) -> str | None:
    if not isinstance(name, str):
        return None
    # "Apache HTTPD" / "Microsoft IIS" → first meaningful token the probe catalog knows
    s = name.strip().lower()[:64]
    if not s:
        return None
    s = re.sub(r"[^a-z0-9._\s-]+", "", s).strip()
    s = re.sub(r"[\s.]+", "_", s)
    s = s.strip("_")[:64]
    if not s or not re.match(r"^[a-z0-9][a-z0-9._-]{0,62}$", s):
        return None
    # Prefer short probe keys (apache, nginx, iis) when AI sends long product names
    for key in ("iis", "nginx", "apache", "express", "wordpress", "tomcat", "graphql"):
        if key in s.replace("-", "_"):
            return key
    return s


def safe_id(s: Any, max_len: int = 64) -> str | None:
    if not isinstance(s, str):
        return None
    t = s.strip()[:max_len]
    return t if t else None


def safe_cookies(raw: Any) -> dict[str, str] | None:
    """Scanner-side session cookies only — never sent as Set-Cookie to the target."""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        return None
    out: dict[str, str] = {}
    for i, (k, v) in enumerate(raw.items()):
        if i >= _MAX_COOKIES:
            break
        if not isinstance(k, str) or not isinstance(v, str):
            continue
        name = k.strip()[:_MAX_COOKIE_NAME]
        if not name or any(c in name for c in " \r\n;"):
            continue
        val = v.strip()[:_MAX_COOKIE_VAL]
        if any(c in val for c in "\r\n"):
            continue
        out[name] = val
    return out


def safe_wordlist_name(name: Any) -> str:
    if not isinstance(name, str):
        return "common"
    n = name.strip().lower()
    if n in ("common", "api", "config", "admin", "short"):
        return n
    return "common"
