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

# Agent probes are read-only: no methods that can create/update/delete application data.
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_HEADER_KEY_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
_MAX_COOKIE_NAME = 64
_MAX_COOKIE_VAL = 512
_MAX_COOKIES = 24


def safe_path(path: Any) -> str | None:
    """Relative URL path only. Rejects absolute URLs, protocol-relative, control chars."""
    if not isinstance(path, str):
        return None
    p = path.strip()
    if not p:
        p = "/"
    if not p.startswith("/") or p.startswith("//"):
        return None
    if "://" in p or "@" in p or "\\" in p:
        return None
    if any(ord(c) < 0x20 or c == " " for c in p):
        return None
    if len(p) > _MAX_PATH:
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
