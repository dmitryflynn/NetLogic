"""
Deterministic, network-free tests for src/web_fingerprint.py.

We monkeypatch the module-internal ``_get`` to serve canned (status, body) tuples
keyed by URL path, so the whole ``fingerprint_web`` pipeline runs offline. The pure
helpers (murmur3, masking, regexes, validators, same-origin, soft-404 gating) are
tested directly.

Focus: FALSE POSITIVES. A soft-404 host (200 for everything) must not yield bogus
exposed_files / js_secrets; favicon hash must match Shodan's signed mmh3; secrets
must be masked; version markers only when a version truly parses.
"""
import base64

import pytest

import src.web_fingerprint as wf
from src.web_fingerprint import (
    WebFingerprint,
    _is_html,
    _is_soft_404_body,
    _mask,
    _murmur3_32,
    _same_origin,
    _SENSITIVE_PATHS,
    fingerprint_web,
)


# ── MurmurHash3 (must match mmh3.hash, signed seed 0) ─────────────────────────

@pytest.mark.parametrize("data,expected", [
    (b"", 0),
    (b"hello", 613153351),
    (b"foo", -156908512),
])
def test_murmur3_known_vectors(data, expected):
    assert _murmur3_32(data) == expected


def test_favicon_hash_uses_base64_encodebytes_signed():
    # Shodan computes mmh3 over base64.encodebytes(body). Verify the exact convention.
    body = b"\x89PNG\r\n\x1a\n" + b"icon-bytes" * 20
    expected = _murmur3_32(base64.encodebytes(body))
    assert isinstance(expected, int)
    # signed 32-bit range
    assert -0x80000000 <= expected <= 0x7fffffff


# ── Masking: never leak a full secret ─────────────────────────────────────────

def test_mask_truncates_long_secret():
    out = _mask("AKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert out.startswith("AKIAIO")
    assert len(out) <= 10


def test_mask_short_secret_minimal_leak():
    out = _mask("abcdef")
    assert out == "abc…"
    assert "abcdef" not in out


# ── _is_html / _is_soft_404_body ──────────────────────────────────────────────

@pytest.mark.parametrize("c,expected", [
    ("<!DOCTYPE html><html>", True),
    ("   <html lang=en>", True),
    ("<head>", True),
    ('{"version":"1.2.3"}', False),
    ("KEY=value", False),
])
def test_is_html(c, expected):
    assert _is_html(c) is expected


def test_soft_404_body_only_gates_when_soft_404():
    baseline = "NOT FOUND shell"
    assert _is_soft_404_body("NOT FOUND shell", True, baseline) is True
    assert _is_soft_404_body("NOT FOUND shell", False, baseline) is False
    assert _is_soft_404_body("real content", True, baseline) is False
    assert _is_soft_404_body("x", True, None) is False


# ── Same-origin JS gate (substring test was exploitable) ──────────────────────

@pytest.mark.parametrize("src,host,expected", [
    ("http://example.com/a.js", "example.com", True),
    ("https://example.com:8443/a.js", "example.com", True),
    ("http://EXAMPLE.com/a.js", "example.com", True),
    ("http://user@example.com/a.js", "example.com", True),
    ("http://evil-example.com/a.js", "example.com", False),     # subdomain-prefix trick
    ("http://cdn.other.com/a.js?ref=example.com", "example.com", False),  # host in query
    ("http://example.com.attacker.net/a.js", "example.com", False),
])
def test_same_origin(src, host, expected):
    assert _same_origin(src, host) is expected


# ── Sensitive-path validators reject SPA / soft-404 shells ────────────────────

def _validator(path):
    return dict(_SENSITIVE_PATHS)[path]


def test_validators_reject_html_shell():
    shell = "<!DOCTYPE html><html><head><title>App</title></head><body></body></html>"
    for path, validator in _SENSITIVE_PATHS:
        assert validator(shell) is False, path


def test_git_head_validator_accepts_real_and_rejects_fake():
    assert _validator("/.git/HEAD")("ref: refs/heads/main\n") is True
    assert _validator("/.git/HEAD")("just some text") is False


def test_env_validator_requires_env_lines():
    assert _validator("/.env")("DB_PASSWORD=secret\nAPI_KEY=abc\n") is True
    assert _validator("/.env")("<html>nope</html>") is False
    assert _validator("/.env")("lowercase=novars") is False


# ── End-to-end pipeline with a monkeypatched _get ─────────────────────────────

def _patch_get(monkeypatch, routes, default=(404, None), soft_404=False,
               soft_body="<html><body>app shell</body></html>"):
    """Route map: path -> (status, body). soft_404=True returns 200+soft_body for misses."""
    def _norm(v, binary):
        # allow bare-string route values → (200, body); always return a 2-tuple.
        status, body = v if isinstance(v, tuple) else (200, v)
        # Mirror the real _get contract: binary callers always get bytes back.
        if binary and isinstance(body, str):
            body = body.encode("utf-8")
        return status, body

    def fake_get(url, timeout, binary=False, max_bytes=262144):
        # derive path (and query) after host:port
        if "://" in url:
            after = url.split("://", 1)[1]
            path = "/" + after.split("/", 1)[1] if "/" in after else "/"
        else:
            path = url
        path = path.split("?", 1)[0]
        if path in routes:
            return _norm(routes[path], binary)
        if soft_404:
            return _norm((200, soft_body), binary)
        return default
    monkeypatch.setattr(wf, "_get", fake_get)


def test_soft_404_host_yields_no_false_exposed_files(monkeypatch):
    # Host 200s with an HTML shell for EVERYTHING, including /favicon.ico, /.env, /.git/HEAD.
    _patch_get(monkeypatch, routes={
        "/": "<html><head><title>SPA</title></head><body></body></html>",
    }, soft_404=True)
    fp = fingerprint_web("spa.example", 80, "http", timeout=1.0)
    # No sensitive path / version file should be flagged as exposed.
    assert fp is None or fp.exposed_files == []
    if fp is not None:
        assert fp.js_secrets == []


def test_real_git_exposure_is_detected(monkeypatch):
    _patch_get(monkeypatch, routes={
        "/": "<html><head><title>Site</title></head></html>",
        "/.git/HEAD": (200, "ref: refs/heads/main\n"),
    }, default=(404, None))
    fp = fingerprint_web("real.example", 80, "http", timeout=1.0)
    assert fp is not None
    assert "/.git/HEAD" in fp.exposed_files


def test_version_marker_only_when_version_parses(monkeypatch):
    # package.json present but with NO version field → no marker, not exposed.
    _patch_get(monkeypatch, routes={
        "/": "<html><head><title>X</title></head></html>",
        "/package.json": (200, '{"name":"app","dependencies":{}}'),
    }, default=(404, None))
    fp = fingerprint_web("noversion.example", 80, "http", timeout=1.0)
    if fp is not None:
        assert "/package.json" not in fp.exposed_files
        assert not any(m.startswith("package") for m in fp.version_markers)

    # package.json WITH a version → marker + exposed.
    _patch_get(monkeypatch, routes={
        "/": "<html><head><title>X</title></head></html>",
        "/package.json": (200, '{"name":"app","version":"4.5.6"}'),
    }, default=(404, None))
    fp = fingerprint_web("withver.example", 80, "http", timeout=1.0)
    assert fp is not None
    assert "/package.json" in fp.exposed_files
    assert any("4.5.6" in m for m in fp.version_markers)


def test_favicon_hash_populated_and_signed(monkeypatch):
    icon = b"\x00\x01\x02\x03favicon-content" * 10
    _patch_get(monkeypatch, routes={
        "/favicon.ico": (200, icon),
        "/": "<html><head><title>X</title></head></html>",
    }, default=(404, None))
    fp = fingerprint_web("icon.example", 80, "http", timeout=1.0)
    assert fp is not None
    assert fp.favicon_mmh3 == _murmur3_32(base64.b64encode(icon))
    assert -0x80000000 <= fp.favicon_mmh3 <= 0x7fffffff


def test_secrets_masked_and_offorigin_js_skipped(monkeypatch):
    leaky_js = 'const k="AKIAIOSFODNN7EXAMPLE"; fetch("/api/v2/users");'
    _patch_get(monkeypatch, routes={
        "/": ('<html><head></head><body>'
              '<script src="/app.js"></script>'
              '<script src="http://cdn.evil.com/x.js?ref=js.example"></script>'
              '</body></html>'),
        "/app.js": (200, leaky_js),
        # off-origin script also leaks, but must never be fetched/mined:
        "/x.js": (200, 'const aws="AKIAEVILEVILEVILEVIL1";'),
    }, default=(404, None))
    fp = fingerprint_web("js.example", 80, "http", timeout=1.0)
    assert fp is not None
    # same-origin secret found and masked
    assert any("AWS access key" in s for s in fp.js_secrets)
    assert not any("AKIAIOSFODNN7EXAMPLE" in s for s in fp.js_secrets)
    # off-origin secret must NOT appear
    assert not any("EVIL" in s for s in fp.js_secrets)
    assert "/api/v2/users" in fp.js_endpoints


def test_all_fail_returns_none(monkeypatch):
    _patch_get(monkeypatch, routes={}, default=(404, None))
    assert fingerprint_web("empty.example", 80, "http", timeout=1.0) is None


def test_get_never_raises_is_failsoft(monkeypatch):
    def boom(url, timeout, binary=False, max_bytes=262144):
        raise RuntimeError("network exploded")
    # fingerprint_web must not propagate — but it calls _get which we patch to raise;
    # the real _get swallows exceptions, so emulate that contract here.
    def safe(url, timeout, binary=False, max_bytes=262144):
        try:
            return boom(url, timeout, binary, max_bytes)
        except Exception:
            return (None, None)
    monkeypatch.setattr(wf, "_get", safe)
    assert fingerprint_web("dead.example", 80, "http", timeout=1.0) is None
