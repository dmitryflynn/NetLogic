"""
Deterministic tests for src.stack_fingerprint — NO real network.

Strategy: monkeypatch the module-level _fetch() with a router that returns
canned (headers, body, status) keyed off the requested URL/path. This lets us
assert positive detections, the ABSENCE of false positives on a neutral page,
case-insensitive header handling, version-only-when-parseable, and crash-safety
on garbage/huge bodies.
"""

import pytest

from src import stack_fingerprint as sf


# ─── Helpers ──────────────────────────────────────────────────────────────────

def install_fetch(monkeypatch, responses):
    """`responses` maps a substring (matched against the URL) -> (headers, body, status).
    The main page "/" should be keyed by "MAIN"; probe/deep-scan URLs fall through
    to an empty (no-WAF, 404) response unless a more specific key matches."""
    def fake_fetch(url, payload=None, timeout=8.0):
        # Most specific (longest) matching key wins; "MAIN" matches the root page.
        best = None
        for key, resp in responses.items():
            if key == "MAIN":
                if url.rstrip("/").endswith("//") or url.count("/") <= 3:
                    if best is None or len(key) > len(best[0]):
                        best = (key, resp)
                continue
            if key in url:
                if best is None or len(key) > len(best[0]):
                    best = (key, resp)
        if best is not None:
            return best[1]
        # default: a benign 404-ish empty response (used by WAF probe / deep scan)
        return ({}, "", 404)
    monkeypatch.setattr(sf, "_fetch", fake_fetch)


def names(result):
    return {t.name for t in result.technologies}


# ─── Positive detections ──────────────────────────────────────────────────────

def test_wordpress_detected_with_version(monkeypatch):
    headers = {
        "server": "Apache/2.4.41",
        "x-generator": "WordPress 6.4.2",
        "set-cookie": "wordpress_logged_in_abc=1; path=/",
    }
    body = '<link rel="stylesheet" href="/wp-content/themes/x/style.css">'
    # Make deep-scan paths look absent so it doesn't add noise.
    install_fetch(monkeypatch, {"MAIN": (headers, body, 200)})

    res = sf.fingerprint_stack("wp.example.com", 443)
    nm = names(res)
    assert "WordPress" in nm
    assert "Apache HTTPD" in nm
    # version parsed from the explicit header signature
    wp = next(t for t in res.technologies if t.name == "WordPress")
    assert wp.version == "6.4.2"
    apache = next(t for t in res.technologies if t.name == "Apache HTTPD")
    assert apache.version == "2.4.41"


def test_nginx_php_detected(monkeypatch):
    headers = {
        "server": "nginx/1.18.0",
        "x-powered-by": "PHP/8.1.2",
        "set-cookie": "PHPSESSID=deadbeef; path=/; HttpOnly",
    }
    install_fetch(monkeypatch, {"MAIN": (headers, "<html>hello</html>", 200)})
    res = sf.fingerprint_stack("php.example.com", 443)
    nm = names(res)
    assert "nginx" in nm
    assert "PHP" in nm
    php = next(t for t in res.technologies if t.name == "PHP")
    assert php.version == "8.1.2"


def test_cloudflare_waf_block_page_high(monkeypatch):
    # Body block-page fingerprint => HIGH confidence WAF.
    headers = {"server": "cloudflare", "cf-ray": "7a1b2c3d4e5f-AMS"}
    body = "Attention Required! | Cloudflare ... Ray ID: 7a1b2c3d4e5f"
    install_fetch(monkeypatch, {"MAIN": (headers, body, 403)})
    res = sf.fingerprint_stack("cf.example.com", 443)
    assert res.waf.detected is True
    assert res.waf.name == "Cloudflare WAF"
    assert res.waf.confidence == "HIGH"
    assert res.cdn == "Cloudflare"


def test_cloudflare_cdn_only_is_not_high_confidence_waf(monkeypatch):
    # Site merely fronted by Cloudflare (no block page). Must NOT be reported
    # as a HIGH-confidence active WAF — that was the cardinal false positive.
    headers = {"server": "cloudflare", "cf-ray": "abc-AMS"}
    body = "<html><body>Welcome to my normal site</body></html>"
    install_fetch(monkeypatch, {"MAIN": (headers, body, 200)})
    res = sf.fingerprint_stack("cf.example.com", 443)
    # CDN should still be attributed...
    assert res.cdn == "Cloudflare"
    # ...but the WAF must not claim HIGH confidence from CDN headers alone.
    assert res.waf.confidence != "HIGH"
    # ...and must not NAME "Cloudflare WAF" off routing headers (server/cf-ray
    # are plain CDN routing IDs, not WAF evidence).
    assert res.waf.name != "Cloudflare WAF"


# ─── Routing-header-only must NOT name a specific WAF ──────────────────────────

def test_plain_aws_routing_headers_no_named_waf(monkeypatch):
    # x-amzn-requestid / x-amzn-trace-id ride on EVERY AWS response. A plain
    # AWS-hosted site (probe returns a generic 403) must not be reported as
    # "AWS WAF" — that was a passive MEDIUM false positive.
    norm = {"x-amzn-requestid": "abc", "x-amzn-trace-id": "Root=1", "server": "Server"}
    def fetch(url, payload=None, timeout=8.0):
        if "alert" in url:  # active probe URL
            return ({"x-amzn-requestid": "z"}, "<html>403</html>", 403)
        return (norm, "<html>ok</html>", 200)
    monkeypatch.setattr(sf, "_fetch", fetch)
    res = sf.fingerprint_stack("aws.example.com", 443)
    assert res.waf.name != "AWS WAF"


def test_plain_fastly_routing_header_no_named_waf(monkeypatch):
    # Single benign x-fastly-request-id + a generic 403 on the probe must not
    # be named "Fastly WAF" (Phase-2 single-routing-header false positive).
    norm = {"x-fastly-request-id": "dead", "server": "nginx"}
    def fetch(url, payload=None, timeout=8.0):
        if "alert" in url:  # active probe URL
            return ({"x-fastly-request-id": "beef"}, "<html>Forbidden</html>", 403)
        return (norm, "<html>welcome</html>", 200)
    monkeypatch.setattr(sf, "_fetch", fetch)
    res = sf.fingerprint_stack("fastly.example.com", 443)
    assert res.waf.name != "Fastly WAF"


def test_real_imperva_strong_header_still_named(monkeypatch):
    # x-iinfo is Imperva-product-specific (a strong header). It must still be
    # attributed at MEDIUM even without a block page — the fix must not
    # over-suppress genuine product fingerprints.
    install_fetch(monkeypatch, {"MAIN": ({"x-iinfo": "1-2-3", "server": "nginx"},
                                         "<html>ok</html>", 200)})
    res = sf.fingerprint_stack("imp.example.com", 443)
    assert res.waf.detected is True
    assert res.waf.name == "Imperva / Incapsula"
    assert res.waf.confidence == "MEDIUM"


def test_ipv6_target_is_bracketed_in_fetch_url(monkeypatch):
    # Bare IPv6 literals must be bracketed to form a valid URL authority; the
    # main fetch previously did not bracket (only the active probe did).
    seen = {}
    def fake_fetch(url, payload=None, timeout=8.0):
        seen.setdefault("first", url)
        return ({"server": "nginx"}, "<html>ok</html>", 200)
    monkeypatch.setattr(sf, "_fetch", fake_fetch)
    sf.fingerprint_stack("2606:4700:4700::1111", 443)
    assert seen["first"] == "https://[2606:4700:4700::1111]/"


# ─── Neutral page: NO false positives ─────────────────────────────────────────

def test_neutral_page_no_false_positives(monkeypatch):
    headers = {
        "server": "nginx",
        "content-type": "text/html; charset=utf-8",
        "x-cache": "HIT",  # bare HIT must NOT yield "Generic CDN/Cache"
    }
    # Body links to Google Fonts and mentions azure/vercel in prose — none of
    # these may produce cloud/CDN attribution.
    body = (
        "<html><head><link href='https://fonts.googleapis.com/css' rel='stylesheet'>"
        "</head><body>We talk about azure skies and our vercel of joy. "
        "Visit google for more.</body></html>"
    )
    install_fetch(monkeypatch, {"MAIN": (headers, body, 200)})
    res = sf.fingerprint_stack("neutral.example.com", 443)

    # nginx is legitimately present; nothing else should be.
    assert names(res) == {"nginx"} or names(res) <= {"nginx"}
    assert res.cloud_provider is None, f"false cloud: {res.cloud_provider}"
    assert res.cdn is None, f"false cdn: {res.cdn}"
    assert "Generic CDN/Cache" not in names(res)
    assert res.waf.detected is False


def test_google_fonts_does_not_imply_google_cloud(monkeypatch):
    headers = {"server": "Apache"}
    body = "<link href='https://fonts.googleapis.com/css2'> google google google"
    install_fetch(monkeypatch, {"MAIN": (headers, body, 200)})
    res = sf.fingerprint_stack("x.example.com", 443)
    assert res.cloud_provider is None


# ─── Case-insensitive header matching ─────────────────────────────────────────

def test_header_matching_is_case_insensitive_on_keys(monkeypatch):
    # Real responses are lower-cased by _flatten_headers; emulate that the
    # detection path itself does not depend on exact value casing.
    headers = {"server": "NGINX/1.20.0", "x-powered-by": "php/8.0.0"}
    install_fetch(monkeypatch, {"MAIN": (headers, "", 200)})
    res = sf.fingerprint_stack("ci.example.com", 443)
    nm = names(res)
    assert "nginx" in nm
    assert "PHP" in nm


def test_detect_from_headers_directly_case_insensitive():
    f = sf.detect_from_headers({"server": "APACHE/2.4.6"})
    assert any(t.name == "Apache HTTPD" and t.version == "2.4.6" for t in f)


# ─── Version only when parseable ──────────────────────────────────────────────

def test_version_none_when_not_present():
    # LiteSpeed signature has no capture group -> version must be None.
    f = sf.detect_from_headers({"server": "LiteSpeed"})
    ls = next(t for t in f if t.name == "LiteSpeed")
    assert ls.version is None


def test_body_match_does_not_fabricate_version():
    # Body contains WordPress marker plus an unrelated version-looking number.
    body = "see /wp-content/ and also jQuery 3.6.0 somewhere"
    f = sf.detect_from_body(body)
    wp = next(t for t in f if t.name == "WordPress")
    # WordPress body signature has no capture group => version stays None,
    # must NOT pick up the unrelated 3.6.0.
    assert wp.version is None


# ─── Cookies (incl. multi Set-Cookie flattening) ──────────────────────────────

def test_multiple_set_cookie_values_all_inspected():
    # _flatten_headers joins multiple Set-Cookie lines with newline; ensure a
    # signature on the *second* cookie still matches.
    headers = {"set-cookie": "foo=bar; path=/\nlaravel_session=xyz; HttpOnly"}
    f = sf.detect_from_cookies(headers)
    assert any(t.name == "Laravel" for t in f)


def test_flatten_headers_preserves_all_set_cookie():
    from email.message import Message
    m = Message()
    m["Set-Cookie"] = "a=1"
    m["Set-Cookie"] = "b=2"
    m["Server"] = "nginx"
    out = sf._flatten_headers(m)
    assert "a=1" in out["set-cookie"] and "b=2" in out["set-cookie"]
    assert out["server"] == "nginx"


# ─── Crash / hang safety on hostile input ─────────────────────────────────────

def test_garbage_and_huge_body_do_not_crash(monkeypatch):
    huge = ("<script>" + "A" * 200000 + "</script>"
            "/wp-content/ <!-- password=hunter2 -->")
    headers = {"server": "nginx", "set-cookie": "\x00\xff garbage \x01"}
    install_fetch(monkeypatch, {"MAIN": (headers, huge, 200)})
    # Should complete without raising and still detect WordPress + the comment finding.
    res = sf.fingerprint_stack("garbage.example.com", 443)
    nm = names(res)
    assert "WordPress" in nm
    assert "Sensitive Data in HTML Comments" in nm


def test_connection_failure_fails_soft(monkeypatch):
    # _fetch returns ({}, "", 0) on total failure for every URL.
    monkeypatch.setattr(sf, "_fetch", lambda *a, **k: ({}, "", 0))
    res = sf.fingerprint_stack("dead.example.com", 443)
    assert res.target == "dead.example.com"
    assert res.technologies == []
    assert res.waf.detected is False
    assert res.cdn is None and res.cloud_provider is None


def test_http_fallback_when_https_empty(monkeypatch):
    # First (https) fetch returns empty; http fallback returns a real page.
    calls = {"n": 0}
    def fake_fetch(url, payload=None, timeout=8.0):
        if url.startswith("https://") and "?" not in url:
            return ({}, "", 0)
        if url.startswith("http://") and "?" not in url and "/wp-" not in url:
            return ({"server": "nginx/1.0.0"}, "<html>ok</html>", 200)
        return ({}, "", 404)
    monkeypatch.setattr(sf, "_fetch", fake_fetch)
    res = sf.fingerprint_stack("fallback.example.com", 443)
    assert "nginx" in names(res)


# ─── Regex safety: no catastrophic backtracking on adversarial body ───────────

def test_no_pathological_runtime_on_adversarial_body(monkeypatch):
    import time
    # Long runs designed to stress .* style signatures.
    body = ("A" * 100000 + "authenticity_token" + "B" * 100000
            + "<!--" + "x" * 50000)
    install_fetch(monkeypatch, {"MAIN": ({"server": "nginx"}, body, 200)})
    start = time.time()
    sf.fingerprint_stack("adv.example.com", 443)
    assert time.time() - start < 5.0, "body detection too slow — possible backtracking"
