"""
Deterministic unit tests for src/header_audit.py — NO real network.

The HTTP fetch (`fetch_headers`) is monkeypatched so we can feed canned
header sets and assert on the audit result. Focus areas:

  - case-insensitive header lookup
  - HSTS only required over HTTPS (not plain HTTP)
  - weak-value detection (HSTS max-age, CSP unsafe-inline, X-Frame ALLOWALL, cookies)
  - duplicate Set-Cookie handling
  - no crash on empty / garbage headers
  - sane "could not audit" result on fetch failure
  - scoring monotonicity
"""

import importlib

import pytest

ha = importlib.import_module("src.header_audit")


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _canned(headers_dict, status=200, origin="https://evil.bad"):
    """
    Build a (headers, status) tuple as fetch_headers would return it:
    keys lowercased, plus the synthetic _request_origin probe key.
    """
    flat = {k.lower(): v for k, v in headers_dict.items()}
    if origin is not None:
        flat["_request_origin"] = origin
    return flat, status


def _patch_fetch(monkeypatch, mapping):
    """
    Patch fetch_headers to return canned data keyed by URL scheme.
    `mapping` maps a scheme substring ("https://", "http://") to a
    (headers, status) tuple, or None to simulate failure.
    """
    def fake_fetch(url, timeout=8.0):
        for key, val in mapping.items():
            if url.startswith(key):
                if val is None:
                    return {}, 0
                return val
        return {}, 0
    monkeypatch.setattr(ha, "fetch_headers", fake_fetch)


SECURE_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), camera=()",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}


# ─── _flatten_headers / case-insensitivity ───────────────────────────────────

def test_flatten_is_case_insensitive():
    from email.message import Message
    m = Message()
    m["STRICT-Transport-Security"] = "max-age=31536000"
    m["X-Frame-Options"] = "DENY"
    flat = ha._flatten_headers(m)
    assert flat["strict-transport-security"] == "max-age=31536000"
    assert flat["x-frame-options"] == "DENY"


def test_flatten_preserves_duplicate_set_cookie():
    from email.message import Message
    m = Message()
    m["Set-Cookie"] = "a=1; Secure; HttpOnly; SameSite=Strict"
    m["Set-Cookie"] = "b=2"  # insecure
    flat = ha._flatten_headers(m)
    # Both cookies must survive (joined with newline), not just the first.
    assert "a=1" in flat["set-cookie"]
    assert "b=2" in flat["set-cookie"]
    assert "\n" in flat["set-cookie"]


def test_flatten_none_returns_empty():
    assert ha._flatten_headers(None) == {}


def test_mixed_case_lookup_not_reported_missing(monkeypatch):
    # Headers supplied in odd casing must still count as present.
    weird = {h.upper(): v for h, v in SECURE_HEADERS.items()}
    _patch_fetch(monkeypatch, {"https://": _canned(weird)})
    res = ha.audit_headers("example.com", 443)
    assert "strict-transport-security" in res.headers_present
    assert res.headers_missing == []


# ─── HSTS only over HTTPS ────────────────────────────────────────────────────

def test_hsts_required_on_https():
    finding = ha.check_hsts({}, is_https=True)
    assert finding is not None
    assert finding.header == "Strict-Transport-Security"


def test_hsts_not_required_on_http():
    # No HSTS header, but plain HTTP -> must NOT flag (false positive otherwise).
    assert ha.check_hsts({}, is_https=False) is None


def test_http_port_does_not_flag_missing_hsts(monkeypatch):
    # Port 80 -> http scheme. Missing HSTS should not appear as a finding
    # nor in headers_missing.
    _patch_fetch(monkeypatch, {"http://": _canned({"Server": "nginx"})})
    res = ha.audit_headers("example.com", 80)
    titles = [f.title for f in res.findings]
    assert not any("HSTS" in t for t in titles)
    assert "strict-transport-security" not in res.headers_missing


def test_https_port_flags_missing_hsts(monkeypatch):
    _patch_fetch(monkeypatch, {"https://": _canned({"Server": "nginx"})})
    res = ha.audit_headers("example.com", 443)
    titles = [f.title for f in res.findings]
    assert any("HSTS" in t for t in titles)


# ─── Weak-value detection ────────────────────────────────────────────────────

def test_weak_hsts_max_age():
    f = ha.check_hsts({"strict-transport-security": "max-age=100"}, is_https=True)
    assert f is not None and f.present is True
    assert "max-age" in f.detail


def test_csp_unsafe_inline():
    f = ha.check_csp({"content-security-policy": "default-src 'self'; script-src 'unsafe-inline'"})
    assert f is not None and f.present is True
    assert "unsafe-inline" in f.detail


def test_csp_wildcard_script_src_with_other_tokens():
    # Regression: previous regex missed "script-src 'self' *".
    f = ha.check_csp({"content-security-policy": "script-src 'self' *"})
    assert f is not None
    assert "Wildcard" in f.detail


def test_csp_host_wildcard_not_flagged():
    # *.example.com is a host wildcard, not a bare-* origin — no false positive.
    f = ha.check_csp({"content-security-policy": "default-src 'self'; script-src *.example.com"})
    assert f is None


def test_xframe_allowall_is_invalid():
    f = ha.check_xframe({"x-frame-options": "ALLOWALL"})
    assert f is not None and f.present is True
    assert "ALLOWALL" in f.detail or "not a recognized" in f.detail


def test_cookie_samesite_none_without_secure_flagged():
    f_list = ha.check_cookies({"set-cookie": "sid=abc; HttpOnly; SameSite=None"})
    assert any("SameSite=None requires Secure" in f.detail for f in f_list)


def test_cookie_samesite_none_with_secure_not_falsely_flagged():
    # Secure present -> the "requires Secure" warning must NOT appear.
    f_list = ha.check_cookies({"set-cookie": "sid=abc; Secure; HttpOnly; SameSite=None"})
    for f in f_list:
        assert "SameSite=None requires Secure" not in f.detail


def test_duplicate_cookies_each_audited():
    val = ("good=1; Secure; HttpOnly; SameSite=Strict\n"
           "bad=2")
    f_list = ha.check_cookies({"set-cookie": val})
    titles = " ".join(f.title for f in f_list)
    assert "bad" in titles
    assert "good" not in titles  # the secure one produces no finding


# ─── Robustness: empty / garbage / failure ───────────────────────────────────

def test_fetch_failure_yields_sane_result(monkeypatch):
    _patch_fetch(monkeypatch, {"https://": None, "http://": None})
    res = ha.audit_headers("unreachable.invalid", 443)
    assert res.status_code == 0
    assert res.findings == []
    # No misleading "all missing" report — missing list is empty when we
    # could not connect at all.
    assert res.headers_missing == []
    assert res.score == 0


def test_garbage_headers_do_not_crash(monkeypatch):
    garbage = {
        "strict-transport-security": "@@@!!!not-a-policy",
        "content-security-policy": "????",
        "x-frame-options": "\x00\x01weird",
        "set-cookie": "=;;;\n;;;=",
        "referrer-policy": "12345",
        "server": "",
    }
    _patch_fetch(monkeypatch, {"https://": _canned(garbage)})
    res = ha.audit_headers("example.com", 443)  # must not raise
    assert isinstance(res.score, int)
    assert 0 <= res.score <= 100


def test_empty_headers_present_means_connection(monkeypatch):
    # Empty dict from fetch == failure path.
    _patch_fetch(monkeypatch, {"https://": ({}, 0), "http://": ({}, 0)})
    res = ha.audit_headers("example.com", 443)
    assert res.findings == []


# ─── CORS reflection ─────────────────────────────────────────────────────────

def test_cors_reflected_origin_with_credentials_critical(monkeypatch):
    hdrs = {
        "Access-Control-Allow-Origin": ha.PROBE_ORIGIN,
        "Access-Control-Allow-Credentials": "true",
    }
    _patch_fetch(monkeypatch, {"https://": _canned(hdrs)})
    res = ha.audit_headers("example.com", 443)
    assert any(f.severity == "CRITICAL" and "CORS" in f.title for f in res.findings)


# ─── Scoring ─────────────────────────────────────────────────────────────────

def test_secure_site_scores_high(monkeypatch):
    _patch_fetch(monkeypatch, {"https://": _canned(SECURE_HEADERS)})
    res = ha.audit_headers("example.com", 443)
    assert res.score >= 90
    assert res.grade == "A"


def test_bare_site_scores_low(monkeypatch):
    _patch_fetch(monkeypatch, {"https://": _canned({"Server": "Apache/2.4.1"})})
    res = ha.audit_headers("example.com", 443)
    assert res.score < 90


def test_scoring_monotonic():
    # Strictly: adding a finding never increases the score.
    base = []
    s0, _ = ha.calculate_score(base, {})
    more = base + [ha.HeaderFinding(severity="HIGH", header="x", title="t",
                                    detail="d", recommendation="r")]
    s1, _ = ha.calculate_score(more, {})
    evenmore = more + [ha.HeaderFinding(severity="CRITICAL", header="y", title="t",
                                        detail="d", recommendation="r")]
    s2, _ = ha.calculate_score(evenmore, {})
    assert s0 >= s1 >= s2


def test_score_bounds_never_negative():
    findings = [ha.HeaderFinding(severity="CRITICAL", header="x", title="t",
                                 detail="d", recommendation="r")
                for _ in range(20)]
    score, grade = ha.calculate_score(findings, {})
    assert score == 0
    assert grade == "F"


def test_missing_csp_is_medium_hardening_not_proven_xss():
    f = ha.check_csp({})
    assert f is not None and f.present is False
    assert f.severity == "MEDIUM"
    assert "fully vulnerable" not in f.detail.lower()


def test_vercel_challenge_skips_app_header_false_positives(monkeypatch):
    """Challenge interstitials must not produce CORS/CSP 'app is broken' findings."""
    _patch_fetch(monkeypatch, {
        "https://": _canned({
            "Server": "Vercel",
            "X-Vercel-Mitigated": "challenge",
            "X-Vercel-Challenge-Token": "tok",
            "X-Vercel-Id": "id",
            "Access-Control-Allow-Origin": "*",  # must be ignored on challenge
        }, status=403),
    })
    res = ha.audit_headers("example.com", 443)
    titles = [f.title for f in res.findings]
    assert any("challenge" in t.lower() for t in titles)
    assert not any("CORS" in t for t in titles)
    assert not any("Missing Content-Security-Policy" in t for t in titles)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
