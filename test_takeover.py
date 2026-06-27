"""
Deterministic tests for src/takeover.py — NO real network.

All DNS/HTTP helpers are monkeypatched. The overriding concern is FALSE
POSITIVES: a takeover must be asserted ONLY when a subdomain CNAMEs to a
known service AND that service returns its documented unclaimed fingerprint.
"""

import pytest

from src import takeover
from src.takeover import (
    TakeoverFinding,
    analyze_subdomain,
    check_subdomain_takeovers,
    match_fingerprints,
)


# ─── Fakes ────────────────────────────────────────────────────────────────

class FakeNet:
    """Configurable stand-in for the DNS/HTTP helpers."""

    def __init__(self, cname_map=None, http_map=None, wildcard=None):
        # subdomain -> list[str] CNAME chain
        self.cname_map = cname_map or {}
        # url-prefix (subdomain) -> (body, status)
        self.http_map = http_map or {}
        self.wildcard = wildcard

    def resolve_cname_chain(self, hostname, max_depth=8):
        return list(self.cname_map.get(hostname, []))

    def fetch_body(self, url, timeout=6.0):
        # url looks like "https://sub/" — pull out the host
        host = url.split("://", 1)[-1].rstrip("/")
        return self.http_map.get(host, ("", 0))

    def detect_wildcard_cname(self, target):
        return self.wildcard

    def check_nxdomain(self, hostname):
        return False


@pytest.fixture
def patch_net(monkeypatch):
    def _apply(fake):
        monkeypatch.setattr(takeover, "resolve_cname_chain", fake.resolve_cname_chain)
        monkeypatch.setattr(takeover, "fetch_body", fake.fetch_body)
        monkeypatch.setattr(takeover, "detect_wildcard_cname", fake.detect_wildcard_cname)
        monkeypatch.setattr(takeover, "check_nxdomain", fake.check_nxdomain)
        return fake
    return _apply


# ─── (i) GitHub Pages CNAME + unclaimed fingerprint → VULNERABLE ────────────

def test_github_pages_unclaimed_is_vulnerable(patch_net):
    fake = patch_net(FakeNet(
        cname_map={"docs.example.com": ["example.github.io"]},
        http_map={"docs.example.com": (
            "<html><body>There isn't a GitHub Pages site here.</body></html>", 404)},
    ))
    finding = analyze_subdomain("docs.example.com")
    assert finding is not None
    assert finding.vulnerable is True
    assert finding.confidence == "HIGH"
    assert finding.provider == "GitHub Pages"
    assert finding.status_code == 404


# ─── (ii) SAME CNAME but CLAIMED/serving → NOT vulnerable (FP guard) ─────────

def test_github_pages_claimed_is_not_vulnerable(patch_net):
    fake = patch_net(FakeNet(
        cname_map={"docs.example.com": ["example.github.io"]},
        http_map={"docs.example.com": (
            "<html><body>Welcome to my project documentation!</body></html>", 200)},
    ))
    finding = analyze_subdomain("docs.example.com")
    # CNAME matches a provider but the page is live → MEDIUM/potential, NEVER vulnerable.
    assert finding is not None
    assert finding.vulnerable is False
    assert finding.confidence == "MEDIUM"


def test_claimed_404_page_with_word_netlify_is_not_vulnerable(patch_net):
    """A claimed Netlify site serving a custom 404 mentioning 'netlify' must
    NOT trip — the bare 'netlify' substring was a false-positive generator."""
    fake = patch_net(FakeNet(
        cname_map={"app.example.com": ["example.netlify.app"]},
        http_map={"app.example.com": (
            "<html>Page not found — powered by netlify</html>", 404)},
    ))
    finding = analyze_subdomain("app.example.com")
    assert finding is not None
    assert finding.vulnerable is False


def test_generic_404_body_does_not_match_cargo(patch_net):
    """Generic '404 Not Found' text must not assert a Cargo takeover."""
    fake = patch_net(FakeNet(
        cname_map={"site.example.com": ["foo.cargocollective.com"]},
        http_map={"site.example.com": ("<h1>404 Not Found</h1>", 404)},
    ))
    finding = analyze_subdomain("site.example.com")
    assert finding is not None
    assert finding.vulnerable is False


# ─── (iii) Normal subdomain, no third-party CNAME → not vulnerable ──────────

def test_no_cname_is_safe(patch_net):
    fake = patch_net(FakeNet(cname_map={"www.example.com": []}))
    assert analyze_subdomain("www.example.com") is None


def test_internal_cname_no_provider_no_nxdomain_is_safe(patch_net):
    fake = patch_net(FakeNet(
        cname_map={"www.example.com": ["lb.internal.example.com"]},
    ))
    # check_nxdomain is patched to False (resolves fine), no provider match.
    assert analyze_subdomain("www.example.com") is None


# ─── (iv) NXDOMAIN / network failure → not vulnerable, no crash ─────────────

def test_nxdomain_dangling_cname_is_potential_not_vulnerable(patch_net, monkeypatch):
    fake = patch_net(FakeNet(cname_map={"old.example.com": ["dead.example.net"]}))
    # The final CNAME does not resolve (NXDOMAIN) and matches no provider.
    monkeypatch.setattr(takeover, "check_nxdomain", lambda h: True)
    finding = analyze_subdomain("old.example.com")
    assert finding is not None
    # Dangling DNS is reported but NEVER auto-asserted as vulnerable.
    assert finding.vulnerable is False
    assert "NXDOMAIN" in finding.provider


def test_network_failure_during_fetch_is_not_vulnerable(patch_net):
    """Provider CNAME matches but HTTP fetch fails (empty body/status 0).
    Must be MEDIUM/potential, never vulnerable."""
    fake = patch_net(FakeNet(
        cname_map={"docs.example.com": ["example.github.io"]},
        http_map={},   # fetch_body returns ("", 0)
    ))
    finding = analyze_subdomain("docs.example.com")
    assert finding is not None
    assert finding.vulnerable is False


def test_resolver_exception_does_not_crash(patch_net, monkeypatch):
    def boom(hostname, max_depth=8):
        raise RuntimeError("DNS exploded")
    monkeypatch.setattr(takeover, "resolve_cname_chain", boom)
    # analyze_subdomain must swallow and return None.
    assert analyze_subdomain("x.example.com") is None


# ─── (v) Wildcard DNS → phantom subdomains suppressed ───────────────────────

def test_wildcard_subdomain_is_suppressed(patch_net):
    """Every enumerated name CNAMEs to the same wildcard target; none should
    be flagged, even though the target page shows an unclaimed fingerprint."""
    wildcard_target = "example.github.io"
    fake = patch_net(FakeNet(
        cname_map={
            "random1.example.com": ["example.github.io"],
            "random2.example.com": ["example.github.io"],
        },
        http_map={
            "random1.example.com": ("There isn't a GitHub Pages site here", 404),
            "random2.example.com": ("There isn't a GitHub Pages site here", 404),
        },
        wildcard=wildcard_target,
    ))
    # Passing wildcard target → suppressed.
    assert analyze_subdomain("random1.example.com", wildcard_cname=wildcard_target) is None
    assert analyze_subdomain("random2.example.com", wildcard_cname=wildcard_target) is None


def test_check_subdomain_takeovers_suppresses_wildcard_phantoms(patch_net):
    fake = patch_net(FakeNet(
        cname_map={
            "a.example.com": ["example.github.io"],
            "b.example.com": ["example.github.io"],
        },
        http_map={
            "a.example.com": ("There isn't a GitHub Pages site here", 404),
            "b.example.com": ("There isn't a GitHub Pages site here", 404),
        },
        wildcard="example.github.io",
    ))
    res = check_subdomain_takeovers("example.com",
                                    ["a.example.com", "b.example.com"])
    assert res.vulnerable == []          # NO false positives via wildcard
    assert res.subdomains_checked == 2


def test_check_subdomain_takeovers_real_takeover_no_wildcard(patch_net):
    fake = patch_net(FakeNet(
        cname_map={"docs.example.com": ["example.github.io"]},
        http_map={"docs.example.com": (
            "There isn't a GitHub Pages site here", 404)},
        wildcard=None,
    ))
    res = check_subdomain_takeovers("example.com", ["docs.example.com"])
    assert len(res.vulnerable) == 1
    assert res.vulnerable[0].provider == "GitHub Pages"


# ─── match_fingerprints unit guards ─────────────────────────────────────────

def test_match_fingerprints_requires_body():
    # Empty body (network failure) must never match.
    assert match_fingerprints("", 404, "GitHub Pages") is False


def test_match_fingerprints_requires_status():
    # Correct fingerprint but wrong status (live 200) → no match.
    assert match_fingerprints("There isn't a GitHub Pages site here", 200,
                              "GitHub Pages") is False


def test_match_fingerprints_positive():
    assert match_fingerprints("There isn't a GitHub Pages site here", 404,
                              "GitHub Pages") is True


def test_match_fingerprints_unknown_provider():
    assert match_fingerprints("anything", 404, "NoSuchProvider") is False
