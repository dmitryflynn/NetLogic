"""
Deterministic unit tests for src/osint.py — NO real network.

All network/DNS helpers are monkeypatched so the precision-critical logic can be
exercised against canned data: canned DoH answers, a wildcard-DNS scenario, an
ASN JSON blob (well-formed and missing-fields), and TXT/HTML containing a mix of
real and bogus email-like strings.

Guards (false data is the cardinal sin):
  * wildcard DNS does not yield false subdomains
  * substring look-alikes are not treated as subdomains
  * historical CT names that no longer resolve are dropped
  * emails are scoped/validated to the target domain
  * ASN parsing survives missing/garbage fields
  * a total failure yields a valid, empty OSINTResult (no crash)
"""
import json
import pytest

from src import osint
from src.osint import (
    OSINTResult,
    ASNInfo,
    DNSRecord,
    SubdomainEntry,
    enumerate_dns,
    fetch_ct_subdomains,
    lookup_asn,
    extract_emails_from_records,
    run_osint,
    _belongs_to_domain,
    _parse_asn_org,
    _clean_dns_value,
)


# ─── helpers ──────────────────────────────────────────────────────────────────

class FakeResp:
    """Minimal context-manager stand-in for urlopen()'s return value."""
    def __init__(self, payload):
        self._payload = payload.encode() if isinstance(payload, str) else payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._payload


# ─── domain suffix matching (subdomain precision core) ──────────────────────────

def test_belongs_to_domain_true_cases():
    assert _belongs_to_domain("example.com", "example.com")
    assert _belongs_to_domain("www.example.com", "example.com")
    assert _belongs_to_domain("a.b.example.com", "example.com")
    assert _belongs_to_domain("EXAMPLE.COM.", "example.com")  # case/trailing dot


def test_belongs_to_domain_rejects_substring_lookalikes():
    # The cardinal-sin cases the old `domain in name` substring check allowed.
    assert not _belongs_to_domain("notexample.com", "example.com")
    assert not _belongs_to_domain("example.com.evil.org", "example.com")
    assert not _belongs_to_domain("fooexample.com", "example.com")


# ─── DNS enumeration: dedup + TXT cleaning ──────────────────────────────────────

def test_clean_dns_value_strips_txt_quotes_and_root_dot():
    assert _clean_dns_value("A", "1.2.3.4.") == "1.2.3.4"
    assert _clean_dns_value("TXT", '"v=spf1 -all"') == "v=spf1 -all"
    # chunked TXT
    assert _clean_dns_value("TXT", '"abc" "def"') == "abcdef"


def test_enumerate_dns_dedupes(monkeypatch):
    def fake_doh(name, rtype):
        if rtype == "A":
            return ["1.2.3.4", "1.2.3.4", "5.6.7.8"]  # duplicate
        return []
    monkeypatch.setattr(osint, "query_dns_doh", fake_doh)
    recs = enumerate_dns("example.com")
    a_vals = sorted(r.value for r in recs if r.record_type == "A")
    assert a_vals == ["1.2.3.4", "5.6.7.8"]


# ─── CT subdomains: wildcard + non-resolving guards ─────────────────────────────

CT_BLOB = json.dumps([
    {"name_value": "www.example.com\n*.example.com"},
    {"name_value": "dead.example.com"},          # historical, no longer resolves
    {"name_value": "wild.example.com"},           # resolves only to wildcard sink
    {"name_value": "evil-example.com.attacker.org"},  # substring look-alike
    {"name_value": "notexample.com"},             # substring look-alike
    "garbage-not-a-dict",
])


def _patch_ct(monkeypatch, resolve_map, wildcard_ip=None):
    monkeypatch.setattr(
        osint.urllib.request, "urlopen",
        lambda req, timeout=0: FakeResp(CT_BLOB),
    )
    monkeypatch.setattr(osint, "_detect_wildcard_ip", lambda d: wildcard_ip)
    monkeypatch.setattr(osint, "_resolve_host", lambda n, timeout=3.0: resolve_map.get(n))


def test_ct_only_reports_resolving_in_scope_names(monkeypatch):
    resolve_map = {
        "www.example.com": "1.1.1.1",
        # dead.example.com intentionally absent -> None -> dropped
    }
    _patch_ct(monkeypatch, resolve_map)
    entries = fetch_ct_subdomains("example.com")
    names = {e.subdomain for e in entries}
    assert names == {"www.example.com"}
    # historical non-resolving name dropped
    assert "dead.example.com" not in names
    # substring look-alikes never appear
    assert "notexample.com" not in names
    assert "evil-example.com.attacker.org" not in names


def test_ct_wildcard_dns_yields_no_false_subdomains(monkeypatch):
    # Every name resolves to the same wildcard sink IP.
    wildcard = "9.9.9.9"
    resolve_map = {
        "www.example.com": wildcard,
        "dead.example.com": wildcard,
        "wild.example.com": wildcard,
    }
    _patch_ct(monkeypatch, resolve_map, wildcard_ip=wildcard)
    entries = fetch_ct_subdomains("example.com")
    # Names resolving ONLY to the wildcard sink are not real evidence.
    assert entries == []


def test_ct_wildcard_keeps_distinct_real_host(monkeypatch):
    wildcard = "9.9.9.9"
    resolve_map = {
        "www.example.com": "1.1.1.1",   # real, distinct IP
        "wild.example.com": wildcard,   # wildcard sink -> drop
    }
    _patch_ct(monkeypatch, resolve_map, wildcard_ip=wildcard)
    entries = fetch_ct_subdomains("example.com")
    assert {e.subdomain for e in entries} == {"www.example.com"}


def test_ct_network_failure_returns_empty(monkeypatch):
    def boom(req, timeout=0):
        raise OSError("network down")
    monkeypatch.setattr(osint.urllib.request, "urlopen", boom)
    assert fetch_ct_subdomains("example.com") == []


def test_ct_garbage_json_does_not_crash(monkeypatch):
    monkeypatch.setattr(
        osint.urllib.request, "urlopen",
        lambda req, timeout=0: FakeResp('{"not": "a list"}'),
    )
    assert fetch_ct_subdomains("example.com") == []


# ─── ASN parsing robustness ─────────────────────────────────────────────────────

def test_parse_asn_wellformed():
    info = _parse_asn_org({"org": "AS13335 Cloudflare, Inc.", "country": "US"})
    assert info.asn == "AS13335"
    assert info.org == "Cloudflare, Inc."
    assert info.country == "US"


def test_parse_asn_missing_fields():
    info = _parse_asn_org({})
    assert isinstance(info, ASNInfo)
    assert info.asn == "" and info.org == "" and info.country == "" and info.cidr == ""


def test_parse_asn_org_without_asn_prefix_not_mislabeled():
    # No 'ASxxxx' prefix -> do NOT shove the org name into the asn field.
    info = _parse_asn_org({"org": "Hetzner Online GmbH", "country": "DE"})
    assert info.asn == ""
    assert info.org == "Hetzner Online GmbH"


def test_parse_asn_garbage_types_survive():
    info = _parse_asn_org({"org": 12345, "country": None})
    assert isinstance(info, ASNInfo)
    assert info.country == ""


def test_lookup_asn_network_failure_returns_none(monkeypatch):
    def boom(req, timeout=0):
        raise OSError("dns fail")
    monkeypatch.setattr(osint.urllib.request, "urlopen", boom)
    assert lookup_asn("1.2.3.4") is None


def test_lookup_asn_empty_ip_returns_none():
    assert lookup_asn("") is None


# ─── email scoping / validation ─────────────────────────────────────────────────

def test_emails_scoped_to_target_domain():
    records = [
        DNSRecord("SOA", "ns1.example.com hostmaster@example.com 2024"),
        DNSRecord("TXT", "v=spf1 include:_spf.google.com -all"),
        DNSRecord("TXT", "v=DMARC1; p=reject; rua=mailto:dmarc@vendor.net"),
        DNSRecord("TXT", "contact admin@example.com for info"),
    ]
    emails = extract_emails_from_records(records, domain="example.com")
    # In-scope, real mailboxes only.
    assert set(emails) == {"hostmaster@example.com", "admin@example.com"}
    # Third-party DMARC sink is excluded.
    assert "dmarc@vendor.net" not in emails


def test_emails_unscoped_still_drops_spf_mechanism_noise():
    records = [DNSRecord("TXT", "v=spf1 include:_spf.google.com ip4:1.2.3.4 -all")]
    emails = extract_emails_from_records(records)  # no domain scope
    # 'include:_spf.google.com' must not be harvested as include@... noise.
    assert all("@" in e and not e.startswith("include@") for e in emails)


def test_emails_no_records_is_empty():
    assert extract_emails_from_records([], domain="example.com") == []


# ─── full orchestrator: total failure -> valid empty result ─────────────────────

def test_run_osint_total_failure_is_valid_empty(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("all sources down")
    monkeypatch.setattr(osint, "enumerate_dns", boom)
    monkeypatch.setattr(osint, "fetch_ct_subdomains", boom)
    monkeypatch.setattr(osint, "lookup_asn", boom)
    monkeypatch.setattr(osint, "fingerprint_http", boom)
    monkeypatch.setattr(osint, "_resolve_host", lambda n, timeout=3.0: None)

    res = run_osint("example.com", ip="1.2.3.4")
    assert isinstance(res, OSINTResult)
    assert res.target == "example.com"
    assert res.dns_records == []
    assert res.subdomains == []
    assert res.asn_info is None
    assert res.technologies == []
    assert res.emails == []
    assert res.certificate_names == []


def test_run_osint_happy_path_dedups_and_scopes(monkeypatch):
    monkeypatch.setattr(osint, "enumerate_dns", lambda t: [
        DNSRecord("TXT", "admin@example.com and stray@other.com"),
    ])
    monkeypatch.setattr(osint, "fetch_ct_subdomains", lambda t: [
        SubdomainEntry("www.example.com", "1.1.1.1"),
        SubdomainEntry("www.example.com", "1.1.1.1"),  # dup
    ])
    monkeypatch.setattr(osint, "lookup_asn", lambda ip: ASNInfo("AS1", "Org", "US", ""))
    monkeypatch.setattr(osint, "fingerprint_http", lambda t: ["nginx", "nginx", "PHP"])

    res = run_osint("example.com", ip="1.2.3.4")
    assert res.technologies == ["nginx", "PHP"]              # deduped, order kept
    assert res.emails == ["admin@example.com"]               # other.com dropped
    assert res.certificate_names == ["www.example.com"]      # deduped
    assert res.asn_info.asn == "AS1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
