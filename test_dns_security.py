"""
Deterministic, offline tests for src/dns_security.py.

NO real network: every test monkeypatches the single resolution chokepoint
(`_doh`) so canned DNS answers (or a simulated resolver failure) can be fed in.

Focus areas (per audit):
  * SPF 'all' policy classification: -all / ~all / ?all / +all / missing
  * DMARC policy: reject / quarantine / none / absent
  * DKIM present vs not-probed
  * Resolver / timeout FAILURE must NOT produce false 'missing/insecure'
    findings — it must surface as lookup_failed (unknown state).
  * No crash on malformed records; orchestrator never raises.
"""

import pytest

import src.dns_security as dns
from src.dns_security import DNSLookupError


# ─── DoH fakes ───────────────────────────────────────────────────────────────

def _answer(data):
    return {"data": data}


def make_doh(table, fail=False, fail_types=None):
    """Build a fake _doh.

    table: dict keyed by (name, rtype) -> list[answer-dict]. Missing key = NXDOMAIN
           (authoritative empty answer).
    fail:  if True, every lookup raises DNSLookupError (total resolver failure).
    fail_types: set of rtypes that should raise DNSLookupError (selective failure).
    """
    fail_types = fail_types or set()

    def _fake(name, rtype):
        if fail:
            raise DNSLookupError(f"simulated total failure for {name}/{rtype}")
        if rtype in fail_types:
            raise DNSLookupError(f"simulated {rtype} failure for {name}")
        return table.get((name, rtype), [])

    return _fake


def patch_doh(monkeypatch, fake):
    monkeypatch.setattr(dns, "_doh", fake)


# ─── SPF policy classification ────────────────────────────────────────────────

def _spf(monkeypatch, record):
    patch_doh(monkeypatch, make_doh({("d.test", "TXT"): [_answer(record)]}))
    return dns.check_spf("d.test")


def test_spf_hardfail_minus_all(monkeypatch):
    r = _spf(monkeypatch, "v=spf1 include:_spf.google.com -all")
    assert r.present and r.lookup_failed is False
    assert r.all_mechanism == "-all"
    assert r.valid is True
    # -all is correct: no SPF policy finding emitted.
    assert not any(f.category == "SPF" for f in r.findings)


def test_spf_softfail_tilde_all(monkeypatch):
    r = _spf(monkeypatch, "v=spf1 mx ~all")
    assert r.all_mechanism == "~all"
    assert any(f.title == "Weak SPF Policy (Softfail)" for f in r.findings)


def test_spf_neutral_question_all(monkeypatch):
    r = _spf(monkeypatch, "v=spf1 a ?all")
    assert r.all_mechanism == "?all"
    assert any(f.title == "Neutral SPF Policy" for f in r.findings)


def test_spf_passall_critical(monkeypatch):
    r = _spf(monkeypatch, "v=spf1 +all")
    assert r.all_mechanism == "+all"
    assert r.valid is False
    assert any(f.severity == "CRITICAL" for f in r.findings)


def test_spf_missing_record(monkeypatch):
    # Authoritative empty answer => genuinely absent => HIGH finding, NOT a failure.
    patch_doh(monkeypatch, make_doh({}))
    r = dns.check_spf("d.test")
    assert r.present is False
    assert r.lookup_failed is False
    assert any(f.title == "Missing SPF Record" for f in r.findings)


def test_spf_all_not_matched_in_include_hostname(monkeypatch):
    # 'include:sendall.example.com' must NOT be parsed as an 'all' mechanism.
    r = _spf(monkeypatch, "v=spf1 include:sendall.example.com -all")
    assert r.all_mechanism == "-all"


def test_spf_lookup_failure_is_not_missing(monkeypatch):
    # Resolver failure must NOT assert 'Missing SPF'.
    patch_doh(monkeypatch, make_doh({}, fail=True))
    r = dns.check_spf("d.test")
    assert r.lookup_failed is True
    assert r.present is False
    assert r.findings == []  # no false finding


def test_spf_multichunk_txt_concatenation(monkeypatch):
    # Long TXT split into quoted chunks must be joined before parsing.
    patch_doh(monkeypatch, make_doh(
        {("d.test", "TXT"): [_answer('"v=spf1 include:a.com " "include:b.com -all"')]}
    ))
    r = dns.check_spf("d.test")
    assert r.present is True
    assert r.all_mechanism == "-all"
    assert "a.com" in r.includes and "b.com" in r.includes


def test_spf_excessive_lookups(monkeypatch):
    rec = "v=spf1 " + " ".join(f"include:h{i}.com" for i in range(11)) + " -all"
    r = _spf(monkeypatch, rec)
    assert any(f.title == "Excessive SPF Lookups" for f in r.findings)


# ─── DMARC policy classification ──────────────────────────────────────────────

def _dmarc(monkeypatch, record, name="_dmarc.d.test"):
    patch_doh(monkeypatch, make_doh({(name, "TXT"): [_answer(record)]}))
    return dns.check_dmarc("d.test")


def test_dmarc_reject(monkeypatch):
    r = _dmarc(monkeypatch, "v=DMARC1; p=reject; rua=mailto:a@d.test")
    assert r.present and r.policy == "reject" and r.valid is True
    assert not any(f.title.startswith("DMARC Policy") for f in r.findings)


def test_dmarc_none_flagged(monkeypatch):
    r = _dmarc(monkeypatch, "v=DMARC1; p=none; rua=mailto:a@d.test")
    assert r.policy == "none"
    assert any(f.title == "DMARC Policy is 'None'" for f in r.findings)


def test_dmarc_quarantine(monkeypatch):
    r = _dmarc(monkeypatch, "v=DMARC1; p=quarantine; rua=mailto:a@d.test")
    assert r.policy == "quarantine" and r.valid is True


def test_dmarc_absent(monkeypatch):
    patch_doh(monkeypatch, make_doh({}))
    r = dns.check_dmarc("d.test")
    assert r.present is False and r.lookup_failed is False
    assert any(f.title == "Missing DMARC Record" for f in r.findings)


def test_dmarc_lookup_failure_is_not_missing(monkeypatch):
    patch_doh(monkeypatch, make_doh({}, fail=True))
    r = dns.check_dmarc("d.test")
    assert r.lookup_failed is True
    assert r.present is False
    assert r.findings == []


def test_dmarc_org_fallback_failure_not_missing(monkeypatch):
    # Apex _dmarc authoritatively absent, but org-domain fallback lookup fails.
    # Must be inconclusive (lookup_failed), NOT 'Missing DMARC'.
    calls = {"n": 0}

    def fake(name, rtype):
        calls["n"] += 1
        if name == "_dmarc.sub.example.com":
            return []  # authoritative empty
        raise DNSLookupError("org fallback failed")

    patch_doh(monkeypatch, fake)
    r = dns.check_dmarc("sub.example.com")
    assert r.lookup_failed is True
    assert r.findings == []


def test_dmarc_invalid_pct(monkeypatch):
    r = _dmarc(monkeypatch, "v=DMARC1; p=reject; pct=abc; rua=mailto:a@d.test")
    assert r.pct == 100
    assert any(f.title == "Invalid DMARC pct Tag" for f in r.findings)


def test_dmarc_subdomain_policy_none(monkeypatch):
    r = _dmarc(monkeypatch, "v=DMARC1; p=reject; sp=none; rua=mailto:a@d.test")
    assert r.subdomain_policy == "none"
    assert any(f.title == "Weak DMARC Subdomain Policy" for f in r.findings)


def test_dmarc_case_insensitive(monkeypatch):
    r = _dmarc(monkeypatch, "v=DMARC1; P=Reject; RUA=mailto:a@d.test")
    assert r.policy == "reject" and r.valid is True


# ─── DKIM ─────────────────────────────────────────────────────────────────────

def test_dkim_present(monkeypatch):
    sel = "google"
    key = "v=DKIM1; k=rsa; p=" + "A" * 400
    patch_doh(monkeypatch, make_doh(
        {(f"{sel}._domainkey.d.test", "TXT"): [_answer(key)]}
    ))
    r = dns.check_dkim("d.test")
    assert sel in r.found_selectors
    assert r.lookup_failed is False
    assert not any(f.title == "No DKIM Selectors Found" for f in r.findings)


def test_dkim_not_probed_authoritative_absent(monkeypatch):
    # All selectors authoritatively absent => genuine 'no DKIM' (MEDIUM finding),
    # NOT a lookup failure.
    patch_doh(monkeypatch, make_doh({}))
    r = dns.check_dkim("d.test")
    assert r.found_selectors == []
    assert r.lookup_failed is False
    assert any(f.title == "No DKIM Selectors Found" for f in r.findings)


def test_dkim_lookup_failure_is_not_absent(monkeypatch):
    # Every selector probe errors => cannot assert DKIM absent.
    patch_doh(monkeypatch, make_doh({}, fail=True))
    r = dns.check_dkim("d.test")
    assert r.lookup_failed is True
    assert r.found_selectors == []
    assert not any(f.title == "No DKIM Selectors Found" for f in r.findings)


def test_dkim_revoked_key(monkeypatch):
    sel = "default"
    patch_doh(monkeypatch, make_doh(
        {(f"{sel}._domainkey.d.test", "TXT"): [_answer("v=DKIM1; k=rsa; p=")]}
    ))
    r = dns.check_dkim("d.test")
    assert sel in r.found_selectors
    assert any(f.title == "Revoked DKIM Key" for f in r.findings)


# ─── DNSSEC ───────────────────────────────────────────────────────────────────

def test_dnssec_enabled(monkeypatch):
    patch_doh(monkeypatch, make_doh({("d.test", "DS"): [_answer("12345 13 2 abcd")]}))
    r = dns.check_dnssec("d.test")
    assert r.enabled is True and r.lookup_failed is False
    assert r.issues == []


def test_dnssec_absent(monkeypatch):
    patch_doh(monkeypatch, make_doh({}))
    r = dns.check_dnssec("d.test")
    assert r.enabled is False and r.lookup_failed is False
    assert any("DNSSEC not enabled" in i for i in r.issues)


def test_dnssec_lookup_failure_not_disabled(monkeypatch):
    patch_doh(monkeypatch, make_doh({}, fail=True))
    r = dns.check_dnssec("d.test")
    assert r.lookup_failed is True
    assert r.enabled is False
    assert r.issues == []  # no false 'not enabled'


# ─── Spoofability scoring ─────────────────────────────────────────────────────

def test_spoofability_lookup_failure_not_scored(monkeypatch):
    # All three failed => score 0, NOT a false 'spoofable'.
    spf = dns.SPFResult(lookup_failed=True)
    dkim = dns.DKIMResult(lookup_failed=True)
    dmarc = dns.DMARCResult(lookup_failed=True)
    spoofable, score = dns.calculate_spoofability(spf, dkim, dmarc)
    assert score == 0 and spoofable is False


def test_spoofability_genuinely_open(monkeypatch):
    spf = dns.SPFResult()        # not present
    dkim = dns.DKIMResult()      # no selectors
    dmarc = dns.DMARCResult()    # not present
    spoofable, score = dns.calculate_spoofability(spf, dkim, dmarc)
    assert spoofable is True and score == 10


# ─── Orchestrator: fail-soft + no false findings on total resolver failure ────

def test_orchestrator_total_failure_no_false_findings(monkeypatch):
    # Every DNS lookup fails. The scan must NOT crash and must NOT emit any
    # 'missing/insecure/spoofable' finding.
    patch_doh(monkeypatch, make_doh({}, fail=True))
    # socket.gethostbyname is only reached via MX/zone-transfer; guard it too.
    monkeypatch.setattr(dns.socket, "gethostbyname",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("no net")))
    res = dns.check_dns_security("d.test")
    assert res.spf.lookup_failed and res.dmarc.lookup_failed
    assert res.dkim.lookup_failed and res.dnssec.lookup_failed
    assert res.caa.lookup_failed
    assert res.wildcard_dns is False
    assert res.email_spoofable is False
    assert res.findings == []  # cardinal sin avoided: zero false positives


def test_orchestrator_does_not_raise_on_wildcard_failure(monkeypatch):
    # Only the wildcard A query fails; everything else authoritatively absent.
    # Previously this raised DNSLookupError out of the orchestrator.
    patch_doh(monkeypatch, make_doh({}, fail_types={"A"}))
    monkeypatch.setattr(dns.socket, "gethostbyname",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("no net")))
    res = dns.check_dns_security("d.test")  # must not raise
    assert res.wildcard_dns is False


def test_orchestrator_malformed_records_no_crash(monkeypatch):
    table = {
        ("d.test", "TXT"): [_answer('"v=spf1"'), _answer("garbage not spf")],
        ("_dmarc.d.test", "TXT"): [_answer("v=DMARC1; p=; pct=; sp=")],
        ("d.test", "DS"): [_answer("")],
    }
    patch_doh(monkeypatch, make_doh(table))
    monkeypatch.setattr(dns.socket, "gethostbyname",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("no net")))
    res = dns.check_dns_security("d.test")  # must not raise
    assert res.domain == "d.test"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
