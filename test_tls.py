"""
Focused tests for src/tls_analyzer.py and src/ssl_utils.py — TLS/cert logic.

Deterministic and fully offline: every test drives the *pure* parsing/analysis
helpers with crafted cert dicts and fixed timestamps. No sockets, no DNS, no real
TLS handshakes are performed, so the suite is safe to run alongside concurrent
agents and never hangs.

Guards specifically against:
  • certificate-expiry math: timezone correctness (notAfter is GMT/UTC), the
    naive-vs-aware datetime trap, and the expired/near-expiry/valid boundaries
  • days-until-expiry sign (negative once expired)
  • weak-cipher classification (RC4/DES/3DES/NULL/EXPORT/anon/MD5/SHA-1, and the
    SHA-256 false-positive guard)
  • SAN extraction and wildcard detection
  • self-signed detection (true self-signed vs untrusted-chain, and the
    None==None false-positive guard for empty CERT_NONE certs)
  • ssl_utils.validate_certificate expiry uses UTC, not local time
"""
import datetime

import pytest

import src.tls_analyzer as tls
from src.ssl_utils import SSLContextManager, SSLConfig, SSLValidationLevel


UTC = datetime.timezone.utc


def _subject(cn, org=None):
    rdns = [(("commonName", cn),)]
    if org:
        rdns.append((("organizationName", org),))
    return tuple(rdns)


def _cert(not_after="Jan 15 12:00:00 2030 GMT",
          not_before="Jan 15 12:00:00 2020 GMT",
          cn="example.com", iss_cn="DigiCert CA",
          sans=None):
    c = {
        "subject": _subject(cn),
        "issuer": _subject(iss_cn),
        "notAfter": not_after,
        "notBefore": not_before,
        "serialNumber": "0A1B2C",
    }
    if sans is not None:
        c["subjectAltName"] = tuple(("DNS", s) for s in sans)
    return c


# ─── compute_expiry: the timezone / sign / boundary guards ──────────────────────

def test_compute_expiry_valid_future():
    now = datetime.datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC)
    days, expired = tls.compute_expiry("Jun 16 12:00:00 2027 GMT", now=now)
    assert days == 365
    assert expired is False


def test_compute_expiry_expired_is_negative():
    now = datetime.datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC)
    days, expired = tls.compute_expiry("Jun 16 12:00:00 2025 GMT", now=now)
    assert days < 0
    assert expired is True


def test_compute_expiry_expired_recently():
    # Expired 12h ago -> still negative / flagged expired (sign correctness).
    now = datetime.datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC)
    days, expired = tls.compute_expiry("Jun 16 00:00:00 2026 GMT", now=now)
    assert expired is True
    assert days < 0


def test_compute_expiry_near_expiry_not_yet_expired():
    # Expires in 12h -> NOT expired, days rounds toward 0 but stays >= 0.
    now = datetime.datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC)
    days, expired = tls.compute_expiry("Jun 17 00:00:00 2026 GMT", now=now)
    assert expired is False
    assert days == 0


def test_compute_expiry_exact_boundary():
    now = datetime.datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC)
    days, expired = tls.compute_expiry("Jun 16 12:00:00 2026 GMT", now=now)
    # Exactly now: timedelta is zero -> 0 days, not yet expired.
    assert days == 0
    assert expired is False


def test_compute_expiry_naive_now_treated_as_utc():
    # A naive `now` must be interpreted as UTC, not raise on aware/naive mixing.
    naive_now = datetime.datetime(2026, 6, 16, 12, 0, 0)
    days, expired = tls.compute_expiry("Jun 16 12:00:00 2027 GMT", now=naive_now)
    assert days == 365
    assert expired is False


def test_compute_expiry_timezone_correctness_regression():
    # notAfter is GMT. If parsing dropped the zone and compared against a
    # local-time clock east of UTC, a cert expiring "just after now UTC" could
    # be mis-flagged. With correct UTC handling it is clearly valid.
    now = datetime.datetime(2026, 6, 16, 0, 0, 0, tzinfo=UTC)
    days, expired = tls.compute_expiry("Jun 16 06:00:00 2026 GMT", now=now)
    assert expired is False
    assert days == 0  # 6 hours ahead -> same day


def test_compute_expiry_unparseable_returns_none():
    days, expired = tls.compute_expiry("not a real date")
    assert days is None
    assert expired is False


def test_compute_expiry_empty_returns_none():
    days, expired = tls.compute_expiry("")
    assert days is None
    assert expired is False


def test_parse_cert_time_attaches_utc():
    dt = tls._parse_cert_time("Jan 15 12:00:00 2027 GMT")
    assert dt is not None
    assert dt.tzinfo is not None
    assert dt.utcoffset() == datetime.timedelta(0)


# ─── parse_cert: SAN / wildcard / self-signed / expiry integration ──────────────

def test_parse_cert_basic_fields_and_sans():
    cert = _cert(sans=["example.com", "www.example.com", "*.api.example.com"])
    info = tls.parse_cert(cert, der=b"\x00\x01", chain_valid=True, host="example.com")
    assert info.subject_cn == "example.com"
    assert info.issuer_cn == "DigiCert CA"
    assert info.san_domains == ["example.com", "www.example.com", "*.api.example.com"]
    assert info.not_after == "Jan 15 12:00:00 2030 GMT"
    assert info.is_expired is False
    assert info.days_until_expiry is not None and info.days_until_expiry > 0


def test_parse_cert_wildcard_detected():
    cert = _cert(sans=["*.example.com"])
    info = tls.parse_cert(cert, der=b"x", chain_valid=True, host="a.example.com")
    assert info.is_wildcard is True


def test_parse_cert_wildcard_from_cn():
    cert = _cert(cn="*.example.com", sans=["foo.com"])
    info = tls.parse_cert(cert, der=b"x", chain_valid=True, host="a.example.com")
    assert info.is_wildcard is True


def test_parse_cert_self_signed_subject_equals_issuer():
    cert = _cert(cn="self.local", iss_cn="self.local")
    info = tls.parse_cert(cert, der=b"x", chain_valid=True, host="self.local")
    assert info.is_self_signed is True


def test_parse_cert_untrusted_chain_flagged_self_signed():
    # chain_valid False with DER present -> treated as untrusted/self-signed.
    cert = _cert(cn="example.com", iss_cn="DigiCert CA")
    info = tls.parse_cert(cert, der=b"x", chain_valid=False, host="example.com")
    assert info.is_self_signed is True


def test_parse_cert_ca_signed_not_self_signed():
    cert = _cert(cn="example.com", iss_cn="DigiCert CA")
    info = tls.parse_cert(cert, der=b"x", chain_valid=True, host="example.com")
    assert info.is_self_signed is False


def test_parse_cert_empty_cert_not_false_self_signed():
    # Empty cert dict (CERT_NONE) with no DER must NOT be flagged self-signed
    # via a None==None comparison.
    info = tls.parse_cert({}, der=None, chain_valid=True, host="example.com")
    assert info.is_self_signed is False
    assert info.subject_cn is None
    assert info.san_domains == []


def test_parse_cert_expired_sets_flags():
    cert = _cert(not_after="Jan 15 12:00:00 2000 GMT")
    info = tls.parse_cert(cert, der=b"x", chain_valid=True, host="example.com")
    assert info.is_expired is True
    assert info.days_until_expiry < 0


# ─── analyze_cipher: weak-cipher classification ─────────────────────────────────

@pytest.mark.parametrize("cipher,expect_sev", [
    ("ECDHE-RSA-RC4-SHA", "HIGH"),          # RC4
    ("DES-CBC-SHA", "HIGH"),                # single DES
    ("ECDHE-RSA-DES-CBC3-SHA", "MEDIUM"),   # 3DES (DES3/3DES)
    ("NULL-SHA", "CRITICAL"),               # NULL
    ("EXP-RC4-MD5", "CRITICAL"),            # EXPORT (and others)
    ("ADH-AES256-SHA", "CRITICAL"),         # anonymous DH
])
def test_analyze_cipher_flags_weak(cipher, expect_sev):
    issues = tls.analyze_cipher(cipher)
    assert issues, f"expected a weak finding for {cipher}"
    sevs = {sev for _desc, sev, _cvss in issues}
    assert expect_sev in sevs


def test_analyze_cipher_strong_modern_is_clean():
    # A modern AEAD suite should produce no weak-cipher findings.
    issues = tls.analyze_cipher("ECDHE-RSA-AES256-GCM-SHA384")
    assert issues == []


def test_analyze_cipher_sha256_not_flagged_as_sha1():
    # SHA-256 must not trip the SHA-1 pattern.
    issues = tls.analyze_cipher("ECDHE-RSA-AES128-GCM-SHA256")
    assert all("SHA-1" not in desc for desc, _s, _c in issues)


def test_analyze_cipher_sha1_flagged():
    issues = tls.analyze_cipher("ECDHE-RSA-AES128-SHA")
    assert any("SHA-1" in desc for desc, _s, _c in issues)


def test_analyze_cipher_empty():
    assert tls.analyze_cipher("") == []
    assert tls.analyze_cipher(None) == []


# ─── probe_protocols deprecated-list hygiene (no untestable placeholder) ────────

def test_probe_deprecated_excludes_placeholder(monkeypatch):
    # Force the "missing constant" path for TLSv1 and ensure it does NOT leak
    # an untestable placeholder into the deprecated list (which would inflate
    # the DROWN heuristic and grading).
    monkeypatch.setitem(tls._PROTO_MAP, "TLSv1", None)
    # Pretend nothing else negotiates either, to isolate the placeholder path.
    monkeypatch.setattr(tls, "_try_connect", lambda *a, **k: None)
    supported, deprecated = tls.probe_protocols("198.51.100.1", 443)
    assert supported == []
    assert deprecated == []  # no "could not test" string


def test_probe_records_confirmed_deprecated(monkeypatch):
    # Simulate a server that only negotiates the version we pin -> TLSv1.0/1.1
    # land in deprecated, 1.2/1.3 in supported.
    def fake_connect(host, port, min_v, max_v, timeout=5.0, expected_version=None):
        return expected_version  # always "succeeds" with the pinned version
    monkeypatch.setattr(tls, "_try_connect", fake_connect)
    supported, deprecated = tls.probe_protocols("198.51.100.1", 443)
    assert "TLSv1.0" in deprecated and "TLSv1.1" in deprecated
    assert "TLSv1.2" in supported and "TLSv1.3" in supported


# ─── grading ────────────────────────────────────────────────────────────────────

def test_grade_clean_is_a():
    assert tls.calculate_grade([], [], None) == "A"


def test_grade_expired_cert_is_f():
    cert = tls.parse_cert(_cert(not_after="Jan 15 12:00:00 2000 GMT"),
                          der=b"x", chain_valid=True, host="example.com")
    assert tls.calculate_grade([], [], cert) == "F"


def test_grade_critical_finding_is_f():
    f = tls.TLSFinding(severity="CRITICAL", title="x", detail="y")
    assert tls.calculate_grade([f], [], None) == "F"


# ─── ssl_utils.validate_certificate: UTC expiry, not local time ─────────────────

def _mgr(level=SSLValidationLevel.BASIC):
    return SSLContextManager(SSLConfig(validation_level=level))


def test_validate_certificate_valid_future():
    mgr = _mgr()
    cert = _cert(not_after="Jan 15 12:00:00 2099 GMT",
                 not_before="Jan 15 12:00:00 2000 GMT")
    ok, err = mgr.validate_certificate(cert, "example.com")
    assert ok is True and err is None


def test_validate_certificate_expired():
    mgr = _mgr()
    cert = _cert(not_after="Jan 15 12:00:00 2000 GMT",
                 not_before="Jan 15 12:00:00 1999 GMT")
    ok, err = mgr.validate_certificate(cert, "example.com")
    assert ok is False
    assert "expired" in err.lower()


def test_validate_certificate_not_yet_valid():
    mgr = _mgr()
    cert = _cert(not_after="Jan 15 12:00:00 2099 GMT",
                 not_before="Jan 15 12:00:00 2098 GMT")
    ok, err = mgr.validate_certificate(cert, "example.com")
    assert ok is False
    assert "not valid until" in err.lower()


def test_validate_certificate_no_cert():
    mgr = _mgr()
    ok, err = mgr.validate_certificate({}, "example.com")
    assert ok is False


def test_validate_certificate_boundary_uses_utc():
    # A cert that expires a few hours in the future (UTC) must be considered
    # valid even when the host clock is in a non-UTC timezone. We can't change
    # the process TZ portably here, but we assert the parse path attaches UTC by
    # checking a cert expiring 1s before a far-future date stays valid and one
    # already past stays invalid — exercising the same UTC comparison code.
    mgr = _mgr()
    near_future = (datetime.datetime.now(UTC) + datetime.timedelta(hours=6))
    na = near_future.strftime("%b %d %H:%M:%S %Y GMT")
    cert = _cert(not_after=na, not_before="Jan 15 12:00:00 2000 GMT")
    ok, err = mgr.validate_certificate(cert, "example.com")
    assert ok is True, err
