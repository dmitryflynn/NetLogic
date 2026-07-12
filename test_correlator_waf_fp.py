"""Regression: a WAF/CDN challenge response must NOT be fingerprinted as a vulnerable appliance.

Root cause (real zipenvy scan): a Vercel Security Checkpoint 403 had its X-Vercel-Challenge-Token
'2.1783577134.60' parsed as a version, and the 2-char key 'f5' matched a hex substring inside the
token → false F5 BIG-IP RCE criticals (CVE-2020-5902/CVE-2022-1388). That's the exact 'worse than
nuclei' false positive; these tests pin it shut.
"""
from src.cve_correlator import _is_challenge_banner, _plausible_version, extract_product_version


_VERCEL_CHALLENGE = (
    "HTTP/1.1 403 Forbidden\r\nServer: Vercel\r\n"
    "X-Vercel-Challenge-Token: 2.1783577134.60.MDVlNTBlZ2e467ff54b61a5118437c673\r\n"
    "X-Vercel-Mitigated: challenge\r\n\r\n"
    "<title>Vercel Security Checkpoint</title>")


def test_vercel_challenge_yields_no_product():
    prod, ver = extract_product_version(_VERCEL_CHALLENGE)
    assert prod is None and ver is None          # the WAF page is not the origin service


def test_challenge_detector_covers_common_wafs():
    assert _is_challenge_banner(_VERCEL_CHALLENGE)
    assert _is_challenge_banner("Attention Required! | Cloudflare  cf-mitigated: challenge")
    assert _is_challenge_banner("Just a moment... __cf_chl_tk")
    assert not _is_challenge_banner("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0")


def test_implausible_version_rejected():
    assert _plausible_version("2.1783577134.60") is None    # 10-digit token component
    assert _plausible_version("99999.1") is None            # > 65535
    assert _plausible_version("16.1.2") == "16.1.2"         # a real version survives
    assert _plausible_version("2.4.41") == "2.4.41"
    assert _plausible_version(None) is None


def test_short_product_key_cannot_match_a_hex_blob():
    # a bare version + a stray 'f5' inside a hex string must NOT resolve to product f5
    prod, ver = extract_product_version("random 7ff54 blob 2.4.41 no real server header here")
    assert prod != "f5"


def test_real_server_banner_still_fingerprints():
    prod, ver = extract_product_version("HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n")
    assert prod == "apache" and ver == "2.4.41"
