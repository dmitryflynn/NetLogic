"""
NetLogic — CVE Correlator precision tests (pytest).

Replaces the legacy standalone ``test_edge_cases.py`` script, which still imported
correlator internals that were removed in the precision refactor (``_apply_tiers``,
``_resolve_port``, ``version_match_confidence``) and which pytest never actually
executed (its ``def test`` helper made collection a no-op). These run in the suite
and target the CURRENT precision API:

  * product/version extraction and product-key matching (no substring false-positives)
  * version comparison incl. OpenSSL patch letters and OpenSSH "pN" suffixes
  * branch-aware version thresholds (no cross-branch over-firing)
  * match-precision tiering (coarse versions / distro backports → POTENTIAL)
  * end-to-end correlate(): OpenSSH false-positive / false-negative guards
  * regression: the same CVE id is never duplicated within one finding
"""

import pytest

from src.cve_correlator import (
    _product_matches,
    _is_version_independent,
    _ver_lt_branch,
    _ver_in_range,
    _match_precision,
    extract_product_version,
    infer_product_from_service,
    calculate_risk,
    correlate,
    CVE,
)
from src.nvd_lookup import _ver_lt as nvd_ver_lt, _parse_ver
from src.scanner import PortResult, ServiceBanner


# ── Deterministic NVD stub (live correlator, no network) ──────────────────────

from src.nvd_lookup import NVDCve, _ver_lt as _nvd_ver_lt


def _nvd(cve_id, cvss=9.8, desc="test"):
    return NVDCve(
        id=cve_id, description=desc, cvss_score=cvss, severity="CRITICAL",
        vector="", published="", last_modified="", cwe="",
    )


@pytest.fixture
def offline(monkeypatch):
    """Stub NVD lookups with a small fixed set for OpenSSH version ranges.

    Offline signature / SQLite VDB paths were removed — tests now exercise the
    live correlate() path with deterministic NVD responses.
    """
    import src.nvd_lookup as nl
    monkeypatch.setattr(nl, "_nvd_unavailable", False, raising=False)
    monkeypatch.setattr(nl, "nvd_is_available", lambda: True)

    def _lookup(product, version, min_cvss=4.0):
        p = (product or "").lower()
        v = version or ""
        out = []
        if p in ("openssh", "ssh"):
            if _nvd_ver_lt(v, "9.3"):
                out.append(_nvd("CVE-2023-38408", 9.8))
            if _nvd_ver_lt(v, "8.5"):
                out.append(_nvd("CVE-2021-41617", 7.0))
            if _nvd_ver_lt(v, "7.7"):
                out.append(_nvd("CVE-2018-15473", 5.3))
            if _nvd_ver_lt(v, "7.3"):
                out.append(_nvd("CVE-2016-3115", 5.5))
        if p == "grafana" and v.startswith("8."):
            # Single CVE once even if multiple ranges would match
            out.append(_nvd("CVE-2021-43798", 7.5, "Grafana path traversal"))
        return [c for c in out if c.cvss_score >= min_cvss]

    monkeypatch.setattr(nl, "lookup_cves_for_service", _lookup)
    import src.cve_correlator as cc
    monkeypatch.setattr(cc, "lookup_cves_for_service", _lookup)
    return True


def _ssh(banner: str):
    return PortResult(port=22, protocol="tcp", state="open", service="ssh",
                      banner=ServiceBanner(raw=banner) if banner else None)


# ── Product-key matching ──────────────────────────────────────────────────────

def test_product_matches_exact_and_token():
    assert _product_matches("php", "php")
    assert _product_matches("tomcat", "apache-tomcat")   # token match
    assert _product_matches("openssh", "openssh")

def test_product_matches_rejects_substring_false_positive():
    # 'php' must NOT match 'phpmyadmin' (the classic substring false positive)
    assert not _product_matches("php", "phpmyadmin")
    assert not _product_matches("tomcat", "tomcatfoo")


# ── Presence (version-independent) signature detection ─────────────────────────

def test_is_version_independent():
    assert _is_version_independent(lambda v: True)              # presence sig
    assert not _is_version_independent(lambda v: nvd_ver_lt(v, "9.0"))
    assert not _is_version_independent(lambda v: bool(v) and v.startswith("10."))


# ── Branch-aware thresholds ────────────────────────────────────────────────────

def test_ver_lt_branch_no_cross_branch_firing():
    fixes = {"9.0": "9.0.31", "8.5": "8.5.51", "7.0": "7.0.100"}
    assert _ver_lt_branch("8.5.40", fixes)        # vulnerable on its own branch
    assert not _ver_lt_branch("8.5.51", fixes)    # patched on its branch
    assert not _ver_lt_branch("9.0.50", fixes)    # newer than its branch fix
    assert not _ver_lt_branch("7.5.1", fixes)     # unknown branch → never assumed vuln


# ── Match precision (false-positive suppression) ──────────────────────────────

def test_match_precision_coarse_iis_is_potential():
    assert _match_precision("iis", "10.0", "Microsoft-IIS/10.0") == "potential"

def test_match_precision_distro_backport_is_potential():
    raw = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
    assert _match_precision("openssh", "8.2", raw) == "potential"

def test_match_precision_clean_banner_is_confirmed():
    assert _match_precision("nginx", "1.18.0", "nginx/1.18.0") == "confirmed"


# ── Extraction ────────────────────────────────────────────────────────────────

def test_extract_skips_generic_http_product():
    b = ServiceBanner(raw="HTTP/1.1 200 OK", product="http 1.1", version=None)
    assert extract_product_version(b) == (None, None)

def test_extract_structured_product_version():
    b = ServiceBanner(raw="nginx/1.18.0", product="nginx", version="1.18.0")
    assert extract_product_version(b) == ("nginx", "1.18.0")

def test_infer_product_from_service_respects_host_os():
    # On a confirmed Windows host, port 21 must NOT be guessed as the unix vsftpd.
    assert infer_product_from_service("ftp", 21, host_os="windows") is None
    assert infer_product_from_service("ftp", 21, host_os="unix") == "vsftpd"


# ── Version comparison: OpenSSL letters & OpenSSH patch suffixes ───────────────

def test_openssl_patch_letters_order():
    assert nvd_ver_lt("1.0.1f", "1.0.1g")        # f < g
    assert not nvd_ver_lt("1.0.1g", "1.0.1f")
    assert _ver_in_range("1.0.1f", "1.0.1", "1.0.1f")   # Heartbleed window

def test_openssh_patch_suffix_not_below_base():
    # 9.3p1 is a patch level ABOVE 9.3, so it must not read as < 9.3.
    assert not nvd_ver_lt("9.3p1", "9.3")
    assert nvd_ver_lt("8.5p1", "9.3")

def test_parse_ver_handles_garbage():
    assert _parse_ver("") == (0,)
    assert _parse_ver("???") == (0,)


# ── Risk scoring ──────────────────────────────────────────────────────────────

def test_calculate_risk_kev_bonus_and_cap():
    base = [CVE(id="C1", description="", cvss_score=8.0, severity="HIGH", vector="", published="")]
    kev  = [CVE(id="C1", description="", cvss_score=8.0, severity="HIGH", vector="", published="", kev=True)]
    assert calculate_risk(kev) > calculate_risk(base)
    assert calculate_risk([]) == 0.0
    huge = [CVE(id=f"C{i}", description="", cvss_score=10.0, severity="CRITICAL",
                vector="", published="", kev=True) for i in range(10)]
    assert calculate_risk(huge) <= 10.0


# ── End-to-end correlate(): precision guards ──────────────────────────────────

def test_correlate_empty_ports(offline):
    assert correlate([], min_cvss=4.0) == []

def test_correlate_openssh_old_no_false_negative(offline):
    res = correlate([_ssh("SSH-2.0-OpenSSH_7.6p1 Debian-4")], min_cvss=4.0)
    ids = [c.id for vm in res for c in vm.cves]
    assert "CVE-2023-38408" in ids   # < 9.3
    assert "CVE-2021-41617" in ids   # < 8.5

def test_correlate_openssh_new_no_false_positive(offline):
    res = correlate([_ssh("SSH-2.0-OpenSSH_9.9p1 Ubuntu")], min_cvss=4.0)
    ids = [c.id for vm in res for c in vm.cves]
    for fp in ("CVE-2023-38408", "CVE-2021-41617", "CVE-2018-15473", "CVE-2016-3115"):
        assert fp not in ids, f"version correlator false-positive on OpenSSH 9.9: {fp}"

def test_correlate_no_duplicate_cve_ids(offline):
    # Regression: grafana lists CVE-2021-43798 under two version thresholds; an old
    # build returned it twice in one finding.
    b = ServiceBanner(raw="X-Grafana-Version: 8.0.0", product="grafana", version="8.0.0")
    p = PortResult(port=3000, protocol="tcp", state="open", service="grafana", banner=b)
    for vm in correlate([p], min_cvss=4.0):
        ids = [c.id for c in vm.cves]
        assert len(ids) == len(set(ids)), f"duplicate CVE ids in finding: {ids}"

def test_correlate_port_only_guess_emits_no_cves(offline):
    # A port with a service name but NO banner is a port-number guess only. It must
    # never produce version-confirmed CVEs (the gate that keeps false positives out).
    p = PortResult(port=22, protocol="tcp", state="open", service="ssh", banner=None)
    res = correlate([p], min_cvss=4.0)
    cve_ids = [c.id for vm in res for c in vm.cves]
    assert cve_ids == [], f"port-only guess produced CVEs without a version: {cve_ids}"


def test_correlate_results_sorted_by_risk(offline):
    ports = [
        _ssh("SSH-2.0-OpenSSH_7.6p1"),
        PortResult(port=80, protocol="tcp", state="open", service="http",
                   banner=ServiceBanner(raw="Server: Apache/2.2.15", product="apache", version="2.2.15")),
    ]
    res = correlate(ports, min_cvss=4.0)
    scores = [r.risk_score for r in res]
    assert scores == sorted(scores, reverse=True)
