"""Precision tests for CPE-aware product + version matching in nvd_lookup.

These guard the two Tier-1 precision fixes:
  1. Product alignment matches ONLY real CPE products for a detected product
     (no "ssh"→"openssh"-style substring cross-matching to unrelated products).
  2. Exact-version CPEs (no versionStart/End range) are captured and matched
     precisely — recovering single-version CVEs like the Apache 2.4.49 RCE.
"""

from src.nvd_lookup import (
    NVDCve,
    _range_product_matches,
    version_is_affected,
    _parse_nvd_item,
)


# ── Product alignment ──────────────────────────────────────────────────────────

def test_range_product_known_alias_matches_cpe_token():
    # Detected "apache" must align with the NVD CPE product "http_server".
    assert _range_product_matches("http_server", "apache")
    assert _range_product_matches("openssh", "ssh")
    assert _range_product_matches("internet_information_services", "iis")
    assert _range_product_matches("sql_server", "mssql")


def test_range_product_known_alias_rejects_wrong_product():
    # A Postgres host must NOT inherit MySQL / MSSQL CVE ranges.
    assert not _range_product_matches("mysql", "postgresql")
    assert not _range_product_matches("sql_server", "postgresql")
    # The classic substring collisions the old matcher allowed:
    assert not _range_product_matches("tftp", "ftp")
    assert not _range_product_matches("http_server", "nginx")


def test_range_product_empty_is_permissive():
    # Can't disprove with no data → don't drop the finding.
    assert _range_product_matches("", "apache")
    assert _range_product_matches("http_server", "")
    assert _range_product_matches(None, "apache")


def test_range_product_unknown_uses_token_boundary_not_substring():
    # Unknown product: a shared distinctive token matches…
    assert _range_product_matches("acme_widget", "widget_acme") is True
    # …but a short/ambiguous overlap ("server") does not cross-match.
    assert not _range_product_matches("some_server", "other_server")


# ── Range matching ─────────────────────────────────────────────────────────────

def _cve_with_ranges(ranges):
    return NVDCve(id="CVE-TEST", description="t", cvss_score=9.8,
                  severity="CRITICAL", vector="", published="2021-01-01",
                  last_modified="2021-01-01", cwe="", version_ranges=ranges)


def test_version_in_matching_product_range():
    cve = _cve_with_ranges([
        {"start": "2.4.0", "end": "2.4.55", "end_including": False, "cpe_product": "http_server"},
    ])
    assert version_is_affected("2.4.41", cve, detected_product="apache")
    assert not version_is_affected("2.4.55", cve, detected_product="apache")  # end-excluding


def test_range_for_other_product_is_dropped():
    # CVE only carries a MySQL range; a Postgres host must not match it.
    cve = _cve_with_ranges([
        {"start": "5.0", "end": "8.0", "end_including": True, "cpe_product": "mysql"},
    ])
    assert not version_is_affected("7.0", cve, detected_product="postgresql")
    assert version_is_affected("7.0", cve, detected_product="mysql")


# ── Exact-version pins ──────────────────────────────────────────────────────────

def test_exact_version_pin_matches_only_that_version():
    cve = _cve_with_ranges([
        {"start": "2.4.49", "end": "2.4.49", "end_including": True,
         "cpe_product": "http_server", "exact": True},
    ])
    assert version_is_affected("2.4.49", cve, detected_product="apache")
    assert not version_is_affected("2.4.48", cve, detected_product="apache")
    assert not version_is_affected("2.4.50", cve, detected_product="apache")


def test_parse_nvd_item_captures_exact_cpe_version():
    # An NVD item whose only vulnerable CPE pins an exact version (no range)
    # must yield a closed [v, v] range so the CVE is matchable.
    item = {
        "cve": {
            "id": "CVE-2021-41773",
            "descriptions": [{"lang": "en", "value": "Apache 2.4.49 path traversal RCE."}],
            "metrics": {"cvssMetricV31": [{
                "cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N"},
                "baseSeverity": "CRITICAL",
            }]},
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                    }],
                }],
            }],
        }
    }
    cve = _parse_nvd_item(item)
    assert any(r.get("exact") and r.get("start") == "2.4.49" for r in cve.version_ranges)
    assert version_is_affected("2.4.49", cve, detected_product="apache")
    assert not version_is_affected("2.4.48", cve, detected_product="apache")
