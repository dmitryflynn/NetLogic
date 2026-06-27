"""
Fuzz-regression for parsers that consume UNTRUSTED input (banners, versions, raw
protocol bytes from arbitrary scan targets). A malformed/hostile response must
never crash a scan — it should degrade to a safe default.

Two real reachable crash bugs are pinned here:
  • _parse_ver blew up on a version with >4300 digits (Python int-string guard) —
    a hostile banner "Server: Foo/<5000 digits>" crashed CVE correlation;
  • extract_product_version raised TypeError when handed a bytes .raw.
Plus broad no-crash guards over the version/banner/protocol-byte parsers.
"""
import pytest

from src import cve_correlator as cc
from src import scanner
from src import service_enum as se


class _B:
    def __init__(self, raw):
        self.raw = raw
        self.product = None


_MALFORMED_VERSIONS = [
    "", " ", ".", "...", "1.", ".1", "1..2", "-1", "1.-2.3",
    "0" * 5000, "9" * 5000, "1" * 10000,                 # digit-DoS (>4300)
    "99999999999999999999999999999", "1.0.0a", "1.0.0-rc1+b.45",
    "\x00\x01\x02", "①.②.③", "💥", "1.2.3p" + "9" * 5000,
    "1.2.3patch" + "8" * 5000, "NaN", "Infinity", "1,2,3", "1.2.3;DROP",
]


@pytest.mark.parametrize("v", _MALFORMED_VERSIONS)
def test_parse_ver_never_crashes(v):
    out = cc._parse_ver(v)
    assert isinstance(out, tuple)


def test_version_comparisons_never_crash_and_stay_correct():
    for a in _MALFORMED_VERSIONS:
        cc._ver_lt(a, "2.0")
        cc._ver_in_range(a, "1.0", "2.0")
        cc._ver_lt_branch(a, {"1.0": "1.5"})
    # Correctness preserved after the length cap:
    assert cc._ver_lt("1.0.1f", "1.0.1g") is True
    assert cc._ver_lt("2.4.49", "2.4.51") is True
    assert cc._ver_lt("9.9", "9.10") is True
    assert cc._ver_in_range("1.0.1c", "1.0.1", "1.0.1f") is True


@pytest.mark.parametrize("raw", _MALFORMED_VERSIONS + ["Server: Apache/2.4.49"])
def test_extract_product_version_handles_str_and_bytes(raw):
    # str and bytes .raw must both work (bytes used to TypeError).
    cc.extract_product_version(_B(raw))
    cc.extract_product_version(_B(raw.encode("utf-8", "ignore")))


@pytest.mark.parametrize("raw", _MALFORMED_VERSIONS)
@pytest.mark.parametrize("svc", ["http", "ssh", "unknown", "ftp"])
def test_parse_banner_never_crashes(raw, svc):
    scanner.parse_banner(raw, svc)


# Raw protocol-byte parsers (the SNMP-bug class) — must survive malformed bytes.
_MALFORMED_BYTES = [
    b"", b"\x00", b"\xff", b"\x00\x00\x00\x00", b"\xff" * 6, bytes(range(256)),
    b"\x03\x00\x00\x13" + b"\xff" * 15, b"\x82\x00\x00\x00" + b"\xff" * 8,
    b"\x14" + b"\x00" * 10, b"\xde\xad\xbe\xef" * 50,
]


@pytest.mark.parametrize("data", _MALFORMED_BYTES)
def test_protocol_byte_parsers_never_crash(data):
    se._parse_ssh_kexinit(data, b"SSH-2.0-OpenSSH_8.9\r\n", 22)
    se._smb_response_is_smbv1(data)
    se._parse_rdp_negotiation(data, 3389)
    scanner._snmp_sysdescr(data)


# NVD JSON item parsing — external API data; a schema change / partial / error
# payload must not crash CVE correlation.
_MALFORMED_NVD = [
    {}, {"cve": {}}, {"cve": None}, {"cve": {"id": None}}, {"random": "junk"},
    {"cve": []}, None, "str", 5, [],
    {"cve": {"id": "CVE-X", "metrics": "notadict"}},
    {"cve": {"id": "CVE-X", "descriptions": ["x", 5, None]}},
    {"cve": {"id": "CVE-X", "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": "high"}}]}}},
    {"cve": {"id": "CVE-X", "weaknesses": ["x", None]}},
    {"cve": {"id": "CVE-X", "references": "notalist"}},
    {"cve": {"id": "CVE-X", "references": ["x", None, 5]}},
    {"cve": {"id": "CVE-X", "published": 99999}},
    {"cve": {"id": "CVE-X", "configurations": [{"nodes": "bad"}]}},
    {"cve": {"id": "CVE-X", "configurations": ["x", {"nodes": ["y", {"cpeMatch": ["z"]}]}]}},
]


@pytest.mark.parametrize("item", _MALFORMED_NVD)
def test_parse_nvd_item_never_crashes(item):
    from src import nvd_lookup
    nvd_lookup._parse_nvd_item(item)


def test_parse_nvd_item_wellformed_still_correct():
    from src import nvd_lookup
    good = {"cve": {"id": "CVE-2021-44228",
            "descriptions": [{"lang": "en", "value": "Log4Shell"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "vectorString": "CVSS:3.1/AV:N"},
                                           "baseSeverity": "CRITICAL"}]},
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"}]}],
            "references": [{"url": "https://exploit-db.com/x"}]}}
    c = nvd_lookup._parse_nvd_item(good)
    assert c.id == "CVE-2021-44228" and c.cvss_score == 10.0 and c.severity == "CRITICAL"


# ── OSINT / topology / takeover / fusion-AI parsers ─────────────────────────────

@pytest.mark.parametrize("data", [None, "str", [], 5, {}, {"org": 123}, {"asn": "x"}, {"country": []}])
def test_parse_asn_org_never_crashes(data):
    # External ASN-API JSON: a malformed/error response must not crash OSINT.
    from src import osint
    osint._parse_asn_org(data)


def test_parse_asn_org_wellformed_correct():
    from src import osint
    r = osint._parse_asn_org({"org": "AS13335 Cloudflare, Inc.", "country": "US"})
    assert r.asn == "AS13335" and "Cloudflare" in r.org and r.country == "US"


@pytest.mark.parametrize("text", [
    "", "not json", "[", "{}", "null", "💥", "x" * 2000,
    "```json\n[{\"id\":1,\"verdict\":\"real\"}]\n```", "garbage [1,2,3] trailing",
    '[{"id":"notint"}]', '[null, 1, "x"]', '{"not":"array"}',
])
def test_robust_json_array_never_crashes(text):
    # AI responses are unpredictable; recovery must never raise.
    from src.fusion.ai import robust_json_array
    robust_json_array(text)


def test_robust_json_array_recovers_fenced_array():
    from src.fusion.ai import robust_json_array
    out = robust_json_array("```json\n[{\"id\": 0, \"verdict\": \"real\"}]\n```")
    assert isinstance(out, list) and out and out[0]["id"] == 0


@pytest.mark.parametrize("stdout", ["", "garbage\n", " 1  1.2.3.4  1ms\n 2  * * *\n", "9" * 5000])
def test_parse_traceroute_never_crashes(stdout):
    from src import topology
    assert isinstance(topology._parse_traceroute(stdout), list)


def test_reporter_render_functions_handle_none():
    # The real "module was skipped" case — every section renderer must accept None.
    import io, contextlib
    from src import reporter as rp
    for fn in (rp.print_service_probe_results, rp.print_vuln_probe_results, rp.print_topology,
               rp.print_auth_result, rp.print_scan_diff, rp.print_web_fingerprint,
               rp.print_service_enum, rp.print_ai_analysis, rp.print_detected_vulnerabilities):
        with contextlib.redirect_stdout(io.StringIO()):
            fn(None)


# ── Fusion gate / adjudicator (AI-finding output is unpredictable) ──────────────

_MALFORMED_FINDINGS = [
    None, "str", [], 5, {}, {"subject": None}, {"subject": 123},
    {"subject": "x", "severity": 99}, {"subject": "x", "kind": None},
    {"subject": "x", "evidence": ["list"]}, {"reason": {}},
]


@pytest.mark.parametrize("finding", _MALFORMED_FINDINGS)
def test_ai_finding_to_signal_never_crashes(finding):
    from src.fusion import adjudicator as adj
    adj.ai_finding_to_signal(finding)
    adj.ai_finding_to_signal(finding, {"host": "h"})


@pytest.mark.parametrize("findings", [_MALFORMED_FINDINGS, None, "notalist", {"a": 1}, [], [None, 5, "x"]])
def test_apply_new_findings_never_crashes(findings):
    from src.fusion import adjudicator as adj
    out = adj.apply_new_findings(findings, {"host": "h"})
    assert isinstance(out, list)


def test_ai_finding_to_signal_wellformed_still_works():
    from src.fusion import adjudicator as adj
    s = adj.ai_finding_to_signal({"subject": "exposed admin", "severity": "high", "evidence": "e"}, {"host": "h"})
    assert s is not None and s.claim == "exposed admin"


def test_gate_handles_nondict_exposure_and_stays_correct():
    from src.fusion.signals import Signal
    from src.fusion.gate import adjudicate, _impact_of
    # Non-dict exposure must not crash the impact computation.
    _impact_of([Signal(source="x", kind="x", claim="c", host="h", exposure="notdict")])
    # And a real KEV-critical signal still pins/confirms.
    v = adjudicate([Signal(source="nvd", kind="vuln", claim="CVE-2021-44228",
                           host="h", cvss=10.0, kev=True)])
    assert v[0].impact == "critical" and v[0].pinned is True


@pytest.mark.parametrize("product,desc", [
    (None, None), (5, 5), ("apache", None), ("", "x"), (123, "y"),
])
def test_vdb_description_matcher_never_crashes(product, desc):
    from src import vdb_engine
    vdb_engine._vdb_description_matches_product(product, desc)
