"""Deterministic finding triage — ranks + buckets matched CVEs into attention vs noise with NO AI,
so the free/offline scan leads with what matters instead of a flat CVE dump."""
from src.triage import TriageResult, triage


def _cve(cid, cvss=5.0, epss=0.0, kev=False, exploit=False, vector="", cwe=""):
    return {"id": cid, "cvss_score": cvss, "epss": epss, "kev": kev,
            "exploit_available": exploit, "vector": vector, "cwe": cwe}


def _match(port, service, cves):
    return {"port": port, "service": service, "cves": cves}


class _Attr:
    def __init__(self, port, attribute, value):
        self.port, self.attribute, self.value = port, attribute, value


class _Enum:
    def __init__(self, attrs):
        self.attributes = attrs


def test_pattern_matched_cves_never_attention():
    """Banner→NVD correlator hits are pattern leads, not findings — even KEV."""
    matches = [_match(443, "https", [
        _cve("CVE-LOW", cvss=4.0),
        _cve("CVE-KEV", cvss=7.5, kev=True),
        _cve("CVE-RCE", cvss=9.1, exploit=True),
        _cve("CVE-EPSS", cvss=6.0, epss=0.9),
    ])]
    enum = _Enum([_Attr(443, "http_auth_state", "open")])
    res = triage(matches, enum)
    assert res.attention == []
    assert {i.cve for i in res.noise} >= {"CVE-KEV", "CVE-RCE", "CVE-EPSS", "CVE-LOW"}
    assert all("not a finding" in i.rationale or "pattern" in i.rationale.lower()
               or "version" in i.rationale.lower() for i in res.noise)


def test_version_match_noise_is_demoted_not_hidden():
    matches = [_match(8443, "https-alt", [_cve("CVE-NOISE", cvss=9.8)])]
    enum = _Enum([_Attr(8443, "http_auth_state", "forbidden")])
    res = triage(matches, enum)
    assert res.attention == []
    assert res.noise and res.noise[0].cve == "CVE-NOISE"


def test_web_findings_still_reach_attention():
    """Content-validated SaaS/exposed-file findings are real, not pattern CVEs."""
    web = {
        "saas": [{"service": "Supabase", "severity": "HIGH", "evidence": "x.supabase.co",
                  "detail": "anon key exposed"}],
        "exposed_files": ["/.env"],
    }
    res = triage([], web_fingerprint=web)
    assert any(i.kind == "web" and i.bucket == "attention" for i in res.attention)
    assert any("Supabase" in (i.title or "") for i in res.attention)


def test_dedup_keeps_highest_priority_instance():
    matches = [
        _match(8443, "https-alt", [_cve("CVE-DUP", cvss=9.5)]),
        _match(80, "http", [_cve("CVE-DUP", cvss=9.5, exploit=True)]),
    ]
    enum = _Enum([_Attr(8443, "http_auth_state", "forbidden"), _Attr(80, "http_auth_state", "open")])
    res = triage(matches, enum)
    all_items = res.attention + res.noise
    assert sum(1 for i in all_items if i.cve == "CVE-DUP") == 1


def test_to_dict_shape_and_counts():
    matches = [_match(80, "http", [_cve("CVE-KEV", kev=True), _cve("CVE-LOW", cvss=3.0)])]
    d = triage(matches).to_dict()
    assert set(d) == {"attention", "noise", "counts"}
    assert d["counts"]["kev"] == 1
    assert d["counts"]["total"] == 2
    assert d["counts"]["attention"] == 0
    assert isinstance(d["noise"], list) and "priority" in d["noise"][0]


def test_web_saas_findings_merge_into_the_hero():
    # WS6: third-party SaaS findings share the ranked hero with CVEs, severity → P1..P5.
    wf = {"saas": [
        {"service": "Supabase", "category": "backend", "evidence": "x.supabase.co",
         "severity": "CRITICAL", "detail": "service_role key leaked"},
        {"service": "Clerk", "category": "auth", "evidence": "inst", "severity": "MEDIUM",
         "detail": "dev instance in prod"},
        {"service": "Clerk", "category": "auth", "evidence": "clerk", "severity": "INFO",
         "detail": "auth in use"},
    ], "exposed_files": []}
    res = triage([], None, wf)
    assert res.attention[0].kind == "web" and res.attention[0].priority == "P1"   # CRITICAL first
    assert res.attention[0].title.startswith("Supabase")
    assert any(i.priority == "P3" and "Clerk" in i.title for i in res.attention)   # MEDIUM → attention
    assert any(i.priority == "P5" and i.bucket == "noise" for i in res.noise)      # INFO → noise (no cry wolf)


def test_web_findings_attention_pattern_cves_noise():
    wf = {"saas": [{"service": "Stripe", "evidence": "sk", "severity": "CRITICAL", "detail": "secret leaked"}]}
    matches = [_match(80, "http", [_cve("CVE-KEV", kev=True)])]
    res = triage(matches, None, wf)
    # Web findings are real; pattern-matched CVEs are filtered leads only
    assert {i.kind for i in res.attention} == {"web"}
    assert any(i.cve == "CVE-KEV" and i.bucket == "noise" for i in res.noise)
    assert res.attention[0].priority == "P1"


def test_exposed_file_is_a_web_finding():
    res = triage([], None, {"exposed_files": ["/.env"]})
    assert res.attention and res.attention[0].kind == "web"
    assert "/.env" in res.attention[0].title


def test_empty_is_empty():
    assert isinstance(triage([]), TriageResult)
    assert triage([]).to_dict()["counts"]["total"] == 0
