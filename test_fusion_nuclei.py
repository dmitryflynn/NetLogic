"""Tests for the Nuclei-template fusion sensor.

Tests cover the simple-HTTP-matcher subset:
  • word / regex / status matchers
  • AND / OR matcher conditions
  • matchers-condition (top-level AND/OR across matchers)
  • negative matchers
  • case-insensitive matching
  • hex-encoded word matchers
  • header / body / status_code parts
  • non-matching templates (no false positives)
  • severity stripping (architectural invariant)
  • extractors
  • Multiple paths (first-match-wins)
"""

import yaml
from src.fusion.sensors import HttpResponse, Nuclei, NucleiTemplate
from src.fusion import adjudicate


def _template(raw: str) -> NucleiTemplate:
    return NucleiTemplate(yaml.safe_load(raw))


def _nucleus(*templates: str) -> Nuclei:
    return Nuclei(templates=[_template(t) for t in templates])


def _resp(**kw) -> HttpResponse:
    defaults = dict(host="10.0.0.5", port=8080, html="", headers={}, status=200)
    defaults.update(kw)
    return HttpResponse(**defaults)


# ── Word matcher (body, default part) ────────────────────────────────────────────

T_WORD = """
id: test-word
info:
  name: Test Word Matcher
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "vulnerable"
          - "exploit"
"""


def test_word_matcher_body_matches():
    sigs = _nucleus(T_WORD).detect(_resp(html="This page is vulnerable"))
    assert len(sigs) == 1
    s = sigs[0]
    assert s.source == "nuclei"
    assert s.claim == "test-word"
    assert s.kind == "exposure"


def test_word_matcher_body_no_match():
    sigs = _nucleus(T_WORD).detect(_resp(html="This page is clean"))
    assert len(sigs) == 0


# ── Regex matcher ───────────────────────────────────────────────────────────────

T_REGEX = r"""
id: test-regex
info:
  name: Test Regex Matcher
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: regex
        regex:
          - 'PHP Version [0-9]+\.[0-9]+'
"""


def test_regex_matcher_matches():
    sigs = _nucleus(T_REGEX).detect(_resp(html="PHP Version 8.1.0"))
    assert len(sigs) == 1
    assert sigs[0].source == "nuclei"


def test_regex_matcher_no_match():
    sigs = _nucleus(T_REGEX).detect(_resp(html="Python 3.11"))
    assert len(sigs) == 0


# ── Status code matcher ──────────────────────────────────────────────────────────

T_STATUS = """
id: test-status
info:
  name: Test Status Matcher
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: status
        status:
          - 200
          - 302
"""


def test_status_matcher_matches():
    sigs = _nucleus(T_STATUS).detect(_resp(status=200))
    assert len(sigs) == 1


def test_status_matcher_no_match():
    sigs = _nucleus(T_STATUS).detect(_resp(status=403))
    assert len(sigs) == 0


# ── AND condition (both words must match) ───────────────────────────────────────

T_AND = """
id: test-and
info:
  name: Test AND Condition
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "[core]"
          - "repositoryformatversion"
        condition: and
"""


def test_and_condition_both_match():
    sigs = _nucleus(T_AND).detect(_resp(html="[core]\n\trepositoryformatversion = 0"))
    assert len(sigs) == 1


def test_and_condition_only_one():
    sigs = _nucleus(T_AND).detect(_resp(html="[core] only"))
    assert len(sigs) == 0


# ── matchers-condition (top-level AND — all matchers must pass) ──────────────────

T_MATCHERS_AND = """
id: test-matchers-and
info:
  name: Test Matchers AND
  severity: critical
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "admin"
"""


def test_matchers_and_both_pass():
    sigs = _nucleus(T_MATCHERS_AND).detect(_resp(status=200, html="admin panel"))
    assert len(sigs) == 1


def test_matchers_and_one_fails():
    sigs = _nucleus(T_MATCHERS_AND).detect(_resp(status=403, html="admin panel"))
    assert len(sigs) == 0


def test_matchers_and_second_fails():
    sigs = _nucleus(T_MATCHERS_AND).detect(_resp(status=200, html="user panel"))
    assert len(sigs) == 0


# ── matchers-condition: or (top-level OR — any matcher passes) ───────────────────

T_MATCHERS_OR = """
id: test-matchers-or
info:
  name: Test Matchers OR
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "PHP"
        part: header
      - type: word
        words:
          - "PHP"
        part: body
"""


def test_matchers_or_header_match():
    sigs = _nucleus(T_MATCHERS_OR).detect(_resp(headers={"X-Powered-By": "PHP/8.1"}, html=""))
    assert len(sigs) == 1


def test_matchers_or_body_match():
    sigs = _nucleus(T_MATCHERS_OR).detect(_resp(headers={}, html="PHP 8.1 is great"))
    assert len(sigs) == 1


def test_matchers_or_neither():
    sigs = _nucleus(T_MATCHERS_OR).detect(_resp(headers={}, html="Python 3.11"))
    assert len(sigs) == 0


# ── Negative matcher ─────────────────────────────────────────────────────────────

T_NEGATIVE = """
id: test-negative
info:
  name: Test Negative Matcher
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "login"
          - "authentication"
        negative: true
"""


def test_negative_should_not_match_clean_page():
    sigs = _nucleus(T_NEGATIVE).detect(_resp(html="Welcome to the dashboard"))
    assert len(sigs) == 1


def test_negative_should_not_match_when_word_present():
    sigs = _nucleus(T_NEGATIVE).detect(_resp(html="Please login to continue"))
    assert len(sigs) == 0


# ── Case insensitive matcher ─────────────────────────────────────────────────────

T_CASE_INSENSITIVE = """
id: test-case-insensitive
info:
  name: Test Case Insensitive
  severity: low
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "vulnerable"
        case-insensitive: true
"""


def test_case_insensitive_matches_uppercase():
    sigs = _nucleus(T_CASE_INSENSITIVE).detect(_resp(html="VULNERABLE"))
    assert len(sigs) == 1


def test_case_insensitive_matches_mixed():
    sigs = _nucleus(T_CASE_INSENSITIVE).detect(_resp(html="Vulnerable"))
    assert len(sigs) == 1


# ── Hex encoded word matcher ────────────────────────────────────────────────────

T_HEX = """
id: test-hex
info:
  name: Test Hex Encoded Words
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        encoding: hex
        words:
          - "50494e47"
"""


def test_hex_encoded_word_matches():
    sigs = _nucleus(T_HEX).detect(_resp(html="PING"))
    assert len(sigs) == 1


def test_hex_encoded_word_no_match():
    sigs = _nucleus(T_HEX).detect(_resp(html="PONG"))
    assert len(sigs) == 0


# ── Header part matching ─────────────────────────────────────────────────────────

T_HEADER = """
id: test-header
info:
  name: Test Header Matching
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "X-Jenkins: 2."
        part: header
"""


def test_header_part_matches():
    sigs = _nucleus(T_HEADER).detect(_resp(headers={"X-Jenkins": "2.426.1"}))
    assert len(sigs) == 1


def test_header_part_no_match():
    sigs = _nucleus(T_HEADER).detect(_resp(headers={"Server": "nginx/1.25"}))
    assert len(sigs) == 0


# ── Severity stripping (architectural invariant) ────────────────────────────────

T_CRITICAL = """
id: test-critical
info:
  name: Critical Severity Template
  severity: critical
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "crit"
"""


def test_severity_is_stripped_from_signal():
    """The template's self-declared severity must NOT appear in the Signal's
    impact fields — the gate computes its own impact deterministically."""
    sigs = _nucleus(T_CRITICAL).detect(_resp(html="critical evidence here"))
    assert len(sigs) == 1
    s = sigs[0]
    # The Signal must NOT carry the template severity as its own cvss/exploit/kev.
    assert s.cvss == 0.0
    assert s.kev is False
    assert s.exploit_available is False
    # The raw severity is retained in raw_metadata for audit.
    assert s.raw_metadata["template_severity"] == "critical"


def test_severity_stripped_flow_through_gate():
    """A lone nuclei signal with the template severity stripped must still pass
    through the gate correctly (no crash, correct grouping)."""
    sigs = _nucleus(T_CRITICAL).detect(_resp(html="critical evidence here"))
    verdicts = adjudicate(sigs)
    assert len(verdicts) == 1
    # Since the template had no CVSS/KEV, impact should be "low",
    # and the lone medium-reliability signal should be auto-discarded.
    assert verdicts[0].impact == "low"
    assert verdicts[0].decision == "discarded"


# ── CVE template (classification with cvss-score) ──────────────────────────────

T_CVE = """
id: CVE-2099-0001
info:
  name: Test CVE Template
  severity: critical
  classification:
    cvss-score: 9.8
    cve-id: CVE-2099-0001
    epss-score: 0.95
  tags: kev,test
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "CVE-2099"
"""


def test_cve_template_populates_signal_fields():
    sigs = _nucleus(T_CVE).detect(_resp(html="CVE-2099 evidence"))
    assert len(sigs) == 1
    s = sigs[0]
    assert s.claim == "cve-2099-0001"
    assert s.cvss == 9.8
    assert s.kev is True
    assert s.epss == 0.95
    assert s.kind == "vuln"
    assert s.version_matched is False


def test_nuclei_signal_includes_observed_data():
    sigs = _nucleus(T_CVE).detect(_resp(html="CVE-2099 evidence here", status=200, headers={"Server": "IIS/10.0"}))
    assert len(sigs) == 1
    view = sigs[0].ai_view()
    od = view.get("observed_data")
    assert od is not None
    assert od["response_status"] == 200
    assert od["response_headers"]["Server"] == "IIS/10.0"
    assert "CVE-2099" in od["body_snippet"]
    assert od["matched_path"] == "/"
    # Sensor name must NOT leak into observed_data
    assert "nuclei" not in str(od)


def test_cve_template_flow_through_gate():
    """A CVE template with proper CVSS/KEV should be pinned by the gate."""
    sigs = _nucleus(T_CVE).detect(_resp(html="CVE-2099 evidence"))
    verdicts = adjudicate(sigs)
    assert len(verdicts) == 1
    # KEV + high CVSS → pinned critical, confirmed
    assert verdicts[0].pinned is True
    assert verdicts[0].decision == "confirmed"
    assert verdicts[0].impact == "critical"


# ── Regex extractors ────────────────────────────────────────────────────────────

T_EXTRACTOR = r"""
id: test-extractor
info:
  name: Test Regex Extractor
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "Version"
    extractors:
      - type: regex
        name: version
        regex:
          - 'Version ([0-9]+\.[0-9]+)'
        group: 1
"""


def test_regex_extractor():
    sigs = _nucleus(T_EXTRACTOR).detect(_resp(html="Version 8.1.0 is installed"))
    assert len(sigs) == 1
    extracted = sigs[0].raw_metadata.get("extracted", {})
    assert extracted.get("version") == "8.1"


# ── Empty / no matchers ─────────────────────────────────────────────────────────

def test_empty_template_list_produces_no_signals():
    nuc = Nuclei(templates=[])
    assert nuc.detect(_resp()) == []


# ── Template with no HTTP matchers ──────────────────────────────────────────────

T_NO_MATCHERS = """
id: test-no-matchers
info:
  name: No Matchers
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
"""


def test_template_with_no_matchers_produces_no_signals():
    sigs = _nucleus(T_NO_MATCHERS).detect(_resp(html="anything"))
    assert len(sigs) == 0


# ── Multiple matchers (two word matchers, separate matcher blocks) ──────────────

T_MULTI_MATCHER = """
id: test-multi-matcher
info:
  name: Multi Matcher
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        name: php
        words:
          - "X-Powered-By: PHP"
          - "PHPSESSID"
        part: header
      - type: word
        name: php-body
        words:
          - "PHP"
        part: body
"""


def test_multiple_matcher_blocks_or_by_default():
    sigs = _nucleus(T_MULTI_MATCHER).detect(_resp(headers={"X-Powered-By": "PHP/8.1"}, html=""))
    assert len(sigs) == 1

    sigs2 = _nucleus(T_MULTI_MATCHER).detect(_resp(headers={}, html="PHP 8.1"))
    assert len(sigs2) == 1

    sigs3 = _nucleus(T_MULTI_MATCHER).detect(_resp(headers={}, html="Python"))
    assert len(sigs3) == 0


# ── status_code part (explicit) ─────────────────────────────────────────────────

T_STATUS_CODE_PART = """
id: test-status-code-part
info:
  name: Status Code Part
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "404"
        part: status_code
"""


def test_status_code_word_on_404():
    sigs = _nucleus(T_STATUS_CODE_PART).detect(_resp(status=404))
    assert len(sigs) == 1


def test_status_code_word_on_200():
    sigs = _nucleus(T_STATUS_CODE_PART).detect(_resp(status=200))
    assert len(sigs) == 0


# ── Path-specific matching ─────────────────────────────────────────────────────

T_PATH_SPECIFIC = """
id: test-path-specific
info:
  name: Path Specific
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers:
      - type: word
        words:
          - "[core]"
"""


def test_path_specific_matches_on_correct_path():
    sigs = _nucleus(T_PATH_SPECIFIC).detect(_resp(html="[core]"), path="/.git/config")
    assert len(sigs) == 1


def test_path_specific_no_match_on_wrong_path():
    sigs = _nucleus(T_PATH_SPECIFIC).detect(_resp(html="[core]"), path="/index.html")
    assert len(sigs) == 0


# ── Stop-at-first-match and multiple paths ─────────────────────────────────────

T_MULTI_PATH_STOP = """
id: test-multi-path
info:
  name: Multi Path
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
      - "{{BaseURL}}/dashboard"
    stop-at-first-match: true
    matchers:
      - type: word
        words:
          - "dashboard"
"""


def test_multi_path_first_match_wins():
    # Path /admin matches first template path; body does NOT contain "dashboard" → no match.
    sigs = _nucleus(T_MULTI_PATH_STOP).detect(_resp(html="admin panel"), path="/admin")
    assert len(sigs) == 0

    # Path /dashboard matches second template path; body contains "dashboard" → match.
    sigs2 = _nucleus(T_MULTI_PATH_STOP).detect(_resp(html="dashboard"), path="/dashboard")
    assert len(sigs2) == 1

    # Path /admin with body containing "dashboard" matches (first path matched, body checked).
    sigs3 = _nucleus(T_MULTI_PATH_STOP).detect(_resp(html="dashboard"), path="/admin")
    assert len(sigs3) == 1
