"""Regression tests for the Nuclei-sensor hardening (crash-safety, lazy yaml, wiring).

These cover the bugs the 'Architect Review' missed: unguarded regexes crashing on
Go/PCRE template syntax, the eager PyYAML import breaking the whole package, and the
sensor not being wired into the pipeline.
"""

from src.fusion.sensors.nuclei import NucleiTemplate, Nuclei, _re_matches
from src.fusion.sensors.wappalyzer import HttpResponse
from src.fusion.cassette import load_cassettes, signals_from_cassette


def _tmpl(matchers, extractors=None):
    block = {"path": ["{{BaseURL}}"], "matchers": matchers}
    if extractors:
        block["extractors"] = extractors
    return NucleiTemplate({"id": "t", "info": {"name": "t"}, "http": [block]})


# ── Crash-safety on real-world (Go/PCRE) regexes ────────────────────────────────

def test_re_matches_swallows_uncompilable_pattern():
    assert _re_matches("(?<x>[0-9]+)", "v123") is False   # Go named group → re.error → False
    assert _re_matches("v[0-9]+", "v123") is True


def test_go_named_group_regex_matcher_does_not_crash():
    t = _tmpl([{"type": "regex", "regex": ["(?<version>[0-9.]+)"]}])
    assert Nuclei([t]).detect(HttpResponse(host="h", html="v1.2.3", status=200)) == []


def test_broken_extractor_regex_does_not_crash_a_match():
    # The word matcher fires; a malformed extractor regex must not abort the signal.
    t = _tmpl([{"type": "word", "words": ["welcome"]}],
              extractors=[{"type": "regex", "name": "v", "regex": ["(?P<x>("]}])
    sigs = Nuclei([t]).detect(HttpResponse(host="h", html="welcome home", status=200))
    assert len(sigs) == 1


def test_valid_regex_still_matches():
    t = _tmpl([{"type": "regex", "regex": ["v[0-9]+"]}])
    assert len(Nuclei([t]).detect(HttpResponse(host="h", html="v123", status=200))) == 1


# ── Severity stripping + metadata invariants ────────────────────────────────────

def test_severity_is_never_emitted_to_signal():
    t = NucleiTemplate({"id": "t", "info": {"name": "t", "severity": "critical"},
                        "http": [{"path": ["{{BaseURL}}"], "matchers": [{"type": "word", "words": ["x"]}]}]})
    [s] = Nuclei([t]).detect(HttpResponse(host="h", html="x", status=200))
    # severity lives only in raw_metadata (audit), never in an impact field.
    assert s.cvss == 0.0 and s.kev is False
    assert s.raw_metadata["template_severity"] == "critical"
    assert "critical" not in s.ai_view().get("evidence", "")


def test_tags_parsing_and_kev_flag():
    assert NucleiTemplate({"id": "t", "info": {}}).tags == []
    assert NucleiTemplate({"id": "t", "info": {"tags": "cve,rce"}}).kev is False
    assert NucleiTemplate({"id": "t", "info": {"tags": ["cve", "kev"]}}).kev is True


# ── Wired into the pipeline ─────────────────────────────────────────────────────

def test_nuclei_runs_against_recorded_traffic_in_cassette_pipeline():
    cs = {c.name: c for c in load_cassettes()}["vulhub-log4shell"]
    sigs = signals_from_cassette(cs)
    hits = [s for s in sigs if s.source == "nuclei" and s.claim == "apache-tomcat-detect"]
    assert len(hits) == 1
    # the extractor pulled the version out of the recorded body
    assert hits[0].raw_metadata.get("extracted", {}).get("version") == "9.0.30"
