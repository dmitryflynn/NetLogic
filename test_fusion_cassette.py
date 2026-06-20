"""Tests for the cassette record/replay harness + cassette-corpus benchmark. Offline."""

import json

from src.fusion.cassette import (
    load_cassettes, signals_from_cassette, CassettePlayer, CassetteHttpClient, run_probe,
)
from src.fusion.corpus import score_cassettes, cases_from_cassettes


def _by_name(cassettes):
    return {c.name: c for c in cassettes}


# ── Loading ─────────────────────────────────────────────────────────────────────

def test_seed_cassettes_load():
    cs = load_cassettes()
    names = {c.name for c in cs}
    assert {"vulhub-log4shell", "vulhub-struts-stateful",
            "clean-nginx-patched", "clean-wordpress"} <= names


# ── Stateful replay ─────────────────────────────────────────────────────────────

def test_player_replays_recorded_responses():
    cs = _by_name(load_cassettes())["vulhub-struts-stateful"]
    player = CassettePlayer(cs)
    assert player.request("GET", "/login").body.find("csrf") != -1
    assert "uid=0(root)" in player.request("POST", "/admin/exec").body
    # unrecorded path → synthetic 404
    assert player.request("GET", "/nope").status == 404


def test_stateful_probe_extracts_token_then_confirms():
    # The Struts probe must GET /login, extract the CSRF token, POST it, and match the
    # uid=root marker — proving multi-request state-passing over recorded traffic.
    cs = _by_name(load_cassettes())["vulhub-struts-stateful"]
    confirmed, evidence = run_probe(CassetteHttpClient(cs), cs.probes[0])
    assert confirmed is True
    assert "uid=0(root)" in evidence


def test_probe_fails_when_success_marker_absent():
    cs = _by_name(load_cassettes())["vulhub-struts-stateful"]
    bad = dict(cs.probes[0])
    bad["steps"] = [dict(cs.probes[0]["steps"][0]),
                    {**cs.probes[0]["steps"][1], "success": "THIS_WILL_NOT_MATCH"}]
    confirmed, _ = run_probe(CassetteHttpClient(cs), bad)
    assert confirmed is False


# ── Signal extraction (real sensors over recorded traffic) ──────────────────────

def test_signals_from_log4shell_cassette():
    cs = _by_name(load_cassettes())["vulhub-log4shell"]
    sigs = {s.claim: s for s in signals_from_cassette(cs)}
    assert "CVE-2021-44228" in sigs
    probe = sigs["CVE-2021-44228"]
    assert probe.source == "probe" and probe.kev is True and probe.reliability == "high"
    assert "apache tomcat" in sigs            # tech inventory also detected (noise)


def test_cve_candidates_emit_one_signal_per_source():
    cs = _by_name(load_cassettes())["clean-wordpress"]
    sources = [s.source for s in signals_from_cassette(cs) if s.claim == "CVE-2023-2745"]
    assert sorted(sources) == ["nuclei", "nvd"]   # corroboration modeled honestly


# ── Corpus benchmark (oracle) ───────────────────────────────────────────────────

def test_corpus_oracle_passes_with_expected_metrics():
    r = score_cassettes(oracle=True)
    assert r.cases == 4 and r.subjects == 11
    assert (r.tp, r.fp, r.fn) == (2, 1, 0)
    assert r.critical_recall == 1.0 and r.critical_fn == 0
    assert abs(r.fp_reduction - (8 / 9)) < 1e-9   # raw 9 FPs -> 1
    assert r.passed is True


def test_corpus_pins_both_probe_confirmed_criticals():
    # Both Vulhub CVEs are probe-confirmed → pinned/confirmed by the gate, no AI needed.
    from src.fusion.gate import adjudicate, gray_band
    for case in cases_from_cassettes():
        verdicts = {v.claim: v for v in adjudicate(case.signals)}
        for cve in ("CVE-2021-44228", "CVE-2018-11776"):
            if cve in verdicts:
                assert verdicts[cve].pinned is True
                assert verdicts[cve].decision == "confirmed"
                assert gray_band([verdicts[cve]]) == []   # AI never sees a pinned critical


# ── Report exports ──────────────────────────────────────────────────────────────

def test_report_exports_are_well_formed():
    r = score_cassettes(oracle=True)
    parsed = json.loads(r.to_json())
    assert parsed["passed"] is True and parsed["fp_reduction"] > 0.8
    md = r.to_markdown()
    assert "Precision" in md and "False-positive reduction" in md and "Result: PASS" in md
    tex = r.to_latex()
    assert r"\begin{tabular}" in tex and r"\bottomrule" in tex
