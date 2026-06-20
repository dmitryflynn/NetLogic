"""Tests for the Wappalyzer fusion sensor + its signals flowing through the gate."""

from src.fusion import adjudicate, Signal
from src.fusion.gate import gray_band, confirmed
from src.fusion.sensors import HttpResponse, Wappalyzer


def _wap():
    return Wappalyzer()   # loads the bundled minimal fingerprints


def _by_claim(signals):
    return {s.claim: s for s in signals}


# ── Detection accuracy + version extraction ─────────────────────────────────────

def test_detects_nginx_with_version_from_server_header():
    sigs = _wap().detect(HttpResponse(host="h", port=443, headers={"Server": "nginx/1.25.3"}))
    s = _by_claim(sigs)["nginx"]
    assert s.source == "wappalyzer" and s.kind == "tech"
    assert s.raw_metadata["version"] == "1.25.3"
    assert "nginx/1.25.3" in s.evidence


def test_detects_apache_version_ignoring_os_suffix():
    sigs = _wap().detect(HttpResponse(host="h", headers={"Server": "Apache/2.4.41 (Ubuntu)"}))
    assert _by_claim(sigs)["apache"].raw_metadata["version"] == "2.4.41"


def test_detects_jenkins_from_header_and_title():
    resp = HttpResponse(host="h", port=8080,
                        headers={"X-Jenkins": "2.426.1"},
                        html="<html><title>Dashboard [Jenkins]</title></html>")
    s = _by_claim(_wap().detect(resp))["jenkins"]
    assert s.raw_metadata["version"] == "2.426.1"
    # both the header and the title contributed evidence
    assert "header X-Jenkins" in s.evidence and "html match" in s.evidence


def test_wordpress_meta_detected_and_implies_php():
    resp = HttpResponse.from_html(
        host="h",
        html='<head><meta name="generator" content="WordPress 6.4.2"></head>',
    )
    sigs = _by_claim(_wap().detect(resp))
    assert sigs["wordpress"].raw_metadata["version"] == "6.4.2"
    # PHP is IMPLIED → present, but lower reliability + flagged implied
    assert "php" in sigs
    assert sigs["php"].reliability == "low"
    assert sigs["php"].raw_metadata["implied"] is True
    assert "implied by WordPress" in sigs["php"].evidence


def test_grafana_detected_from_cookie():
    sigs = _wap().detect(HttpResponse(host="h", cookies={"grafana_session": "abc123"}))
    assert "grafana" in _by_claim(sigs)


def test_from_html_extracts_scripts_and_metas():
    resp = HttpResponse.from_html(
        host="h",
        html='<script src="/static/app.js"></script><meta name="Generator" content="WordPress 5.0">',
    )
    assert resp.scripts == ["/static/app.js"]
    assert resp.metas["generator"] == "WordPress 5.0"


# ── Precision: no false positives, no crashes ───────────────────────────────────

def test_no_false_positive_on_unrelated_server():
    sigs = _wap().detect(HttpResponse(host="h", headers={"Server": "cloudflare"}))
    claims = {s.claim for s in sigs}
    assert "nginx" not in claims and "apache" not in claims


def test_empty_response_yields_no_signals():
    assert _wap().detect(HttpResponse(host="h")) == []


def test_bad_regex_in_dataset_is_skipped_not_crashed():
    bad = {"technologies": {"Broken": {"headers": {"Server": "([unclosed"}}}}
    # A malformed regex must neither crash nor match.
    sigs = Wappalyzer(data=bad["technologies"]).detect(HttpResponse(host="h", headers={"Server": "anything"}))
    assert sigs == []


def test_confidence_tag_is_carried_through():
    # Tomcat's Server pattern carries \;confidence:75
    sigs = _by_claim(_wap().detect(HttpResponse(host="h", headers={"Server": "Apache-Coyote/1.1"})))
    assert abs(sigs["apache tomcat"].confidence - 0.75) < 1e-9


# ── Signals flow through the gate ───────────────────────────────────────────────

def test_lone_tech_signal_is_inventory_and_auto_discarded():
    # A single tech detection with no corroboration / no exploitation context is
    # inventory, not a finding — the gate discards it (it never reaches the AI).
    sigs = _wap().detect(HttpResponse(host="h", port=443, headers={"Server": "nginx/1.25.3"}))
    verdicts = adjudicate(sigs)
    nginx = next(v for v in verdicts if v.claim == "nginx")
    assert nginx.decision == "discarded"
    assert confirmed(verdicts) == []


def test_tech_corroborated_by_banner_is_not_discarded():
    # Wappalyzer + an independent banner sensor agree on the same tech+port → the
    # gate stops treating it as droppable noise (lifts it to the AI for context).
    resp = HttpResponse(host="h", port=8080, headers={"X-Jenkins": "2.426.1"},
                        html="<title>Jenkins</title>")
    sigs = _wap().detect(resp)
    sigs.append(Signal(source="banner", kind="tech", claim="jenkins", host="h", port=8080,
                       reliability="medium", evidence="Server: Jetty(9.4.x) X-Jenkins-Session"))
    jenkins = next(v for v in adjudicate(sigs) if v.claim == "jenkins")
    assert jenkins.agreement == 2
    assert jenkins.decision != "discarded"


def test_tech_plus_kev_vuln_on_same_subject_pins_the_vuln():
    # The tech detection is inventory; a KEV vuln signal for the SAME host:port is a
    # separate subject (the CVE) and must be pinned/confirmed regardless of the tech.
    resp = HttpResponse(host="h", port=8080, headers={"X-Jenkins": "2.137"})
    sigs = _wap().detect(resp)
    sigs.append(Signal(source="nvd", kind="vuln", claim="CVE-2019-1003000", host="h", port=8080,
                       cvss=9.8, kev=True, exploit_available=True,
                       evidence="Jenkins 2.137 < 2.138 Script Security RCE"))
    verdicts = {v.claim: v for v in adjudicate(sigs)}
    assert verdicts["jenkins"].decision == "discarded"           # tech = inventory
    assert verdicts["CVE-2019-1003000"].pinned is True           # vuln = un-droppable
    assert verdicts["CVE-2019-1003000"].decision == "confirmed"
    assert gray_band(list(verdicts.values())) == []              # nothing wasted on the AI here
