"""UDP reply attribution + finding-id normalize — HackerOne-grade false-positive guards."""
from __future__ import annotations

from src.ip_scope import (
    host_matches_scope,
    is_private_or_local,
    normalize_finding_id,
    reply_from_target,
    resolve_host_ips,
)
from src.reasoning.agent.tools import ToolRuntime
from src.reasoning.agent.findings import merge_agent_into_investigations


def test_host_matches_scope_is_label_bounded():
    assert host_matches_scope("example.com", "example.com")
    assert host_matches_scope("sub.example.com", "example.com")
    assert not host_matches_scope("example.com", "ample.com")
    assert not host_matches_scope("notexample.com", "example.com")
    assert not host_matches_scope("ample.com", "example.com")


def test_host_matches_scope_ip_is_not_a_dns_suffix():
    assert host_matches_scope("10.0.0.5", "10.0.0.5")
    assert host_matches_scope("10.0.0.5:443", "10.0.0.5")
    assert not host_matches_scope("evil.10.0.0.5", "10.0.0.5")
    assert not host_matches_scope("evil.2001:db8::1", "2001:db8::1")
    assert host_matches_scope("2001:db8::1", "2001:db8::1")
    assert host_matches_scope("[2001:db8::1]", "2001:db8::1")


def test_private_ip_detection():
    assert is_private_or_local("192.168.0.1")
    assert is_private_or_local("10.0.0.5")
    assert is_private_or_local("127.0.0.1")
    assert not is_private_or_local("104.17.69.73")
    assert not is_private_or_local("1.1.1.1")


def test_reply_from_public_target_rejects_lan_gateway():
    # Cloudflare edge must never accept home-router UPnP as evidence
    assert not reply_from_target("192.168.0.1", "104.17.69.73")
    assert not reply_from_target("192.168.0.1", "lwsd.org")
    # Matching public IP is accepted
    assert reply_from_target("104.17.69.73", "104.17.69.73")


def test_reply_from_private_lab_target_allows_private():
    # Scanning a lab box at 10.0.0.5 — private replies from that host are OK
    assert reply_from_target("10.0.0.5", "10.0.0.5")
    assert not reply_from_target("192.168.0.1", "10.0.0.5")  # different private host


def test_normalize_finding_id_collapses_ssdp_and_tech():
    assert normalize_finding_id("ssdp-exposed") == "ssdp_exposed"
    assert normalize_finding_id("upnp-exposure", "UPnP Device Discovery") == "ssdp_exposed"
    assert normalize_finding_id("ssdp-exposure") == "ssdp_exposed"
    assert normalize_finding_id("tech:cloudflare") == "tech_cloudflare"
    assert normalize_finding_id("cloudflare-protection") == "tech_cloudflare"
    assert normalize_finding_id("CVE-2021-31166-CONFIRMED") == "cve-2021-31166"
    assert normalize_finding_id("cve-2021-31166") == "cve-2021-31166"


def test_assert_finding_dedupes_ssdp_variants():
    rt = ToolRuntime(host="ex.com")
    # Fake an in-scope ssdp observation
    rt.observations.append({
        "ok": True, "observation_id": "obs_1", "tool": "ssdp_discover",
        "summary": "ssdp :1900 → 1 reply(ies) from target",
        "data": {"replies": ["from 203.0.113.5:1900\nSERVER: UPnP/1.0"], "port": 1900},
    })
    for fid, title in (
        ("ssdp-exposed", "UPnP Exposed"),
        ("upnp-exposure", "UPnP Discovery"),
        ("ssdp-exposure", "SSDP Service Exposed"),
    ):
        rt.execute("assert_finding", {
            "id": fid, "title": title, "severity": "medium",
            "status": "confirmed", "evidence_refs": ["obs_1"],
            "rationale": "ssdp replies",
        })
    ids = [f["id"] for f in rt.findings]
    assert ids.count("ssdp_exposed") == 1
    assert len(rt.findings) == 1
    assert rt.findings[0]["status"] == "confirmed"
    assert len(rt.findings[0]["evidence_refs"]) >= 1


def test_assert_finding_ssdp_cannot_confirm_without_in_scope_replies():
    rt = ToolRuntime(host="ex.com")
    # Off-target / empty replies observation
    rt.observations.append({
        "ok": False, "observation_id": "obs_1", "tool": "ssdp_discover",
        "summary": "ssdp :1900 → no target reply (ignored 5 off-target)",
        "data": {"replies": [], "ignored_sources": ["192.168.0.1:1900"]},
    })
    r = rt.execute("assert_finding", {
        "id": "ssdp-exposed", "title": "UPnP", "status": "confirmed",
        "evidence_refs": ["obs_1"],
    })
    assert r.ok
    assert rt.findings[0]["status"] == "lead"  # demoted — no in-scope replies


def test_merge_agent_dedupes_and_skips_tech_inventory():
    invs = []
    agent = {
        "findings": [
            {"id": "ssdp-exposed", "title": "A", "status": "confirmed",
             "evidence_refs": ["obs_1"], "rationale": "r1"},
            {"id": "upnp-exposure", "title": "B", "status": "confirmed",
             "evidence_refs": ["obs_2"], "rationale": "r2 longer rationale here"},
            {"id": "tech-cloudflare", "title": "CF", "status": "confirmed",
             "evidence_refs": ["obs_3"], "rationale": "cdn"},
        ]
    }
    out = merge_agent_into_investigations(invs, agent)
    subjects = [i["subject"] for i in out]
    assert subjects.count("ssdp_exposed") == 1
    assert not any(str(s).startswith("tech_") for s in subjects)


def test_probe_targets_drops_public_hosts():
    from src.network_prober import probe_targets
    assert probe_targets(["8.8.8.8", "127.0.0.1", "169.254.1.1"], [80, 443]) == []
