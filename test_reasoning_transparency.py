"""Reasoning Transparency Invariant (Phase 1).

Given identical scan inputs and no AI-driven adaptive loop, enabling the reasoning subsystem
must not change emitted scan events, findings, ordering, or confidence values. The reasoning
state is built passively and attached to `art["reasoning"]`; every reporter whitelists keys,
so it can never leak into output. These tests pin that contract.
"""
import json

from src import engine
from src.reasoning import build_reasoning_state
from src.scanner import HostResult


def _art():
    return {
        "host_result": HostResult(target="ex.com", ip="1.2.3.4", hostname="ex.com",
                                  ttl=50, os_guess="Linux", ports=[], scan_duration_s=1.0,
                                  timestamp="2026-06-26T00:00:00Z"),
        "vuln_matches": [],
    }


def test_json_report_identical_with_and_without_reasoning():
    base = _art()
    r1 = engine.build_json_report(dict(base))

    withr = dict(base)
    # a fully-built reasoning state attached to art must not change the report
    withr["reasoning"] = build_reasoning_state(
        "ex.com", ["ex.com"],
        {"host_result": {"ip": "1.2.3.4", "hostname": "ex.com"},
         "vuln_matches": [{"port": 80, "service": "http", "product": "nginx", "version": "1.25",
                           "detection_confidence": "HIGH",
                           "cves": [{"id": "CVE-2024-1", "cvss_score": 7.5}]}]},
    ).to_dict()
    r2 = engine.build_json_report(withr)

    assert json.dumps(r1, sort_keys=True, default=str) == json.dumps(r2, sort_keys=True, default=str)


def test_builder_takes_no_emit_and_is_pure():
    # The builder cannot emit events — it has no emit/callback parameter, so it is
    # structurally incapable of changing the event stream.
    import inspect
    params = set(inspect.signature(build_reasoning_state).parameters)
    assert "emit" not in params and "on_token" not in params
