"""Reasoning Transparency Invariant (Phase 1, revised in Surfacing 1a).

The reasoning subsystem must never change the actual scan FINDINGS — ports, vulns, TLS, headers,
ordering, or confidence. Originally the report whitelisted keys so reasoning never appeared at all.
As of the "surface the reasoning" work, the report intentionally carries a `reasoning` key (and
Phase-7 `change_*` keys) so the GUI can render the evidence graph / objectives / plans. The invariant
that still matters — and that these tests pin — is the stronger one: reasoning is *purely additive*.
Stripping the reasoning/change keys from a with-reasoning report yields the exact without-reasoning
report; no finding is ever perturbed.
"""
import json

from src import engine
from src.reasoning import build_reasoning_state
from src.scanner import HostResult

# Keys the reasoning subsystem is allowed to ADD to the report (and nothing else).
_REASONING_KEYS = {"reasoning", "change_delta", "change_seed", "change_report"}


def _art():
    return {
        "host_result": HostResult(target="ex.com", ip="1.2.3.4", hostname="ex.com",
                                  ttl=50, os_guess="Linux", ports=[], scan_duration_s=1.0,
                                  timestamp="2026-06-26T00:00:00Z"),
        "vuln_matches": [],
    }


def test_reasoning_is_purely_additive_to_the_report():
    """Reasoning may add its own keys, but must not change any existing finding."""
    base = _art()
    r1 = engine.build_json_report(dict(base))

    withr = dict(base)
    withr["reasoning"] = build_reasoning_state(
        "ex.com", ["ex.com"],
        {"host_result": {"ip": "1.2.3.4", "hostname": "ex.com"},
         "vuln_matches": [{"port": 80, "service": "http", "product": "nginx", "version": "1.25",
                           "detection_confidence": "HIGH",
                           "cves": [{"id": "CVE-2024-1", "cvss_score": 7.5}]}]},
    ).to_dict()
    r2 = engine.build_json_report(withr)

    # The reasoning key IS now surfaced (the whole point of the surfacing work).
    assert "reasoning" in r2 and "reasoning" not in r1
    # …but stripping the reasoning-owned keys recovers the byte-identical baseline report —
    # no finding (ports/vulns/tls/headers/confidence) was perturbed.
    stripped = {k: v for k, v in r2.items() if k not in _REASONING_KEYS}
    assert json.dumps(stripped, sort_keys=True, default=str) == \
        json.dumps(r1, sort_keys=True, default=str)


def test_builder_takes_no_emit_and_is_pure():
    # The builder cannot emit events — it has no emit/callback parameter, so it is
    # structurally incapable of changing the event stream.
    import inspect
    params = set(inspect.signature(build_reasoning_state).parameters)
    assert "emit" not in params and "on_token" not in params
