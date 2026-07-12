"""Observation translator — the deterministic bridge from an AI QUESTION (information goal) to an
approved read-only observation, or an explicit CAPABILITY GAP (a discovered missing sensor)."""
import json

from src.reasoning.observation_translator import (
    CapabilityGap, ObservationStrategy, ObservationTranslator, design_information_goals,
)
from src.reasoning.state import ReasoningState


def test_known_goals_resolve_to_observation_strategies():
    t = ObservationTranslator()
    active = t.translate("engine_io")
    assert isinstance(active, ObservationStrategy) and active.mode == "active"
    assert active.probe.path.startswith("/socket.io")
    passive = t.translate("server_header")
    assert passive.mode == "passive" and passive.evidence_type == "server_header"
    # a technology name is itself observable (confirm nginx → nginx probe)
    assert t.translate("nginx").mode == "active"


def test_unknown_goal_is_a_capability_gap_not_a_guess():
    t = ObservationTranslator()
    assert t.translate("totally_unknown_sensor_xyz") is None      # no invented request
    strategies, gaps = t.plan(["engine_io", "totally_unknown_sensor_xyz"])
    assert len(strategies) == 1 and strategies[0].goal == "engine_io"
    assert len(gaps) == 1 and gaps[0].goal == "totally_unknown_sensor_xyz"
    assert gaps[0].kind == "missing_sensor" and "no approved" in gaps[0].reason


def test_intrusive_goals_are_out_of_scope_not_missing_sensors():
    """Request smuggling / CL-TE desync are policy ceilings, not product holes."""
    t = ObservationTranslator()
    assert t.translate("request_smuggling_behavior") is None
    strategies, gaps = t.plan([
        "engine_io", "request_smuggling_behavior", "transfer_encoding_normalization",
        "http2_downgrade_headers",
    ])
    assert len(strategies) == 1
    assert {g.goal for g in gaps} == {
        "request_smuggling_behavior", "transfer_encoding_normalization", "http2_downgrade_headers",
    }
    assert all(g.kind == "out_of_scope" for g in gaps)
    assert all("safe_active" in g.reason or "intrusive" in g.reason for g in gaps)


def test_plan_dedupes_goals():
    strategies, gaps = ObservationTranslator().plan(["server_header", "SERVER_HEADER", "server_header"])
    assert len(strategies) == 1 and not gaps


def test_passive_synonyms_and_version_goals_are_not_missing_sensors():
    """Accuracy fix: trivially-observable goals the AI phrases loosely must resolve, not become bogus
    capability gaps. 'server_headers' (plural), any '<tech>_version', and header/cookie synonyms are
    read passively off the response — never a missing sensor. Genuinely un-passive goals still gap."""
    t = ObservationTranslator()
    for goal, ev in [("server_headers", "http_headers"), ("iis_version", "version"),
                     ("http_sys_version", "version"), ("nginx_version", "version"),
                     ("security_headers", "http_headers"), ("powered_by", "http_headers"),
                     ("set_cookie", "cookie_set"),
                     ("http_sys_response_behavior", "server_header"),
                     ("ftp_anonymous_access", "banner"), ("ftp_auth_mechanism", "banner")]:
        s = t.translate(goal)
        assert s is not None and s.mode == "passive" and s.evidence_type == ev, goal
    # intrusive goals are out_of_scope gaps, not passive observations
    assert t.translate("http2_downgrade_headers") is None
    strategies, gaps = t.plan(["server_headers", "iis_version", "http2_downgrade_headers"])
    assert {s.goal for s in strategies} == {"server_headers", "iis_version"}
    assert [g.goal for g in gaps] == ["http2_downgrade_headers"]
    assert gaps[0].kind == "out_of_scope"


def test_collapsed_substring_resolves_verbose_goal():
    # "check_engine_io_handshake" should still map to the engine.io probe
    s = ObservationTranslator().translate("check_engine_io_handshake")
    assert s is not None and s.mode == "active" and "socket.io" in s.probe.path


def _state():
    s = ReasoningState(target="ex.com:80", scope=["ex.com"])
    s.world.technology = ["Microsoft IIS 10.0"]
    s.investigation.hypotheses.add_hypothesis(label="framework_of:svc", created_by="rule",
                                              likelihoods={"iis": 0.6, "nginx": 0.4})
    return s


def test_ai_proposes_questions_translated_to_strategies_and_gaps():
    def cassette(system, user):
        # AI asks WHAT it needs to know — not how to fetch it
        return json.dumps(["iis", "server_header", "http2_downgrade_headers", "mystery_sensor"])
    ig = design_information_goals(cassette, _state())
    assert ig.goals == ["iis", "server_header", "http2_downgrade_headers", "mystery_sensor"]
    resolved = {s.goal for s in ig.strategies}
    assert "iis" in resolved and "server_header" in resolved
    by_goal = {g.goal: g for g in ig.gaps}
    assert by_goal["http2_downgrade_headers"].kind == "out_of_scope"
    assert by_goal["mystery_sensor"].kind == "missing_sensor"


def test_design_information_goals_fail_soft():
    s = _state()
    assert design_information_goals(None, s).goals == []
    assert design_information_goals(lambda sy, u: "garbage", s).goals == []
    assert design_information_goals(lambda sy, u: json.dumps({"not": "list"}), s).goals == []

    def boom(sy, u):
        raise RuntimeError("down")
    assert design_information_goals(boom, s).goals == []


def test_the_ai_never_supplies_the_http_request():
    """The information-goal path takes only slugs; the DETERMINISTIC translator owns the request. An
    attempt to smuggle a path/URL is just an unknown goal → a capability gap, never an executed URL."""
    def cassette(system, user):
        return json.dumps(["http://evil.com/x", "/etc/passwd"])
    ig = design_information_goals(cassette, _state())
    assert ig.strategies == []                          # neither resolved to a probe
    assert {g.goal for g in ig.gaps} == {"http://evil.com/x", "/etc/passwd"}
