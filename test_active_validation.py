"""Active validation (un-gated safe_active) — CONFIRM hypotheses via non-destructive checks, through
the ActionGate. Ungating safe_active must NOT open intrusive/exploit; scope + opt-in are mandatory."""
import time

from src.reasoning.action_gate import ActionGate, AuthorizationToken, GateContext
from src.reasoning.actions import Action, ActionDescriptor, ActionSemantics, RiskTier
from src.reasoning.active_validation import (
    ActiveValidationRunner, SafeActiveExecutor, ValidationProbe, probes_for_state,
)
from src.reasoning.state import ReasoningState


def _state(target="localhost:3000", scope=("localhost",), candidates=("express", "nginx")):
    s = ReasoningState(target=target, scope=list(scope))
    s.investigation.hypotheses.add_hypothesis(
        label="framework_of:svc", created_by="rule",
        likelihoods={c: 1.0 / len(candidates) for c in candidates})
    return s


def _get_with(marker):
    def _get(url):
        return (200, f"HTTP/1.1 200 OK\n{marker}\n\n<html>ok</html>")
    return _get


# ── The capability: a safe_active check CONFIRMS a hypothesis ──

def test_safe_active_check_confirms_hypothesis():
    s = _state()
    runner = ActiveValidationRunner(executor=SafeActiveExecutor(http_get=_get_with("X-Powered-By: Express")))
    res = runner.validate(s, enabled=True)
    assert any(r.executed and r.succeeded and r.confirms == "express" for r in res)
    assert s.investigation.hypotheses.all()[0].status == "confirmed"
    # a proof Observation landed (Phase 8c), and every attempt was audited
    assert any(o.kind == "proof" for n in s.world.graph.nodes() for o in n.observations())
    assert len(runner.audit) >= 1


def test_non_matching_response_does_not_confirm():
    s = _state()
    res = ActiveValidationRunner(executor=SafeActiveExecutor(http_get=_get_with("Server: whatever"))).validate(s, enabled=True)
    assert all(not r.succeeded for r in res)
    assert s.investigation.hypotheses.all()[0].status == "active"


# ── Opt-in only ──

def test_disabled_makes_zero_requests():
    s = _state()
    calls = []
    runner = ActiveValidationRunner(executor=SafeActiveExecutor(http_get=lambda u: calls.append(u)))
    assert runner.validate(s, enabled=False) == []
    assert calls == [] and len(runner.audit) == 0
    assert s.investigation.hypotheses.all()[0].status == "active"


# ── Scope is mandatory (the gate blocks, execution never happens) ──

def test_out_of_scope_is_gated_and_never_executed():
    s = _state(target="evil.com:80", scope=("localhost",))
    calls = []
    runner = ActiveValidationRunner(executor=SafeActiveExecutor(http_get=lambda u: calls.append(u) or (200, "")))
    res = runner.validate(s, enabled=True)
    assert res and all(not r.gated_allowed and not r.executed for r in res)
    assert calls == []                                   # gate blocked before any request
    assert s.investigation.hypotheses.all()[0].status == "active"


def test_executor_refuses_off_scope_even_if_gate_bypassed():
    # Defense in depth: the executor itself refuses an off-scope target.
    probe = ValidationProbe("confirm_framework:express", "/", ("express",), "express")
    outcome, why = SafeActiveExecutor(http_get=lambda u: (200, "express")).execute(
        probe, "evil.com:80", scope=["localhost"])
    assert not outcome.authorized and not outcome.succeeded and "scope" in why


# ── Ungating safe_active did NOT open intrusive/exploit ──

def test_intrusive_still_denied_even_with_active_validation_on():
    intrusive = Action(descriptor=ActionDescriptor(id="x", risk_tier=RiskTier.INTRUSIVE),
                       semantics=ActionSemantics())
    ctx = GateContext(scope=["localhost"], active_validation_enabled=True)   # the flag we now use
    d = ActionGate().evaluate(intrusive, "localhost:3000", ctx)
    assert not d.allowed
    assert any("external authorized executor" in r for r in d.denials)


def test_exploit_denied_even_with_token_but_no_executor():
    tok = AuthorizationToken(targets=("localhost",), max_risk_tier=RiskTier.EXPLOIT,
                             expires_at=time.time() + 3600)
    ctx = GateContext(scope=["localhost"], active_validation_enabled=True,
                      execution_authorized=True, authorization=tok)   # everything but an executor
    d = ActionGate().evaluate(
        Action(descriptor=ActionDescriptor(id="e", risk_tier=RiskTier.EXPLOIT),
               semantics=ActionSemantics()), "localhost:3000", ctx)
    assert not d.allowed          # core ships no offensive executor → still denied


def test_all_validation_actions_are_safe_active_and_reversible():
    s = _state(candidates=("express", "wordpress", "spring_boot", "django"))
    for probe in probes_for_state(s):
        a = probe.as_action()
        assert a.risk_tier == RiskTier.SAFE_ACTIVE
        assert a.descriptor.reversible is True


# ── Breadth: the validator library + free-form candidate resolution ──

def test_every_builtin_validator_is_safe_active_reversible_with_markers():
    from src.reasoning.active_validation import _FRAMEWORK_PROBES
    assert len(_FRAMEWORK_PROBES) >= 12          # breadth-first coverage of common stacks
    for probe in _FRAMEWORK_PROBES.values():
        a = probe.as_action()
        assert a.risk_tier == RiskTier.SAFE_ACTIVE and a.descriptor.reversible is True
        assert probe.path.startswith("/") and probe.markers and probe.confirms


def test_free_form_candidates_resolve_to_the_right_validator():
    from src.reasoning.active_validation import _probe_for_candidate
    cases = {"Express": "express", "Ruby on Rails": "rails", "nginx reverse proxy": "nginx",
             "ASP.NET": "aspnet", "Spring Boot": "spring_boot", "node.js": "express",
             "GraphQL": "graphql", "Laravel": "laravel", "FastAPI": "fastapi"}
    for phrasing, expected in cases.items():
        probe = _probe_for_candidate(phrasing)
        assert probe is not None and probe.confirms == expected, phrasing
    assert _probe_for_candidate("totally-unknown-xyz") is None   # no spurious match


def test_ai_phrased_hypothesis_gets_a_probe():
    # the exact free-form candidates the live AI produced ("nginx reverse proxy", "Ruby on Rails")
    s = _state(candidates=("nginx reverse proxy", "Ruby on Rails", "FastAPI"))
    confirms = {p.confirms for p in probes_for_state(s)}
    assert {"nginx", "rails", "fastapi"} <= confirms


# ── AI-proposed probes: the AI directs investigation beyond the fixed sensor suite (safely) ──

import json as _json


def _ai_state():
    s = ReasoningState(target="localhost:3000", scope=["localhost"])
    s.investigation.hypotheses.add_hypothesis(label="framework_of:svc", created_by="rule",
                                              likelihoods={"spring_boot": 0.5, "express": 0.5})
    return s


def test_ai_designs_probes_beyond_the_fixed_sensor_suite():
    from src.reasoning.active_validation import design_ai_probes
    def cassette(system, user):
        return _json.dumps([
            {"path": "/actuator", "markers": ['"_links"'], "confirms": "spring_boot"},
            {"path": "/.git/config", "markers": ["[core]"], "confirms": "git_exposure"},
        ])
    probes = design_ai_probes(cassette, _ai_state())
    got = {p.confirms: p.path for p in probes}
    assert got.get("spring_boot") == "/actuator"
    assert got.get("git_exposure") == "/.git/config"     # NOT one of OSINT/DNS/stack/headers/TLS/takeover
    for p in probes:                                     # still safe_active + reversible
        assert p.as_action().risk_tier == RiskTier.SAFE_ACTIVE and p.as_action().descriptor.reversible


def test_ai_probe_sanitizer_blocks_ssrf_and_injection():
    from src.reasoning.active_validation import _safe_path, design_ai_probes
    assert _safe_path("http://evil.com/x") is None        # absolute URL (SSRF) rejected
    assert _safe_path("//evil.com") is None               # protocol-relative rejected
    assert _safe_path("/a b") is None                     # whitespace rejected
    assert _safe_path("/api/v2") == "/api/v2"             # benign relative path allowed

    def malicious(system, user):
        return _json.dumps([
            {"path": "http://evil.com/steal", "markers": ["x"], "confirms": "ssrf"},   # dropped
            {"path": "/ok", "markers": ["marker"], "confirms": "legit"},               # kept
        ])
    probes = design_ai_probes(malicious, _ai_state())
    assert [p.confirms for p in probes] == ["legit"]       # only the benign probe survived


def test_ai_probes_reject_abstract_security_conclusions():
    """confirms must be a tech slug — not 'vulnerable_iis_version' / 'waf_masking_backend'."""
    from src.reasoning.active_validation import design_ai_probes

    def cassette(system, user):
        return _json.dumps([
            {"path": "/", "markers": ["iis"], "confirms": "vulnerable_iis_version"},
            {"path": "/", "markers": ["iis"], "confirms": "waf_masking_backend"},
            {"path": "/", "markers": ["microsoft-iis"], "confirms": "iis"},
        ])
    probes = design_ai_probes(cassette, _ai_state())
    assert [p.confirms for p in probes] == ["iis"]


def test_ai_probes_are_gated_and_audited_like_built_ins():
    from src.reasoning.active_validation import design_ai_probes
    def cassette(system, user):
        return _json.dumps([{"path": "/actuator", "markers": ["_links"], "confirms": "spring_boot"}])
    s = _ai_state()
    probes = design_ai_probes(cassette, s)
    runner = ActiveValidationRunner(executor=SafeActiveExecutor(http_get=_get_with('{"_links": {}}')))
    res = runner.validate(s, probes=probes, enabled=True)
    assert res and res[0].gated_allowed and res[0].executed and res[0].succeeded
    assert len(runner.audit) == 1                          # AI probe audited exactly like a built-in


def test_ai_probes_fail_soft():
    from src.reasoning.active_validation import design_ai_probes
    s = _ai_state()
    assert design_ai_probes(None, s) == []
    assert design_ai_probes(lambda sy, u: "not json", s) == []
    assert design_ai_probes(lambda sy, u: _json.dumps({"not": "a list"}), s) == []
    def boom(sy, u):
        raise RuntimeError("down")
    assert design_ai_probes(boom, s) == []


# ── AI's role in WHAT RUNS: veto + prioritize, but never escalate past the gate ──

def _adj(verdicts_json):
    def _c(system, user):
        return verdicts_json
    return _c


def test_ai_can_veto_a_probe():
    from src.reasoning.active_validation import ProbeAdjudicator
    s = _state(candidates=("express", "nginx"))   # probes_for_state → [express(0), nginx(1)]
    verdicts = _json.dumps([{"index": 0, "run": True}, {"index": 1, "run": False, "reason": "low value"}])
    runner = ActiveValidationRunner(executor=SafeActiveExecutor(http_get=_get_with("X-Powered-By: Express")),
                                    adjudicator=ProbeAdjudicator(_adj(verdicts)))
    res = {r.confirms: r for r in runner.validate(s, enabled=True)}
    assert res["nginx"].ai_skipped and not res["nginx"].executed          # AI veto → never ran
    assert res["express"].executed                                         # AI-approved → ran (gate ok)


def test_ai_safety_veto_is_overridden_relevance_veto_survives():
    """The core accuracy fix: the AI must NOT be able to skip a benign GET on safety/risk grounds
    (that's the gate's exclusive job) — the real bug where '/web.config is high-risk/aggressive'
    vetoed a plain GET and blinded the scan. A safety-flavoured veto is dropped (the gate decides);
    a genuine RELEVANCE veto still skips."""
    from src.reasoning.active_validation import ProbeAdjudicator
    s = _state(candidates=("express", "nginx"))          # probes: express(0), nginx(1)
    verdicts = _json.dumps([
        {"index": 0, "run": False, "reason": "accessing web.config is high-risk/aggressive"},
        {"index": 1, "run": False, "reason": "server is clearly Apache, not nginx"}])
    runner = ActiveValidationRunner(executor=SafeActiveExecutor(http_get=_get_with("X-Powered-By: Express")),
                                    adjudicator=ProbeAdjudicator(_adj(verdicts)))
    res = {r.confirms: r for r in runner.validate(s, enabled=True)}
    assert not res["express"].ai_skipped and res["express"].executed        # safety-veto overridden → ran
    assert res["nginx"].ai_skipped and not res["nginx"].executed            # relevance-veto preserved


def test_ai_run_recommendation_cannot_override_the_gate():
    """The safety property: an AI 'run' verdict NEVER authorizes a probe the deterministic gate denies
    (here: off-scope). AI can subtract from the allowed set, never add to it."""
    from src.reasoning.active_validation import ProbeAdjudicator
    s = _state(target="evil.com:80", scope=("localhost",), candidates=("express", "nginx"))
    run_all = _json.dumps([{"index": 0, "run": True, "priority": 1.0},
                           {"index": 1, "run": True, "priority": 1.0}])
    res = ActiveValidationRunner(executor=SafeActiveExecutor(http_get=_get_with("Express")),
                                 adjudicator=ProbeAdjudicator(_adj(run_all))).validate(s, enabled=True)
    assert res and all(not r.gated_allowed and not r.executed and not r.ai_skipped for r in res)
    assert all("not in scope" in " ".join(r.denials) for r in res)         # gate denied despite AI 'run'


def test_broken_adjudicator_defers_to_the_gate():
    from src.reasoning.active_validation import ProbeAdjudicator
    s = _state(candidates=("express",))
    def boom(system, user):
        raise RuntimeError("model down")
    # broken AI ⇒ no verdicts ⇒ every probe still goes through the gate (broken AI == no AI)
    res = ActiveValidationRunner(executor=SafeActiveExecutor(http_get=_get_with("X-Powered-By: Express")),
                                 adjudicator=ProbeAdjudicator(boom)).validate(s, enabled=True)
    assert res and res[0].executed and not res[0].ai_skipped


def test_adjudicator_orders_by_priority():
    from src.reasoning.active_validation import ProbeAdjudicator
    s = _state(candidates=("express", "nginx"))
    # give nginx higher priority than express → nginx should be evaluated first
    verdicts = _json.dumps([{"index": 0, "run": True, "priority": 0.1},
                            {"index": 1, "run": True, "priority": 0.9}])
    res = ActiveValidationRunner(executor=SafeActiveExecutor(http_get=lambda u: (200, "")),
                                 adjudicator=ProbeAdjudicator(_adj(verdicts))).validate(s, enabled=True)
    assert res[0].confirms == "nginx"                                      # higher-priority first
