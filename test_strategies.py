"""Strategy + Investigation Template layer (Phase 8a-3): adaptive generate_plan, staged templates."""
from src.reasoning.actions import Action, ActionDescriptor, ActionSemantics, Predicate, RiskTier
from src.reasoning.strategies import (
    InvestigationTemplate,
    Strategy,
    StrategyRegistry,
)


def _action(aid, pre=None, eff=None, risk=RiskTier.READ_ONLY):
    return Action(
        descriptor=ActionDescriptor(id=aid, risk_tier=risk),
        semantics=ActionSemantics(
            preconditions=tuple(Predicate.from_spec(p) for p in (pre or [])),
            effects=tuple(Predicate.from_spec(e) for e in (eff or []))))


# ── Strategy.generate_plan is adaptive (conditional on world) ──

def test_static_strategy_yields_next_useful_action():
    # try headers (gives framework), else body
    headers = _action("headers", eff=["framework_known"])
    body = _action("body", eff=["framework_known"])
    s = Strategy.of_actions("fp", "framework_known", [headers, body])

    # nothing known yet → first useful action offered
    plan = s.generate_plan({})
    assert [a.id for a in plan] == ["headers", "body"]   # both applicable, effects not yet held

    # once framework is known, neither is "useful" (effects already hold)
    assert s.generate_plan({"framework_known": True}) == []


def test_deferred_strategy_branches_on_world():
    def gen(facts):
        if not facts.get("http_ok"):
            return []
        if facts.get("headers_seen"):
            return [_action("body")]
        return [_action("headers")]
    s = Strategy.deferred("fp", "framework_known", gen)

    assert s.generate_plan({}) == []                      # no http → nothing
    assert [a.id for a in s.generate_plan({"http_ok": True})] == ["headers"]
    assert [a.id for a in s.generate_plan({"http_ok": True, "headers_seen": True})] == ["body"]


def test_strategy_applicability_gate():
    s = Strategy.of_actions("wp", "framework_known", [_action("wp_login")],
                            applicability=(Predicate.from_spec("port_open:443"),))
    assert not s.applies({})
    assert s.applies({"port_open:443": True})


# ── Investigation Template: staged ──

def test_default_template_is_single_stage():
    t = InvestigationTemplate(id="t", goal_class="framework_known")
    assert t.first_stage() == "default"
    assert t.next_stage("default") is None


def test_multi_stage_template_advances():
    t = InvestigationTemplate(id="confirm_cve", goal_class="cve_confirmed",
                              stages=("version", "exploitability", "evidence"))
    assert t.first_stage() == "version"
    assert t.next_stage("version") == "exploitability"
    assert t.next_stage("exploitability") == "evidence"
    assert t.next_stage("evidence") is None


# ── Registry ──

def test_registry_groups_by_goal_class_and_defaults_template():
    reg = StrategyRegistry()
    reg.register_strategy(Strategy.of_actions("a", "framework_known", [_action("x")]))
    reg.register_strategy(Strategy.of_actions("b", "framework_known", [_action("y")]))
    reg.register_strategy(Strategy.of_actions("c", "cve_confirmed", [_action("z")]))

    assert {s.id for s in reg.strategies_for("framework_known")} == {"a", "b"}
    assert {s.id for s in reg.strategies_for("cve_confirmed")} == {"c"}
    # default template for an unregistered class
    assert reg.template_for("framework_known").first_stage() == "default"
