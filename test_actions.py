"""Action model (Phase 8a-1): descriptor/semantics split, risk-tier ordering, predicates."""
import dataclasses as dc

from src.reasoning.actions import (
    Action,
    ActionDescriptor,
    ActionLibrary,
    ActionSemantics,
    Predicate,
    RiskTier,
    satisfied,
)


# ── Risk tier ordering ──

def test_risk_tiers_are_ordered():
    assert RiskTier.READ_ONLY < RiskTier.SAFE_ACTIVE < RiskTier.INTRUSIVE < RiskTier.EXPLOIT


def test_risk_tier_parse():
    assert RiskTier.parse("exploit") is RiskTier.EXPLOIT
    assert RiskTier.parse("safe_active") is RiskTier.SAFE_ACTIVE
    assert RiskTier.parse(0) is RiskTier.READ_ONLY
    assert RiskTier.parse("nonsense") is RiskTier.READ_ONLY     # fail-closed to safest


# ── Predicates ──

def test_predicate_eq_and_exists():
    facts = {"framework": "wordpress", "port_open:443": True}
    assert Predicate("framework", "eq", "wordpress").evaluate(facts)
    assert not Predicate("framework", "eq", "drupal").evaluate(facts)
    assert Predicate("port_open:443", "exists").evaluate(facts)
    assert not Predicate("port_open:22", "exists").evaluate(facts)


def test_predicate_lt_gt():
    facts = {"version": "6.2"}
    assert Predicate("version", "lt", 6.4).evaluate(facts)
    assert not Predicate("version", "gt", 6.4).evaluate(facts)


def test_predicate_from_spec_shapes():
    assert Predicate.from_spec("tech=wordpress") == Predicate("tech", "eq", "wordpress")
    assert Predicate.from_spec("port_open:443").op == "exists"
    assert Predicate.from_spec("framework_known").op == "exists"
    assert Predicate.from_spec({"key": "v", "op": "gt", "value": 5}) == Predicate("v", "gt", 5)


def test_satisfied_helper():
    facts = {"a": 1, "b": "x"}
    assert satisfied([Predicate("a", "exists"), Predicate("b", "eq", "x")], facts)
    assert not satisfied([Predicate("c", "exists")], facts)


# ── Descriptor / semantics split ──

def test_action_split_descriptor_and_semantics():
    a = Action(
        descriptor=ActionDescriptor(id="check_actuator", name="Check actuator",
                                    risk_tier=RiskTier.SAFE_ACTIVE, references=("CWE-200",)),
        semantics=ActionSemantics(
            preconditions=(Predicate("framework", "eq", "spring_boot"),),
            effects=(Predicate("actuator_exposed", "eq", True),)))
    assert a.id == "check_actuator"
    assert a.risk_tier is RiskTier.SAFE_ACTIVE
    # descriptor carries identity/risk/refs; semantics carries pre/effects (separate concerns)
    desc_fields = {f.name for f in dc.fields(ActionDescriptor)}
    assert desc_fields == {"id", "name", "technique_ref", "risk_tier", "reversible", "references"}
    sem_fields = {f.name for f in dc.fields(ActionSemantics)}
    assert sem_fields == {"preconditions", "effects"}


def test_action_applicable_and_apply():
    a = Action(
        descriptor=ActionDescriptor(id="x"),
        semantics=ActionSemantics(
            preconditions=(Predicate("framework", "eq", "spring_boot"),),
            effects=(Predicate("version_known", "eq", True),)))
    facts = {"framework": "spring_boot"}
    assert a.applicable(facts)
    after = a.apply(facts)
    assert after["version_known"] is True
    assert "version_known" not in facts          # apply returns a NEW dict (immutable input)


def test_action_round_trip():
    spec = {
        "descriptor": {"id": "a1", "name": "A1", "risk_tier": "intrusive", "references": ["CVE-2024-1"]},
        "preconditions": ["tech=wordpress", "port_open:443"],
        "effects": ["admin_access=true"],
    }
    a = Action.from_dict(spec)
    assert a.risk_tier is RiskTier.INTRUSIVE
    assert a.semantics.preconditions[0] == Predicate("tech", "eq", "wordpress")
    assert Action.from_dict(a.to_dict()).id == "a1"


# ── ActionLibrary ──

def test_action_library_from_specs_skips_bad():
    lib = ActionLibrary.from_specs([
        {"descriptor": {"id": "good"}, "preconditions": [], "effects": []},
        {"no_id": True},                          # bad → skipped, not fatal
    ])
    assert len(lib) == 1
    assert lib.get("good") is not None
