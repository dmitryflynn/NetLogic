"""Objective goal-predicate + ObjectiveSource (Phase 8a-2)."""
from src.reasoning.objective import Objective, ObjectiveDAG, ObjectiveSource


def test_objective_defaults_are_backward_compatible():
    o = Objective(name="identify_framework:ex.com")
    assert o.goal_predicate == []
    assert o.risk_budget == "read_only"
    assert o.source.generated_by == "generator"
    # legacy boolean satisfaction still works when there's no predicate
    assert o.predicate_satisfied({}) is False
    o.satisfied = True
    assert o.predicate_satisfied({}) is True


def test_goal_predicate_satisfaction():
    o = Objective(name="confirm", goal_predicate=[{"key": "framework", "op": "eq", "value": "wordpress"}])
    assert not o.predicate_satisfied({"framework": "drupal"})
    assert o.predicate_satisfied({"framework": "wordpress"})


def test_goal_predicate_string_specs():
    o = Objective(name="confirm", goal_predicate=["framework=wordpress", "version_known"])
    assert not o.predicate_satisfied({"framework": "wordpress"})            # version_known missing
    assert o.predicate_satisfied({"framework": "wordpress", "version_known": True})


def test_objective_source_provenance():
    o = Objective(name="x", source=ObjectiveSource(generated_by="delta", reason="new CVE", confidence=0.9))
    assert o.source.generated_by == "delta"
    assert o.source.reason == "new CVE"


def test_objective_round_trip_preserves_phase8_fields():
    o = Objective(name="x", goal_predicate=["a=1"], constraints={"max_steps": 5},
                  risk_budget="safe_active",
                  source=ObjectiveSource(generated_by="planner", reason="chain"))
    r = Objective.from_dict(o.to_dict())
    assert r.goal_predicate == ["a=1"]
    assert r.constraints == {"max_steps": 5}
    assert r.risk_budget == "safe_active"
    assert r.source.generated_by == "planner"


def test_objective_dag_still_works():
    dag = ObjectiveDAG()
    dag.add(Objective(name="a"))
    dag.add(Objective(name="b", dependencies=["a"]))
    assert {o.name for o in dag.ready()} == {"a"}      # b blocked until a satisfied
    dag.get("a").satisfied = True
    assert {o.name for o in dag.ready()} == {"b"}
