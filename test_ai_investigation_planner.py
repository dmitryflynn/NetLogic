"""AI Investigation Planner (ai/agents) — the overlay OVER the deterministic Architecture Summary.

Reviewer's constraint: the AI reasons over established components to PRIORITISE what to investigate;
it must NOT invent technologies, must NOT claim vulnerabilities, and every objective must be GROUNDED
in a detected component (anti-hallucination). Fail-soft on broken AI.
"""
import json

from src.reasoning.ai.agents import InvestigationPlanner

_ARCH = {
    "stack_kind": "serverless-spa", "execution_model": "Serverless",
    "components": [
        {"role": "frontend", "name": "React SPA"},
        {"role": "hosting", "name": "Vercel"},
        {"role": "auth", "name": "Clerk"},
        {"role": "backend", "name": "Supabase"},
    ],
    "attack_surfaces": ["authentication flows", "exposed API endpoints",
                        "Supabase configuration / Row-Level Security"],
}


def _completer(items):
    def c(system, user):
        return json.dumps(items)
    return c


def test_produces_grounded_prioritised_objectives():
    plan = InvestigationPlanner(_completer([
        {"title": "Verify Clerk configuration", "reason": "Authentication is externally exposed",
         "component": "Clerk", "priority": 1},
        {"title": "Enumerate Supabase REST endpoints", "reason": "Backend identified",
         "component": "Supabase", "priority": 2},
        {"title": "Inspect the React bundle", "reason": "Likely contains API references",
         "component": "React SPA", "priority": 3},
    ])).plan(_ARCH)
    assert [o["title"] for o in plan][:1] == ["Verify Clerk configuration"]   # priority-sorted
    assert all(o["component"].lower() in {"react spa", "vercel", "clerk", "supabase"} for o in plan)
    assert plan[0]["priority"] == 1


def test_ungrounded_objective_is_dropped():
    # the AI references a technology that was NEVER detected → must be discarded (anti-hallucination)
    plan = InvestigationPlanner(_completer([
        {"title": "Test the WordPress admin", "reason": "…", "component": "WordPress", "priority": 1},
        {"title": "Verify Clerk configuration", "reason": "…", "component": "Clerk", "priority": 2},
    ])).plan(_ARCH)
    assert [o["component"] for o in plan] == ["Clerk"]        # WordPress dropped


def test_priority_clamped_and_sorted():
    plan = InvestigationPlanner(_completer([
        {"title": "b", "component": "Supabase", "priority": 9},
        {"title": "a", "component": "Clerk", "priority": 1},
    ])).plan(_ARCH)
    assert plan[0]["title"] == "a"
    assert all(1 <= o["priority"] <= 5 for o in plan)


def test_empty_architecture_yields_nothing():
    assert InvestigationPlanner(_completer([{"title": "x", "component": "y", "priority": 1}])).plan({}) == []
    assert InvestigationPlanner(_completer([])).plan(_ARCH) == []


def test_broken_ai_is_failsoft():
    def boom(system, user):
        raise RuntimeError("model down")
    assert InvestigationPlanner(boom).plan(_ARCH) == []
    def garbage(system, user):
        return "not json {{{"
    assert InvestigationPlanner(garbage).plan(_ARCH) == []
