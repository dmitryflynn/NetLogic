"""Reasoning benchmark corpus — the golden set, treated like a compiler test suite.

Each case under tests/reasoning/corpus/*.json declares a kind (generate | infer | audit), a
compact input, and STRUCTURAL expectations (prefixes / containment / counts — never unstable
IDs). The harness replays the deterministic reasoning pipeline network-independently and asserts
the structures + that the ReasoningValidator stays clean. Includes happy, ambiguous, and
contradictory cases, plus invalid_state cases that validate the validator itself.

Adding a golden case = adding a JSON file.
"""
import glob
import json
import os

import pytest

from src.reasoning import ReasoningState, build_reasoning_state, generators
from src.reasoning.compiler import Compiler
from src.reasoning.execution_planner import ExecutionPlanner
from src.reasoning.inference import InferenceEngine
from src.reasoning.objective import Objective
from src.reasoning.primitive_registry import default_registry
from src.reasoning.reasoning_validator import ReasoningValidator

_DIR = os.path.join(os.path.dirname(__file__), "tests", "reasoning", "corpus")


def _cases():
    out = []
    for path in sorted(glob.glob(os.path.join(_DIR, "*.json"))):
        with open(path, encoding="utf-8") as fh:
            c = json.load(fh)
        c["_file"] = os.path.basename(path)
        out.append(c)
    return out


_CASES = _cases()


def _known_ports(art):
    host = art.get("host_result") or {}
    return [{"port": p.get("port"), "service": p.get("service", ""), "tls": p.get("tls", False),
             "state": p.get("state", "open")} for p in (host.get("ports") or [])]


def _no_fatal(state):
    bad = [i for i in ReasoningValidator().audit(state) if i.severity in ("error", "fatal")]
    assert not bad, f"validator not clean: {[i.code for i in bad]}"


def test_corpus_present():
    assert _CASES, "no benchmark cases found"


@pytest.mark.parametrize("case", _CASES, ids=[c["_file"] for c in _CASES])
def test_benchmark_case(case):
    kind, exp = case["kind"], case.get("expect", {})

    if kind == "generate":
        s = build_reasoning_state(case["target"], case.get("scope", [case["target"]]),
                                  case["input_artifacts"])
        generators.populate(s)
        intents = generators.generate_intents(s)
        graph = Compiler().compile_many(intents, _known_ports(case["input_artifacts"]))
        plan = ExecutionPlanner(default_registry()).plan(graph, _known_ports(case["input_artifacts"]))
        onames = [o.name for o in s.investigation.objectives.all()]
        for pre in exp.get("objectives_with_prefix", []):
            assert any(n.startswith(pre) for n in onames), f"no objective with prefix {pre}"
        reasons = {h.reason for h in s.investigation.hypotheses.all()}
        for pre in exp.get("hypothesis_reasons_with_prefix", []):
            assert any((r or "").startswith(pre) for r in reasons)
        goals = [i.goal for i in intents]
        for pre in exp.get("intent_goals_with_prefix", []):
            assert any(g.startswith(pre) for g in goals)
        pe = exp.get("plan", {})
        assert len(plan) >= pe.get("min_plans", 0)
        protos = {p.spec.protocol for p in plan.all_plans()}
        for pr in pe.get("protocols_contain", []):
            assert pr in protos
        assert not ReasoningValidator.audit_plan_graph(plan)   # planner DAG is sane
        _no_fatal(s)

    elif kind == "infer":
        b = case["build"]
        s = ReasoningState(target="ex.com", scope=["ex.com"])
        s.investigation.objectives.add(Objective(name=b["objective"]))
        s.investigation.hypotheses.add_hypothesis("fw", likelihoods=b["candidates"],
                                                  reason=b["objective"])
        node = s.world.graph.upsert_node("service", "ex.com:80")
        for ev in b.get("observations", []):
            s.world.graph.observe(node, kind="http_headers", evidence=ev, source="phase3")
        steps = InferenceEngine().infer(s)
        decisions = {st.decision for st in steps}
        for d in exp.get("decisions_contain", []):
            assert d in decisions, f"missing inference decision {d}; got {decisions}"
        if "contradictions_min" in exp:
            assert len(s.investigation.contradictions) >= exp["contradictions_min"]
        if exp.get("objective_satisfied"):
            assert s.investigation.objectives.get(b["objective"]).satisfied
        if exp.get("hypothesis_status"):
            h = next(h for h in s.investigation.hypotheses.all() if h.reason == b["objective"])
            assert h.status == exp["hypothesis_status"]
        _no_fatal(s)

    elif kind == "audit":
        s = ReasoningState()
        b = case["build"]
        if "orphan_objective" in b:
            o = b["orphan_objective"]
            s.investigation.objectives.add(Objective(name=o["name"], dependencies=o["deps"]))
        if b.get("confirmed_without_evidence"):
            hid = s.investigation.hypotheses.add_hypothesis("h", likelihoods={"a": 0.5, "b": 0.5})
            s.investigation.hypotheses.resolve(hid, "confirmed")
        codes = {i.code for i in ReasoningValidator().audit(s)}
        for c in exp.get("audit_codes_contain", []):
            assert c in codes, f"validator missed {c}; got {codes}"

    else:
        pytest.fail(f"unknown kind {kind}")
