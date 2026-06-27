"""Declarative injection corpus — adds an attack = adds a JSON file under
tests/reasoning/injection_cases/. The runner feeds each adversarial AI output through the
ProposalParser (the input boundary) and asserts only safe, enum-valid structure survives.
Also asserts the AIProposer never targets a host the model named (scope safety).
"""
import glob
import json
import os

import pytest

from src.reasoning import ReasoningState
from src.reasoning.ai_proposer import AIProposer
from src.reasoning.intent import EvidenceType
from src.reasoning.proposal_parser import ProposalParser, ValidationError

_CASES_DIR = os.path.join(os.path.dirname(__file__), "tests", "reasoning", "injection_cases")
_P = ProposalParser({e.value for e in EvidenceType})


def _load_cases():
    cases = []
    for path in sorted(glob.glob(os.path.join(_CASES_DIR, "*.json"))):
        with open(path, encoding="utf-8") as fh:
            case = json.load(fh)
        case["_file"] = os.path.basename(path)
        cases.append(case)
    return cases


_CASES = _load_cases()


def test_corpus_is_present():
    assert _CASES, "no injection cases found"


@pytest.mark.parametrize("case", _CASES, ids=[c["_file"] for c in _CASES])
def test_injection_case(case):
    raw, kind = case["raw"], case["kind"]
    if case.get("expect_error"):
        with pytest.raises(ValidationError):
            (_P.parse_evidence_types if kind == "evidence_types"
             else _P.parse_framework_proposals)(raw)
        return
    if kind == "evidence_types":
        assert _P.parse_evidence_types(raw) == case["expect_evidence"]
    elif kind == "framework_proposals":
        out = _P.parse_framework_proposals(raw)
        assert out and out[0].candidates == case["expect_candidates"]
    else:
        pytest.fail(f"unknown kind {kind}")


def test_ai_proposer_intents_stay_in_scope_under_any_corpus_output():
    """No corpus output can make the AIProposer target a host other than state.target."""
    s = ReasoningState(target="ex.com", scope=["ex.com"])
    for case in _CASES:
        fake = lambda sysp, usr, _raw=case["raw"]: _raw
        for intent in AIProposer(fake).propose_intents(s):
            assert intent.target_ref == "ex.com"
