"""ProposalParser: typed parsing, bounds, and a property-based fuzz test (totality)."""
import json
import random

import pytest

from src.reasoning.intent import EvidenceType
from src.reasoning.proposal_parser import ProposalParser, ValidationError

_EV = {e.value for e in EvidenceType}
P = ProposalParser(_EV)


def test_parses_framework_proposals():
    raw = json.dumps([{"objective": "identify_framework:h:80",
                       "candidates": {"spring_boot": 0.7, "django": 0.3}}])
    out = P.parse_framework_proposals(raw)
    assert len(out) == 1 and out[0].candidates["spring_boot"] == 0.7


def test_drops_bad_candidates():
    raw = json.dumps([{"objective": "o", "candidates": {"a": -1, "b": "x", "c": 0.5}}])
    out = P.parse_framework_proposals(raw)
    assert out[0].candidates == {"c": 0.5}              # negative + non-numeric dropped


def test_parse_evidence_types_filters_to_enum():
    raw = json.dumps(["http_headers", "exfiltrate", "rm -rf", "tls_version"])
    assert P.parse_evidence_types(raw) == ["http_headers", "tls_version"]


def test_rejects_oversized_input():
    with pytest.raises(ValidationError):
        P.parse_evidence_types("x" * 20_001)


def test_rejects_non_json():
    with pytest.raises(ValidationError):
        P.parse_framework_proposals("not json at all")
    with pytest.raises(ValidationError):
        P.parse_evidence_types("{not: json}")


def test_strips_code_fence():
    raw = "```json\n[\"dns_records\"]\n```"
    assert P.parse_evidence_types(raw) == ["dns_records"]


def test_property_fuzz_parser_is_total():
    """For ANY input the parser returns a value or raises ValidationError — never anything else,
    never partial garbage."""
    rng = random.Random(20260626)
    alphabet = list('{}[]":,0123456789abcdef \n\t\\/.-_‮​ﬀ') + ["\x00", "💥"]
    for _ in range(3000):
        n = rng.randint(0, 400)
        blob = "".join(rng.choice(alphabet) for _ in range(n))
        for fn in (P.parse_framework_proposals, P.parse_evidence_types):
            try:
                result = fn(blob)
                assert isinstance(result, list)            # always a list on success
            except ValidationError:
                pass                                       # the only permitted exception


def test_property_fuzz_on_random_json_documents():
    rng = random.Random(7)
    def rand(depth):
        if depth > 4 or rng.random() < 0.3:
            return rng.choice([1, -1, 0.5, "x", "http_headers", None, True])
        if rng.random() < 0.5:
            return [rand(depth + 1) for _ in range(rng.randint(0, 5))]
        return {str(rng.randint(0, 9)): rand(depth + 1) for _ in range(rng.randint(0, 5))}
    for _ in range(2000):
        blob = json.dumps(rand(0))
        for fn in (P.parse_framework_proposals, P.parse_evidence_types):
            try:
                assert isinstance(fn(blob), list)
            except ValidationError:
                pass
