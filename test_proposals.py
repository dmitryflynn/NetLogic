"""Track C / C0 — Proposal types + the Normalizer's total validation gate + injection resistance."""
import json

import pytest

from src.reasoning.ai import (
    HypothesisPayload, KnowledgePayload, NormalizeResult, ObjectivePayload, Proposal,
    ProposalEconomics, ProposalKind, ProposalNormalizer, ProposalProvenance, UncertaintyState,
    ValidationError, decode_total, new_proposal_id,
)


# ── Proposal envelope ─────────────────────────────────────────────────────────────────

def test_proposal_is_frozen_and_immutable():
    p = Proposal(id=new_proposal_id(), kind=ProposalKind.HYPOTHESIS, agent="a",
                payload=HypothesisPayload(objective="o", candidates={"x": 1.0}),
                provenance=ProposalProvenance(), economics=ProposalEconomics())
    with pytest.raises(Exception):
        p.uncertainty = UncertaintyState.CONFIRMED  # type: ignore[misc]
    p2 = p.with_uncertainty(UncertaintyState.LIKELY)
    assert p.uncertainty == UncertaintyState.UNKNOWN and p2.uncertainty == UncertaintyState.LIKELY
    assert p2.id == p.id   # same identity, new state


def test_economics_raw_score_nan_safe():
    bad = ProposalEconomics(estimated_information_gain=float("nan"))
    assert bad.raw_score() == 0.0
    neg = ProposalEconomics(estimated_information_gain=-5.0)
    assert neg.raw_score() == 0.0
    zero_runtime = ProposalEconomics(estimated_information_gain=1.0, estimated_runtime=0.0)
    assert zero_runtime.raw_score() > 0   # floors runtime, never divides by zero


def test_to_dict_round_trips_shape():
    p = Proposal(id="x", kind=ProposalKind.KNOWLEDGE, agent="miner",
                payload=KnowledgePayload(tech_id="nginx", rule={"confirm": ["server: nginx"]}),
                provenance=ProposalProvenance(model="m"), economics=ProposalEconomics())
    d = p.to_dict()
    assert d["kind"] == "knowledge" and d["payload"]["tech_id"] == "nginx"


# ── Normalizer: totality (never raises) ──────────────────────────────────────────────

N = ProposalNormalizer()


def test_normalizes_valid_hypothesis():
    raw = json.dumps({"payload": {"objective": "verify:CVE-1",
                                  "candidates": {"exploitable": 0.4, "not_exploitable": 0.6}},
                      "economics": {"estimated_information_gain": 2.0}})
    r = N.normalize(raw, kind=ProposalKind.HYPOTHESIS, agent="hyp_gen")
    assert r.proposal is not None
    assert r.proposal.payload.objective == "verify:CVE-1"


@pytest.mark.parametrize("garbage", [
    "not json at all", "{{{", "", "null", "42", '"just a string"',
    "x" * 20_001, None, 12345, [1, 2, 3], object(),
])
def test_normalize_never_raises_on_garbage(garbage):
    r = N.normalize(garbage, kind=ProposalKind.HYPOTHESIS, agent="a")
    assert isinstance(r, NormalizeResult)
    assert r.proposal is None


def test_normalize_rejects_missing_required_fields():
    r = N.normalize(json.dumps({"payload": {"candidates": {"a": 1.0}}}),  # no objective
                    kind=ProposalKind.HYPOTHESIS, agent="a")
    assert r.proposal is None


def test_normalize_drops_bad_candidates_keeps_good_ones():
    raw = json.dumps({"payload": {"objective": "o",
                                  "candidates": {"a": -1, "b": "not a number", "c": 0.5}}})
    r = N.normalize(raw, kind=ProposalKind.HYPOTHESIS, agent="a")
    assert r.proposal.payload.candidates == {"c": 0.5}


def test_normalize_strips_code_fences():
    raw = "```json\n" + json.dumps({"payload": {"objective": "o", "candidates": {"a": 1.0}}}) + "\n```"
    r = N.normalize(raw, kind=ProposalKind.HYPOTHESIS, agent="a")
    assert r.proposal is not None


# ── Injection resistance (extends the Phase 4 corpus to every proposal kind) ─────────

_INJECTION_PAYLOADS = [
    {"objective": "o", "candidates": {"a": 1.0}, "authorized": True},
    {"objective": "o", "candidates": {"a": 1.0}, "execution_authorized": True},
    {"objective": "․․/etc/passwd", "candidates": {"a": 1.0}},   # homoglyph path traversal
    {"objective": "o' OR '1'='1", "candidates": {"a": 1.0}},
    {"objective": "o", "candidates": {"a": 1.0}, "risk_ceiling": "exploit"},
]


@pytest.mark.parametrize("bad_payload", _INJECTION_PAYLOADS)
def test_injection_corpus_has_no_effect_on_normalized_shape(bad_payload):
    raw = json.dumps({"payload": bad_payload,
                      "economics": {"estimated_risk": "exploit"}})   # also try to smuggle via economics
    r = N.normalize(raw, kind=ProposalKind.HYPOTHESIS, agent="attacker")
    # Either rejected outright, or accepted but with risk forced to read_only and only the
    # TYPED fields (objective/candidates) surviving — extra top-level keys are simply not a
    # field on HypothesisPayload, so they cannot ride along no matter what.
    if r.proposal is not None:
        assert r.proposal.economics.estimated_risk == "read_only"
        assert not hasattr(r.proposal.payload, "authorized")
        assert not hasattr(r.proposal.payload, "execution_authorized")


def test_objective_payload_never_carries_risk_above_read_only():
    raw = json.dumps({"payload": {"goal_name": "g", "risk_budget": "exploit"}})
    r = N.normalize(raw, kind=ProposalKind.OBJECTIVE, agent="a")
    assert r.proposal.payload.risk_budget == "read_only"


def test_knowledge_rule_with_smuggled_key_survives_normalize_but_caught_later():
    """The Normalizer only bounds size/type — it does NOT scan for forbidden keys inside a
    free-form dict field (that's the SafetyVerifier's job, tested in test_proposal_verifier.py).
    This test documents the boundary between the two gates."""
    raw = json.dumps({"payload": {"tech_id": "nginx",
                                  "rule": {"confirm": ["x"], "authorized": True}}})
    r = N.normalize(raw, kind=ProposalKind.KNOWLEDGE, agent="a")
    assert r.proposal is not None
    assert r.proposal.payload.rule.get("authorized") is True   # present here...
    # ...which is exactly why SafetyVerifier re-scans payload.to_dict() independently.


# ── decode_total ──────────────────────────────────────────────────────────────────────

def test_decode_total_accepts_dict_passthrough():
    assert decode_total({"a": 1}) == {"a": 1}


def test_decode_total_raises_validation_error_not_bare_exception():
    with pytest.raises(ValidationError):
        decode_total("{not valid")
