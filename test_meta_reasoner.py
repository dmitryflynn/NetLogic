"""Track C / C0 — MetaReasoner: deterministic pruning, "already tested" via InvestigationMemory,
loop abandonment, no-uncertainty-reduction. NOT an LLM — pure functions of its inputs."""
from src.reasoning.ai import HypothesisPayload, MetaReasoner, ProposalEconomics, ProposalKind, \
    ProposalProvenance, proposal_signature
from src.reasoning.ai.proposals import Proposal, new_proposal_id
from src.reasoning.investigation_memory import InvestigationMemory


def _hyp(objective, agent="a", candidates=None):
    return Proposal(id=new_proposal_id(), kind=ProposalKind.HYPOTHESIS, agent=agent,
                    payload=HypothesisPayload(objective=objective,
                                              candidates=candidates or {"a": 1.0}),
                    provenance=ProposalProvenance(), economics=ProposalEconomics())


# ── Loop abandonment ──────────────────────────────────────────────────────────────────

def test_prunes_after_max_repeats():
    mr = MetaReasoner(max_repeats=2)
    p = _hyp("verify:1")
    assert not mr.evaluate(p).prune
    mr.record(p)
    assert not mr.evaluate(p).prune
    mr.record(p)
    decision = mr.evaluate(p)
    assert decision.prune and "loop" in decision.reason


def test_different_signature_is_not_treated_as_a_repeat():
    mr = MetaReasoner(max_repeats=1)
    a = _hyp("verify:1", candidates={"x": 1.0})
    b = _hyp("verify:2", candidates={"x": 1.0})   # different objective -> different signature
    mr.record(a)
    assert not mr.evaluate(b).prune


# ── "Already tested" via InvestigationMemory ─────────────────────────────────────────

def test_prunes_when_investigation_memory_says_already_failed_here():
    mem = InvestigationMemory()
    mem.record("verify:1", "hyp_gen", "failed", facts={"world": "v1"})
    mr = MetaReasoner(memory=mem)
    p = _hyp("verify:1", agent="hyp_gen")
    decision = mr.evaluate(p, facts={"world": "v1"})
    assert decision.prune and "already tested" in decision.reason


def test_re_eligible_after_world_changes():
    mem = InvestigationMemory()
    mem.record("verify:1", "hyp_gen", "failed", facts={"world": "v1"})
    mr = MetaReasoner(memory=mem)
    p = _hyp("verify:1", agent="hyp_gen")
    assert not mr.evaluate(p, facts={"world": "v2"}).prune   # different fingerprint -> eligible


def test_succeeded_attempts_never_block_reproposal():
    mem = InvestigationMemory()
    mem.record("verify:1", "hyp_gen", "succeeded", facts={"world": "v1"})
    mr = MetaReasoner(memory=mem)
    p = _hyp("verify:1", agent="hyp_gen")
    assert not mr.evaluate(p, facts={"world": "v1"}).prune


# ── No-uncertainty-reduction ──────────────────────────────────────────────────────────

def test_prunes_duplicate_of_an_existing_signature():
    mr = MetaReasoner()
    p = _hyp("verify:1")
    sig = proposal_signature(p)
    decision = mr.evaluate(p, existing_signatures=frozenset({sig}))
    assert decision.prune and "uncertainty" in decision.reason


# ── Determinism: same call sequence -> same decisions, always ───────────────────────

def test_same_sequence_replayed_twice_gives_identical_decisions():
    seq = [_hyp("verify:1") for _ in range(5)]

    def run(items):
        mr = MetaReasoner(max_repeats=2)
        out = []
        for item in items:
            out.append(mr.evaluate(item).prune)
            mr.record(item)
        return out

    assert run(seq) == run(seq)


def test_prune_frontier_batch_matches_manual_interleaving():
    seq = [_hyp("verify:1") for _ in range(4)]

    manual = MetaReasoner(max_repeats=2)
    manual_kept = []
    for item in seq:
        if not manual.evaluate(item).prune:
            manual_kept.append(item)
        manual.record(item)

    batch = MetaReasoner(max_repeats=2)
    batch_kept = batch.prune_frontier(seq)

    assert [p.id for p in manual_kept] == [p.id for p in batch_kept]


def test_signature_ignores_id_and_timestamp():
    a = _hyp("verify:1")
    b = _hyp("verify:1")   # different id/timestamp, same "aboutness"
    assert proposal_signature(a) == proposal_signature(b)
