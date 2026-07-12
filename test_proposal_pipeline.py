"""Track C / C0 — the staged pipeline: generate -> normalize -> rank -> prune -> verify.

Ranking by economics, garbage pruned before it ever reaches the verifier, and every rejection
retained in the store (never silently dropped).
"""
import json

from src.reasoning.ai import (
    AgentTask, AICoordinator, ProposalEconomics, ProposalKind, ProposalNormalizer,
    ProposalProvenance, ProposalRanker, ProposalStatus, VerifierContext, new_proposal_id,
)
from src.reasoning.ai.proposals import HypothesisPayload, Proposal


def _hyp(agent, objective, gain=1.0, runtime=1.0, probes=1, prob_correct=0.5):
    return Proposal(
        id=new_proposal_id(), kind=ProposalKind.HYPOTHESIS, agent=agent,
        payload=HypothesisPayload(objective=objective, candidates={"a": 1.0}),
        provenance=ProposalProvenance(),
        economics=ProposalEconomics(estimated_information_gain=gain, estimated_runtime=runtime,
                                    estimated_probe_count=probes,
                                    estimated_prob_correct=prob_correct, estimated_risk="read_only"))


# ── Ranking reflects the economy, not arrival order ──────────────────────────────────

def test_ranker_orders_by_economy_not_insertion_order():
    cheap_high_gain = _hyp("a", "verify:1", gain=10, runtime=1, probes=1, prob_correct=0.9)
    expensive_low_gain = _hyp("a", "verify:2", gain=1, runtime=20, probes=10, prob_correct=0.5)
    ranked = ProposalRanker().rank([expensive_low_gain, cheap_high_gain])
    assert ranked[0].proposal.payload.objective == "verify:1"
    assert ranked[0].score > ranked[1].score


def test_ranker_is_stable_and_deterministic_on_ties():
    a = _hyp("a", "verify:1", gain=1, runtime=1, probes=1, prob_correct=0.5)
    b = _hyp("b", "verify:1", gain=1, runtime=1, probes=1, prob_correct=0.5)
    r1 = [rp.proposal.id for rp in ProposalRanker().rank([a, b])]
    r2 = [rp.proposal.id for rp in ProposalRanker().rank([b, a])]
    assert r1 == r2   # order of the SAME set is independent of input order (tie-break by id)


def test_prune_keeps_only_top_k():
    proposals = [_hyp("a", f"verify:{i}", gain=i) for i in range(10)]
    kept = ProposalRanker().prune(proposals, top_k=3)
    assert len(kept) == 3
    assert kept[0].proposal.payload.objective == "verify:9"   # highest gain


# ── AICoordinator: atomic run, garbage never reaches the verifier ───────────────────

def test_garbage_task_is_pruned_before_verification_ever_runs():
    coordinator = AICoordinator()
    tasks = [
        AgentTask(agent="a", kind=ProposalKind.HYPOTHESIS, raw="not json"),
        AgentTask(agent="a", kind=ProposalKind.HYPOTHESIS, raw=json.dumps({"nope": True})),
    ]
    accepted = coordinator.run(tasks)
    assert accepted == []
    # Nothing was even GENERATED for the garbage tasks — normalize() returned no Proposal, so
    # there was never an object to record. The store stays empty, not full of nulls.
    assert len(coordinator.store) == 0


def test_valid_proposal_flows_generated_through_verified():
    coordinator = AICoordinator()
    raw = json.dumps({"payload": {"objective": "verify:CVE-1", "candidates": {"a": 1.0}},
                      "economics": {"estimated_information_gain": 3.0}})
    tasks = [AgentTask(agent="hyp_gen", kind=ProposalKind.HYPOTHESIS, raw=raw)]
    ctx = VerifierContext(known_objectives=frozenset({"verify:CVE-1"}))
    accepted = coordinator.run(tasks, ctx=ctx)
    assert len(accepted) == 1
    records = coordinator.store.all()
    assert len(records) == 1 and records[0].status == ProposalStatus.VERIFIED
    # full history retained: GENERATED -> RANKED -> VERIFIED
    history = coordinator.store.history_for(accepted[0].proposal.id)
    assert [r.status for r in history] == \
        [ProposalStatus.GENERATED, ProposalStatus.RANKED, ProposalStatus.VERIFIED]


def test_rejected_proposal_is_retained_forever_not_dropped():
    coordinator = AICoordinator()
    raw = json.dumps({"payload": {"objective": "verify:UNKNOWN", "candidates": {"a": 1.0}}})
    tasks = [AgentTask(agent="a", kind=ProposalKind.HYPOTHESIS, raw=raw)]
    ctx = VerifierContext(known_objectives=frozenset({"verify:KNOWN_ONLY"}))
    accepted = coordinator.run(tasks, ctx=ctx)
    assert accepted == []
    rejected = coordinator.store.rejected()
    assert len(rejected) == 1
    assert rejected[0].stage_failed == "semantic"


def test_run_respects_top_k():
    coordinator = AICoordinator()
    tasks = [AgentTask(agent="a", kind=ProposalKind.HYPOTHESIS,
                       raw=json.dumps({"payload": {"objective": f"verify:{i}",
                                                   "candidates": {"a": 1.0}}}))
            for i in range(20)]
    ctx = VerifierContext(known_objectives=frozenset({f"verify:{i}" for i in range(20)}))
    accepted = coordinator.run(tasks, ctx=ctx, top_k=5)
    assert len(accepted) <= 5


def test_normalizer_is_the_same_total_contract_used_directly():
    """The Normalizer works standalone (not only via the coordinator) — this is the seam future
    agents call directly before batching into AgentTasks."""
    normalizer = ProposalNormalizer()
    r = normalizer.normalize("garbage", kind=ProposalKind.HYPOTHESIS, agent="x")
    assert r.proposal is None and r.reason
