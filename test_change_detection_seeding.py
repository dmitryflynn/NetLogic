"""Re-investigation seeding (Phase 7b): deltas warm-start the next scan as ordering hints +
objective seeds. The hard guarantee is ISOLATION — seeding writes no confidence/beliefs/
hypotheses/evidence; history owns priority, evidence owns beliefs."""
from src.reasoning.change_detection import (
    ObservationDiffer,
    ReinvestigationSeed,
    seed_from_delta,
)
from src.reasoning.candidate import Candidate
from src.reasoning.decision_policy import GreedyPolicy
from src.reasoning.intent import Intent
from src.reasoning.learned_patterns import PriorityHint
from src.reasoning.state import ReasoningState


def _state(target="web.ex.com:80"):
    return ReasoningState(target=target, scope=["ex.com"])


def _observe(s, node_key, *, node_kind="service", kind="http_headers", evidence=""):
    n = s.world.graph.upsert_node(node_kind, node_key)
    s.world.graph.observe(n, kind=kind, evidence=evidence, source="scan")


def _delta_with_new_cve():
    a = _state()
    b = _state()
    _observe(b, "CVE-2024-9999", node_kind="cve", kind="cve", evidence="CVE-2024-9999 critical RCE")
    return ObservationDiffer().diff(a.world.graph.snapshot(), b.world.graph.snapshot())


def _delta_with_new_host():
    a = _state()
    b = _state()
    _observe(b, "mail.ex.com", node_kind="host", kind="host", evidence="mail.ex.com")
    return ObservationDiffer().diff(a.world.graph.snapshot(), b.world.graph.snapshot())


# ── Seeding produces hints + objectives ──

def test_new_cve_seeds_hint_and_objective():
    seed = seed_from_delta(_delta_with_new_cve())
    assert isinstance(seed, ReinvestigationSeed)
    assert any(h.tag == "cve-2024-9999" for h in seed.hints)
    assert "verify_cve:cve-2024-9999" in seed.objectives


def test_new_host_seeds_identify_framework():
    seed = seed_from_delta(_delta_with_new_host())
    assert "identify_framework:mail.ex.com" in seed.objectives
    assert any(h.tag == "mail.ex.com" for h in seed.hints)


def test_severity_drives_boost():
    cve_seed = seed_from_delta(_delta_with_new_cve())      # critical → high boost
    cve_boost = max(h.boost for h in cve_seed.hints)
    assert cve_boost >= 0.7


def test_objectives_are_deduped():
    a = _state()
    b = _state()
    # two new hosts → two distinct objectives, no dupes
    _observe(b, "mail.ex.com", node_kind="host", kind="host", evidence="mail.ex.com")
    _observe(b, "vpn.ex.com", node_kind="host", kind="host", evidence="vpn.ex.com")
    seed = seed_from_delta(ObservationDiffer().diff(a.world.graph.snapshot(), b.world.graph.snapshot()))
    assert len(seed.objectives) == len(set(seed.objectives))
    assert set(seed.objectives) == {"identify_framework:mail.ex.com", "identify_framework:vpn.ex.com"}


def test_empty_delta_seeds_nothing():
    s = _state()
    _observe(s, "web.ex.com:80", evidence="open")
    seed = seed_from_delta(ObservationDiffer().diff(s.world.graph.snapshot(), s.world.graph.snapshot()))
    assert seed.hints == [] and seed.objectives == []


# ── Seeded hints actually reorder candidates (consume via the existing channel) ──

def test_seeded_hints_reorder_candidates():
    seed = seed_from_delta(_delta_with_new_host())
    # candidates: a generic one and one targeting the new host
    generic = Candidate.deferred(source="generator", kind="Generic", factory=lambda: [Intent(goal="g")], gain=1.0)
    host_cand = Candidate.deferred(source="cross_host", kind="expand:mail.ex.com",
                                   factory=lambda: [Intent(goal="h")], gain=1.0)
    ranked = GreedyPolicy().rank_candidates([generic, host_cand], hints=seed.hints)
    # the new-host hint boosts the mail.ex.com candidate above the tie
    assert ranked[0].candidate.kind == "expand:mail.ex.com"


# ── THE isolation invariant ──

def test_seeding_mutates_no_reasoning_state():
    """Running the full delta→seed pipeline (and applying hints via ranking) writes nothing to
    confidence, beliefs, belief_records, hypotheses, or observations."""
    s = _state()
    s.world.beliefs = {"existing": 0.4}
    s.world.belief_records = [{"claim": "existing", "confidence": 0.4}]
    hid = s.investigation.hypotheses.add_hypothesis(label="fw", likelihoods={"x": 0.5, "y": 0.5})
    _observe(s, "web.ex.com:80", evidence="open")

    before_beliefs = dict(s.world.beliefs)
    before_records = [dict(r) for r in s.world.belief_records]
    before_hyp = {h.id: (h.status, dict(h.likelihoods)) for h in s.investigation.hypotheses.all()}
    before_obs = sorted(o.obs_id for n in s.world.graph.nodes() for o in n.observations())

    seed = seed_from_delta(_delta_with_new_cve())
    GreedyPolicy().rank_candidates(
        [Candidate.deferred(source="generator", kind="cve-2024-9999", factory=lambda: [], gain=1.0)],
        hints=seed.hints)

    assert s.world.beliefs == before_beliefs
    assert [dict(r) for r in s.world.belief_records] == before_records
    assert {h.id: (h.status, dict(h.likelihoods)) for h in s.investigation.hypotheses.all()} == before_hyp
    assert sorted(o.obs_id for n in s.world.graph.nodes() for o in n.observations()) == before_obs


def test_seed_output_is_only_hints_and_objective_strings():
    seed = seed_from_delta(_delta_with_new_cve())
    assert all(isinstance(h, PriorityHint) for h in seed.hints)
    assert all(isinstance(o, str) for o in seed.objectives)
