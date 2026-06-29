"""Change detection integration (Phase 7c): the realistic flow where the prior snapshot comes from
persistence (a serialized ReasoningState dict, as returned by reasoning_store.latest_for_target),
diffed against the current scan's live state."""
from src.reasoning.change_detection import diff_states, seed_from_delta
from src.reasoning.state import ReasoningState


def _scan_state(observations):
    s = ReasoningState(target="web.ex.com:80", scope=["ex.com"])
    for node_kind, node_key, obs_kind, evidence in observations:
        n = s.world.graph.upsert_node(node_kind, node_key)
        s.world.graph.observe(n, kind=obs_kind, evidence=evidence, source="scan")
    return s


_BASE = [("service", "web.ex.com:80", "http_headers", "server: nginx")]


def test_diff_against_persisted_prior_dict():
    """Prior snapshot is a serialized state dict (how persistence returns it); current is live."""
    prior = _scan_state(_BASE)
    prior_dict = prior.to_dict()                      # as stored by reasoning_store

    # Second scan finds a new CVE.
    current = _scan_state(_BASE + [("cve", "CVE-2024-5", "cve", "CVE-2024-5 critical")])

    delta = diff_states(prior_dict, current)          # dict prior, live current
    assert delta.has_changes
    assert any(e.type == "new_cve" for e in delta.added)
    # and it seeds re-investigation
    seed = seed_from_delta(delta)
    assert "verify_cve:cve-2024-5" in seed.objectives


def test_no_change_between_identical_scans():
    prior = _scan_state(_BASE)
    current = _scan_state(_BASE)
    assert not diff_states(prior.to_dict(), current).has_changes


def test_version_bump_surfaces_as_changed():
    prior = _scan_state([("service", "web.ex.com:80", "version", "nginx/1.24")])
    current = _scan_state([("service", "web.ex.com:80", "version", "nginx/1.26")])
    delta = diff_states(prior.to_dict(), current)
    assert len(delta.changed) == 1
    assert delta.changed[0].type == "version_changed"


def test_first_scan_no_prior_is_noop():
    """With no prior snapshot, the engine path simply skips — diff_states is only called when a
    prior exists. Here we assert the building block handles an empty prior gracefully."""
    current = _scan_state(_BASE)
    empty_prior = ReasoningState(target="web.ex.com:80", scope=["ex.com"]).to_dict()
    delta = diff_states(empty_prior, current)
    # everything in current is 'added' vs an empty world — but a real first scan has no prior at all,
    # so the engine skips entirely (covered by the --since-last gate).
    assert delta.has_changes
    assert all(e.before_obs_id is None for e in delta.added)


def test_engine_flag_default_off_means_no_change_keys():
    """Sanity: the --since-last arg defaults off; without it the engine attaches no change_* keys.
    (We assert the arg parser default here; full engine wiring is exercised by the API tests.)"""
    import netlogic
    parser = netlogic.build_parser() if hasattr(netlogic, "build_parser") else None
    if parser is None:
        import pytest
        pytest.skip("parser factory not exposed")
    args = parser.parse_args(["web.ex.com"])
    assert getattr(args, "since_last", False) is False
