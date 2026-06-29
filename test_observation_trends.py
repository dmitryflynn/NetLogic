"""Observation trends (Phase 7c): per-entity lifecycle over a snapshot series — flapping,
persistence, age. A separate analytics domain from the pairwise differ."""
from src.reasoning.analytics.observation_trends import TrendAnalyzer, trend_report
from src.reasoning.state import ReasoningState


def _snap(observations):
    """Build a snapshot from [(node_kind, node_key, obs_kind, evidence), ...]."""
    s = ReasoningState(target="web.ex.com:80", scope=["ex.com"])
    for node_kind, node_key, obs_kind, evidence in observations:
        n = s.world.graph.upsert_node(node_kind, node_key)
        s.world.graph.observe(n, kind=obs_kind, evidence=evidence, source="scan")
    return s.world.graph.snapshot()


_PORT = ("service", "web.ex.com:8080", "open_port", "open")
_CVE = ("cve", "CVE-2024-1", "cve", "CVE-2024-1")


def test_flapping_port_reports_flap_count():
    # present, absent, present, absent  → 2 present→absent transitions
    series = [_snap([_PORT]), _snap([]), _snap([_PORT]), _snap([])]
    trends = TrendAnalyzer().analyze(series)
    port = next(t for t in trends if t.obs_kind == "open_port")
    assert port.flap_count == 2
    assert port.is_flapping
    assert port.present_now is False
    assert port.occurrence_count == 2


def test_persistent_cve_reports_age():
    series = [_snap([_CVE]), _snap([_CVE]), _snap([_CVE])]
    timestamps = [0.0, 86400.0, 30 * 86400.0]      # spans 30 days
    trends = TrendAnalyzer().analyze(series, timestamps=timestamps)
    cve = next(t for t in trends if t.obs_kind == "cve")
    assert cve.occurrence_count == 3
    assert cve.flap_count == 0
    assert cve.is_persistent
    assert cve.age_seconds == 30 * 86400.0


def test_new_entity_first_seen_index():
    # CVE appears only from the 2nd scan onward
    series = [_snap([_PORT]), _snap([_PORT, _CVE]), _snap([_PORT, _CVE])]
    trends = TrendAnalyzer().analyze(series)
    cve = next(t for t in trends if t.obs_kind == "cve")
    assert cve.first_index == 1
    assert cve.occurrence_count == 2
    assert cve.present_now


def test_transition_count_distinct_from_flap():
    # present, absent, present → transitions=2, flaps(present→absent)=1
    series = [_snap([_PORT]), _snap([]), _snap([_PORT])]
    port = next(t for t in TrendAnalyzer().analyze(series) if t.obs_kind == "open_port")
    assert port.transition_count == 2
    assert port.flap_count == 1


def test_stable_entity_is_not_flapping():
    series = [_snap([_PORT]), _snap([_PORT]), _snap([_PORT])]
    port = next(t for t in TrendAnalyzer().analyze(series) if t.obs_kind == "open_port")
    assert port.flap_count == 0
    assert not port.is_flapping
    assert port.is_persistent


def test_empty_series():
    assert TrendAnalyzer().analyze([]) == []


def test_deterministic_ordering():
    series = [_snap([_PORT, _CVE]), _snap([_PORT, _CVE])]
    a = [t.to_dict() for t in TrendAnalyzer().analyze(series)]
    b = [t.to_dict() for t in TrendAnalyzer().analyze(series)]
    assert a == b


def test_trend_report_highlights_flapping_and_persistent():
    series = [_snap([_PORT, _CVE]), _snap([_CVE]), _snap([_PORT, _CVE]), _snap([_CVE])]
    report = trend_report(TrendAnalyzer().analyze(series))
    assert "Flapping" in report          # port flaps
    assert "Persistent" in report        # cve persists
