"""Change detection (Phase 7a): observation-level diff, factual ScanDelta, provenance, typing.

The headline invariant: diff immutable OBSERVATIONS, not ReasoningState — a re-scan that reasons
better over identical evidence must produce an EMPTY delta.
"""
import dataclasses as dc

from src.reasoning.change_detection import (
    DeltaAnalyzer,
    DeltaEvent,
    DeltaTyper,
    ObservationDiffer,
    ObservationSnapshot,
    ScanDelta,
    delta_report,
)
from src.reasoning.state import ReasoningState


def _state(target="web.ex.com:80"):
    return ReasoningState(target=target, scope=["ex.com"])


def _observe(state, node_key, *, node_kind="service", kind="http_headers", evidence="", data=None):
    n = state.world.graph.upsert_node(node_kind, node_key)
    state.world.graph.observe(n, kind=kind, evidence=evidence, source="scan", data=data or {})
    return n


def _snap(state):
    return state.world.graph.snapshot()


# ── Snapshot extraction is owned by the graph ──

def test_graph_owns_snapshot():
    s = _state()
    _observe(s, "web.ex.com:80", evidence="server: nginx")
    snap = s.world.graph.snapshot()
    assert isinstance(snap, ObservationSnapshot)
    assert len(snap.observations) == 1
    # host derived from node key for grouping
    assert next(iter(snap.observations.values())).host == "web.ex.com"


def test_snapshot_round_trip():
    s = _state()
    _observe(s, "web.ex.com:80", evidence="server: nginx")
    snap = _snap(s)
    assert ObservationSnapshot.from_dict(snap.to_dict()).to_dict() == snap.to_dict()


# ── THE distinguishing invariant: diff observations, not state ──

def test_identical_observations_different_inference_yields_empty_delta():
    """Same evidence, but scan B has 'better' inference (beliefs/hypotheses mutated). The delta MUST
    be empty — change detection reads observations only, never interpretation."""
    a = _state()
    _observe(a, "web.ex.com:80", evidence="server: nginx wp-content")

    b = _state()
    _observe(b, "web.ex.com:80", evidence="server: nginx wp-content")
    # B reasons further over the SAME evidence:
    b.world.beliefs = {"wordpress": 0.95}
    b.world.belief_records = [{"claim": "wordpress", "confidence": 0.95, "impact": "high"}]
    b.investigation.hypotheses.add_hypothesis(label="fw", likelihoods={"wordpress": 0.95})
    b.investigation.contradictions.append({"signal": "x", "source": "inference"})

    delta = ObservationDiffer().diff(_snap(a), _snap(b))
    assert not delta.has_changes, "inference improvement must not register as an environmental change"


def test_empty_when_snapshots_equal():
    s = _state()
    _observe(s, "web.ex.com:80", evidence="server: nginx")
    assert not ObservationDiffer().diff(_snap(s), _snap(s)).has_changes


# ── Determinism ──

def test_diff_is_deterministic():
    a = _state(); _observe(a, "web.ex.com:80", evidence="server: nginx")
    b = _state()
    _observe(b, "web.ex.com:80", evidence="server: nginx")
    _observe(b, "web.ex.com:443", evidence="server: nginx")
    d1 = ObservationDiffer().diff(_snap(a), _snap(b)).to_dict()
    d2 = ObservationDiffer().diff(_snap(a), _snap(b)).to_dict()
    assert d1 == d2


# ── Semantic typing ──

def test_new_port_event():
    a = _state(); _observe(a, "web.ex.com:80", evidence="open")
    b = _state(); _observe(b, "web.ex.com:80", evidence="open"); _observe(b, "web.ex.com:443", evidence="open")
    delta = ObservationDiffer().diff(_snap(a), _snap(b))
    assert any(e.type == "new_port" for e in delta.added)


def test_port_closed_event():
    a = _state(); _observe(a, "web.ex.com:80", evidence="open"); _observe(a, "web.ex.com:443", evidence="open")
    b = _state(); _observe(b, "web.ex.com:80", evidence="open")
    delta = ObservationDiffer().diff(_snap(a), _snap(b))
    assert any(e.type == "port_closed" for e in delta.removed)


def test_new_cve_event():
    a = _state()
    b = _state(); _observe(b, "CVE-2024-1", node_kind="cve", kind="cve", evidence="CVE-2024-1")
    delta = ObservationDiffer().diff(_snap(a), _snap(b))
    assert any(e.type == "new_cve" for e in delta.added)


def test_new_host_event():
    a = _state()
    b = _state(); _observe(b, "mail.ex.com", node_kind="host", kind="host", evidence="mail.ex.com")
    delta = ObservationDiffer().diff(_snap(a), _snap(b))
    assert any(e.type == "new_host" for e in delta.added)


def test_tech_added_event():
    a = _state()
    b = _state(); _observe(b, "wordpress", node_kind="technology", kind="technology", evidence="wordpress")
    delta = ObservationDiffer().diff(_snap(a), _snap(b))
    assert any(e.type == "tech_added" for e in delta.added)


# ── Changed != add+remove (one event, with provenance) ──

def test_version_change_is_one_changed_event_with_provenance():
    a = _state(); _observe(a, "web.ex.com:80", kind="version", evidence="nginx/1.24")
    b = _state(); _observe(b, "web.ex.com:80", kind="version", evidence="nginx/1.26")
    delta = ObservationDiffer().diff(_snap(a), _snap(b))
    assert delta.added == [] and delta.removed == []
    assert len(delta.changed) == 1
    ev = delta.changed[0]
    assert ev.type == "version_changed"
    # delta provenance: references BOTH originating observations
    assert ev.before_obs_id and ev.after_obs_id and ev.before_obs_id != ev.after_obs_id
    assert "1.24" in ev.detail and "1.26" in ev.detail


def test_added_event_has_only_after_provenance():
    a = _state()
    b = _state(); _observe(b, "web.ex.com:443", evidence="open")
    ev = ObservationDiffer().diff(_snap(a), _snap(b)).added[0]
    assert ev.after_obs_id is not None and ev.before_obs_id is None


# ── Factual delta vs interpretation ──

def test_scandelta_has_no_severity_fields():
    fields = {f.name for f in dc.fields(ScanDelta)}
    assert fields == {"added", "removed", "changed"}, f"ScanDelta must stay factual: {fields}"
    ev_fields = {f.name for f in dc.fields(DeltaEvent)}
    assert "severity" not in ev_fields and "priority" not in ev_fields


def test_analyzer_owns_severity():
    a = _state()
    b = _state(); _observe(b, "CVE-2024-1", node_kind="cve", kind="cve", evidence="CVE-2024-1")
    delta = ObservationDiffer().diff(_snap(a), _snap(b))
    assess = DeltaAnalyzer().analyze(delta)
    assert assess.top_severity == "critical"      # new_cve weighted critical, in the analyzer
    assert assess.severity_counts.get("critical") == 1


# ── DeltaTyper registry is extensible ──

def test_delta_typer_registry_extensible():
    typer = DeltaTyper()
    typer.register(obs_kind="tls_cert", direction="changed", event_type="certificate_changed")
    assert typer.type_for("service", "tls_cert", "changed") == "certificate_changed"
    # fully unknown (node + obs) falls back, never crashes
    assert typer.type_for("claim", "mystery", "added") == "observation_added"
    # a registered node-level rule still applies (service added → new_port)
    assert typer.type_for("service", "anything", "added") == "new_port"


# ── Multi-host grouping ──

def test_changes_are_grouped_per_host():
    a = _state()
    _observe(a, "web.ex.com:80", evidence="open")
    _observe(a, "mail.ex.com:25", evidence="open")
    b = _state()
    _observe(b, "web.ex.com:80", evidence="open")
    _observe(b, "mail.ex.com:25", evidence="open")
    _observe(b, "mail.ex.com:587", evidence="open")     # change on mail only
    delta = ObservationDiffer().diff(_snap(a), _snap(b))
    added_hosts = {e.host for e in delta.added}
    assert added_hosts == {"mail.ex.com"}               # web unaffected


# ── Report ──

def test_delta_report_no_changes():
    s = _state(); _observe(s, "web.ex.com:80", evidence="open")
    assert "No environmental changes" in delta_report(ObservationDiffer().diff(_snap(s), _snap(s)))


def test_delta_report_lists_changes():
    a = _state()
    b = _state(); _observe(b, "CVE-2024-1", node_kind="cve", kind="cve", evidence="CVE-2024-1")
    report = delta_report(ObservationDiffer().diff(_snap(a), _snap(b)))
    assert "new_cve" in report and "critical" in report
