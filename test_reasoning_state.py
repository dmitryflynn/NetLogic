"""ReasoningState round-trips through JSON; MemoryStore dedups equivalent probes."""
import dataclasses

import pytest

from src.reasoning import MemoryStore, Objective, ReasoningState
from src.reasoning.state import SCHEMA_VERSION


def test_reasoning_state_json_roundtrip():
    s = ReasoningState(target="example.com", scope=["example.com", "1.2.3.4"])
    s.world.observations.append({"type": "port", "port": 80})
    s.world.beliefs["nginx"] = 0.8
    s.investigation.persona = "technology_fingerprinting"
    s.investigation.objectives.add(Objective(name="identify framework", priority=0.9))
    s.execution.tokens_used = 1234

    restored = ReasoningState.from_json(s.to_json())

    assert restored.target == "example.com"
    assert restored.scope == ["example.com", "1.2.3.4"]
    assert restored.world.observations == [{"type": "port", "port": 80}]
    assert restored.world.beliefs["nginx"] == 0.8
    assert restored.investigation.persona == "technology_fingerprinting"
    assert restored.investigation.objectives.get("identify framework") is not None
    assert restored.investigation.objectives.get("identify framework").name == "identify framework"  # type: ignore[union-attr]
    assert restored.execution.tokens_used == 1234
    assert restored.schema_version == SCHEMA_VERSION


def test_schema_version_is_persisted_and_read_back():
    s = ReasoningState(target="t")
    assert s.schema_version == SCHEMA_VERSION
    # An older row without the field falls back to the current version, not a crash.
    assert ReasoningState.from_dict({"target": "t"}).schema_version == SCHEMA_VERSION
    # A stored version is preserved (so a future loader can detect+migrate it).
    assert ReasoningState.from_dict({"schema_version": 0}).schema_version == 0


def test_from_dict_ignores_unknown_and_fills_defaults():
    # Forward/backward compatible: extra keys ignored, missing layers defaulted.
    restored = ReasoningState.from_dict({"target": "t", "world": {"beliefs": {"a": 0.5}},
                                         "future_field": "ignored"})
    assert restored.target == "t"
    assert restored.world.beliefs == {"a": 0.5}
    assert restored.investigation.persona == "service_discovery"  # default


def test_memory_store_dedups_equivalent_probes():
    m = MemoryStore()
    spec_a = {"id": "p1", "transport": "tcp", "protocol": "http",
              "target_host": "h", "target_port": 80, "request_spec": {"path": "/"}}
    # Same semantic identity, different incidental fields (id, cost) → same key.
    spec_b = {"id": "p2", "transport": "tcp", "protocol": "http",
              "target_host": "h", "target_port": 80, "request_spec": {"path": "/"},
              "estimated_cost": {"tokens": 50}}
    spec_c = {"id": "p3", "transport": "tcp", "protocol": "http",
              "target_host": "h", "target_port": 80, "request_spec": {"path": "/admin"}}

    assert not m.seen(spec_a)
    m.record(spec_a, success=True, info_gained=0.4)
    assert m.seen(spec_b)          # equivalent probe is deduped
    assert not m.seen(spec_c)      # different request is distinct
    assert MemoryStore.probe_key(spec_a) == MemoryStore.probe_key(spec_b)
    assert len(m) == 1


def test_memory_store_records_and_roundtrips():
    m = MemoryStore()
    spec = {"transport": "tcp", "protocol": "ssh", "target_host": "h", "target_port": 22,
            "request_spec": {}}
    m.record(spec, success=False, latency_ms=12.5, result_summary="timeout")
    assert len(m.failures()) == 1
    restored = MemoryStore.from_dict(m.to_dict())
    assert restored.seen(spec)
    assert restored.failures()[0].result_summary == "timeout"


def test_memory_store_is_append_only_immutable_event_log():
    m = MemoryStore()
    spec = {"transport": "tcp", "protocol": "http", "target_host": "h", "target_port": 80,
            "request_spec": {"path": "/"}}
    m.record(spec, success=False, result_summary="first")
    m.record(spec, success=True, result_summary="second")   # re-probe → new event, not overwrite
    assert len(m) == 2
    assert [e.result_summary for e in m.events()] == ["first", "second"]
    assert m.latest(spec).result_summary == "second"         # newest wins for lookups
    # events are immutable (frozen) — history cannot be rewritten
    with pytest.raises(dataclasses.FrozenInstanceError):
        m.events()[0].success = True
    # ordered round-trip preserves both events
    restored = MemoryStore.from_dict(m.to_dict())
    assert [e.result_summary for e in restored.events()] == ["first", "second"]
