"""ReasoningStateStore round-trips (in-memory always; Pg path if a DB is configured)."""
import os

import pytest

from api.storage.reasoning_store import InMemoryReasoningStore, persist_from_art
from src.reasoning import ReasoningState, build_reasoning_state


def _state() -> ReasoningState:
    art = {"host_result": {"ip": "1.2.3.4", "hostname": "ex.com"},
           "vuln_matches": [{"port": 80, "service": "http", "product": "nginx", "version": "1.25",
                             "detection_confidence": "HIGH",
                             "cves": [{"id": "CVE-2024-1", "cvss_score": 7.5}]}]}
    return build_reasoning_state("ex.com", ["ex.com"], art)


def test_in_memory_store_persist_get_latest():
    store = InMemoryReasoningStore()
    s = _state().to_dict()
    store.persist("job-1", "org-a", "ex.com", s)
    assert store.get("job-1") == s
    assert store.latest_for_target("org-a", "ex.com") == s
    # org scoping + unknown target
    assert store.latest_for_target("org-b", "ex.com") is None
    assert store.get("missing") is None


def test_in_memory_latest_returns_most_recent():
    store = InMemoryReasoningStore()
    store.persist("job-1", "o", "ex.com", {"schema_version": 1, "tag": "old"})
    store.persist("job-2", "o", "ex.com", {"schema_version": 1, "tag": "new"})
    assert store.latest_for_target("o", "ex.com")["tag"] == "new"


def test_persist_from_art_is_noop_without_reasoning():
    # Should not raise when art has no reasoning block.
    persist_from_art("job-x", "org", "ex.com", {"host_result": {}})


def test_state_roundtrips_through_store():
    store = InMemoryReasoningStore()
    s = _state()
    store.persist("job-1", "o", "ex.com", s.to_dict())
    restored = ReasoningState.from_dict(store.get("job-1"))
    assert restored.target == "ex.com"
    assert restored.world.beliefs == s.world.beliefs


@pytest.mark.skipif(not os.environ.get("NETLOGIC_DATABASE_URL"),
                    reason="no Postgres configured")
def test_pg_store_roundtrip():
    from api.storage.reasoning_store import PgReasoningStore
    store = PgReasoningStore()
    s = _state().to_dict()
    store.persist("11111111-1111-1111-1111-111111111111", "org-a", "ex.com", s)
    assert store.get("11111111-1111-1111-1111-111111111111")["target"] == "ex.com"
