"""Cancel vs local-agent finalisation: a cancelled scan must not be marked completed."""
from __future__ import annotations

import threading
from unittest.mock import MagicMock

from api.agents.local_agent import _run_job
from api.agents.registry import AgentRegistry
from api.jobs.manager import JobCancelled, JobManager
from api.models.scan_request import ScanRequest
from api.storage.json_store import JsonScanStore


def _isolated_manager(tmp_path) -> JobManager:
    mgr = JobManager.__new__(JobManager)
    mgr._jobs = {}
    mgr._lock = threading.RLock()
    mgr._pg = False
    mgr._pg_store = None
    mgr.store = JsonScanStore(str(tmp_path))
    return mgr


def _install(monkeypatch, mgr: JobManager, registry: AgentRegistry) -> None:
    monkeypatch.setattr("api.jobs.manager.job_manager", mgr)
    monkeypatch.setattr("api.agents.registry.agent_registry", registry)
    monkeypatch.setattr("api.jobs.executor.try_dispatch_queued", lambda org_id="": 0)


def _agent_and_job(mgr: JobManager, registry: AgentRegistry):
    agent_id, _ = registry.register(
        hostname="local-test",
        capabilities=["scan"],
        version="test",
        tags={"type": "test"},
        org_id="org-a",
    )
    registry.heartbeat(agent_id)
    job = mgr.create(ScanRequest(target="example.com"), org_id="org-a")
    job.assigned_agent_id = agent_id
    assert registry.assign_task(agent_id, job.job_id)
    return agent_id, job


def test_engine_return_after_cancel_stays_cancelled(monkeypatch, tmp_path):
    """User cancel wins try_set_terminal; engine then returns normally.

    The pre-fix worker assigned job.status = "completed" unconditionally, so a
    cancel in this window was persisted as a finished scan.
    """
    mgr = _isolated_manager(tmp_path)
    registry = AgentRegistry(persist_path=None)
    _install(monkeypatch, mgr, registry)
    agent_id, job = _agent_and_job(mgr, registry)

    def fake_scan(**_kwargs):
        mgr.try_set_terminal(
            job.job_id, "cancelled", org_id="org-a",
            error="Cancelled by user request.",
        )
        job._stop_flag.set()

    monkeypatch.setattr("src.json_bridge.run_streaming_scan", fake_scan)

    assert _run_job(agent_id, job.job_id, "org-a") is True
    live = mgr.get(job.job_id, org_id="org-a")
    assert live is not None
    assert live.status == "cancelled"
    assert live.error == "Cancelled by user request."


def test_jobcancelled_after_cancel_stays_cancelled(monkeypatch, tmp_path):
    """Cooperative cancel: engine raises JobCancelled after cancel_job."""
    mgr = _isolated_manager(tmp_path)
    registry = AgentRegistry(persist_path=None)
    _install(monkeypatch, mgr, registry)
    agent_id, job = _agent_and_job(mgr, registry)

    def fake_scan(**_kwargs):
        mgr.try_set_terminal(
            job.job_id, "cancelled", org_id="org-a",
            error="Cancelled by user request.",
        )
        job._stop_flag.set()
        raise JobCancelled(job.job_id)

    monkeypatch.setattr("src.json_bridge.run_streaming_scan", fake_scan)

    assert _run_job(agent_id, job.job_id, "org-a") is True
    live = mgr.get(job.job_id, org_id="org-a")
    assert live is not None
    assert live.status == "cancelled"


def test_successful_scan_still_completes(monkeypatch, tmp_path):
    mgr = _isolated_manager(tmp_path)
    registry = AgentRegistry(persist_path=None)
    _install(monkeypatch, mgr, registry)
    agent_id, job = _agent_and_job(mgr, registry)

    monkeypatch.setattr("src.json_bridge.run_streaming_scan", MagicMock())

    assert _run_job(agent_id, job.job_id, "org-a") is True
    live = mgr.get(job.job_id, org_id="org-a")
    assert live is not None
    assert live.status == "completed"
    assert live.progress == 100.0
    assert any(e.get("type") == "done" for e in live.events)
