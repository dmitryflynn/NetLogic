"""
Built-in local scan agent — always-on, in-process execution.

Registers itself in the AgentRegistry on startup and runs scans directly
using src.json_bridge.run_streaming_scan.  Provides baseline capacity so
scans work immediately without any external agent processes.

Two daemon threads are used:
  • heartbeat thread — keeps the agent "online" in the registry
  • worker thread    — polls for assigned jobs and runs them sequentially
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Optional

_log = logging.getLogger("netlogic.local_agent")

_HEARTBEAT_INTERVAL = 20   # seconds — well within the 60 s offline timeout
_POLL_INTERVAL      = 3    # seconds between idle polls


def start(org_id: str = "") -> str:
    """Register the built-in agent and start background threads.  Returns agent_id."""
    from api.agents.registry import agent_registry  # noqa: PLC0415

    agent_id, _ = agent_registry.register(
        hostname="localhost (built-in)",
        capabilities=["scan", "tls", "dns", "headers", "osint", "probe", "takeover", "stack"],
        version="built-in",
        tags={"type": "local"},
        org_id=org_id,
    )
    agent_registry.heartbeat(agent_id)   # mark online immediately — don't wait for first poll

    threading.Thread(
        target=_heartbeat_loop, args=(agent_id,), daemon=True, name="nl-heartbeat",
    ).start()
    threading.Thread(
        target=_worker_loop, args=(agent_id, org_id), daemon=True, name="nl-worker",
    ).start()

    _log.info("Built-in local agent started (id=%s…)", agent_id[:8])
    return agent_id


# ── Background threads ────────────────────────────────────────────────────────

def _heartbeat_loop(agent_id: str) -> None:
    from api.agents.registry import agent_registry  # noqa: PLC0415
    while True:
        time.sleep(_HEARTBEAT_INTERVAL)
        try:
            agent_registry.heartbeat(agent_id)
        except Exception as exc:
            _log.warning("Heartbeat error: %s", exc)


def _worker_loop(agent_id: str, org_id: str) -> None:
    from api.agents.registry import agent_registry  # noqa: PLC0415
    from api.jobs.executor import try_dispatch_queued  # noqa: PLC0415

    while True:
        try:
            # Pick up any jobs that were queued before this agent came online
            try_dispatch_queued(org_id=org_id)

            job_ids = agent_registry.get_pending_tasks(agent_id)
            for job_id in job_ids:
                _run_job(agent_id, job_id, org_id)

        except Exception as exc:
            _log.warning("Worker error: %s", exc)

        time.sleep(_POLL_INTERVAL)


# ── Scan execution ────────────────────────────────────────────────────────────

def _run_job(agent_id: str, job_id: str, org_id: str) -> None:
    from api.agents.registry import agent_registry  # noqa: PLC0415
    from api.jobs.manager import job_manager  # noqa: PLC0415

    agent = agent_registry.get(agent_id)
    job   = job_manager.get(job_id, org_id=org_id)
    if not job or not agent or job.status != "queued":
        return

    job.status           = "running"
    job.started_at       = time.time()
    job.assigned_agent_id = agent_id
    agent.current_job_id = job_id

    try:
        from src.json_bridge import run_streaming_scan   # noqa: PLC0415
        from src.scanner   import COMMON_PORTS, EXTENDED_PORTS  # noqa: PLC0415
    except ImportError as exc:
        _finish(job, agent, error=f"Scan engine unavailable: {exc}")
        return

    cfg = job.config

    if cfg.ports == "full":
        ports = EXTENDED_PORTS
    elif cfg.ports.startswith("custom="):
        ports = [int(p) for p in cfg.ports[7:].split(",") if p.strip().isdigit()]
    else:
        ports = COMMON_PORTS

    def emit(event_type: str, data=None, message: str = "") -> None:
        ev: dict = {"type": event_type}
        if data is not None:
            ev["data"] = data
        if message:
            ev["message"] = message
        job.push_event(ev)
        if event_type == "progress" and isinstance(data, dict):
            pct = data.get("percent")
            if isinstance(pct, (int, float)):
                job.progress = float(pct)

    try:
        run_streaming_scan(
            target      = cfg.target,
            ports       = ports,
            timeout     = cfg.timeout,
            threads     = cfg.threads,
            do_osint    = cfg.do_osint,
            cidr        = cfg.cidr,
            do_tls      = cfg.do_tls,
            do_headers  = cfg.do_headers,
            do_stack    = cfg.do_stack,
            do_dns      = cfg.do_dns,
            do_full     = cfg.do_full,
            do_probe    = cfg.do_probe,
            do_takeover = cfg.do_takeover,
            min_cvss    = cfg.min_cvss,
            emit_callback = emit,
        )
        job.status   = "completed"
        job.progress = 100.0
        job.push_event({"type": "done", "data": {"message": "Scan complete."}})
    except Exception as exc:
        _log.exception("Scan failed for job %s", job_id)
        _finish(job, agent, error=str(exc))
        return

    _finish(job, agent)


def _finish(job, agent, error: Optional[str] = None) -> None:
    from api.jobs.manager import job_manager  # noqa: PLC0415
    from api.jobs.executor import try_dispatch_queued  # noqa: PLC0415

    if error:
        job.status = "failed"
        job.error  = error
        job.push_event({"type": "error", "message": error})

    job.completed_at = time.time()
    job.push_sentinel()
    job_manager.persist_job(job)

    if agent:
        agent.current_job_id = None

    # Pick up the next queued job immediately
    try_dispatch_queued(org_id=job.org_id)
