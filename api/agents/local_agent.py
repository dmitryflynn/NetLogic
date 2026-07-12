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

    # The built-in agent gets a fresh UUID each process start. Without cleanup,
    # every server restart would leave behind another dead "localhost (built-in)"
    # record in agents.json (and the Agents dashboard). Prune prior built-ins for
    # this org first so there is exactly one live built-in agent.
    for existing in agent_registry.list(org_id=org_id):
        if existing.org_id == org_id and existing.tags.get("type") == "local":
            agent_registry.deregister(existing.agent_id)

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
    from api.jobs.executor import try_dispatch_queued, reclaim_stale_jobs  # noqa: PLC0415

    while True:
        try:
            # Self-healing: requeue jobs stranded on agents that went offline,
            # then dispatch anything queued (including those just reclaimed).
            reclaim_stale_jobs()
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
    agent_registry.mark_active(agent_id, job_id)

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
        # Flatten nested vuln structure: emit one event per CVE
        if event_type == "vuln" and isinstance(data, dict) and data.get("cves"):
            port    = data.get("port")
            service = data.get("service", "")
            for cve in data["cves"]:
                refs = cve.get("references") or []
                job.push_event({"type": "vuln", "data": {
                    "cve_id":          cve.get("id"),
                    "cvss":            cve.get("cvss_score"),
                    "severity":        cve.get("severity"),
                    "description":     cve.get("description", ""),
                    "port":            port,
                    "service":         service,
                    "exploitable":     cve.get("exploit_available", False),
                    "exploit_ref":     refs[0] if refs else None,
                    "references":      refs,
                    "kev":             cve.get("kev", False),
                    # EPSS is the primary prioritization signal — carry it (and its
                    # percentile) through so the dashboard badge and sort work.
                    "epss":            cve.get("epss", 0.0),
                    "epss_percentile": cve.get("epss_percentile", 0.0),
                }})
            for note in (data.get("notes") or []):
                if note:
                    job.push_event({"type": "info", "message": str(note)})
            return

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

    from api.jobs.manager import JobCancelled  # noqa: PLC0415

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
            do_ai       = getattr(cfg, "do_ai", False),
            ssh_user    = getattr(cfg, "ssh_user", ""),
            ssh_key     = getattr(cfg, "ssh_key", ""),
            ssh_pass    = getattr(cfg, "ssh_pass", ""),
            ssh_port    = getattr(cfg, "ssh_port", 22),
            ai_key      = cfg.ai_key.get_secret_value() if getattr(cfg, "ai_key", None) else "",
            ai_provider = getattr(cfg, "ai_provider", ""),
            ai_model    = getattr(cfg, "ai_model", ""),
            ai_base_url = getattr(cfg, "ai_base_url", ""),
            deep_probe  = getattr(cfg, "deep_probe", False),
            do_reason   = getattr(cfg, "do_reason", False),
            do_since_last = getattr(cfg, "do_since_last", False),
            do_multi_host = getattr(cfg, "do_multi_host", False),
            do_active_validate = getattr(cfg, "do_active_validate", False),
            do_ai_driven = getattr(cfg, "do_ai_driven", False),
            do_ai_agent = getattr(cfg, "do_ai_agent", False) or getattr(cfg, "agent_depth", False),
            agent_depth = getattr(cfg, "agent_depth", False),
            allow_crash_probes = getattr(cfg, "allow_crash_probes", False),
            agent_max_steps = getattr(cfg, "agent_max_steps", 12),
            agent_max_requests = getattr(cfg, "agent_max_requests", 40),
            # Scope AI/fusion key resolution to the org that owns the job — never a
            # process-global key. Empty string keeps single-tenant/CLI on env config.
            org_id      = getattr(job, "org_id", "") or "",
            emit_callback = emit,
        )
        job.status   = "completed"
        job.progress = 100.0
        try:
            job.push_event({"type": "done", "data": {"message": "Scan complete."}})
        except JobCancelled:
            # Cancel raced the final "done" emit — treat as cancelled, not complete.
            _log.info("Scan cancelled for job %s (during finalisation)", job_id)
            if job.status not in ("failed", "cancelled"):
                job.status = "cancelled"
                job.error = job.error or "Cancelled by user request."
            _finish(job, agent)
            return
    except JobCancelled:
        # Cooperative cancel via push_event after cancel/delete set _stop_flag.
        # cancel_job() already set terminal status; delete_job() may not have.
        _log.info("Scan cancelled for job %s", job_id)
        if job.status not in ("completed", "failed", "cancelled"):
            job.status = "cancelled"
            job.error = job.error or "Cancelled by user request."
        _finish(job, agent)
        return
    except Exception as exc:
        _log.exception("Scan failed for job %s", job_id)
        _finish(job, agent, error=str(exc))
        return

    _finish(job, agent)


def _finish(job, agent, error: Optional[str] = None) -> None:
    from api.jobs.manager import JobCancelled, job_manager  # noqa: PLC0415
    from api.jobs.executor import try_dispatch_queued  # noqa: PLC0415

    if error and job.status not in ("completed", "failed", "cancelled"):
        job.status = "failed"
        job.error  = error
        try:
            job.push_event({"type": "error", "message": error})
        except JobCancelled:
            # stop_flag set (e.g. deleted while failing) — status already failed.
            pass
    elif job.status == "running":
        # Safety: never leave a finished worker job stuck in "running" (breaks UI
        # terminal state and historically hid persisted event history).
        job.status = "completed"
        job.progress = 100.0

    if job.completed_at is None:
        job.completed_at = time.time()
    job.push_sentinel()
    job_manager.persist_job(job)

    if agent:
        from api.agents.registry import agent_registry  # noqa: PLC0415
        agent_registry.mark_done(agent.agent_id, job.job_id)

    # Pick up the next queued job immediately
    try_dispatch_queued(org_id=job.org_id)
