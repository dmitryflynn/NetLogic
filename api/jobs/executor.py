"""
NetLogic API — SaaS scan dispatcher.

In a SaaS model the controller never executes scans locally — that would be
expensive and a security risk.  All scan work runs on registered remote agents.

Public API
──────────
  submit_scan(job)          Called by POST /jobs after the job is created.
                             Sets up the SSE async queue, then dispatches the
                             job to an agent.  Always returns immediately.

  try_dispatch_queued(org)  Called on every heartbeat and task-complete so
                             that queued jobs are assigned as soon as an agent
                             becomes idle.  Returns the count dispatched.

Dispatch rules
──────────────
1. job.config.agent_id set  → assign to that specific agent; fail immediately
                               if the agent is offline / unknown.
2. No agent_id              → pick the first idle online agent in the org;
                               the job stays "queued" (SSE keeps pinging) until
                               an agent heartbeats and the dispatcher retries.

The `assigned_agent_id` field on ScanJob always records which agent was
actually given the work, regardless of whether the user specified one.
"""

from __future__ import annotations

import asyncio
import threading
import time

from api.agents.registry import agent_registry
from api.jobs.manager import ScanJob, job_manager

# Prevent double-assignment race: only one thread may run try_dispatch_queued
# at a time.  The lock is non-reentrant so callers must not hold it already.
_dispatch_lock = threading.Lock()

# A job reclaimed from this many dead agents is failed instead of requeued again,
# so a request that no agent can ever satisfy doesn't loop forever.
MAX_DISPATCH_ATTEMPTS = 3


# ── Public entry point ────────────────────────────────────────────────────────

async def submit_scan(job: ScanJob) -> None:
    """Schedule a job for execution on a remote agent.

    Sets up the SSE queue so consumers can start listening immediately, then
    dispatches the job.  Returns without blocking regardless of whether an
    agent was found.
    """
    loop = asyncio.get_running_loop()
    job._loop = loop
    job._queue = asyncio.Queue(maxsize=1000)

    if job.config.agent_id:
        _assign_to_agent(job, job.config.agent_id)
    else:
        # Best-effort serialisation with try_dispatch_queued: if the dispatch
        # lock is free, grab it so we don't race. If it's busy, another thread
        # is already dispatching — skip here; try_dispatch_queued will pick up
        # this job (it's already in the registry) when it releases the lock.
        if _dispatch_lock.acquire(blocking=False):
            try:
                _assign_to_any(job)
            finally:
                _dispatch_lock.release()
        # If no agent was available the job stays "queued"; it will be
        # dispatched by try_dispatch_queued() on the next heartbeat.


def try_dispatch_queued(org_id: str = "") -> int:
    """Flush the queue: assign every waiting job to an idle agent.

    Should be called whenever agent availability changes:
      - POST /agents/{id}/heartbeat   (agent just checked in)
      - POST /agents/{id}/tasks/{id}/complete  (agent just freed up)

    Protected by _dispatch_lock to prevent concurrent calls from double-assigning
    the same job to multiple agents.

    Returns the number of jobs dispatched this call.
    """
    if not _dispatch_lock.acquire(blocking=False):
        # Another thread is already dispatching — skip to avoid double-assignment.
        return 0
    try:
        dispatched = 0
        for job in job_manager.list_queued_unassigned(org_id=org_id):
            if _assign_to_any(job):
                dispatched += 1
        return dispatched
    finally:
        _dispatch_lock.release()


# ── Internal helpers ──────────────────────────────────────────────────────────

def _assign_to_agent(job: ScanJob, agent_id: str) -> bool:
    """Assign to a specific (pinned) agent, failing the job if it's unavailable."""
    if job.assigned_agent_id:
        return True  # already assigned — idempotency guard
    agent = agent_registry.get(agent_id, org_id=job.org_id)
    if agent is None or agent.status in ("offline", "disabled"):
        reason = "disabled" if (agent and agent.disabled) else "offline or not registered"
        job.status = "failed"
        job.error = f"Agent '{agent_id[:8]}…' is {reason}."
        job.completed_at = time.time()
        job.push_event({"type": "error", "message": job.error})
        job.push_sentinel()
        return False
    if not agent_registry.assign_task(agent_id, job.job_id):
        job.status = "failed"
        job.error = f"Agent '{agent_id[:8]}…' rejected the task (disabled or at capacity)."
        job.completed_at = time.time()
        job.push_event({"type": "error", "message": job.error})
        job.push_sentinel()
        return False
    job.assigned_agent_id = agent_id
    job.dispatch_attempts += 1
    return True


def _eligible_agents(job: ScanJob) -> list:
    """Online agents that can serve this job: org + capabilities + tag selector.

    Org rule: same org as the job, OR a built-in/global agent (org_id="") which
    serves every org. "online" already excludes disabled, offline, and at-capacity
    (busy) agents, so the result is exactly the set with spare capacity.
    """
    caps = job.config.required_capabilities
    sel  = job.config.agent_selector
    out  = []
    for agent in agent_registry.list():
        if agent.org_id and agent.org_id != job.org_id:
            continue
        if agent.status != "online":
            continue
        if not agent.matches(caps, sel):
            continue
        out.append(agent)
    return out


def _assign_to_any(job: ScanJob) -> bool:
    """Dispatch to the least-loaded eligible agent (capability/selector-aware).

    If no agent currently qualifies the job stays "queued" and is retried by
    try_dispatch_queued() whenever agent availability changes. The first time a
    job can't be placed we emit one explanatory event so the UI shows *why* it's
    pending (e.g. no agent in the requested region) instead of an opaque wait.
    """
    if job.assigned_agent_id:
        return True  # already assigned — idempotency guard
    candidates = _eligible_agents(job)
    if not candidates:
        _note_unschedulable(job)
        return False

    # Least-loaded balancing: fewest committed jobs first, then the agent with
    # the most spare capacity. Spreads load and fills high-concurrency agents.
    best = min(candidates, key=lambda a: (a.load, -(a.concurrency - a.load)))
    if not agent_registry.assign_task(best.agent_id, job.job_id):
        return False  # agent rejected (disabled or at capacity); retry later
    job.assigned_agent_id = best.agent_id
    job.dispatch_attempts += 1
    return True


def _note_unschedulable(job: ScanJob) -> None:
    """Emit a one-time, human-readable reason a job is still waiting for an agent."""
    if getattr(job, "_waiting_noted", False):
        return
    reqs = []
    if job.config.required_capabilities:
        reqs.append("capabilities " + ", ".join(job.config.required_capabilities))
    if job.config.agent_selector:
        reqs.append("tags " + ", ".join(f"{k}={v}" for k, v in job.config.agent_selector.items()))
    detail = (" matching " + " and ".join(reqs)) if reqs else ""
    job.push_event({"type": "info",
                    "message": f"Waiting for an available agent{detail}…"})
    job._waiting_noted = True


def reclaim_stale_jobs(org_id: str = "") -> int:
    """Reclaim jobs stranded on agents that have gone offline.

    For every queued/running job pinned to an agent that is now offline (or gone),
    release the job from the agent and either requeue it (so another agent can pick
    it up) or, once it has exhausted MAX_DISPATCH_ATTEMPTS, fail it cleanly. This is
    what makes the fleet self-healing: a crashed agent no longer strands its work.

    Returns the number of jobs reclaimed. Called periodically by the worker loop.
    """
    reclaimed = 0
    for job in job_manager.list_dispatched_active(org_id=org_id):
        agent = agent_registry.get(job.assigned_agent_id)
        if agent is not None and agent.status not in ("offline", "disabled"):
            continue  # agent still alive (online or busy) — leave the job alone

        if agent is not None:
            agent_registry.mark_done(job.assigned_agent_id, job.job_id)

        if job.dispatch_attempts >= MAX_DISPATCH_ATTEMPTS:
            job.status = "failed"
            job.error = (f"No healthy agent available after {job.dispatch_attempts} "
                         "attempt(s) — last assigned agent went offline.")
            job.completed_at = time.time()
            job.push_event({"type": "error", "message": job.error})
            job.push_sentinel()
            job_manager.persist_job(job)
        else:
            job.assigned_agent_id = None
            job.status = "queued"
            job.started_at = None
            job.progress = 0.0
            job._waiting_noted = False
            job.push_event({"type": "info",
                            "message": "Assigned agent went offline — requeuing for another agent."})
            job_manager.persist_job(job)
        reclaimed += 1

    if reclaimed:
        try_dispatch_queued(org_id=org_id)
    return reclaimed
