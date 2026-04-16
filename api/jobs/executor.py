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
        _assign_to_any(job)
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
    """Assign to a specific agent, failing the job immediately if unavailable."""
    agent = agent_registry.get(agent_id, org_id=job.org_id)
    if agent is None or agent.status == "offline":
        job.status = "failed"
        job.error = f"Agent '{agent_id[:8]}…' is not available (offline or not registered)."
        job.completed_at = time.time()
        job.push_event({"type": "error", "message": job.error})
        job.push_sentinel()
        return False
    job.assigned_agent_id = agent_id
    agent_registry.assign_task(agent_id, job.job_id)
    return True


def _assign_to_any(job: ScanJob) -> bool:
    """Pick the first truly idle online agent in the org and assign the job.

    An agent is considered idle when:
      • Its heartbeat was received within the last 60 s (status == "online")
      • Its current_job_id is None (not already running a scan)
      • Its pending_tasks list is empty (nothing queued but not yet polled)

    Returns True if dispatched, False if no suitable agent was found.
    """
    for agent in agent_registry.list(org_id=job.org_id):
        if agent.status == "online" and not agent.pending_tasks:
            job.assigned_agent_id = agent.agent_id
            agent_registry.assign_task(agent.agent_id, job.job_id)
            return True
    return False
