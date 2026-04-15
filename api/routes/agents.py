"""
NetLogic API — Cloud Agent endpoints.

Agent lifecycle (called by the agent process)
─────────────────────────────────────────────
  POST   /agents/register                       Register → {agent_id, token}
  POST   /agents/{id}/heartbeat                 Keep-alive signal every 30 s
  GET    /agents/{id}/tasks                     Poll for pending scan jobs
  POST   /agents/{id}/tasks/{job_id}/events     Stream scan events back
  POST   /agents/{id}/tasks/{job_id}/complete   Mark job done or failed

Management (called by the dashboard / operator)
────────────────────────────────────────────────
  GET    /agents                                List all agents with live status
  GET    /agents/{id}                           Inspect a single agent
  DELETE /agents/{id}                           Deregister an agent

Authentication
──────────────
Agent-facing endpoints (heartbeat, tasks, events, complete) require the Bearer
token issued at registration time:
    Authorization: Bearer <agent-token>

Registration and management endpoints (list, get, delete) require a signed JWT:
    Authorization: Bearer <jwt>

Phase 3: org_id embedded in the JWT scopes agent visibility.  An agent
registered by org A is not visible to org B.
"""

from __future__ import annotations

import time
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from api.agents.registry import Agent, agent_registry
from api.auth.dependencies import require_org
from api.jobs.executor import try_dispatch_queued
from api.jobs.manager import job_manager
from api.models.agent import AgentRegistration, AgentTaskComplete

router = APIRouter(prefix="/agents", tags=["agents"])
_bearer = HTTPBearer(auto_error=False)


# ── Agent-token authentication dependency ─────────────────────────────────────


def _auth_agent(
    agent_id: str,
    creds: Annotated[Optional[HTTPAuthorizationCredentials], Depends(_bearer)],
) -> Agent:
    """Resolve agent_id + Bearer token → verified Agent, or raise 401/404.

    Note: this dependency uses the agent's own registration token, NOT a JWT.
    It intentionally does NOT apply org scoping here — the agent is already
    identified by its unique agent_id; org cross-checks are enforced on the
    job-level operations (events, complete).
    """
    # Use unfiltered get (no org_id) because we authenticate by token, not JWT.
    agent = agent_registry.get(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
    if not creds or not agent.verify_token(creds.credentials):
        raise HTTPException(status_code=401, detail="Invalid or missing agent token.")
    return agent


# ── POST /agents/register ─────────────────────────────────────────────────────


@router.post(
    "/register",
    status_code=201,
    summary="Register a new agent",
    response_description="Agent ID and one-time secret token",
)
async def register_agent(
    payload: AgentRegistration,
    org_id: str = Depends(require_org),
) -> dict:
    """
    Called by the agent process on first startup.

    Requires a valid JWT so the new agent is scoped to the caller's
    organisation.  Returns an `agent_id` and a one-time `token`.  The token
    must be stored securely by the agent and included as a Bearer credential
    in all subsequent agent-facing requests.
    """
    agent_id, secret = agent_registry.register(
        hostname=payload.hostname,
        capabilities=payload.capabilities,
        version=payload.version,
        tags=payload.tags,
        org_id=org_id,
    )
    return {
        "agent_id": agent_id,
        "token": secret,
        "org_id": org_id,
        "message": "Agent registered. Store the token securely — it is shown only once.",
    }


# ── POST /agents/{id}/heartbeat ───────────────────────────────────────────────


@router.post(
    "/{agent_id}/heartbeat",
    summary="Agent heartbeat",
    response_description="Acknowledgement with server timestamp",
)
async def agent_heartbeat(
    agent_id: str,
    agent: Annotated[Agent, Depends(_auth_agent)],
) -> dict:
    """
    Agent calls this every 30 s to signal it is alive.  The controller uses
    the last heartbeat timestamp to compute online/offline status.
    """
    agent_registry.heartbeat(agent_id)
    # Dispatch any queued jobs now that this agent has checked in.
    try_dispatch_queued(org_id=agent.org_id)
    return {"status": "ok", "server_time": time.time()}


# ── GET /agents/{id}/tasks ────────────────────────────────────────────────────


@router.get(
    "/{agent_id}/tasks",
    summary="Poll for pending scan tasks",
    response_description="List of scan tasks to execute (may be empty)",
)
async def get_pending_tasks(
    agent_id: str,
    agent: Annotated[Agent, Depends(_auth_agent)],
) -> list[dict]:
    """
    Returns all scan jobs queued for this agent and clears the queue.

    The agent should poll this endpoint every ~5 s while idle.  Each task
    includes the full `config` dict so the agent can call
    `run_streaming_scan()` without additional API calls.

    Calling this endpoint implicitly counts as a heartbeat.
    """
    # Implicit heartbeat on every poll — no separate call needed.
    agent_registry.heartbeat(agent_id)

    job_ids = agent_registry.get_pending_tasks(agent_id)
    tasks = []
    for job_id in job_ids:
        job = job_manager.get(job_id)
        if job and job.status == "queued":
            job.status = "running"
            job.started_at = time.time()
            agent.current_job_id = job_id
            tasks.append({
                "job_id": job.job_id,
                "config": job.config.model_dump(),
            })
    return tasks


# ── POST /agents/{id}/tasks/{job_id}/events ──────────────────────────────────


@router.post(
    "/{agent_id}/tasks/{job_id}/events",
    summary="Submit a batch of scan events",
    response_description="Number of events accepted",
)
async def submit_events(
    agent_id: str,
    job_id: str,
    events: list[dict],
    agent: Annotated[Agent, Depends(_auth_agent)],
) -> dict:
    """
    Agent POSTs batches of scan events as they are emitted.

    Each event is forwarded into the job's event store and wakes any SSE
    consumers watching `GET /jobs/{id}/stream` on the controller in real-time.
    """
    job = job_manager.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")
    if job.assigned_agent_id != agent_id:
        raise HTTPException(status_code=403, detail="Job does not belong to this agent.")
    if agent.org_id and job.org_id and agent.org_id != job.org_id:
        raise HTTPException(status_code=403, detail="Cross-organisation access denied.")

    for event in events:
        job.push_event(event)

    return {"accepted": len(events)}


# ── POST /agents/{id}/tasks/{job_id}/complete ─────────────────────────────────


@router.post(
    "/{agent_id}/tasks/{job_id}/complete",
    summary="Mark a scan job as complete or failed",
    response_description="Final job status",
)
async def complete_task(
    agent_id: str,
    job_id: str,
    payload: AgentTaskComplete,
    agent: Annotated[Agent, Depends(_auth_agent)],
) -> dict:
    """
    Agent calls this once the local scan thread exits.

    * If `error` is null/omitted → job is marked `completed`.
    * If `error` is set → job is marked `failed` with the error message.
    """
    job = job_manager.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")
    if job.assigned_agent_id != agent_id:
        raise HTTPException(status_code=403, detail="Job does not belong to this agent.")
    if agent.org_id and job.org_id and agent.org_id != job.org_id:
        raise HTTPException(status_code=403, detail="Cross-organisation access denied.")

    # Ignore completion calls for jobs already in a terminal state (e.g. cancelled).
    if job.status not in ("running", "queued"):
        agent.current_job_id = None
        return {"job_id": job_id, "status": job.status}

    if payload.error:
        job.status = "failed"
        job.error = payload.error
        job.push_event({"type": "error", "message": payload.error})
    else:
        job.status = "completed"
        job.push_event({"type": "done", "data": {"message": "Scan complete (remote agent)."}})

    job.progress = 100.0
    job.completed_at = time.time()
    job.push_sentinel()        # wake + close all SSE consumers
    agent.current_job_id = None
    job_manager.persist_job(job)

    # Agent is now idle — dispatch any waiting jobs immediately.
    try_dispatch_queued(org_id=agent.org_id)

    return {"job_id": job_id, "status": job.status}


# ── GET /agents ───────────────────────────────────────────────────────────────


@router.get(
    "",
    summary="List all registered agents",
    response_description="Array of agent summaries with live status",
)
async def list_agents(
    org_id: str = Depends(require_org),
) -> list[dict]:
    """Return status summary for every agent belonging to the caller's organisation."""
    return [_agent_summary(a) for a in agent_registry.list(org_id=org_id)]


# ── GET /agents/{id} ─────────────────────────────────────────────────────────


@router.get(
    "/{agent_id}",
    summary="Get agent details",
    response_description="Single agent summary",
)
async def get_agent(
    agent_id: str,
    org_id: str = Depends(require_org),
) -> dict:
    """Inspect a single agent by ID.  Returns 404 if it belongs to a different org."""
    agent = agent_registry.get(agent_id, org_id=org_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
    return _agent_summary(agent)


# ── DELETE /agents/{id} ───────────────────────────────────────────────────────


@router.delete(
    "/{agent_id}",
    status_code=204,
    summary="Deregister an agent",
)
async def deregister_agent(
    agent_id: str,
    org_id: str = Depends(require_org),
) -> Response:
    """
    Remove an agent from the registry.  Returns 404 if the agent does not
    exist or belongs to a different organisation.
    """
    agent = agent_registry.get(agent_id, org_id=org_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
    agent_registry.deregister(agent_id)
    return Response(status_code=204)


# ── Shared helper ─────────────────────────────────────────────────────────────


def _agent_summary(agent: Agent) -> dict:
    return {
        "agent_id":       agent.agent_id,
        "org_id":         agent.org_id,
        "hostname":       agent.hostname,
        "capabilities":   agent.capabilities,
        "version":        agent.version,
        "tags":           agent.tags,
        "status":         agent.status,
        "registered_at":  agent.registered_at,
        "last_heartbeat": agent.last_heartbeat,
        "current_job_id": agent.current_job_id,
    }
