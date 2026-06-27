"""
NetLogic — Cloud Agent Registry

Tracks all registered remote scan agents.  Each agent:
  • Has a unique agent_id (UUID) and a secret token (SHA-256 hashed for storage)
  • Reports a heartbeat every ≤30 s — considered offline after HEARTBEAT_TIMEOUT
  • Holds a pending_tasks queue: job_ids dispatched but not yet picked up
  • Reports its current_job_id while actively running a scan

Design notes
────────────
• token_hash — SHA-256 of the plaintext secret; plaintext is never retained.
• status is computed dynamically from last_heartbeat so there is no stale state.
• verify_token uses hmac.compare_digest for constant-time comparison (no timing attacks).
• Persistence — agent metadata is written to a JSON file on register/deregister.
  Transient fields (last_heartbeat, current_job_id, pending_tasks) are NOT persisted;
  agents must re-heartbeat after a server restart to become online again.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

_log = logging.getLogger("netlogic.agents")

# Agent is considered offline after this many seconds without a heartbeat.
HEARTBEAT_TIMEOUT = 60.0

# Agent tokens expire after this many seconds (default: 7 days).
AGENT_TOKEN_MAX_AGE: float = float(
    os.environ.get("NETLOGIC_AGENT_TOKEN_MAX_AGE", str(7 * 24 * 3600))
)

# Maximum pending task queue length per agent — prevents memory exhaustion.
AGENT_PENDING_CAP: int = int(os.environ.get("NETLOGIC_AGENT_PENDING_CAP", "50"))

# Maximum agents per organisation — prevents registry exhaustion.
MAX_AGENTS_PER_ORG: int = int(os.environ.get("NETLOGIC_MAX_AGENTS_PER_ORG", "100"))

# Path to the agent persistence file.
_AGENTS_FILE: str = os.path.join(
    os.environ.get("NETLOGIC_SCANS_DIR", os.path.join(os.path.expanduser("~"), ".netlogic")),
    "agents.json",
)


@dataclass
class Agent:
    agent_id: str
    hostname: str
    capabilities: list[str]
    version: str
    tags: dict[str, str]
    token_hash: str              # SHA-256 hex of the secret
    token_plaintext: str = ""   # stored in local agents.json so UI can display it
    org_id: str = ""             # owning organisation — empty string = no tenant
    concurrency: int = 1         # max simultaneous scans this agent will run
    disabled: bool = False       # manually deactivated — won't receive jobs
    registered_at: float = field(default_factory=time.time)
    token_issued_at: float = field(default_factory=time.time)  # for expiry enforcement
    last_heartbeat: Optional[float] = None
    # job_ids the agent has accepted and is actively running (transient).
    active_jobs: set = field(default_factory=set)
    pending_tasks: list = field(default_factory=list)  # job_ids queued for this agent

    @property
    def current_job_id(self) -> Optional[str]:
        """A representative running job (back-compat for single-job UIs)."""
        return next(iter(self.active_jobs), None)

    @property
    def load(self) -> int:
        """Total committed work: jobs running + jobs queued but not yet picked up."""
        return len(self.active_jobs) + len(self.pending_tasks)

    @property
    def has_capacity(self) -> bool:
        """True if the agent can accept another job under its concurrency limit."""
        return self.load < max(1, self.concurrency)

    @property
    def status(self) -> str:
        """Dynamically computed: online | busy | offline | disabled."""
        if self.disabled:
            return "disabled"
        if self.last_heartbeat is None:
            return "offline"
        if time.time() - self.last_heartbeat > HEARTBEAT_TIMEOUT:
            return "offline"
        if not self.has_capacity:
            return "busy"
        return "online"

    def matches(self, required_capabilities=None, selector=None) -> bool:
        """Eligibility filter for intelligent dispatch.

        • required_capabilities — agent must advertise ALL of them.
        • selector — agent.tags must contain every key=value pair (vantage-point
          routing, e.g. {"region": "us-east", "network": "corp-vpc"}).
        Empty/None requirements match every agent (backward compatible).
        """
        if required_capabilities:
            caps = set(self.capabilities or [])
            if not set(required_capabilities).issubset(caps):
                return False
        if selector:
            for key, val in selector.items():
                if self.tags.get(key) != val:
                    return False
        return True

    def verify_token(self, secret: str) -> bool:
        """Constant-time comparison + token-age enforcement."""
        if time.time() - self.token_issued_at > AGENT_TOKEN_MAX_AGE:
            return False
        expected = hashlib.sha256(secret.encode()).hexdigest()
        return hmac.compare_digest(self.token_hash, expected)

    def to_dict(self) -> dict:
        """Serialise persistent fields only (transient state excluded)."""
        return {
            "agent_id":        self.agent_id,
            "hostname":        self.hostname,
            "capabilities":    self.capabilities,
            "version":         self.version,
            "tags":            self.tags,
            "token_hash":      self.token_hash,
            "token_plaintext": self.token_plaintext,
            "org_id":          self.org_id,
            "concurrency":     self.concurrency,
            "disabled":        self.disabled,
            "registered_at":   self.registered_at,
            "token_issued_at": self.token_issued_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Agent:
        return cls(
            agent_id        = data["agent_id"],
            hostname        = data["hostname"],
            capabilities    = data.get("capabilities", []),
            version         = data.get("version", ""),
            tags            = data.get("tags", {}),
            token_hash      = data["token_hash"],
            token_plaintext = data.get("token_plaintext", ""),
            org_id          = data.get("org_id", ""),
            concurrency     = int(data.get("concurrency", 1) or 1),
            disabled        = data.get("disabled", False),
            registered_at   = data.get("registered_at", time.time()),
            token_issued_at = data.get("token_issued_at", time.time()),
            last_heartbeat  = None,
            active_jobs     = set(),
            pending_tasks   = [],
        )


class AgentRegistry:
    """Process-wide singleton: registry of all remote agents with file persistence."""

    def __init__(self, persist_path: str | None = _AGENTS_FILE) -> None:
        self._agents: dict[str, Agent] = {}
        self._persist_path = persist_path  # None = memory-only (used in tests)
        # Re-entrant lock: the registry is mutated by background agent threads
        # (heartbeat/worker) while FastAPI request handlers read/iterate it.
        # Without this, a concurrent register() could raise "dict changed size
        # during iteration" in list(), or race the per-org cap check (TOCTOU).
        # RLock so a locked public method may call another (e.g. via _save).
        self._lock = threading.RLock()
        if persist_path:
            self._load()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self) -> None:
        """Re-hydrate agents from the JSON file on startup."""
        if not os.path.exists(self._persist_path):
            return
        try:
            with open(self._persist_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            for record in data:
                agent = Agent.from_dict(record)
                self._agents[agent.agent_id] = agent
            _log.info("Loaded %d agent(s) from %s", len(self._agents), self._persist_path)
        except Exception as exc:
            _log.warning("Could not load agents file: %s", exc)

    def _save(self) -> bool:
        """Write all agent records to the JSON file. Returns True on success."""
        if not self._persist_path:
            return True
        try:
            os.makedirs(os.path.dirname(self._persist_path), exist_ok=True)
            tmp = self._persist_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump([a.to_dict() for a in self._agents.values()], fh, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._persist_path)
            return True
        except Exception as exc:
            _log.error("Could not save agents file: %s", exc)
            return False

    # ── Registration ──────────────────────────────────────────────────────────

    def register(
        self,
        hostname: str,
        capabilities: list[str],
        version: str,
        tags: dict[str, str],
        org_id: str = "",
        concurrency: int = 1,
    ) -> tuple[str, str]:
        """
        Create a new agent record and persist it.
        Returns (agent_id, plaintext_secret) — secret shown only once to caller.
        Raises ValueError if the per-org agent cap is exceeded.
        """
        with self._lock:
            if org_id:
                org_count = sum(1 for a in self._agents.values() if a.org_id == org_id)
                if org_count >= MAX_AGENTS_PER_ORG:
                    raise ValueError(
                        f"Organisation '{org_id}' has reached the maximum of "
                        f"{MAX_AGENTS_PER_ORG} registered agents."
                    )
            now        = time.time()
            agent_id   = str(uuid.uuid4())
            secret     = str(uuid.uuid4())
            token_hash = hashlib.sha256(secret.encode()).hexdigest()
            self._agents[agent_id] = Agent(
                agent_id=agent_id,
                hostname=hostname,
                capabilities=capabilities,
                version=version,
                tags=tags,
                token_hash=token_hash,
                token_plaintext=secret,
                org_id=org_id,
                concurrency=max(1, int(concurrency or 1)),
                registered_at=now,
                token_issued_at=now,
            )
            if not self._save():
                _log.error("Agent %s registered in memory but failed to persist to disk.", agent_id)
            return agent_id, secret

    def deregister(self, agent_id: str) -> bool:
        with self._lock:
            if agent_id in self._agents:
                del self._agents[agent_id]
                if not self._save():
                    _log.error("Agent %s deregistered in memory but failed to persist.", agent_id)
                return True
            return False

    # ── Query ─────────────────────────────────────────────────────────────────

    def get(self, agent_id: str, org_id: str = "") -> Optional[Agent]:
        """Return the agent if it exists and belongs to org_id (or org_id is unset)."""
        with self._lock:
            agent = self._agents.get(agent_id)
            if agent is None:
                return None
            if org_id and agent.org_id != org_id:
                return None  # treat as not found — prevents cross-org enumeration
            return agent

    def list(self, org_id: str = "") -> list[Agent]:
        """Return all agents, optionally filtered to a single organisation."""
        with self._lock:
            agents = list(self._agents.values())
        if org_id:
            agents = [a for a in agents if a.org_id == org_id]
        return agents

    def list_visible(self, org_id: str) -> list[Agent]:
        """Agents an org may SEE: its own agents plus shared/global (org_id="") ones.

        Used by the dashboard so the always-on built-in agent (which is global and
        serves every org) appears in the fleet view instead of looking empty. The
        route redacts the token for agents the caller doesn't own.
        """
        with self._lock:
            agents = list(self._agents.values())
        return [a for a in agents if not a.org_id or a.org_id == org_id]

    # ── Heartbeat ─────────────────────────────────────────────────────────────

    def heartbeat(self, agent_id: str) -> bool:
        with self._lock:
            agent = self._agents.get(agent_id)
            if not agent:
                return False
            agent.last_heartbeat = time.time()
            return True

    # ── Task dispatch ─────────────────────────────────────────────────────────

    def set_disabled(self, agent_id: str, disabled: bool) -> bool:
        """Enable or disable an agent. Persists the change. Returns False if not found."""
        with self._lock:
            agent = self._agents.get(agent_id)
            if not agent:
                return False
            agent.disabled = disabled
            if not self._save():
                _log.error("Agent %s disabled state changed in memory but failed to persist.", agent_id)
            return True

    def assign_task(self, agent_id: str, job_id: str) -> bool:
        """Push a job_id onto the agent's pending queue.

        Returns False if the agent is not found, disabled, the queue is at capacity,
        or the agent has no remaining capacity under its concurrency limit.
        """
        with self._lock:
            agent = self._agents.get(agent_id)
            if not agent:
                return False
            if agent.disabled:
                return False
            if not agent.has_capacity:
                return False
            if len(agent.pending_tasks) >= AGENT_PENDING_CAP:
                return False
            agent.pending_tasks.append(job_id)
            return True

    def get_pending_tasks(self, agent_id: str) -> list[str]:
        """Atomically drain and return the agent's pending task queue."""
        with self._lock:
            agent = self._agents.get(agent_id)
            if not agent:
                return []
            tasks = list(agent.pending_tasks)
            agent.pending_tasks.clear()
            return tasks

    # ── Capacity tracking ─────────────────────────────────────────────────────

    def mark_active(self, agent_id: str, job_id: str) -> None:
        """Record that the agent has accepted a job and is now running it.

        Moves the job out of pending (if present) into the active set so the
        agent's load reflects work in progress, not just queued work.
        """
        with self._lock:
            agent = self._agents.get(agent_id)
            if not agent:
                return
            if job_id in agent.pending_tasks:
                agent.pending_tasks.remove(job_id)
            agent.active_jobs.add(job_id)

    def mark_done(self, agent_id: str, job_id: str) -> None:
        """Release a job from the agent (finished, failed, or reclaimed)."""
        with self._lock:
            agent = self._agents.get(agent_id)
            if not agent:
                return
            agent.active_jobs.discard(job_id)
            if job_id in agent.pending_tasks:
                agent.pending_tasks.remove(job_id)

    def find_idle_agent(self) -> Optional[Agent]:
        """Return the first online/idle (non-disabled) agent, or None."""
        with self._lock:
            for agent in self._agents.values():
                if agent.status == "online":  # disabled agents return "disabled", not "online"
                    return agent
            return None


# Process-wide singleton — imported by executor and routes.
agent_registry = AgentRegistry()
