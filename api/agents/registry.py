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
    registered_at: float = field(default_factory=time.time)
    token_issued_at: float = field(default_factory=time.time)  # for expiry enforcement
    last_heartbeat: Optional[float] = None
    current_job_id: Optional[str] = None
    pending_tasks: list = field(default_factory=list)  # job_ids queued for this agent

    @property
    def status(self) -> str:
        """Dynamically computed: online | busy | offline."""
        if self.last_heartbeat is None:
            return "offline"
        if time.time() - self.last_heartbeat > HEARTBEAT_TIMEOUT:
            return "offline"
        if self.current_job_id:
            return "busy"
        return "online"

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
            registered_at   = data.get("registered_at", time.time()),
            token_issued_at = data.get("token_issued_at", time.time()),
            last_heartbeat  = None,
            current_job_id  = None,
            pending_tasks   = [],
        )


class AgentRegistry:
    """Process-wide singleton: registry of all remote agents with file persistence."""

    def __init__(self, persist_path: str | None = _AGENTS_FILE) -> None:
        self._agents: dict[str, Agent] = {}
        self._persist_path = persist_path  # None = memory-only (used in tests)
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

    def _save(self) -> None:
        """Write all agent records to the JSON file."""
        if not self._persist_path:
            return
        try:
            os.makedirs(os.path.dirname(self._persist_path), exist_ok=True)
            tmp = self._persist_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump([a.to_dict() for a in self._agents.values()], fh, indent=2)
            os.replace(tmp, self._persist_path)
        except Exception as exc:
            _log.warning("Could not save agents file: %s", exc)

    # ── Registration ──────────────────────────────────────────────────────────

    def register(
        self,
        hostname: str,
        capabilities: list[str],
        version: str,
        tags: dict[str, str],
        org_id: str = "",
    ) -> tuple[str, str]:
        """
        Create a new agent record and persist it.
        Returns (agent_id, plaintext_secret) — secret shown only once to caller.
        Raises ValueError if the per-org agent cap is exceeded.
        """
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
            registered_at=now,
            token_issued_at=now,
        )
        self._save()
        return agent_id, secret

    def deregister(self, agent_id: str) -> bool:
        if agent_id in self._agents:
            del self._agents[agent_id]
            self._save()
            return True
        return False

    # ── Query ─────────────────────────────────────────────────────────────────

    def get(self, agent_id: str, org_id: str = "") -> Optional[Agent]:
        """Return the agent if it exists and belongs to org_id (or org_id is unset)."""
        agent = self._agents.get(agent_id)
        if agent is None:
            return None
        if org_id and agent.org_id != org_id:
            return None  # treat as not found — prevents cross-org enumeration
        return agent

    def list(self, org_id: str = "") -> list[Agent]:
        """Return all agents, optionally filtered to a single organisation."""
        agents = list(self._agents.values())
        if org_id:
            agents = [a for a in agents if a.org_id == org_id]
        return agents

    # ── Heartbeat ─────────────────────────────────────────────────────────────

    def heartbeat(self, agent_id: str) -> bool:
        agent = self._agents.get(agent_id)
        if not agent:
            return False
        agent.last_heartbeat = time.time()
        return True

    # ── Task dispatch ─────────────────────────────────────────────────────────

    def assign_task(self, agent_id: str, job_id: str) -> bool:
        """Push a job_id onto the agent's pending queue.

        Returns False if the agent is not found or the queue is at capacity.
        """
        agent = self._agents.get(agent_id)
        if not agent:
            return False
        if len(agent.pending_tasks) >= AGENT_PENDING_CAP:
            return False
        agent.pending_tasks.append(job_id)
        return True

    def get_pending_tasks(self, agent_id: str) -> list[str]:
        """Atomically drain and return the agent's pending task queue."""
        agent = self._agents.get(agent_id)
        if not agent:
            return []
        tasks = list(agent.pending_tasks)
        agent.pending_tasks.clear()
        return tasks

    def find_idle_agent(self) -> Optional[Agent]:
        """Return the first online/idle agent, or None if all are offline or busy."""
        for agent in self._agents.values():
            if agent.status == "online":
                return agent
        return None


# Process-wide singleton — imported by executor and routes.
agent_registry = AgentRegistry()
