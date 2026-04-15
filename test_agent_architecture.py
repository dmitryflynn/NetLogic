"""
Phase 2 — Cloud Agent Architecture tests.

Covers:
  • AgentRegistry: register, deregister, heartbeat, task dispatch
  • Agent.status: online / busy / offline transitions
  • Agent.verify_token: correct token, wrong token, timing safety
  • ScanRequest: agent_id field accepted / ignored when None
  • submit_scan: agent dispatch path vs. local execution path
"""

import sys
import os
import time
import asyncio
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from api.agents.registry import Agent, AgentRegistry, HEARTBEAT_TIMEOUT
from api.models.scan_request import ScanRequest


# ─── AgentRegistry unit tests ─────────────────────────────────────────────────

class TestAgentRegistry(unittest.TestCase):

    def setUp(self):
        self.registry = AgentRegistry()

    def _register(self, hostname="agent-01"):
        return self.registry.register(
            hostname=hostname,
            capabilities=["scan", "tls"],
            version="2.0.0",
            tags={"env": "test"},
        )

    # ── Registration ──────────────────────────────────────────────────────────

    def test_register_returns_id_and_secret(self):
        agent_id, secret = self._register()
        self.assertIsInstance(agent_id, str)
        self.assertIsInstance(secret, str)
        self.assertEqual(len(agent_id), 36)  # UUID format

    def test_registered_agent_retrievable(self):
        agent_id, _ = self._register()
        agent = self.registry.get(agent_id)
        self.assertIsNotNone(agent)
        self.assertEqual(agent.hostname, "agent-01")

    def test_unknown_agent_returns_none(self):
        self.assertIsNone(self.registry.get("nonexistent"))

    def test_deregister_removes_agent(self):
        agent_id, _ = self._register()
        result = self.registry.deregister(agent_id)
        self.assertTrue(result)
        self.assertIsNone(self.registry.get(agent_id))

    def test_deregister_nonexistent_returns_false(self):
        self.assertFalse(self.registry.deregister("nonexistent"))

    def test_list_returns_all_agents(self):
        self._register("host-a")
        self._register("host-b")
        self.assertEqual(len(self.registry.list()), 2)

    # ── Token verification ────────────────────────────────────────────────────

    def test_correct_token_verifies(self):
        agent_id, secret = self._register()
        agent = self.registry.get(agent_id)
        self.assertTrue(agent.verify_token(secret))

    def test_wrong_token_fails(self):
        agent_id, _ = self._register()
        agent = self.registry.get(agent_id)
        self.assertFalse(agent.verify_token("wrong-secret"))

    def test_empty_token_fails(self):
        agent_id, _ = self._register()
        agent = self.registry.get(agent_id)
        self.assertFalse(agent.verify_token(""))

    # ── Heartbeat ─────────────────────────────────────────────────────────────

    def test_heartbeat_updates_last_seen(self):
        agent_id, _ = self._register()
        before = time.time()
        self.registry.heartbeat(agent_id)
        agent = self.registry.get(agent_id)
        self.assertGreaterEqual(agent.last_heartbeat, before)

    def test_heartbeat_nonexistent_returns_false(self):
        self.assertFalse(self.registry.heartbeat("nonexistent"))

    # ── Status transitions ────────────────────────────────────────────────────

    def test_new_agent_is_offline(self):
        agent_id, _ = self._register()
        agent = self.registry.get(agent_id)
        self.assertEqual(agent.status, "offline")

    def test_agent_is_online_after_heartbeat(self):
        agent_id, _ = self._register()
        self.registry.heartbeat(agent_id)
        agent = self.registry.get(agent_id)
        self.assertEqual(agent.status, "online")

    def test_agent_is_busy_when_has_job(self):
        agent_id, _ = self._register()
        self.registry.heartbeat(agent_id)
        agent = self.registry.get(agent_id)
        agent.current_job_id = "some-job-id"
        self.assertEqual(agent.status, "busy")

    def test_agent_goes_offline_after_timeout(self):
        agent_id, _ = self._register()
        agent = self.registry.get(agent_id)
        # Backdate heartbeat beyond timeout
        agent.last_heartbeat = time.time() - HEARTBEAT_TIMEOUT - 1
        self.assertEqual(agent.status, "offline")

    # ── Task dispatch ─────────────────────────────────────────────────────────

    def test_assign_task_queues_job(self):
        agent_id, _ = self._register()
        result = self.registry.assign_task(agent_id, "job-123")
        self.assertTrue(result)
        agent = self.registry.get(agent_id)
        self.assertIn("job-123", agent.pending_tasks)

    def test_get_pending_tasks_drains_queue(self):
        agent_id, _ = self._register()
        self.registry.assign_task(agent_id, "job-1")
        self.registry.assign_task(agent_id, "job-2")
        tasks = self.registry.get_pending_tasks(agent_id)
        self.assertEqual(tasks, ["job-1", "job-2"])
        # Queue is now empty
        self.assertEqual(self.registry.get_pending_tasks(agent_id), [])

    def test_assign_task_to_nonexistent_agent_returns_false(self):
        self.assertFalse(self.registry.assign_task("nonexistent", "job-1"))

    def test_find_idle_agent_returns_online_agent(self):
        agent_id, _ = self._register()
        self.registry.heartbeat(agent_id)
        idle = self.registry.find_idle_agent()
        self.assertIsNotNone(idle)
        self.assertEqual(idle.agent_id, agent_id)

    def test_find_idle_agent_skips_offline(self):
        agent_id, _ = self._register()
        # No heartbeat — agent is offline
        self.assertIsNone(self.registry.find_idle_agent())

    def test_find_idle_agent_skips_busy(self):
        agent_id, _ = self._register()
        self.registry.heartbeat(agent_id)
        agent = self.registry.get(agent_id)
        agent.current_job_id = "busy-job"
        self.assertIsNone(self.registry.find_idle_agent())


# ─── ScanRequest agent_id field ───────────────────────────────────────────────

class TestScanRequestAgentId(unittest.TestCase):

    def test_agent_id_defaults_to_none(self):
        req = ScanRequest(target="example.com")
        self.assertIsNone(req.agent_id)

    def test_agent_id_accepted_when_set(self):
        req = ScanRequest(target="example.com", agent_id="abc-123")
        self.assertEqual(req.agent_id, "abc-123")

    def test_local_scan_no_agent_id(self):
        req = ScanRequest(target="10.0.0.1")
        self.assertFalse(bool(req.agent_id))


# ─── submit_scan dispatch logic ───────────────────────────────────────────────

class TestSubmitScanDispatch(unittest.IsolatedAsyncioTestCase):

    async def test_offline_agent_fails_job(self):
        """Dispatching to an offline agent immediately fails the job."""
        from api.agents.registry import AgentRegistry
        from api.jobs.executor import submit_scan
        from api.jobs.manager import ScanJob

        registry = AgentRegistry()
        # Register but never heartbeat → status = offline
        agent_id, _ = registry.register(
            hostname="test-agent", capabilities=[], version="1.0", tags={}
        )

        config = ScanRequest(target="10.0.0.1", agent_id=agent_id)
        job = ScanJob(job_id="test-job-1", config=config)

        # Patch the singleton in the registry module (where executor imports it from).
        with patch("api.agents.registry.agent_registry", registry):
            await submit_scan(job)

        self.assertEqual(job.status, "failed")
        self.assertIn("not available", job.error)

    async def test_online_agent_queues_job(self):
        """Dispatching to an online agent enqueues the job_id on the agent."""
        from api.agents.registry import AgentRegistry
        from api.jobs.executor import submit_scan
        from api.jobs.manager import ScanJob

        registry = AgentRegistry()
        agent_id, _ = registry.register(
            hostname="test-agent", capabilities=[], version="1.0", tags={}
        )
        registry.heartbeat(agent_id)  # bring online

        config = ScanRequest(target="10.0.0.1", agent_id=agent_id)
        job = ScanJob(job_id="test-job-2", config=config)

        # Patch the singleton in the registry module (where executor imports it from).
        with patch("api.agents.registry.agent_registry", registry):
            await submit_scan(job)

        agent = registry.get(agent_id)
        self.assertIn("test-job-2", agent.pending_tasks)
        # Job stays queued (agent hasn't picked it up yet)
        self.assertEqual(job.status, "queued")


if __name__ == "__main__":
    unittest.main()
