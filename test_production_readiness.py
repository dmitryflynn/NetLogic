"""
Production-readiness tests — Phase 1.9

Covers gaps identified in the pre-AI production audit:
  - Rate limiter: window enforcement, per-key reset
  - Health endpoint: returns ok status with sub-checks
  - API versioning: v1 prefix on all routes
  - Full agent lifecycle: register → heartbeat → get_tasks → submit_events → complete
  - Cross-org isolation: org-A jobs/agents invisible to org-B
"""

from __future__ import annotations

import os
import sys
import time
import unittest

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

os.environ.setdefault("NETLOGIC_JWT_SECRET", "ci-test-secret-that-is-long-enough-for-tests")
os.environ.setdefault("NETLOGIC_ADMIN_KEY", "ci-admin-key")
os.environ.setdefault("NETLOGIC_NO_BROWSER", "1")

from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)
ADMIN_HEADERS = {"X-Admin-Key": os.environ["NETLOGIC_ADMIN_KEY"]}


def _make_org(org_id: str) -> dict:
    """Create an API key + JWT for org_id, return auth headers."""
    key_resp = client.post("/v1/auth/keys", json={"org_id": org_id}, headers=ADMIN_HEADERS)
    assert key_resp.status_code == 201, key_resp.text
    api_key = key_resp.json()["api_key"]
    tok_resp = client.post("/v1/auth/token", json={"api_key": api_key})
    assert tok_resp.status_code == 200, tok_resp.text
    return {"Authorization": f"Bearer {tok_resp.json()['token']}"}


# ── Rate limiter ──────────────────────────────────────────────────────────────

class TestRateLimiter(unittest.TestCase):

    def setUp(self):
        from api.auth.rate_limit import token_limiter
        token_limiter.reset("127.0.0.1")

    def test_allows_requests_within_limit(self):
        from api.auth.rate_limit import RateLimiter
        lim = RateLimiter(max_calls=5, window_seconds=60)
        for _ in range(5):
            self.assertTrue(lim.allow("key"))

    def test_blocks_on_limit_exceeded(self):
        from api.auth.rate_limit import RateLimiter
        lim = RateLimiter(max_calls=3, window_seconds=60)
        for _ in range(3):
            lim.allow("key")
        self.assertFalse(lim.allow("key"))

    def test_reset_clears_key(self):
        from api.auth.rate_limit import RateLimiter
        lim = RateLimiter(max_calls=2, window_seconds=60)
        lim.allow("key")
        lim.allow("key")
        self.assertFalse(lim.allow("key"))
        lim.reset("key")
        self.assertTrue(lim.allow("key"))

    def test_different_keys_independent(self):
        from api.auth.rate_limit import RateLimiter
        lim = RateLimiter(max_calls=1, window_seconds=60)
        lim.allow("a")
        self.assertFalse(lim.allow("a"))
        self.assertTrue(lim.allow("b"))  # b is unaffected

    def tearDown(self):
        from api.auth.rate_limit import token_limiter
        token_limiter.reset("testclient")

    def test_auth_endpoint_rate_limited(self):
        """POST /v1/auth/token returns 429 after 10 bad attempts from same IP."""
        from api.auth.rate_limit import token_limiter
        token_limiter.reset("testclient")
        # Exhaust the 10-per-minute budget
        for _ in range(10):
            client.post("/v1/auth/token", json={"api_key": "bad"})
        resp = client.post("/v1/auth/token", json={"api_key": "bad"})
        self.assertEqual(resp.status_code, 429)


# ── Health endpoint ────────────────────────────────────────────────────────────

class TestHealthEndpoint(unittest.TestCase):

    def test_health_returns_200(self):
        resp = client.get("/health")
        self.assertEqual(resp.status_code, 200)

    def test_health_v1_returns_200(self):
        resp = client.get("/v1/health")
        self.assertEqual(resp.status_code, 200)

    def test_health_has_status_field(self):
        data = client.get("/health").json()
        self.assertIn("status", data)
        self.assertIn(data["status"], ("ok", "degraded"))

    def test_health_has_checks(self):
        data = client.get("/health").json()
        self.assertIn("checks", data)
        self.assertIsInstance(data["checks"], dict)

    def test_health_has_uptime(self):
        data = client.get("/health").json()
        self.assertIn("uptime_s", data)
        self.assertGreaterEqual(data["uptime_s"], 0)


# ── API versioning ────────────────────────────────────────────────────────────

class TestApiVersioning(unittest.TestCase):

    def test_v1_auth_token_reachable(self):
        resp = client.post("/v1/auth/token", json={"api_key": "nonexistent"})
        # 401 (not 404) confirms the route exists
        self.assertEqual(resp.status_code, 401)

    def test_v1_jobs_requires_auth(self):
        resp = client.get("/v1/jobs")
        self.assertEqual(resp.status_code, 401)

    def test_v1_agents_requires_auth(self):
        resp = client.get("/v1/agents")
        self.assertEqual(resp.status_code, 401)

    def test_unversioned_routes_return_404(self):
        # /jobs (unversioned) should not exist
        resp = client.get("/jobs")
        # Either 404 (route not found) or caught by SPA catch-all (200 index.html)
        # Either way it must NOT be a 401 from the jobs router
        self.assertNotEqual(resp.status_code, 401)


# ── Full agent lifecycle ──────────────────────────────────────────────────────

class TestAgentLifecycle(unittest.TestCase):

    def setUp(self):
        from api.auth.rate_limit import register_limiter, token_limiter
        register_limiter.reset("testclient")
        token_limiter.reset("testclient")
        self.headers = _make_org("agent-lifecycle-org")

    def _register_agent(self) -> tuple[str, str]:
        """Register a test agent via the API, return (agent_id, token)."""
        resp = client.post(
            "/v1/agents/register",
            json={
                "hostname": "test-host",
                "capabilities": ["scan"],
                "version": "1.0",
                "tags": {},
            },
            headers=self.headers,
        )
        self.assertEqual(resp.status_code, 201, resp.text)
        data = resp.json()
        return data["agent_id"], data["token"]

    def test_register_returns_agent_id_and_token(self):
        agent_id, token = self._register_agent()
        self.assertTrue(agent_id)
        self.assertTrue(token)

    def test_heartbeat_acknowledged(self):
        agent_id, token = self._register_agent()
        agent_headers = {"Authorization": f"Bearer {token}"}
        resp = client.post(f"/v1/agents/{agent_id}/heartbeat", headers=agent_headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "ok")

    def test_list_agents_shows_registered(self):
        agent_id, _ = self._register_agent()
        resp = client.get("/v1/agents", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        ids = [a["agent_id"] for a in resp.json()]
        self.assertIn(agent_id, ids)

    def test_get_tasks_initially_empty(self):
        agent_id, token = self._register_agent()
        agent_headers = {"Authorization": f"Bearer {token}"}
        resp = client.get(f"/v1/agents/{agent_id}/tasks", headers=agent_headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), [])

    def test_deregister_removes_agent(self):
        agent_id, _ = self._register_agent()
        resp = client.delete(f"/v1/agents/{agent_id}", headers=self.headers)
        self.assertEqual(resp.status_code, 204)
        resp2 = client.get("/v1/agents", headers=self.headers)
        ids = [a["agent_id"] for a in resp2.json()]
        self.assertNotIn(agent_id, ids)

    def test_wrong_token_gets_401(self):
        agent_id, _ = self._register_agent()
        bad_headers = {"Authorization": "Bearer wrong-token"}
        resp = client.post(f"/v1/agents/{agent_id}/heartbeat", headers=bad_headers)
        self.assertEqual(resp.status_code, 401)

    def test_full_task_lifecycle(self):
        """Simulate: create job → agent polls → submits events → marks complete."""
        agent_id, token = self._register_agent()
        agent_headers = {"Authorization": f"Bearer {token}"}

        # Bring agent online via heartbeat
        client.post(f"/v1/agents/{agent_id}/heartbeat", headers=agent_headers)

        # Create a scan job (will be dispatched to the online agent)
        job_resp = client.post(
            "/v1/jobs",
            json={"target": "127.0.0.1", "agent_id": agent_id},
            headers=self.headers,
        )
        self.assertEqual(job_resp.status_code, 202, job_resp.text)
        job_id = job_resp.json()["job_id"]

        # Agent polls for tasks
        tasks_resp = client.get(f"/v1/agents/{agent_id}/tasks", headers=agent_headers)
        self.assertEqual(tasks_resp.status_code, 200)
        tasks = tasks_resp.json()
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["job_id"], job_id)

        # Agent submits an event
        events_resp = client.post(
            f"/v1/agents/{agent_id}/tasks/{job_id}/events",
            json=[{"type": "port", "data": {"port": 80, "service": "http"}}],
            headers=agent_headers,
        )
        self.assertEqual(events_resp.status_code, 200)
        self.assertEqual(events_resp.json()["accepted"], 1)

        # Agent marks job complete
        complete_resp = client.post(
            f"/v1/agents/{agent_id}/tasks/{job_id}/complete",
            json={"error": None},
            headers=agent_headers,
        )
        self.assertEqual(complete_resp.status_code, 200)
        self.assertEqual(complete_resp.json()["status"], "completed")

        # Job status is now completed
        job_detail = client.get(f"/v1/jobs/{job_id}", headers=self.headers)
        self.assertEqual(job_detail.json()["status"], "completed")


# ── Cross-org isolation ───────────────────────────────────────────────────────

class TestCrossOrgIsolation(unittest.TestCase):

    def setUp(self):
        from api.auth.rate_limit import register_limiter, token_limiter
        register_limiter.reset("testclient")
        token_limiter.reset("testclient")
        self.headers_a = _make_org("iso-org-a")
        self.headers_b = _make_org("iso-org-b")

    def test_org_a_jobs_invisible_to_org_b(self):
        # Create a job as org-a
        resp = client.post("/v1/jobs", json={"target": "10.0.0.1"}, headers=self.headers_a)
        self.assertEqual(resp.status_code, 202, resp.text)
        job_id = resp.json()["job_id"]

        # Org-b cannot see the job in the list
        list_b = client.get("/v1/jobs", headers=self.headers_b).json()
        ids_b = [j["job_id"] for j in list_b]
        self.assertNotIn(job_id, ids_b)

        # Org-b gets 404 when fetching by id
        get_resp = client.get(f"/v1/jobs/{job_id}", headers=self.headers_b)
        self.assertEqual(get_resp.status_code, 404)

    def test_org_a_agents_invisible_to_org_b(self):
        # Register an agent as org-a
        reg_resp = client.post(
            "/v1/agents/register",
            json={"hostname": "agent-a", "capabilities": [], "version": "1.0", "tags": {}},
            headers=self.headers_a,
        )
        self.assertEqual(reg_resp.status_code, 201)
        agent_id = reg_resp.json()["agent_id"]

        # Org-b cannot see the agent in its list
        list_b = client.get("/v1/agents", headers=self.headers_b).json()
        ids_b = [a["agent_id"] for a in list_b]
        self.assertNotIn(agent_id, ids_b)

        # Org-b gets 404 when fetching by id
        get_resp = client.get(f"/v1/agents/{agent_id}", headers=self.headers_b)
        self.assertEqual(get_resp.status_code, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
