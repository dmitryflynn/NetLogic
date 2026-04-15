"""
Phase 3 — Multi-tenancy + JWT Auth tests.

Covers:
  • jwt_handler: create_token / verify_token (valid, expired, tampered)
  • ApiKeyStore: seed from env, create, lookup, revoke, list_keys
  • verify_admin: correct key, wrong key
  • require_org dependency: happy path, missing header, bad token
  • JobManager org_id isolation: create, get (own/cross), list (filtered)
  • AgentRegistry org_id isolation: register, get (own/cross), list (filtered)
  • Auth routes: POST /auth/token, POST /auth/keys, GET /auth/keys, DELETE /auth/keys/{key}
"""

from __future__ import annotations

import os
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ─── JWT handler tests ────────────────────────────────────────────────────────

class TestJwtHandler(unittest.TestCase):

    def setUp(self):
        # Patch JWT_SECRET so tests are deterministic
        import api.auth.jwt_handler as jh
        self._orig_secret = jh.JWT_SECRET
        jh.JWT_SECRET = "test-secret-phase3"

    def tearDown(self):
        import api.auth.jwt_handler as jh
        jh.JWT_SECRET = self._orig_secret

    def test_round_trip_valid_token(self):
        from api.auth.jwt_handler import create_token, verify_token
        token = create_token(org_id="acme", sub="key123")
        claims = verify_token(token)
        self.assertIsNotNone(claims)
        self.assertEqual(claims["org_id"], "acme")
        self.assertEqual(claims["sub"], "key123")

    def test_token_contains_exp(self):
        from api.auth.jwt_handler import create_token, verify_token
        token = create_token(org_id="acme", sub="key123", expiry_seconds=60)
        claims = verify_token(token)
        self.assertIn("exp", claims)
        self.assertGreater(claims["exp"], time.time())

    def test_expired_token_rejected(self):
        from api.auth.jwt_handler import create_token, verify_token
        token = create_token(org_id="acme", sub="key123", expiry_seconds=-1)
        self.assertIsNone(verify_token(token))

    def test_tampered_signature_rejected(self):
        from api.auth.jwt_handler import create_token, verify_token
        token = create_token(org_id="acme", sub="key123")
        parts = token.split(".")
        # Corrupt the signature
        parts[2] = parts[2][:-3] + "xxx"
        self.assertIsNone(verify_token(".".join(parts)))

    def test_tampered_payload_rejected(self):
        from api.auth.jwt_handler import create_token, verify_token
        import base64, json
        token = create_token(org_id="acme", sub="key123")
        header, payload_b64, sig = token.split(".")
        # Decode payload, change org_id, re-encode
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        claims = json.loads(base64.urlsafe_b64decode(payload_b64))
        claims["org_id"] = "evil-corp"
        new_payload = base64.urlsafe_b64encode(
            json.dumps(claims).encode()
        ).rstrip(b"=").decode()
        tampered = f"{header}.{new_payload}.{sig}"
        self.assertIsNone(verify_token(tampered))

    def test_garbage_token_rejected(self):
        from api.auth.jwt_handler import verify_token
        self.assertIsNone(verify_token("not.a.jwt.at.all"))
        self.assertIsNone(verify_token(""))
        self.assertIsNone(verify_token("onlytwoparts.here"))

    def test_different_orgs_produce_different_tokens(self):
        from api.auth.jwt_handler import create_token
        t1 = create_token(org_id="org-a", sub="k")
        t2 = create_token(org_id="org-b", sub="k")
        self.assertNotEqual(t1, t2)


# ─── ApiKeyStore tests ────────────────────────────────────────────────────────

class TestApiKeyStore(unittest.TestCase):

    def _fresh_store(self, env_val: str = "") -> object:
        """Create a fresh ApiKeyStore without singleton pollution."""
        with patch.dict(os.environ, {"NETLOGIC_API_KEYS": env_val}, clear=False):
            from api.auth import api_keys as mod
            store_cls = mod.ApiKeyStore
            return store_cls()

    def test_create_and_lookup(self):
        store = self._fresh_store()
        key = store.create("org-a")
        self.assertEqual(store.lookup(key), "org-a")

    def test_lookup_unknown_returns_none(self):
        store = self._fresh_store()
        self.assertIsNone(store.lookup("nonexistent-key"))

    def test_revoke_removes_key(self):
        store = self._fresh_store()
        key = store.create("org-b")
        self.assertTrue(store.revoke(key))
        self.assertIsNone(store.lookup(key))

    def test_revoke_nonexistent_returns_false(self):
        store = self._fresh_store()
        self.assertFalse(store.revoke("ghost-key"))

    def test_seed_from_env(self):
        store = self._fresh_store(env_val="mykey:acme,otherkey:beta")
        self.assertEqual(store.lookup("mykey"), "acme")
        self.assertEqual(store.lookup("otherkey"), "beta")

    def test_list_keys_masks_key(self):
        store = self._fresh_store()
        key = store.create("masked-org")
        entries = store.list_keys()
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertTrue(entry["key_masked"].endswith("…"))
        self.assertNotEqual(entry["key_masked"], key)
        self.assertEqual(entry["org_id"], "masked-org")

    def test_created_key_is_32_hex_chars(self):
        store = self._fresh_store()
        key = store.create("org-c")
        self.assertEqual(len(key), 32)
        self.assertTrue(all(c in "0123456789abcdef" for c in key))


class TestVerifyAdmin(unittest.TestCase):

    def test_correct_key_passes(self):
        from api.auth.api_keys import verify_admin
        with patch("api.auth.api_keys.ADMIN_KEY", "secret-admin"):
            self.assertTrue(verify_admin("secret-admin"))

    def test_wrong_key_fails(self):
        from api.auth.api_keys import verify_admin
        with patch("api.auth.api_keys.ADMIN_KEY", "secret-admin"):
            self.assertFalse(verify_admin("wrong"))

    def test_empty_key_fails(self):
        from api.auth.api_keys import verify_admin
        with patch("api.auth.api_keys.ADMIN_KEY", "secret-admin"):
            self.assertFalse(verify_admin(""))


# ─── require_org dependency tests ────────────────────────────────────────────

class TestRequireOrg(unittest.TestCase):

    def _make_creds(self, token: str):
        creds = MagicMock()
        creds.credentials = token
        return creds

    def test_valid_token_returns_org_id(self):
        from api.auth.dependencies import require_org
        from api.auth.jwt_handler import create_token
        import api.auth.jwt_handler as jh
        orig = jh.JWT_SECRET
        try:
            jh.JWT_SECRET = "dep-test-secret"
            token = create_token(org_id="my-org", sub="k")
            result = require_org(self._make_creds(token))
            self.assertEqual(result, "my-org")
        finally:
            jh.JWT_SECRET = orig

    def test_no_creds_raises_401(self):
        from api.auth.dependencies import require_org
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            require_org(None)
        self.assertEqual(ctx.exception.status_code, 401)

    def test_bad_token_raises_401(self):
        from api.auth.dependencies import require_org
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            require_org(self._make_creds("garbage.token.here"))
        self.assertEqual(ctx.exception.status_code, 401)

    def test_expired_token_raises_401(self):
        from api.auth.dependencies import require_org
        from api.auth.jwt_handler import create_token
        from fastapi import HTTPException
        import api.auth.jwt_handler as jh
        orig = jh.JWT_SECRET
        try:
            jh.JWT_SECRET = "dep-test-secret"
            token = create_token(org_id="my-org", sub="k", expiry_seconds=-1)
            with self.assertRaises(HTTPException) as ctx:
                require_org(self._make_creds(token))
            self.assertEqual(ctx.exception.status_code, 401)
        finally:
            jh.JWT_SECRET = orig


# ─── JobManager org_id isolation tests ───────────────────────────────────────

class TestJobManagerOrgIsolation(unittest.TestCase):

    def setUp(self):
        from api.jobs.manager import JobManager
        from unittest.mock import MagicMock
        self.manager = JobManager.__new__(JobManager)
        self.manager._jobs = {}
        self.manager.store = MagicMock()

    def _make_request(self, target: str = "10.0.0.1"):
        from api.models.scan_request import ScanRequest
        return ScanRequest(target=target)

    def test_create_assigns_org_id(self):
        req = self._make_request()
        job = self.manager.create(req, org_id="org-a")
        self.assertEqual(job.org_id, "org-a")

    def test_get_own_job_succeeds(self):
        req = self._make_request()
        job = self.manager.create(req, org_id="org-a")
        retrieved = self.manager.get(job.job_id, org_id="org-a")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.job_id, job.job_id)

    def test_get_cross_org_job_returns_none(self):
        req = self._make_request()
        job = self.manager.create(req, org_id="org-a")
        retrieved = self.manager.get(job.job_id, org_id="org-b")
        self.assertIsNone(retrieved)

    def test_get_no_org_filter_returns_job(self):
        req = self._make_request()
        job = self.manager.create(req, org_id="org-a")
        retrieved = self.manager.get(job.job_id)  # no org_id filter
        self.assertIsNotNone(retrieved)

    def test_list_filters_by_org(self):
        req = self._make_request()
        self.manager.create(req, org_id="org-a")
        self.manager.create(req, org_id="org-a")
        self.manager.create(req, org_id="org-b")
        org_a_jobs = self.manager.list(org_id="org-a")
        self.assertEqual(len(org_a_jobs), 2)

    def test_list_no_filter_returns_all(self):
        req = self._make_request()
        self.manager.create(req, org_id="org-a")
        self.manager.create(req, org_id="org-b")
        all_jobs = self.manager.list()
        self.assertEqual(len(all_jobs), 2)

    def test_list_empty_org_returns_empty(self):
        req = self._make_request()
        self.manager.create(req, org_id="org-a")
        result = self.manager.list(org_id="org-c")
        self.assertEqual(result, [])


# ─── AgentRegistry org_id isolation tests ────────────────────────────────────

class TestAgentRegistryOrgIsolation(unittest.TestCase):

    def setUp(self):
        from api.agents.registry import AgentRegistry
        self.registry = AgentRegistry()

    def _register(self, hostname: str = "h", org_id: str = "") -> tuple:
        return self.registry.register(
            hostname=hostname,
            capabilities=[],
            version="1.0",
            tags={},
            org_id=org_id,
        )

    def test_register_assigns_org_id(self):
        agent_id, _ = self._register(org_id="org-x")
        agent = self.registry.get(agent_id)
        self.assertEqual(agent.org_id, "org-x")

    def test_get_own_agent_succeeds(self):
        agent_id, _ = self._register(org_id="org-x")
        agent = self.registry.get(agent_id, org_id="org-x")
        self.assertIsNotNone(agent)

    def test_get_cross_org_agent_returns_none(self):
        agent_id, _ = self._register(org_id="org-x")
        agent = self.registry.get(agent_id, org_id="org-y")
        self.assertIsNone(agent)

    def test_get_no_filter_returns_agent(self):
        agent_id, _ = self._register(org_id="org-x")
        agent = self.registry.get(agent_id)
        self.assertIsNotNone(agent)

    def test_list_filters_by_org(self):
        self._register("a1", org_id="org-a")
        self._register("a2", org_id="org-a")
        self._register("b1", org_id="org-b")
        org_a = self.registry.list(org_id="org-a")
        self.assertEqual(len(org_a), 2)

    def test_list_no_filter_returns_all(self):
        self._register("a", org_id="org-a")
        self._register("b", org_id="org-b")
        all_agents = self.registry.list()
        self.assertEqual(len(all_agents), 2)


# ─── Auth HTTP route tests ────────────────────────────────────────────────────

class TestAuthRoutes(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        from fastapi.testclient import TestClient
        from api.main import create_app
        self.app = create_app()
        from starlette.testclient import TestClient as SyncClient
        self.client = SyncClient(self.app)

    def _admin_headers(self):
        from api.auth.api_keys import ADMIN_KEY
        return {"X-Admin-Key": ADMIN_KEY}

    def test_create_key_and_get_token(self):
        # Create an API key
        resp = self.client.post(
            "/auth/keys",
            json={"org_id": "test-org"},
            headers=self._admin_headers(),
        )
        self.assertEqual(resp.status_code, 201)
        api_key = resp.json()["api_key"]
        self.assertIsNotNone(api_key)

        # Exchange for JWT
        resp2 = self.client.post("/auth/token", json={"api_key": api_key})
        self.assertEqual(resp2.status_code, 200)
        data = resp2.json()
        self.assertIn("token", data)
        self.assertEqual(data["org_id"], "test-org")
        self.assertEqual(data["token_type"], "bearer")

    def test_invalid_api_key_returns_401(self):
        resp = self.client.post("/auth/token", json={"api_key": "bad-key"})
        self.assertEqual(resp.status_code, 401)

    def test_create_key_wrong_admin_returns_403(self):
        resp = self.client.post(
            "/auth/keys",
            json={"org_id": "test-org"},
            headers={"X-Admin-Key": "wrong"},
        )
        self.assertEqual(resp.status_code, 403)

    def test_list_keys_admin(self):
        self.client.post(
            "/auth/keys",
            json={"org_id": "list-test-org"},
            headers=self._admin_headers(),
        )
        resp = self.client.get("/auth/keys", headers=self._admin_headers())
        self.assertEqual(resp.status_code, 200)
        entries = resp.json()
        self.assertTrue(any(e["org_id"] == "list-test-org" for e in entries))

    def test_revoke_key(self):
        resp = self.client.post(
            "/auth/keys",
            json={"org_id": "revoke-org"},
            headers=self._admin_headers(),
        )
        api_key = resp.json()["api_key"]

        # Revoke it
        rev_resp = self.client.delete(
            f"/auth/keys/{api_key}",
            headers=self._admin_headers(),
        )
        self.assertEqual(rev_resp.status_code, 204)

        # Now token exchange should fail
        token_resp = self.client.post("/auth/token", json={"api_key": api_key})
        self.assertEqual(token_resp.status_code, 401)

    def test_jobs_endpoint_requires_jwt(self):
        resp = self.client.get("/jobs")
        self.assertEqual(resp.status_code, 401)

    def test_agents_endpoint_requires_jwt(self):
        resp = self.client.get("/agents")
        self.assertEqual(resp.status_code, 401)

    def test_job_list_scoped_to_org(self):
        """Jobs created by org-a are not visible to org-b."""
        # Create API keys for two orgs
        ka_resp = self.client.post(
            "/auth/keys", json={"org_id": "org-a"}, headers=self._admin_headers()
        )
        kb_resp = self.client.post(
            "/auth/keys", json={"org_id": "org-b"}, headers=self._admin_headers()
        )
        key_a = ka_resp.json()["api_key"]
        key_b = kb_resp.json()["api_key"]

        token_a = self.client.post("/auth/token", json={"api_key": key_a}).json()["token"]
        token_b = self.client.post("/auth/token", json={"api_key": key_b}).json()["token"]

        headers_a = {"Authorization": f"Bearer {token_a}"}
        headers_b = {"Authorization": f"Bearer {token_b}"}

        # Patch submit_scan to be a no-op (we don't want actual scans)
        with patch("api.routes.jobs.submit_scan") as mock_submit:
            mock_submit.return_value = None

            # Create a job as org-a
            create_resp = self.client.post(
                "/jobs",
                json={"target": "10.0.0.1"},
                headers=headers_a,
            )
            self.assertEqual(create_resp.status_code, 202)
            job_id = create_resp.json()["job_id"]

        # org-a can see the job
        list_a = self.client.get("/jobs", headers=headers_a).json()
        self.assertTrue(any(j["job_id"] == job_id for j in list_a))

        # org-b cannot see the job
        list_b = self.client.get("/jobs", headers=headers_b).json()
        self.assertFalse(any(j["job_id"] == job_id for j in list_b))

        # org-b cannot access the job by ID
        get_resp = self.client.get(f"/jobs/{job_id}", headers=headers_b)
        self.assertEqual(get_resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()
