"""Tests for security hardening fixes (credential redaction, SaaS scan policy, JWT revocation)."""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from api.models.scan_request import ScanRequest


class TestCredentialRedaction(unittest.TestCase):
    def test_public_dump_masks_ai_key_and_ssh_pass(self):
        req = ScanRequest(
            target="example.com",
            do_ai=True,
            ai_provider="openai",
            ai_key="ai-secret",
            ssh_user="admin",
            ssh_pass="ssh-secret",
        )
        pub = req.public_dump()
        self.assertEqual(pub["ai_key"], "**********")
        self.assertEqual(pub["ssh_pass"], "**********")
        self.assertEqual(pub["ssh_user"], "admin")

    def test_persisted_dump_strips_secrets(self):
        req = ScanRequest(
            target="example.com",
            ai_key="ai-secret",
            ssh_pass="ssh-secret",
        )
        persisted = req.persisted_dump()
        self.assertEqual(persisted["ai_key"], "")
        self.assertEqual(persisted["ssh_pass"], "")

    def test_task_dump_keeps_live_credentials(self):
        req = ScanRequest(
            target="example.com",
            ai_key="ai-secret",
            ssh_pass="ssh-secret",
        )
        task = req.task_dump()
        self.assertEqual(task["ai_key"], "ai-secret")
        self.assertEqual(task["ssh_pass"], "ssh-secret")


class TestSaasScanPolicy(unittest.TestCase):
    def test_private_ip_blocked_when_saas_flag_set(self):
        with patch.dict(os.environ, {"NETLOGIC_SAAS": "1"}, clear=False):
            with self.assertRaises(ValueError) as ctx:
                ScanRequest(target="10.0.0.5")
            self.assertIn("hosted mode", str(ctx.exception).lower())

    def test_public_target_allowed_when_saas_flag_set(self):
        with patch.dict(os.environ, {"NETLOGIC_SAAS": "1"}, clear=False):
            req = ScanRequest(target="scanme.nmap.org")
            self.assertEqual(req.target, "scanme.nmap.org")

    def test_private_ip_allowed_when_restrictions_off(self):
        with patch.dict(os.environ, {"NETLOGIC_SAAS": "", "NETLOGIC_DATABASE_URL": ""}, clear=False):
            with patch("api.scan_policy.saas_scan_restrictions_enabled", return_value=False):
                req = ScanRequest(target="192.168.1.1")
                self.assertEqual(req.target, "192.168.1.1")

    def test_metadata_hostname_blocked(self):
        with patch.dict(os.environ, {"NETLOGIC_SAAS": "1"}, clear=False):
            with self.assertRaises(ValueError):
                ScanRequest(target="metadata.google.internal")


class TestJwtRevocation(unittest.TestCase):
    def setUp(self):
        from api.auth import jwt_handler as j
        from api.auth import token_revocation as tr
        self.j = j
        self.tr = tr
        tr.reset_for_tests()

    def test_revoked_token_rejected(self):
        tok = self.j.create_token(org_id="acme", sub="k")
        claims = self.j.verify_token(tok)
        self.assertIsNotNone(claims)
        self.assertIn("jti", claims)
        self.tr.revoke_token(claims["jti"], claims["exp"])
        self.assertIsNone(self.j.verify_token(tok))

    def test_new_tokens_carry_jti(self):
        tok = self.j.create_token(org_id="acme", sub="k")
        claims = self.j.verify_token(tok)
        self.assertTrue(claims["jti"])


class TestLicenseProduction(unittest.TestCase):
    def test_nl_stub_disabled_in_production(self):
        from api.auth import license as lic
        with patch.dict(os.environ, {"NETLOGIC_ENV": "production", "NETLOGIC_VALID_LICENSES": ""}, clear=False):
            self.assertIsNone(lic.validate_license_key("NL-dev-test-key-12345"))

    def test_nl_stub_works_in_dev(self):
        from api.auth import license as lic
        with patch.dict(os.environ, {"NETLOGIC_ENV": "development", "NETLOGIC_VALID_LICENSES": ""}, clear=False):
            result = lic.validate_license_key("NL-dev-test-key-12345")
            self.assertIsNotNone(result)
            self.assertTrue(result.get("valid"))


if __name__ == "__main__":
    unittest.main()
