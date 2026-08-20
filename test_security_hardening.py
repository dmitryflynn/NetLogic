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

    def test_localhost_blocked_in_saas(self):
        with patch.dict(os.environ, {"NETLOGIC_SAAS": "1"}, clear=False):
            with self.assertRaises(ValueError):
                ScanRequest(target="localhost")

    def test_unresolved_hostname_blocked_in_saas(self):
        with patch.dict(os.environ, {"NETLOGIC_SAAS": "1"}, clear=False):
            with patch("api.scan_policy._resolve_host_ips", return_value=set()):
                with self.assertRaises(ValueError) as ctx:
                    ScanRequest(target="definitely-not-a-real-host.invalid")
                self.assertIn("could not be resolved", str(ctx.exception).lower())


class TestLlmBaseUrlSsrf(unittest.TestCase):
    """Tenant-controlled LLM URLs must not turn the API into an SSRF relay."""

    def test_desktop_allows_local_ollama(self):
        with patch("api.scan_policy.saas_scan_restrictions_enabled", return_value=False):
            req = ScanRequest(target="example.com", ai_base_url="http://127.0.0.1:11434/v1")
            self.assertEqual(req.ai_base_url, "http://127.0.0.1:11434/v1")
            req = ScanRequest(target="example.com", ai_base_url="http://10.0.0.5:11434/v1")
            self.assertEqual(req.ai_base_url, "http://10.0.0.5:11434/v1")

    def test_desktop_blocks_metadata_http(self):
        with patch("api.scan_policy.saas_scan_restrictions_enabled", return_value=False):
            for url in (
                "http://169.254.169.254/",
                "http://169.254.169.254/latest/meta-data/",
                "http://[::ffff:169.254.169.254]/",
                "https://169.254.169.254/",
                "https://metadata.google.internal/",
            ):
                with self.assertRaises(ValueError):
                    ScanRequest(target="example.com", ai_base_url=url)

    def test_saas_blocks_http_and_internal_https(self):
        with patch.dict(os.environ, {"NETLOGIC_SAAS": "1"}, clear=False):
            for url in (
                "http://127.0.0.1:11434/v1",
                "http://10.0.0.5:11434/v1",
                "http://169.254.169.254/",
                "https://169.254.169.254/",
                "https://127.0.0.1/",
                "https://10.0.0.1/v1",
                "https://metadata.google.internal/",
            ):
                with self.assertRaises(ValueError):
                    ScanRequest(target="8.8.8.8", ai_base_url=url)

    def test_saas_allows_public_https(self):
        with patch.dict(os.environ, {"NETLOGIC_SAAS": "1"}, clear=False):
            req = ScanRequest(
                target="8.8.8.8",
                ai_base_url="https://openrouter.ai/api/v1",
            )
            self.assertEqual(req.ai_base_url, "https://openrouter.ai/api/v1")


class TestLlmHttpNoRedirect(unittest.TestCase):
    def test_http_post_does_not_follow_redirects(self):
        """A 302 to another path must not be fetched (redirect SSRF)."""
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer

        import urllib.error

        from src.ai_analyst import _http_post

        hits = {"redirect": 0, "secret": 0}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                if self.path.startswith("/secret"):
                    hits["secret"] += 1
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"ok":true}')
                    return
                hits["redirect"] += 1
                self.send_response(302)
                self.send_header(
                    "Location",
                    "http://127.0.0.1:%s/secret" % self.server.server_address[1],
                )
                self.end_headers()

            def log_message(self, format, *args):  # noqa: A003
                return

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                _http_post(
                    f"http://127.0.0.1:{port}/start",
                    {"Content-Type": "application/json"},
                    {"model": "x", "messages": []},
                    timeout=2.0,
                )
            self.assertEqual(ctx.exception.code, 302)
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(hits["redirect"], 1)
        self.assertEqual(hits["secret"], 0)


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
