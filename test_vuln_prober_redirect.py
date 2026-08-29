"""vuln_prober must not follow off-origin HTTP redirects.

urllib.request.urlopen follows 3xx by default. A public scan target that
returns ``Location: http://169.254.169.254/...`` (or another host) would
make the agent fetch that body and confirm Tomcat / directory-listing
findings from it — scanner SSRF plus false CRITICAL results.

These tests use two local HTTP servers: origin 302s to a "metadata" host
that records hits.
"""
from __future__ import annotations

import http.server
import threading

import pytest

from src.vuln_prober import _http_get, probe_directory_listing, probe_tomcat_default_creds


def _two_servers(off_body: bytes = b"instance-id-i-0secret\nIndex of /secret\n"):
    """Origin 302s to off-origin /secret. Off-origin 200s and counts hits."""
    hits = {"secret": 0}

    class Off(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits["secret"] += 1
            self.send_response(200)
            self.send_header("Server", "imds-fake")
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(off_body)

        def log_message(self, *_a):
            return

    off = http.server.HTTPServer(("127.0.0.1", 0), Off)
    off_port = off.server_address[1]

    class Origin(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{off_port}/secret")
            self.send_header("Server", "in-scope")
            self.end_headers()

        def log_message(self, *_a):
            return

    origin = http.server.HTTPServer(("127.0.0.1", 0), Origin)
    threads = [
        threading.Thread(target=origin.serve_forever, daemon=True),
        threading.Thread(target=off.serve_forever, daemon=True),
    ]
    for t in threads:
        t.start()
    return origin, off, hits


@pytest.fixture
def redirect_pair():
    origin, off, hits = _two_servers()
    try:
        yield origin.server_address[1], hits
    finally:
        origin.shutdown()
        off.shutdown()
        origin.server_close()
        off.server_close()


def test_http_get_does_not_follow_off_origin_redirect(redirect_pair):
    origin_port, hits = redirect_pair
    status, body = _http_get("127.0.0.1", origin_port, "/", timeout=2.0)
    assert status == 302
    assert "instance-id" not in (body or "")
    assert hits["secret"] == 0


def test_tomcat_probe_does_not_confirm_from_redirect_destination(redirect_pair):
    origin_port, hits = redirect_pair
    finding = probe_tomcat_default_creds("127.0.0.1", origin_port, timeout=2.0)
    assert finding is None
    assert hits["secret"] == 0


def test_directory_listing_does_not_confirm_from_redirect_destination(redirect_pair):
    origin_port, hits = redirect_pair
    finding = probe_directory_listing("127.0.0.1", origin_port, timeout=2.0)
    assert finding is None
    assert hits["secret"] == 0


def test_http_get_still_returns_200_body():
    """A normal 200 must still be fetched (redirects are the only thing blocked)."""

    class Ok(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Server", "ok")
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"hello-target")

        def log_message(self, *_a):
            return

    srv = http.server.HTTPServer(("127.0.0.1", 0), Ok)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.server_address[1]
        status, body = _http_get("127.0.0.1", port, "/", timeout=2.0)
        assert status == 200
        assert "hello-target" in (body or "")
    finally:
        srv.shutdown()
        srv.server_close()
