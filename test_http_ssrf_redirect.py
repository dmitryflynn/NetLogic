"""Off-origin HTTP redirects must not be followed by target-facing fetchers.

urllib.request.urlopen follows 3xx by default. A public scan target that
returns ``Location: http://169.254.169.254/...`` (or another host) would
make the agent connect there — scanner SSRF. These tests use two local
HTTP servers: origin 302s to a "metadata" host that records hits.
"""
from __future__ import annotations

import http.server
import threading

import pytest

from src.header_audit import fetch_headers
from src.http_fetch import urlopen_no_redirect
from src.service_enum import probe_http_auth_state
from src.service_prober import _http_get
from src.stack_fingerprint import _fetch
from src.web_fingerprint import _get


def _two_servers():
    """Origin 302s to off-origin /secret. Off-origin 200s and counts hits."""
    hits = {"secret": 0}

    class Off(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits["secret"] += 1
            self.send_response(200)
            self.send_header("Server", "imds-fake")
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"instance-id-i-0secret")

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


def test_urlopen_no_redirect_does_not_fetch_destination(redirect_pair):
    import urllib.error
    import urllib.request

    origin_port, hits = redirect_pair
    req = urllib.request.Request(f"http://127.0.0.1:{origin_port}/")
    with pytest.raises(urllib.error.HTTPError) as ctx:
        urlopen_no_redirect(req, timeout=2.0)
    assert ctx.value.code == 302
    assert hits["secret"] == 0


def test_fetch_headers_does_not_follow_off_origin_redirect(redirect_pair):
    origin_port, hits = redirect_pair
    headers, status = fetch_headers(f"http://127.0.0.1:{origin_port}/", timeout=2.0)
    assert status == 302
    assert "in-scope" in (headers.get("server") or "")
    assert "instance-id" not in headers.get("_body_snippet", "")
    assert hits["secret"] == 0


def test_stack_fingerprint_does_not_follow_off_origin_redirect(redirect_pair):
    origin_port, hits = redirect_pair
    headers, body, status = _fetch(f"http://127.0.0.1:{origin_port}/", timeout=2.0)
    assert status == 302
    assert "imds-fake" not in (headers.get("server") or "")
    assert "instance-id" not in (body or "")
    assert hits["secret"] == 0


def test_service_prober_http_get_does_not_follow_off_origin_redirect(redirect_pair):
    origin_port, hits = redirect_pair
    result = _http_get("127.0.0.1", origin_port, "/", timeout=2.0)
    assert result is not None
    status, hdrs, body = result
    assert status == 302
    assert "instance-id" not in (body or "")
    assert hits["secret"] == 0


def test_web_fingerprint_get_does_not_follow_off_origin_redirect(redirect_pair):
    origin_port, hits = redirect_pair
    status, body = _get(f"http://127.0.0.1:{origin_port}/", timeout=2.0)
    assert status == 302
    assert "instance-id" not in (body or "")
    assert hits["secret"] == 0


def test_service_enum_does_not_classify_redirect_destination_as_open(redirect_pair):
    """302 to another host must not be fetched; must not look 'open' from the 200."""
    origin_port, hits = redirect_pair
    attrs = probe_http_auth_state("127.0.0.1", origin_port, scheme="http", timeout=2.0)
    assert hits["secret"] == 0
    values = {a.value for a in attrs}
    assert "open" not in values


def test_fetch_headers_still_returns_200_body():
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
        headers, status = fetch_headers(f"http://127.0.0.1:{port}/", timeout=2.0)
        assert status == 200
        assert "ok" in (headers.get("server") or "")
        assert "hello-target" in headers.get("_body_snippet", "")
    finally:
        srv.shutdown()
        srv.server_close()
