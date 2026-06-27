"""
Deterministic, network-free tests for src/service_prober.py and src/vuln_prober.py.

These are the most intrusive probes in NetLogic, so the guarantees under test are:

  • a genuinely vulnerable / misconfigured response IS detected,
  • a normal / secure / auth-enforced response yields NO finding
    (false-positive guards for every check type — false positives are the cardinal sin),
  • malformed / empty / timeout responses yield no finding and never crash or hang,
  • probes stay read-only / non-destructive (no STOR/DELETE/SLAVEOF/FLUSH payloads,
    Shellshock only echoes a marker, etc.).

No real sockets are opened: the low-level helpers (_tcp_send_recv, _http_get,
_raw_http) are monkeypatched to feed canned responses.
"""
import struct

import pytest

from src import service_prober as sp
from src import vuln_prober as vp


# ─── fakes ────────────────────────────────────────────────────────────────────

def _mk_port(port, service=None, tls=False):
    """Minimal stand-in for scanner.PortResult (only fields the probers read)."""
    class P:
        pass
    p = P()
    p.port = port
    p.service = service
    p.tls = tls
    return p


# ════════════════════════════════════════════════════════════════════════════
# service_prober — key/value & infra noauth checks
# ════════════════════════════════════════════════════════════════════════════

def test_redis_noauth_detected(monkeypatch):
    monkeypatch.setattr(sp, "_tcp_send_recv",
                        lambda *a, **k: b"$100\r\nredis_version:6.2.7\r\nos:Linux\r\n")
    f = sp.check_redis_noauth("h", 6379)
    assert f and f.severity == "CRITICAL" and "6.2.7" in f.detail


def test_redis_auth_enforced_no_finding(monkeypatch):
    # Redis with requirepass replies NOAUTH to INFO — must NOT be flagged.
    monkeypatch.setattr(sp, "_tcp_send_recv",
                        lambda *a, **k: b"-NOAUTH Authentication required.\r\n")
    assert sp.check_redis_noauth("h", 6379) is None


def test_redis_empty_and_garbage_no_finding(monkeypatch):
    monkeypatch.setattr(sp, "_tcp_send_recv", lambda *a, **k: None)
    assert sp.check_redis_noauth("h", 6379) is None
    monkeypatch.setattr(sp, "_tcp_send_recv", lambda *a, **k: b"\x00\xff\x01garbage")
    assert sp.check_redis_noauth("h", 6379) is None


def test_memcached_detected_and_negative(monkeypatch):
    monkeypatch.setattr(sp, "_tcp_send_recv", lambda *a, **k: b"VERSION 1.6.21\r\n")
    f = sp.check_memcached_noauth("h", 11211)
    assert f and f.severity == "CRITICAL"
    # An HTTP service mistakenly probed must not look like memcached.
    monkeypatch.setattr(sp, "_tcp_send_recv", lambda *a, **k: b"HTTP/1.1 400 Bad Request\r\n")
    assert sp.check_memcached_noauth("h", 11211) is None


def test_redis_probe_is_read_only():
    """The Redis probe must only issue read-only INFO, never a mutating command."""
    sent = {}
    def fake(host, port, data, timeout=3.0, recv=4096):
        sent["data"] = data
        return b"redis_version:7.0.0\r\n"
    import src.service_prober as m
    orig = m._tcp_send_recv
    m._tcp_send_recv = fake
    try:
        m.check_redis_noauth("h", 6379)
    finally:
        m._tcp_send_recv = orig
    payload = sent["data"].upper()
    assert b"INFO" in payload
    for danger in (b"SET", b"FLUSHALL", b"FLUSHDB", b"CONFIG SET", b"SLAVEOF", b"DEL", b"MODULE LOAD"):
        assert danger not in payload


def test_mongodb_packet_is_wellformed_and_detected(monkeypatch):
    captured = {}
    def fake(host, port, data, timeout=3.0, recv=4096):
        captured["pkt"] = data
        # canned isMaster reply (field names appear as ASCII in BSON)
        return b"\x00" * 16 + b"...ismaster...maxBsonObjectSize...localTime..." + b"\x00" * 8
    monkeypatch.setattr(sp, "_tcp_send_recv", fake)
    f = sp.check_mongodb_noauth("h", 27017)
    assert f and f.severity == "CRITICAL"
    # Regression guard: messageLength field must equal the total packet length.
    pkt = captured["pkt"]
    assert struct.unpack("<I", pkt[:4])[0] == len(pkt)


def test_mongodb_short_or_unrelated_no_finding(monkeypatch):
    monkeypatch.setattr(sp, "_tcp_send_recv", lambda *a, **k: b"short")
    assert sp.check_mongodb_noauth("h", 27017) is None
    monkeypatch.setattr(sp, "_tcp_send_recv",
                        lambda *a, **k: b"\x00" * 40 + b"no relevant keywords here at all")
    assert sp.check_mongodb_noauth("h", 27017) is None


def test_elasticsearch_detected_vs_auth(monkeypatch):
    body = '{"cluster_name":"prod","version":{"number":"7.10.0"}}'
    monkeypatch.setattr(sp, "_http_get", lambda *a, **k: (200, {}, body))
    f = sp.check_elasticsearch_noauth("h", 9200)
    assert f and f.severity == "CRITICAL" and "prod" in f.detail
    # 401 → secured → no finding
    monkeypatch.setattr(sp, "_http_get", lambda *a, **k: (401, {}, "unauthorized"))
    assert sp.check_elasticsearch_noauth("h", 9200) is None


def test_couchdb_detected_vs_secure(monkeypatch):
    monkeypatch.setattr(sp, "_http_get", lambda *a, **k: (200, {}, '["_users","mydb"]'))
    assert sp.check_couchdb_noauth("h", 5984).severity == "CRITICAL"
    monkeypatch.setattr(sp, "_http_get", lambda *a, **k: (401, {}, ""))
    assert sp.check_couchdb_noauth("h", 5984) is None


def test_docker_api_detected_vs_random_200(monkeypatch):
    monkeypatch.setattr(sp, "_http_get",
                        lambda *a, **k: (200, {}, '{"Version":"24.0.5","ApiVersion":"1.43"}'))
    assert sp.check_docker_noauth("h", 2375).severity == "CRITICAL"
    # A 200 page with no Docker keys must not flag.
    monkeypatch.setattr(sp, "_http_get", lambda *a, **k: (200, {}, "<html>hello</html>"))
    assert sp.check_docker_noauth("h", 2375) is None


def test_vault_uninitialized_vs_sealed(monkeypatch):
    monkeypatch.setattr(sp, "_http_get",
                        lambda *a, **k: (200, {}, '{"initialized":false,"sealed":true}'))
    f = sp.check_vault_noauth("h", 8200)
    assert f and f.severity == "CRITICAL"
    # Initialized + sealed → no finding (the secure baseline).
    monkeypatch.setattr(sp, "_http_get",
                        lambda *a, **k: (200, {}, '{"initialized":true,"sealed":true}'))
    assert sp.check_vault_noauth("h", 8200) is None


def test_rabbitmq_default_creds_detected_vs_rejected(monkeypatch):
    monkeypatch.setattr(sp, "_http_get",
                        lambda *a, **k: (200, {}, '{"rabbitmq_version":"3.12.0","product_name":"RabbitMQ"}'))
    assert sp.check_rabbitmq_default_creds("h", 15672).severity == "CRITICAL"
    # guest:guest rejected → 401 → no finding (false-positive guard)
    monkeypatch.setattr(sp, "_http_get", lambda *a, **k: (401, {}, ""))
    assert sp.check_rabbitmq_default_creds("h", 15672) is None


def test_ftp_anonymous_detected(monkeypatch):
    class FakeSock:
        def __init__(self):
            self._q = [b"220 ready\r\n", b"331 need password\r\n", b"230 Login successful\r\n"]
            self.sent = []
        def settimeout(self, t): pass
        def sendall(self, d): self.sent.append(d)
        def recv(self, n): return self._q.pop(0)
        def __enter__(self): return self
        def __exit__(self, *a): pass
    fs = FakeSock()
    monkeypatch.setattr(sp.socket, "create_connection", lambda *a, **k: fs)
    f = sp.check_ftp_anonymous("h", 21)
    assert f and f.severity == "HIGH"
    # read-only: must not send STOR/DELE/RMD/MKD
    joined = b" ".join(fs.sent).upper()
    for danger in (b"STOR", b"DELE", b"RMD", b"MKD", b"RNFR"):
        assert danger not in joined


def test_ftp_login_rejected_no_finding(monkeypatch):
    class FakeSock:
        def __init__(self):
            self._q = [b"220 ready\r\n", b"331 need password\r\n", b"530 Login incorrect\r\n"]
        def settimeout(self, t): pass
        def sendall(self, d): pass
        def recv(self, n): return self._q.pop(0)
        def __enter__(self): return self
        def __exit__(self, *a): pass
    monkeypatch.setattr(sp.socket, "create_connection", lambda *a, **k: FakeSock())
    assert sp.check_ftp_anonymous("h", 21) is None


# ─── http admin panel probing (false-positive surface) ──────────────────────────

def test_admin_panel_env_with_creds(monkeypatch):
    def fake(host, port, path, scheme="http", timeout=4.0):
        if path == "/.env":
            return (200, {}, "DB_PASSWORD=hunter2\nSECRET_KEY=abc")
        return (404, {}, "")
    monkeypatch.setattr(sp, "_http_get", fake)
    out = sp.check_http_admin_panels("h", 80)
    assert any(f.severity == "CRITICAL" and "/.env" in f.evidence for f in out)


def test_admin_panel_spa_catchall_no_false_critical(monkeypatch):
    """
    The cardinal-sin case: a single-page app returns HTTP 200 with a big HTML
    body for EVERY path (catch-all routing). No CRITICAL/HIGH finding may fire —
    especially not /actuator/heapdump or /graphql which previously had empty
    keyword lists and trusted a bare 200.
    """
    spa = "<!doctype html><html><head><title>My App</title></head><body>" + "x" * 500 + "</body></html>"
    monkeypatch.setattr(sp, "_http_get", lambda *a, **k: (200, {}, spa))
    out = sp.check_http_admin_panels("h", 80)
    assert not any(f.severity in ("CRITICAL", "HIGH") for f in out), \
        [(_f.title, _f.severity) for _f in out]


def test_admin_panel_heapdump_requires_hprof_magic(monkeypatch):
    def fake(host, port, path, scheme="http", timeout=4.0):
        if path == "/actuator/heapdump":
            return (200, {}, "JAVA PROFILE 1.0.2\x00\x00\x00" + "binary heap")
        return (404, {}, "")
    monkeypatch.setattr(sp, "_http_get", fake)
    out = sp.check_http_admin_panels("h", 80)
    assert any("heapdump" in f.evidence and f.severity == "CRITICAL" for f in out)


def test_admin_panel_tomcat_manager_basic_auth(monkeypatch):
    def fake(host, port, path, scheme="http", timeout=4.0):
        if path == "/manager/html":
            return (401, {}, "401 Unauthorized")
        return (404, {}, "")
    monkeypatch.setattr(sp, "_http_get", fake)
    out = sp.check_http_admin_panels("h", 80)
    # 401 challenge on manager path is itself evidence the panel exists.
    assert any("Tomcat Manager" in f.title for f in out)


def test_admin_panel_all_404_no_findings(monkeypatch):
    monkeypatch.setattr(sp, "_http_get", lambda *a, **k: (404, {}, "not found"))
    assert sp.check_http_admin_panels("h", 80) == []


def test_admin_panel_helper_returns_none_no_crash(monkeypatch):
    monkeypatch.setattr(sp, "_http_get", lambda *a, **k: None)
    assert sp.check_http_admin_panels("h", 80) == []


# ─── orchestrator ──────────────────────────────────────────────────────────────

def test_probe_services_routes_and_survives_errors(monkeypatch):
    # All checks raise-free via canned no-finding responses.
    monkeypatch.setattr(sp, "_tcp_send_recv", lambda *a, **k: None)
    monkeypatch.setattr(sp, "_http_get", lambda *a, **k: None)
    ports = [_mk_port(6379, "redis"), _mk_port(80, "http", tls=False),
             _mk_port(443, "https", tls=True)]
    res = sp.probe_services("h", ports, timeout=1.0)
    assert res.target == "h"
    assert res.probes_run >= 1
    assert res.findings == []


# ════════════════════════════════════════════════════════════════════════════
# vuln_prober — CVE probes
# ════════════════════════════════════════════════════════════════════════════

def test_apache_traversal_detected_vs_clean(monkeypatch):
    monkeypatch.setattr(vp, "_raw_http",
                        lambda *a, **k: "HTTP/1.1 200 OK\r\n\r\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:")
    f = vp.probe_apache_path_traversal("h", 80)
    assert f and f.confirmed and f.cve_id == "CVE-2021-41773"
    # Patched server returns 404 / no passwd content → no finding.
    monkeypatch.setattr(vp, "_raw_http", lambda *a, **k: "HTTP/1.1 404 Not Found\r\n\r\n")
    assert vp.probe_apache_path_traversal("h", 80) is None
    # Echoed path but no real passwd content → must not confirm.
    monkeypatch.setattr(vp, "_raw_http",
                        lambda *a, **k: "HTTP/1.1 200 OK\r\n\r\nyou requested /etc/passwd")
    assert vp.probe_apache_path_traversal("h", 80) is None


def test_apache_traversal_handles_none(monkeypatch):
    monkeypatch.setattr(vp, "_raw_http", lambda *a, **k: None)
    assert vp.probe_apache_path_traversal("h", 80) is None


def test_grafana_traversal(monkeypatch):
    monkeypatch.setattr(vp, "_http_get",
                        lambda *a, **k: (200, "root:x:0:0:root:/root:/bin/bash"))
    assert vp.probe_grafana_path_traversal("h", 3000).cve_id == "CVE-2021-43798"
    monkeypatch.setattr(vp, "_http_get", lambda *a, **k: (404, ""))
    assert vp.probe_grafana_path_traversal("h", 3000) is None


def test_shellshock_marker_required_and_safe(monkeypatch):
    seen = {}
    def fake(host, port, req, timeout=5.0):
        seen["req"] = req
        return "HTTP/1.1 200 OK\r\n\r\n\n\nNETLOGIC_SHELLSHOCK_CONFIRMED\n"
    monkeypatch.setattr(vp, "_raw_http", fake)
    f = vp.probe_shellshock("h", 80)
    assert f and f.confirmed
    # payload must only echo a marker — no destructive shell commands
    req = seen["req"].decode("latin1").lower()
    for danger in ("rm ", "cat /etc/shadow", "wget", "curl", "/bin/sh -c", "mkfifo", ";reboot"):
        assert danger not in req
    # Normal CGI output without the marker → no finding.
    monkeypatch.setattr(vp, "_raw_http", lambda *a, **k: "HTTP/1.1 200 OK\r\n\r\nhello world")
    assert vp.probe_shellshock("h", 80) is None


def test_spring_actuator_detect_vs_empty(monkeypatch):
    monkeypatch.setattr(vp, "_http_get",
                        lambda h, p, path, **k: (200, '{"propertySources":[]}') if path == "/actuator/env" else (404, ""))
    out = vp.probe_spring_actuator("h", 8080)
    assert any(p.title.startswith("Spring Boot /actuator/env") for p in out)
    # All 404 → nothing.
    monkeypatch.setattr(vp, "_http_get", lambda *a, **k: (404, ""))
    assert vp.probe_spring_actuator("h", 8080) == []


def test_phpinfo_requires_table_signature(monkeypatch):
    monkeypatch.setattr(vp, "_http_get",
                        lambda *a, **k: (200, "<html><h1>PHP Version 8.1.2</h1><table border>...</table>"))
    assert len(vp.probe_php_info_exposure("h", 80)) >= 1
    # Mentions the words but is not a phpinfo table → no finding.
    monkeypatch.setattr(vp, "_http_get",
                        lambda *a, **k: (200, "Our blog post about PHP Version upgrades"))
    assert vp.probe_php_info_exposure("h", 80) == []


def test_backup_files_requires_secret_keywords(monkeypatch):
    monkeypatch.setattr(vp, "_http_get",
                        lambda *a, **k: (200, "DB_PASSWORD=s3cret\nSECRET=abc"))
    assert any(p.severity == "CRITICAL" for p in vp.probe_backup_files("h", 80))
    # 200 but no recognizable secret content → skipped (false-positive guard).
    monkeypatch.setattr(vp, "_http_get", lambda *a, **k: (200, "just some plain text file"))
    assert vp.probe_backup_files("h", 80) == []


def test_tomcat_default_creds_vs_rejected(monkeypatch):
    def fake(host, port, path, scheme="http", timeout=5.0, headers=None):
        if headers and "Authorization" in headers:
            # accept only admin:admin
            import base64
            if base64.b64encode(b"admin:admin").decode() in headers["Authorization"]:
                return (200, "Tomcat Web Application Manager")
            return (401, "")
        return (401, "")  # unauth challenge
    monkeypatch.setattr(vp, "_http_get", fake)
    f = vp.probe_tomcat_default_creds("h", 8080)
    assert f and "admin:admin" in f.title
    # All creds rejected → no finding (no false positive from a 401 wall).
    def reject(host, port, path, scheme="http", timeout=5.0, headers=None):
        return (401, "")
    monkeypatch.setattr(vp, "_http_get", reject)
    assert vp.probe_tomcat_default_creds("h", 8080) is None


def test_open_redirect_requires_reflected_marker(monkeypatch):
    class FakeResp:
        def __init__(self, code, loc):
            self.status = code
            self.headers = {"location": loc}
    class FakeOpener:
        def open(self, req, timeout=None):
            return FakeResp(302, "https://netlogic-redirect-test.invalid/")
    monkeypatch.setattr(vp.urllib.request, "build_opener", lambda *a, **k: FakeOpener())
    f = vp.probe_open_redirect("h", 80)
    assert f and f.cve_id == "CWE-601"

    # Redirect that does NOT honor our marker (internal redirect) → no finding.
    class SafeOpener:
        def open(self, req, timeout=None):
            return FakeResp(302, "https://example.com/dashboard")
    monkeypatch.setattr(vp.urllib.request, "build_opener", lambda *a, **k: SafeOpener())
    assert vp.probe_open_redirect("h", 80) is None


def test_ghostcat_cpong_vs_silence(monkeypatch):
    class FakeSock:
        def __init__(self, resp): self._resp = resp
        def sendall(self, d): pass
        def settimeout(self, t): pass
        def recv(self, n): return self._resp
        def __enter__(self): return self
        def __exit__(self, *a): pass
    monkeypatch.setattr(vp.socket, "create_connection",
                        lambda *a, **k: FakeSock(b"\x41\x42\x00\x01\x09"))
    assert vp.probe_ghostcat("h", 8009).cve_id == "CVE-2020-1938"
    # Non-AJP / no response → no finding.
    monkeypatch.setattr(vp.socket, "create_connection",
                        lambda *a, **k: FakeSock(b"HTTP/1.1 400"))
    assert vp.probe_ghostcat("h", 8009) is None


def test_directory_listing_signature_required(monkeypatch):
    monkeypatch.setattr(vp, "_http_get",
                        lambda *a, **k: (200, "<html><title>Index of /uploads</title><a>Parent Directory</a>"))
    assert vp.probe_directory_listing("h", 80).cve_id == "CWE-548"
    monkeypatch.setattr(vp, "_http_get", lambda *a, **k: (200, "<html>normal homepage</html>"))
    assert vp.probe_directory_listing("h", 80) is None


def test_nginx_alias_traversal(monkeypatch):
    def fake(host, port, path, scheme="http", timeout=4.0):
        if path.endswith("/"):       # prefix existence check
            return (200, "ok")
        if "etc/passwd" in path:
            return (200, "root:x:0:0:root:/root:/bin/bash")
        return (404, "")
    monkeypatch.setattr(vp, "_http_get", fake)
    assert vp.probe_nginx_alias_traversal("h", 80).cve_id == "CWE-22"
    # No passwd content → no finding.
    monkeypatch.setattr(vp, "_http_get", lambda *a, **k: (200, "ok"))
    assert vp.probe_nginx_alias_traversal("h", 80) is None


def test_log4shell_passive_unconfirmed(monkeypatch):
    monkeypatch.setattr(vp, "_http_get",
                        lambda *a, **k: (500, "javax.naming.CommunicationException at com.sun.jndi.ldap"))
    f = vp.probe_log4shell_headers("h", 80)
    assert f and f.confirmed is False     # passive heuristic must stay unconfirmed
    monkeypatch.setattr(vp, "_http_get", lambda *a, **k: (200, "normal page"))
    assert vp.probe_log4shell_headers("h", 80) is None


def test_iis_shortname_requires_divergence(monkeypatch):
    # Tilde 404, invalid 400 on IIS → divergence → (unconfirmed) finding.
    def diverge(host, port, req, timeout=4.0):
        if b"/~1/" in req:
            return "HTTP/1.1 404 Not Found\r\nServer: Microsoft-IIS/10.0\r\n\r\n"
        return "HTTP/1.1 400 Bad Request\r\nServer: Microsoft-IIS/10.0\r\n\r\n"
    monkeypatch.setattr(vp, "_raw_http", diverge)
    f = vp.probe_iis_shortname("h", 80)
    assert f and f.confirmed is False
    # Same status (404) for both → secure baseline → NO finding (regression guard).
    monkeypatch.setattr(vp, "_raw_http",
                        lambda *a, **k: "HTTP/1.1 404 Not Found\r\nServer: Microsoft-IIS/10.0\r\n\r\n")
    assert vp.probe_iis_shortname("h", 80) is None


def test_probe_web_vulnerabilities_no_http_ports():
    res = vp.probe_web_vulnerabilities("h", [_mk_port(22, "ssh")], timeout=1.0)
    assert res.confirmed == []


def test_probe_web_vulnerabilities_survives_all_none(monkeypatch):
    monkeypatch.setattr(vp, "_http_get", lambda *a, **k: (None, None))
    monkeypatch.setattr(vp, "_raw_http", lambda *a, **k: None)
    # probe_open_redirect builds its own urllib opener (it does not go through
    # _http_get), so stub it out to keep this test network-free.
    class _DeadOpener:
        def open(self, *a, **k):
            raise OSError("no network in tests")
    monkeypatch.setattr(vp.urllib.request, "build_opener", lambda *a, **k: _DeadOpener())
    res = vp.probe_web_vulnerabilities("h", [_mk_port(80, "http")], timeout=1.0)
    assert res.target == "h"
    assert res.confirmed == []
    assert res.probes_run >= 1


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
