"""
Deterministic, offline tests for src/topology.py.

NO real network or subprocess: every external chokepoint is monkeypatched —
  * subprocess.run        → canned Windows AND Unix traceroute stdout
  * socket.gethostbyname  → canned target IP
  * socket.gethostbyaddr  → canned / failing reverse DNS
  * socket.getaddrinfo    → canned / failing IPv6
  * urllib.request.urlopen→ canned / malformed / failing ip-api.com response

Focus areas (per audit):
  * Hop extraction is correct for both OSes (latency columns are NOT mistaken
    for hop IPs; the trailing token is the hop address).
  * hop_count semantics: equals path depth to the last RESPONDING hop, with
    interior "*" counted and trailing "*" trimmed.
  * A traceroute that only times out (all "*") fails soft — no hops, a clear
    note, never raises.
  * ASN parsing survives missing fields, a non-success status, malformed JSON,
    and a hard urllib failure.
  * map_topology returns a valid Topology on total failure with no crash, and
    every field degrades to None/empty.
"""

import subprocess

import pytest

import src.topology as topo_mod
from src.topology import Topology, map_topology, _parse_traceroute, _traceroute


# ─── canned traceroute output ────────────────────────────────────────────────

WIN_OK = """
Tracing route to example.com [93.184.216.34]
over a maximum of 8 hops:

  1     1 ms     1 ms     1 ms  192.168.1.1
  2     8 ms     9 ms     7 ms  10.0.0.1
  3     *        *        *     Request timed out.
  4    22 ms    21 ms    20 ms  93.184.216.34

Trace complete.
"""

UNIX_OK = """traceroute to example.com (93.184.216.34), 8 hops max, 60 byte packets
 1  192.168.1.1  0.512 ms  0.480 ms  0.470 ms
 2  10.0.0.1  8.1 ms  9.0 ms  7.2 ms
 3  * * *
 4  93.184.216.34  21.3 ms  20.9 ms  20.1 ms
"""

# Path that reaches the target early, then the OS pads with non-responders.
WIN_TRAILING_STARS = """
Tracing route to example.com [93.184.216.34]
over a maximum of 8 hops:

  1     1 ms     1 ms     1 ms  192.168.1.1
  2    20 ms    20 ms    20 ms  93.184.216.34
  3     *        *        *     Request timed out.
  4     *        *        *     Request timed out.
"""

ALL_STARS = """
Tracing route to example.com [93.184.216.34]
over a maximum of 8 hops:

  1     *        *        *     Request timed out.
  2     *        *        *     Request timed out.

Trace complete.
"""


# ─── parser unit tests ───────────────────────────────────────────────────────

def test_parse_windows_hops():
    hops = _parse_traceroute(WIN_OK)
    # Latency "ms" columns must NOT be picked up as IPs.
    assert hops == ["192.168.1.1", "10.0.0.1", "*", "93.184.216.34"]


def test_parse_unix_hops():
    hops = _parse_traceroute(UNIX_OK)
    assert hops == ["192.168.1.1", "10.0.0.1", "*", "93.184.216.34"]


def test_parse_trims_trailing_stars():
    hops = _parse_traceroute(WIN_TRAILING_STARS)
    # Trailing "*" padding after the target answered is removed.
    assert hops == ["192.168.1.1", "93.184.216.34"]


def test_parse_all_stars_is_empty():
    assert _parse_traceroute(ALL_STARS) == []


def test_parse_empty_and_garbage():
    assert _parse_traceroute("") == []
    assert _parse_traceroute("no hop lines here\njust text") == []


# ─── _traceroute fail-soft tests ─────────────────────────────────────────────

def _fake_run(stdout):
    def run(cmd, **kw):
        # overall timeout must be generously bounded (path depth * probes * wait)
        assert kw.get("timeout") and kw["timeout"] >= 8 * 3 * 0.6
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")
    return run


def test_traceroute_timeout_fails_soft(monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="tracert", timeout=1)
    monkeypatch.setattr(topo_mod.subprocess, "run", boom)
    assert _traceroute("example.com") == []


def test_traceroute_missing_binary_fails_soft(monkeypatch):
    def boom(*a, **k):
        raise OSError("traceroute: command not found")
    monkeypatch.setattr(topo_mod.subprocess, "run", boom)
    assert _traceroute("example.com") == []


def test_traceroute_parses_run_output(monkeypatch):
    monkeypatch.setattr(topo_mod.subprocess, "run", _fake_run(UNIX_OK))
    assert _traceroute("example.com") == ["192.168.1.1", "10.0.0.1", "*", "93.184.216.34"]


# ─── ip-api.com (_asn_lookup) robustness ─────────────────────────────────────

class _FakeResp:
    def __init__(self, body: bytes):
        self._body = body
    def read(self):
        return self._body
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False


def _patch_urlopen(monkeypatch, body=None, exc=None, capture=None):
    import urllib.request
    def fake(req, timeout=None):
        if capture is not None:
            capture["url"] = req.full_url
            capture["timeout"] = timeout
        if exc is not None:
            raise exc
        return _FakeResp(body)
    monkeypatch.setattr(urllib.request, "urlopen", fake)


def test_asn_success(monkeypatch):
    body = b'{"status":"success","country":"United States","isp":"Edgecast","org":"EdgeCast Networks","as":"AS15133 Edgecast"}'
    cap = {}
    _patch_urlopen(monkeypatch, body=body, capture=cap)
    asn, org, country = topo_mod._asn_lookup("93.184.216.34", timeout=5.0)
    assert asn == "AS15133 Edgecast"
    assert org == "EdgeCast Networks"
    assert country == "United States"
    # Confirm ONLY the target IP is sent to the third party, nothing else.
    assert "93.184.216.34" in cap["url"]
    assert cap["url"].startswith("https://ip-api.com/json/")
    assert cap["timeout"] == 5.0


def test_asn_missing_fields(monkeypatch):
    # status success but org/as absent → org falls back to isp, missing → None.
    _patch_urlopen(monkeypatch, body=b'{"status":"success","isp":"SomeISP"}')
    asn, org, country = topo_mod._asn_lookup("1.2.3.4")
    assert asn is None
    assert org == "SomeISP"
    assert country is None


def test_asn_status_fail(monkeypatch):
    _patch_urlopen(monkeypatch, body=b'{"status":"fail","message":"reserved range"}')
    assert topo_mod._asn_lookup("10.0.0.1") == (None, None, None)


def test_asn_malformed_json(monkeypatch):
    _patch_urlopen(monkeypatch, body=b'this is not json <<<')
    assert topo_mod._asn_lookup("1.2.3.4") == (None, None, None)


def test_asn_network_failure(monkeypatch):
    _patch_urlopen(monkeypatch, exc=OSError("connection refused"))
    assert topo_mod._asn_lookup("1.2.3.4") == (None, None, None)


def test_asn_empty_ip_no_call(monkeypatch):
    # Should short-circuit and never hit the network.
    def fail(*a, **k):
        raise AssertionError("urlopen must not be called for empty ip")
    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", fail)
    assert topo_mod._asn_lookup("") == (None, None, None)


# ─── map_topology integration (all I/O faked) ────────────────────────────────

def _patch_all(monkeypatch, *, ghbn=None, ghba=None, ipv6=None,
               trace=UNIX_OK, asn=("AS1", "Org", "US")):
    import socket
    if ghbn is not None:
        monkeypatch.setattr(socket, "gethostbyname", lambda t: ghbn)
    if ghba is not None:
        monkeypatch.setattr(socket, "gethostbyaddr", ghba)
    if ipv6 is not None:
        monkeypatch.setattr(socket, "getaddrinfo", ipv6)
    monkeypatch.setattr(topo_mod, "_asn_lookup", lambda ip, timeout=5.0: asn)
    monkeypatch.setattr(topo_mod.subprocess, "run",
                        _fake_run(trace) if trace is not None else None)


def test_map_topology_full(monkeypatch):
    import socket
    _patch_all(
        monkeypatch,
        ghba=lambda ip: ("host.example.com", [], [ip]),
        ipv6=lambda *a, **k: [(socket.AF_INET6, None, None, "", ("2606:2800::1", 0, 0, 0))],
        trace=WIN_OK,
    )
    t = map_topology("example.com", "93.184.216.34")
    assert isinstance(t, Topology)
    assert t.ip == "93.184.216.34"
    assert t.ptr == "host.example.com"
    assert t.asn == "AS1" and t.asn_org == "Org" and t.country == "US"
    assert t.ipv6 == ["2606:2800::1"]
    assert t.traceroute_hops == ["192.168.1.1", "10.0.0.1", "*", "93.184.216.34"]
    # hop_count = path depth (4), 3 responders. Private (192.168/10.x) hops are annotated
    # as scanner-path, then the public hop toward the target.
    assert t.hop_count == 4
    assert any("local/scanner hop" in n for n in t.notes)
    assert any("IPv6 reachable" in n for n in t.notes)


def test_map_topology_all_stars_traceroute_fails_soft(monkeypatch):
    _patch_all(
        monkeypatch,
        ghba=lambda ip: (_ for _ in ()).throw(OSError()),
        ipv6=lambda *a, **k: (_ for _ in ()).throw(OSError()),
        trace=ALL_STARS,
    )
    t = map_topology("example.com", "93.184.216.34")
    assert t.traceroute_hops == []
    assert t.hop_count is None
    assert any("not traceable" in n for n in t.notes)


def test_map_topology_total_failure(monkeypatch):
    import socket
    # Resolution fails, no ip passed, every probe raises.
    monkeypatch.setattr(socket, "gethostbyname",
                        lambda t: (_ for _ in ()).throw(socket.gaierror()))
    monkeypatch.setattr(socket, "gethostbyaddr",
                        lambda ip: (_ for _ in ()).throw(OSError()))
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: (_ for _ in ()).throw(OSError()))
    monkeypatch.setattr(topo_mod, "_asn_lookup",
                        lambda ip, timeout=5.0: (None, None, None))
    def boom(*a, **k):
        raise OSError("no traceroute")
    monkeypatch.setattr(topo_mod.subprocess, "run", boom)

    t = map_topology("nonexistent.invalid")
    assert isinstance(t, Topology)
    assert t.ip is None
    assert t.ptr is None
    assert t.asn is None and t.asn_org is None and t.country is None
    assert t.ipv6 == []
    assert t.traceroute_hops == []
    assert t.hop_count is None


def test_map_topology_skips_traceroute_when_disabled(monkeypatch):
    def fail(*a, **k):
        raise AssertionError("traceroute must not run when do_traceroute=False")
    monkeypatch.setattr(topo_mod.subprocess, "run", fail)
    monkeypatch.setattr(topo_mod, "_asn_lookup", lambda ip, timeout=5.0: (None, None, None))
    import socket
    monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: (_ for _ in ()).throw(OSError()))
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: (_ for _ in ()).throw(OSError()))
    t = map_topology("example.com", "1.2.3.4", do_traceroute=False)
    assert t.traceroute_hops == []
    assert t.hop_count is None
