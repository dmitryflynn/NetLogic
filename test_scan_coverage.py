"""
Scan accuracy & thoroughness coverage (the improvements that broaden what a scan
finds and how precisely it versions services).

  • the 'full' preset is a superset of 'quick' and covers CVE-dense long-tail ports,
  • SERVICE_MAP names the new ports so they get the right probe,
  • banner patterns extract versions for newly-reached services,
  • UDP fingerprinting covers NetBIOS + SSDP,
  • the generic HTTP second-chance probe recovers web apps on non-standard ports
    (previously "open/unknown/no version" → no CVE correlation).
"""
import socket
import threading
import http.server
import socketserver
import time

import pytest

from src import scanner
from src.cve_correlator import extract_product_version


class _B:
    def __init__(self, raw):
        self.raw = raw
        self.product = None


# ── Thoroughness: port + service coverage ───────────────────────────────────────

def test_full_preset_is_superset_of_quick():
    assert set(scanner.COMMON_PORTS) <= set(scanner.EXTENDED_PORTS)
    assert len(scanner.EXTENDED_PORTS) == len(set(scanner.EXTENDED_PORTS))  # no dups


@pytest.mark.parametrize("port,service", [
    (7001, "weblogic"), (8009, "ajp"), (389, "ldap"), (2049, "nfs"),
    (1099, "java-rmi"), (10000, "webmin"), (10250, "kubelet"), (5985, "winrm"),
])
def test_service_map_covers_cve_dense_ports(port, service):
    assert scanner.SERVICE_MAP.get(port) == service


def test_http_panels_get_http_probed():
    # Long-tail admin panels must be HTTP-probed so a version can be recovered.
    for svc in ("weblogic", "activemq", "webmin", "kubelet"):
        assert svc in scanner.HTTP_SERVICES


# ── Accuracy: banner → product/version ──────────────────────────────────────────

@pytest.mark.parametrize("raw,product,version", [
    ("Server: ActiveMQ/5.15.0", "activemq", "5.15.0"),
    ("Server: MiniServ/1.890", "webmin", "1.890"),
    ("WebLogic Server 12.2.1.3", "weblogic", "12.2.1.3"),
])
def test_new_banner_patterns_extract(raw, product, version):
    p, v = extract_product_version(_B(raw))
    assert p == product and v == version


@pytest.mark.parametrize("raw,product", [
    ("HTTP/1.1 200\r\nSet-Cookie: NSC_AAAA=x; path=/", "netscaler"),     # Citrix
    ("HTTP/1.1 200\r\nSet-Cookie: SVPNCOOKIE=abc", "fortios"),           # Fortinet
    ("HTTP/1.1 200\r\nSet-Cookie: BIGipServerp=1", "big-ip"),            # F5
    ("HTTP/1.1 302\r\nLocation: /dana-na/auth/welcome.cgi", "pulse-connect-secure"),  # Ivanti/Pulse
    ("<title>GlobalProtect Portal</title>", "pan-os"),                  # Palo Alto
])
def test_edge_device_fingerprints(raw, product):
    # The most-exploited (KEV-heavy) edge/VPN appliances are identified by their
    # distinctive cookie/path/product markers even when the Server header is hidden.
    p, _ = extract_product_version(_B(raw))
    assert p == product


def test_edge_fingerprints_do_not_false_positive_on_plain_servers():
    # A vanilla nginx/Apache must NOT be reclassified as an edge appliance.
    assert extract_product_version(_B("Server: nginx/1.24.0"))[0] == "nginx"
    assert extract_product_version(_B("Server: Apache/2.4.58"))[0] == "apache"


# ── Thoroughness: UDP coverage ──────────────────────────────────────────────────

def test_udp_probes_cover_netbios_and_ssdp():
    # These ports are recognised probe targets; the function returns None (no
    # answer) or a (proto, detail) tuple — never a KeyError / unprobed path.
    for p in (53, 123, 161, 137, 1900):
        res = scanner.probe_udp_protocol("127.0.0.1", p, timeout=0.2)
        assert res is None or (isinstance(res, tuple) and len(res) == 2)


def test_snmp_sysdescr_extracted_for_cve_correlation():
    # A synthetic SNMP GET-RESPONSE carrying sysDescr.0 = a versioned device
    # string must be parsed out (→ version-confirmed CVE correlation).
    sysdescr = b"Cisco IOS Software, Version 15.1(4)M"
    # OID 1.3.6.1.2.1.1.1.0 followed by OCTET STRING value.
    pkt = bytes.fromhex("06082b06010201010100") + b"\x04" + bytes([len(sysdescr)]) + sysdescr
    assert scanner._snmp_sysdescr(pkt) == "Cisco IOS Software, Version 15.1(4)M"
    assert scanner._snmp_sysdescr(b"no oid here") is None


@pytest.mark.parametrize("pkt", [
    bytes.fromhex("06082b06010201010100"),                      # OID at very end (no value)
    bytes.fromhex("06082b06010201010100") + b"\x04",           # tag but no length byte
    bytes.fromhex("06082b06010201010100") + b"\x04\x81",       # long-form len, no len bytes
    bytes.fromhex("06082b06010201010100") + b"\x04\xff",       # claims 255 bytes, none present
    b"",
])
def test_snmp_sysdescr_is_crash_safe_on_malformed_input(pkt):
    # Untrusted network input must never raise (the OID-as-last-byte case used to
    # IndexError on resp[j+1]).
    assert scanner._snmp_sysdescr(pkt) in (None, "")  # never raises, no garbage


# ── Accuracy+thoroughness: generic HTTP second-chance probe ─────────────────────

def test_second_chance_http_probe_detects_web_app_on_odd_port():
    class H(http.server.BaseHTTPRequestHandler):
        server_version = "CoverageSrv/4.2.1"
        def do_GET(self):
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        def log_message(self, *a): pass

    # Bind an ephemeral port that is NOT in SERVICE_MAP (so service starts "unknown").
    srv = socketserver.TCPServer(("127.0.0.1", 0), H)
    srv.allow_reuse_address = True
    port = srv.server_address[1]
    assert port not in scanner.SERVICE_MAP
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.2)
    try:
        r = scanner.probe_port("127.0.0.1", port, timeout=2.0)
    finally:
        srv.shutdown()
    assert r.state == "open"
    assert r.service in ("http", "https")                 # reclassified
    assert r.banner and r.banner.version == "4.2.1"       # version recovered → CVE-correlatable
    assert r.detection_confidence == "high"
