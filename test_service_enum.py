"""
Deterministic, network-free tests for src/service_enum.py.

These drive the binary protocol parsers with crafted byte buffers (valid,
truncated, and garbage) and monkeypatch sockets with a fake that returns canned
bytes for the socket-facing probes. The central guarantees under test:

  • correct attribute on a valid response,
  • NO attribute (no false exploit precondition) on negative/garbage/truncated input,
  • no crash / no hang on malformed input.
"""
import socket
import struct

import pytest

from src import service_enum as se


# ─── helpers to build canned protocol responses ──────────────────────────────────

def _ssh_namelist(s: str) -> bytes:
    b = s.encode()
    return struct.pack(">I", len(b)) + b


def build_ssh_kexinit(banner: bytes, kex, hostkeys, enc_c2s, enc_s2c, macs_c2s, macs_s2c) -> bytes:
    payload = b"\x14" + b"\x00" * 16            # SSH_MSG_KEXINIT + 16-byte cookie
    for nlist in (kex, hostkeys, enc_c2s, enc_s2c, macs_c2s, macs_s2c,
                  "none", "none", "", ""):       # + comp c2s/s2c, lang c2s/s2c
        payload += _ssh_namelist(nlist)
    payload += b"\x00" + b"\x00" * 4            # first_kex_packet_follows + reserved
    pad = b"\x00" * 5
    pkt_len = 1 + len(payload) + len(pad)        # padding_length byte + payload + padding
    pkt = struct.pack(">I", pkt_len) + bytes([len(pad)]) + payload + pad
    return banner + pkt


def build_rdp_cc(neg_type: int, selected_protocol: int) -> bytes:
    # TPKT(4) + X.224 CC(7) + RDP_NEG structure(8); selectedProtocol uint32-LE @15.
    body = (b"\x03\x00\x00\x13"                  # TPKT, total length 19
            b"\x0e\xd0\x00\x00\x12\x34\x00")      # X.224 Connection Confirm
    body += bytes([neg_type, 0x00]) + struct.pack("<H", 8) + struct.pack("<I", selected_protocol)
    return body


def build_snmp_response(community: str, version: int = 0, pdu_type: int = 0xa2) -> bytes:
    c = community.encode()
    pdu = bytes([pdu_type, 0x02, 0x02, 0x01, 0x00])   # short, content irrelevant to acceptance check
    body = bytes([0x02, 0x01, version]) + bytes([0x04, len(c)]) + c + pdu
    return bytes([0x30, len(body)]) + body


# ─── SSH parser ──────────────────────────────────────────────────────────────────

def test_ssh_valid_detects_weak_algorithms():
    data = build_ssh_kexinit(
        b"SSH-2.0-OpenSSH_7.4\r\n",
        kex="diffie-hellman-group14-sha1,curve25519-sha256",   # one weak
        hostkeys="ssh-rsa,rsa-sha2-256",                        # ssh-rsa weak
        enc_c2s="aes128-cbc,aes256-gcm@openssh.com",            # cbc weak
        enc_s2c="aes256-gcm@openssh.com",
        macs_c2s="hmac-md5,hmac-sha2-256",                      # md5 weak
        macs_s2c="hmac-sha2-256",
    )
    attrs = se._parse_ssh_kexinit(data, b"SSH-2.0-OpenSSH_7.4\r\n", 22)
    keys = {a.attribute for a in attrs}
    assert "ssh_weak_kex" in keys
    assert "ssh_weak_cipher" in keys
    assert "ssh_weak_mac" in keys
    assert "ssh_weak_hostkey" in keys
    assert "ssh_algorithms" in keys


def test_ssh_strong_only_no_weak_precondition():
    data = build_ssh_kexinit(
        b"SSH-2.0-OpenSSH_9.6\r\n",
        kex="curve25519-sha256",
        hostkeys="ssh-ed25519",
        enc_c2s="aes256-gcm@openssh.com",
        enc_s2c="aes256-gcm@openssh.com",
        macs_c2s="hmac-sha2-256",
        macs_s2c="hmac-sha2-256",
    )
    attrs = se._parse_ssh_kexinit(data, b"SSH-2.0-OpenSSH_9.6\r\n", 22)
    keys = {a.attribute for a in attrs}
    assert "ssh_weak_kex" not in keys
    assert "ssh_weak_cipher" not in keys
    assert "ssh_weak_mac" not in keys
    assert "ssh_weak_hostkey" not in keys
    # The informational surface attr is still emitted.
    assert "ssh_algorithms" in keys


def test_ssh_v1_banner_flagged():
    attrs = se._parse_ssh_kexinit(b"SSH-1.99-foo\r\n", b"SSH-1.99-foo\r\n", 22)
    assert any(a.attribute == "ssh_protocol" and a.value == "SSHv1" for a in attrs)


def test_ssh_truncated_kexinit_no_crash_no_weak():
    # Banner present but the KEXINIT is cut off mid-name-list.
    full = build_ssh_kexinit(b"SSH-2.0-x\r\n", "aes128-cbc", "ssh-rsa",
                             "aes128-cbc", "aes128-cbc", "hmac-md5", "hmac-md5")
    truncated = full[:len(b"SSH-2.0-x\r\n") + 10]
    attrs = se._parse_ssh_kexinit(truncated, b"SSH-2.0-x\r\n", 22)
    # No KEXINIT recognised → no weak-crypto attributes asserted.
    assert all(a.attribute not in ("ssh_weak_cipher", "ssh_weak_mac",
                                   "ssh_weak_hostkey", "ssh_algorithms") for a in attrs)


def test_ssh_garbage_no_crash():
    for buf in (b"", b"\x00" * 3, b"not ssh at all", b"\xff" * 200):
        attrs = se._parse_ssh_kexinit(buf, buf, 22)
        assert isinstance(attrs, list)  # never raises


def test_ssh_namelist_bounds_checked():
    # Length field claims 1000 bytes but buffer is short → slice-safe, no raise.
    buf = struct.pack(">I", 1000) + b"abc"
    items, off = se._ssh_namelist(buf, 0)
    assert isinstance(items, list)


# ─── SMB parser ──────────────────────────────────────────────────────────────────

def test_smb_negotiate_packet_is_wellformed():
    pkt = se._SMB1_NEGOTIATE
    assert pkt[3] == len(pkt) - 4            # NetBIOS length matches SMB body
    assert pkt[4:8] == b"\xffSMB"
    assert len(pkt) - 4 == 47                # 32-byte header + wordcount + bytecount + dialect


def test_smb_smbv1_reply_detected():
    resp = b"\x00\x00\x00\x55" + b"\xffSMB" + b"\x72" + b"\x00" * 40
    assert se._smb_response_is_smbv1(resp) is True


def test_smb_smb2_reply_not_flagged():
    resp = b"\x00\x00\x00\x55" + b"\xfeSMB" + b"\x40" + b"\x00" * 40  # SMB2 magic
    assert se._smb_response_is_smbv1(resp) is False


def test_smb_truncated_and_garbage_no_false_precondition():
    for resp in (b"", b"\x00\x00", b"\x00\x00\x00\x04\xffS", b"random bytes here"):
        assert se._smb_response_is_smbv1(resp) is False


# ─── RDP parser ──────────────────────────────────────────────────────────────────

def test_rdp_nla_required():
    resp = build_rdp_cc(neg_type=0x02, selected_protocol=0x02)  # PROTOCOL_HYBRID
    attrs = se._parse_rdp_negotiation(resp, 3389)
    assert any(a.attribute == "rdp_nla" and a.value == "required" for a in attrs)
    # Must NOT assert the BlueKeep precondition when NLA is required.
    assert not any("CVE-2019-0708" in a.exploit_precondition_for for a in attrs)


def test_rdp_nla_not_required_is_bluekeep_precondition():
    resp = build_rdp_cc(neg_type=0x02, selected_protocol=0x00)  # PROTOCOL_RDP only
    attrs = se._parse_rdp_negotiation(resp, 3389)
    assert any(a.attribute == "rdp_nla" and a.value == "not_required" for a in attrs)
    assert any("CVE-2019-0708" in a.exploit_precondition_for for a in attrs)


def test_rdp_negotiation_failure_is_enforced():
    resp = build_rdp_cc(neg_type=0x03, selected_protocol=0x00)  # RDP_NEG_FAILURE
    attrs = se._parse_rdp_negotiation(resp, 3389)
    assert any(a.attribute == "rdp_nla" and a.value == "enforced" for a in attrs)


def test_rdp_truncated_and_garbage_no_attribute():
    for resp in (b"", b"\x03\x00", b"\x03\x00\x00\x0b" + b"\x00" * 5,  # too short for offset 18
                 b"\xff" * 30,                                          # not TPKT
                 b"\x03" + b"\x00" * 18):                               # TPKT but neg_type=0 (unknown)
        attrs = se._parse_rdp_negotiation(resp, 3389)
        assert attrs == [] or all(a.attribute == "rdp_nla" and a.value not in ("required",)
                                  for a in attrs) or attrs == []
    # Specifically: unknown neg_type yields no attribute.
    assert se._parse_rdp_negotiation(b"\x03" + b"\x00" * 18, 3389) == []


# ─── SNMP construction + response validation ─────────────────────────────────────

def test_snmp_packet_lengths_consistent():
    pkt = se._snmp_get_sysdescr("public")
    assert pkt[0] == 0x30
    assert pkt[1] == len(pkt) - 2            # outer SEQUENCE length matches


def test_snmp_valid_response_accepted():
    assert se._snmp_response_accepts(build_snmp_response("public"), "public") is True
    assert se._snmp_response_accepts(build_snmp_response("private"), "private") is True


def test_snmp_community_mismatch_rejected():
    # Response echoes a different community than the one we sent → not accepted.
    assert se._snmp_response_accepts(build_snmp_response("public"), "private") is False


def test_snmp_non_getresponse_rejected():
    # A datagram that is a SEQUENCE but not a GetResponse PDU must not count as success.
    resp = build_snmp_response("public", pdu_type=0xa0)  # GetRequest, not GetResponse
    assert se._snmp_response_accepts(resp, "public") is False


def test_snmp_garbage_and_truncated_rejected():
    for resp in (b"", b"\x30", b"\x30\x05\x00", b"\xff" * 50,
                 b"\x30\x80\x00\x00",          # long-form length
                 build_snmp_response("public")[:6]):
        assert se._snmp_response_accepts(resp, "public") is False


# ─── socket-facing probes via a fake socket (no real network) ─────────────────────

class _FakeTCPSocket:
    def __init__(self, chunks):
        self._chunks = list(chunks)
        self.closed = False

    def settimeout(self, t): pass
    def sendall(self, b): pass

    def recv(self, n):
        if not self._chunks:
            return b""
        return self._chunks.pop(0)

    def close(self): self.closed = True
    def __enter__(self): return self
    def __exit__(self, *a): self.close()


def test_probe_smb_via_fake_socket(monkeypatch):
    resp = b"\x00\x00\x00\x55" + b"\xffSMB" + b"\x72" + b"\x00" * 40
    monkeypatch.setattr(se.socket, "create_connection",
                        lambda *a, **k: _FakeTCPSocket([resp]))
    attrs = se.probe_smb("10.0.0.1", 445, timeout=0.1)
    assert any(a.attribute == "smbv1_enabled" for a in attrs)


def test_probe_smb_closed_port_returns_empty(monkeypatch):
    def boom(*a, **k):
        raise ConnectionRefusedError()
    monkeypatch.setattr(se.socket, "create_connection", boom)
    assert se.probe_smb("10.0.0.1", 445, timeout=0.1) == []


def test_probe_rdp_via_fake_socket(monkeypatch):
    resp = build_rdp_cc(0x02, 0x00)  # NLA not required
    monkeypatch.setattr(se.socket, "create_connection",
                        lambda *a, **k: _FakeTCPSocket([resp]))
    attrs = se.probe_rdp("10.0.0.1", 3389, timeout=0.1)
    assert any(a.value == "not_required" for a in attrs)


def test_probe_rdp_timeout_returns_empty(monkeypatch):
    def boom(*a, **k):
        raise socket.timeout()
    monkeypatch.setattr(se.socket, "create_connection", boom)
    assert se.probe_rdp("10.0.0.1", 3389, timeout=0.1) == []


def test_probe_ssh_via_fake_socket(monkeypatch):
    data = build_ssh_kexinit(b"SSH-2.0-OpenSSH_7.4\r\n",
                             "diffie-hellman-group14-sha1", "ssh-ed25519",
                             "aes128-cbc", "aes128-cbc", "hmac-sha2-256", "hmac-sha2-256")
    banner_part = data[:data.find(b"\n") + 1]
    rest = data[data.find(b"\n") + 1:]
    monkeypatch.setattr(se.socket, "create_connection",
                        lambda *a, **k: _FakeTCPSocket([banner_part, rest]))
    attrs = se.probe_ssh("10.0.0.1", 22, timeout=0.1)
    assert any(a.attribute == "ssh_weak_cipher" for a in attrs)


# ─── SNMP UDP probe via a fake datagram socket ───────────────────────────────────

class _FakeUDPSocket:
    def __init__(self, resp):
        self._resp = resp
        self.closed = False

    def settimeout(self, t): pass
    def sendto(self, b, addr): pass

    def recvfrom(self, n):
        if self._resp is None:
            raise socket.timeout()
        return self._resp, ("10.0.0.1", 161)

    def close(self): self.closed = True


def test_probe_snmp_accepts_public(monkeypatch):
    fake = _FakeUDPSocket(build_snmp_response("public"))
    monkeypatch.setattr(se.socket, "socket", lambda *a, **k: fake)
    attrs = se.probe_snmp("10.0.0.1", 161, timeout=0.1)
    assert any(a.attribute == "snmp_default_community" and a.value == "public" for a in attrs)
    assert fake.closed


def test_probe_snmp_no_response_no_attribute(monkeypatch):
    monkeypatch.setattr(se.socket, "socket", lambda *a, **k: _FakeUDPSocket(None))
    assert se.probe_snmp("10.0.0.1", 161, timeout=0.1) == []


# ─── orchestrator gating ─────────────────────────────────────────────────────────

class _Port:
    def __init__(self, port, service="", tls=False, state="open"):
        self.port = port
        self.service = service
        self.tls = tls
        self.state = state


def test_enumerate_snmp_gating_only_when_161_present(monkeypatch):
    calls = []
    monkeypatch.setattr(se, "probe_snmp", lambda *a, **k: calls.append(a) or [])
    # No 161 → probe_snmp must NOT run.
    se.enumerate_services("h", [_Port(80, "http")])
    assert calls == []
    # 161 present by number → probe_snmp runs.
    se.enumerate_services("h", [_Port(161, "")])
    assert len(calls) == 1
    # snmp by service name (non-standard port) → probe_snmp runs.
    se.enumerate_services("h", [_Port(1161, "snmp")])
    assert len(calls) == 2


def test_enumerate_skips_closed_ports(monkeypatch):
    monkeypatch.setattr(se, "probe_ssh", lambda *a, **k: [se.ServiceAttribute(22, "ssh", "x", "y", "z")])
    res = se.enumerate_services("h", [_Port(22, "ssh", state="closed")])
    assert res.attributes == []


def test_enumerate_handles_empty_and_none():
    assert se.enumerate_services("h", None).attributes == []
    assert se.enumerate_services("h", []).attributes == []


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
