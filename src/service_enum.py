"""
NetLogic - Service Exploitability Enumeration
=============================================
Goes beyond "port X is open" to extract the protocol-level ATTRIBUTES that decide
whether a version-matched CVE is actually exploitable — the difference between a
guess and a precondition:

  • SMB   — is SMBv1 enabled? (the actual EternalBlue/WannaCry precondition)
  • RDP   — is NLA (CredSSP) required, or is legacy RDP security allowed? (BlueKeep)
  • SSH   — KEX/cipher/MAC/host-key algorithms → weak crypto, and protocol version
  • SNMP  — does a default community string ('public'/'private') work?
  • HTTP  — is the surface open (200) or auth-gated (401/403/login)? exposure context

All probes are read-only protocol negotiations, stdlib sockets only, and fail
soft (return [] on any error / closed port). These attributes feed the AI so it
can reason about real exploitability instead of version guesses.
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field


@dataclass
class ServiceAttribute:
    port: int
    service: str
    attribute: str       # machine key, e.g. "smbv1_enabled"
    value: str           # human-readable value
    detail: str
    severity: str = "INFO"      # INFO / LOW / MEDIUM / HIGH / CRITICAL
    exploit_precondition_for: list[str] = field(default_factory=list)  # CVE IDs this enables


@dataclass
class ServiceEnumResult:
    target: str
    attributes: list[ServiceAttribute] = field(default_factory=list)


# ─── SSH (port 22) ─────────────────────────────────────────────────────────────

_SSH_WEAK_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
                 "diffie-hellman-group-exchange-sha1"}
_SSH_WEAK_CIPHERS = {"3des-cbc", "arcfour", "arcfour128", "arcfour256", "blowfish-cbc",
                     "aes128-cbc", "aes192-cbc", "aes256-cbc", "cast128-cbc", "des-cbc"}
_SSH_WEAK_MACS = {"hmac-md5", "hmac-md5-96", "hmac-sha1-96", "umac-64@openssh.com"}
_SSH_WEAK_HOSTKEYS = {"ssh-dss", "ssh-rsa"}   # ssh-rsa = SHA-1 signature


def _ssh_namelist(buf: bytes, off: int):
    """Parse one SSH name-list: uint32 length + comma-joined ascii. Returns (items, new_off)."""
    if off + 4 > len(buf):
        return [], off
    ln = struct.unpack(">I", buf[off:off + 4])[0]
    off += 4
    raw = buf[off:off + ln].decode("ascii", errors="replace")
    off += ln
    return [x for x in raw.split(",") if x], off


def _parse_ssh_kexinit(data: bytes, banner: bytes, port: int) -> list[ServiceAttribute]:
    """Parse the SSH banner + KEXINIT packet from `data` and emit weak-crypto attrs.

    `data` is everything read from the server (banner line + binary KEXINIT). `banner`
    is the banner bytes used for the protocol-version check. All offset math is
    bounds-checked via `_ssh_namelist`; a missing/short/garbage KEXINIT yields only the
    protocol-version attr (or nothing) — never a wrong weak-crypto precondition, never a raise."""
    attrs: list[ServiceAttribute] = []
    # Locate the binary part (after the banner line).
    nl = data.find(b"\n")
    bin_start = nl + 1 if nl != -1 else 0
    blob = data[bin_start:]
    # SSH binary packet: uint32 packet_length, byte padding_length, payload[0]=msg_type.
    have_kexinit = len(blob) >= 6 and blob[5] == 0x14   # 0x14 = SSH_MSG_KEXINIT
    kex = hostkeys = enc_c2s = enc_s2c = macs_c2s = macs_s2c = []
    if have_kexinit:
        off = 6 + 16   # skip packet_length(4)+pad_len(1)+msg_type(1)+cookie(16)
        kex, off       = _ssh_namelist(blob, off)
        hostkeys, off  = _ssh_namelist(blob, off)
        enc_c2s, off   = _ssh_namelist(blob, off)
        enc_s2c, off   = _ssh_namelist(blob, off)
        macs_c2s, off  = _ssh_namelist(blob, off)
        macs_s2c, off  = _ssh_namelist(blob, off)

    proto = banner.decode("ascii", errors="replace").strip()
    if proto.startswith("SSH-1") or "SSH-1." in proto:
        attrs.append(ServiceAttribute(port, "ssh", "ssh_protocol", "SSHv1",
            "Server offers the obsolete, cryptographically broken SSH protocol v1.",
            "HIGH"))

    # A genuine KEXINIT always carries a non-empty kex name-list. If it parsed empty,
    # the packet was truncated/garbage past the msg-type byte — don't emit algorithm
    # attributes built from partial data (avoids noisy/garbage surface readings).
    if not have_kexinit or not kex:
        return attrs

    weak_kex = sorted(set(kex) & _SSH_WEAK_KEX)
    weak_enc = sorted((set(enc_c2s) | set(enc_s2c)) & _SSH_WEAK_CIPHERS)
    weak_mac = sorted((set(macs_c2s) | set(macs_s2c)) & _SSH_WEAK_MACS)
    weak_hk  = sorted(set(hostkeys) & _SSH_WEAK_HOSTKEYS)

    if weak_kex:
        attrs.append(ServiceAttribute(port, "ssh", "ssh_weak_kex", ", ".join(weak_kex),
            "SHA-1 / weak Diffie-Hellman key exchange algorithms offered.", "MEDIUM"))
    if weak_enc:
        attrs.append(ServiceAttribute(port, "ssh", "ssh_weak_cipher", ", ".join(weak_enc),
            "Weak/CBC ciphers offered (susceptible to known attacks).", "MEDIUM"))
    if weak_mac:
        attrs.append(ServiceAttribute(port, "ssh", "ssh_weak_mac", ", ".join(weak_mac),
            "Weak MAC algorithms offered (MD5/truncated/64-bit).", "LOW"))
    if weak_hk:
        attrs.append(ServiceAttribute(port, "ssh", "ssh_weak_hostkey", ", ".join(weak_hk),
            "Weak host-key algorithms (DSA or SHA-1 RSA signatures).", "LOW"))
    # Always record the negotiated algorithm surface for AI context.
    attrs.append(ServiceAttribute(port, "ssh", "ssh_algorithms",
        f"kex={len(kex)} ciphers={len(set(enc_c2s) | set(enc_s2c))} hostkeys={','.join(hostkeys[:3])}",
        "SSH algorithm negotiation surface.", "INFO"))
    return attrs


def probe_ssh(host: str, port: int, timeout: float = 4.0) -> list[ServiceAttribute]:
    attrs: list[ServiceAttribute] = []
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        banner = b""
        # Read the server banner line (ends in \n); KEXINIT follows.
        while b"\n" not in banner and len(banner) < 512:
            try:
                chunk = sock.recv(256)
            except socket.timeout:
                break
            if not chunk:
                break
            banner += chunk
        sock.sendall(b"SSH-2.0-NetLogic_2.0\r\n")
        data = banner
        while len(data) < 8192:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if b"\x14" in data and len(data) > 60:
                break
        return _parse_ssh_kexinit(data, banner, port)
    except Exception:
        return attrs
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


# ─── SMB (port 445) — SMBv1 enabled? ─────────────────────────────────────────────

# A minimal SMBv1 SMB_COM_NEGOTIATE requesting the "NT LM 0.12" dialect, wrapped in
# a NetBIOS session message. If the server answers with an SMBv1 packet (\xffSMB),
# SMBv1 is ENABLED — the precondition for MS17-010 / EternalBlue / WannaCry.
#
# SMB1 header is exactly 32 bytes:
#   \xffSMB | cmd(1) | status(4) | flags(1) | flags2(2) | pidHigh(2) |
#   signature(8) | reserved(2) | tid(2) | pidLow(2) | uid(2) | mid(2)
# followed by wordCount(1)=0, byteCount(2)=12, and the 12-byte dialect entry.
# Total SMB payload = 32 + 1 + 2 + 12 = 47 bytes → NetBIOS length 0x2f.
_SMB1_NEGOTIATE = (
    b"\x00\x00\x00\x2f"                          # NetBIOS session message, length 0x2f (47)
    b"\xffSMB\x72"                               # \xffSMB + SMB_COM_NEGOTIATE (0x72)
    b"\x00\x00\x00\x00"                          # NT status = 0
    b"\x18"                                      # flags
    b"\x53\xc8"                                  # flags2
    b"\x00\x00"                                  # pidHigh
    b"\x00\x00\x00\x00\x00\x00\x00\x00"          # signature (8)
    b"\x00\x00"                                  # reserved
    b"\x00\x00"                                  # tid
    b"\x44\x00"                                  # pidLow
    b"\x00\x00"                                  # uid
    b"\x00\x00"                                  # mid
    b"\x00"                                      # wordCount = 0
    b"\x0c\x00"                                  # byteCount = 12
    b"\x02NT LM 0.12\x00"                        # dialect: "NT LM 0.12"
)


def _smb_response_is_smbv1(resp: bytes) -> bool:
    """A reply whose SMB header magic is \\xffSMB means the server spoke SMBv1 — i.e.
    SMBv1 is ENABLED. An SMBv2+ only server replies with \\xfeSMB / \\xfdSMB or resets,
    so this magic is a reliable positive. Bounds-checked: short replies → False."""
    return len(resp) >= 8 and resp[4:8] == b"\xffSMB"


def probe_smb(host: str, port: int = 445, timeout: float = 4.0) -> list[ServiceAttribute]:
    attrs: list[ServiceAttribute] = []
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(_SMB1_NEGOTIATE)
            resp = sock.recv(512)
        if _smb_response_is_smbv1(resp):
            # SMBv1 spoken. Byte after the 32-byte header region carries the
            # SecurityMode (signing) in the negotiate response word block.
            attrs.append(ServiceAttribute(
                port, "smb", "smbv1_enabled", "yes",
                "SMBv1 is ENABLED. SMBv1 is the precondition for MS17-010 / EternalBlue "
                "(WannaCry, NotPetya) and should be disabled on all modern systems.",
                "HIGH",
                exploit_precondition_for=["CVE-2017-0144", "CVE-2017-0143", "CVE-2017-0145"]))
        # If it didn't answer SMBv1, SMBv1 is disabled (good) — record nothing noisy.
    except Exception:
        return attrs
    return attrs


# ─── RDP (port 3389) — NLA required? ─────────────────────────────────────────────

# X.224 Connection Request requesting RDP|TLS|CredSSP|Hybrid-EX (0x0B).
_RDP_CR = (
    b"\x03\x00\x00\x13"                  # TPKT header, length 19
    b"\x0e\xe0\x00\x00\x00\x00\x00"      # X.224 Connection Request
    b"\x01\x00\x08\x00\x0b\x00\x00\x00"  # RDP_NEG_REQ, requestedProtocols=0x0b
)


def _parse_rdp_negotiation(resp: bytes, port: int = 3389) -> list[ServiceAttribute]:
    """Parse an RDP X.224 Connection Confirm and emit the NLA attribute.

    Layout: TPKT(4) + X.224 CC(7) + RDP_NEG_RSP/FAILURE(8). The negotiation
    structure starts at offset 11: type(1) @11, flags(1) @12, length(2) @13,
    selectedProtocol uint32-LE @15. Every read is bounds-checked; a short,
    non-TPKT, or unexpected reply yields NO attribute (no false precondition).
    """
    attrs: list[ServiceAttribute] = []
    # Need the full 8-byte negotiation structure (offsets 11..18) and TPKT magic.
    if len(resp) < 19 or resp[0] != 0x03:
        return attrs
    neg_type = resp[11]
    if neg_type == 0x02:   # RDP_NEG_RSP
        selected = struct.unpack("<I", resp[15:19])[0]
        if selected & 0x02:   # PROTOCOL_HYBRID = CredSSP = NLA
            attrs.append(ServiceAttribute(port, "rdp", "rdp_nla", "required",
                "RDP requires NLA (CredSSP) — network-level auth before session setup. "
                "Hardened against pre-auth RDP CVEs like BlueKeep.", "INFO"))
        else:
            attrs.append(ServiceAttribute(port, "rdp", "rdp_nla", "not_required",
                "RDP allows legacy (non-NLA) security. Pre-authentication is reachable, "
                "the precondition for BlueKeep (CVE-2019-0708) and similar RDP pre-auth RCEs.",
                "HIGH", exploit_precondition_for=["CVE-2019-0708"]))
    elif neg_type == 0x03:  # RDP_NEG_FAILURE
        attrs.append(ServiceAttribute(port, "rdp", "rdp_nla", "enforced",
            "RDP negotiation requires a security protocol the client lacked — strong (NLA/TLS enforced).",
            "INFO"))
    return attrs


def probe_rdp(host: str, port: int = 3389, timeout: float = 4.0) -> list[ServiceAttribute]:
    attrs: list[ServiceAttribute] = []
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(_RDP_CR)
            resp = sock.recv(512)
        return _parse_rdp_negotiation(resp, port)
    except Exception:
        return attrs


# ─── SNMP (UDP 161) — default community strings ──────────────────────────────────

def _snmp_get_sysdescr(community: str) -> bytes:
    """Build an SNMPv1 GET for sysDescr.0 (1.3.6.1.2.1.1.1.0) with a community string."""
    c = community.encode()
    # varbind: OID sysDescr.0 + NULL value
    oid = b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"
    null = b"\x05\x00"
    vb = b"\x30" + bytes([len(oid) + len(null)]) + oid + null
    vblist = b"\x30" + bytes([len(vb)]) + vb
    # PDU: GET (0xa0), request-id, error-status, error-index, varbindlist
    pdu_body = (b"\x02\x01\x01"          # request-id = 1
                b"\x02\x01\x00"          # error-status = 0
                b"\x02\x01\x00"          # error-index = 0
                + vblist)
    pdu = b"\xa0" + bytes([len(pdu_body)]) + pdu_body
    # message: version(0=v1) + community + pdu
    body = b"\x02\x01\x00" + b"\x04" + bytes([len(c)]) + c + pdu
    return b"\x30" + bytes([len(body)]) + body


def _snmp_response_accepts(resp: bytes, community: str) -> bool:
    """True only if `resp` is a well-formed SNMPv1 GetResponse echoing `community`.

    A wrong community is normally dropped silently by the agent (no datagram at all),
    but we must not treat an arbitrary UDP datagram that merely starts with 0x30 as a
    success — that would assert a false precondition. We require:
      • outer SEQUENCE (0x30) with a sane length,
      • version INTEGER == 0 (SNMPv1),
      • community OCTET STRING equal to the one we sent,
      • the PDU to be a GetResponse (0xa2).
    Lengths are short-form (< 0x80) for our tiny request/response, which is the common
    case; we bounds-check every read so truncated/garbage input returns False, never raises.
    """
    try:
        if len(resp) < 2 or resp[0] != 0x30:
            return False
        seq_len = resp[1]
        if seq_len & 0x80:          # long-form length — outside our simple expectation
            return False
        if len(resp) < 2 + seq_len:  # truncated payload
            return False
        i = 2
        # version: INTEGER, 1 byte, value 0 (SNMPv1)
        if i + 3 > len(resp) or resp[i] != 0x02 or resp[i + 1] != 0x01 or resp[i + 2] != 0x00:
            return False
        i += 3
        # community: OCTET STRING
        if i + 2 > len(resp) or resp[i] != 0x04:
            return False
        clen = resp[i + 1]
        i += 2
        if i + clen > len(resp):
            return False
        if resp[i:i + clen] != community.encode():
            return False
        i += clen
        # PDU type must be GetResponse (0xa2)
        if i >= len(resp) or resp[i] != 0xa2:
            return False
        return True
    except Exception:
        return False


def probe_snmp(host: str, port: int = 161, timeout: float = 3.0) -> list[ServiceAttribute]:
    attrs: list[ServiceAttribute] = []
    for community in ("public", "private"):
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(_snmp_get_sysdescr(community), (host, port))
            resp, _ = sock.recvfrom(2048)
            if _snmp_response_accepts(resp, community):
                attrs.append(ServiceAttribute(
                    port, "snmp", "snmp_default_community", community,
                    f"SNMP responds to the default community string '{community}'. This exposes "
                    "device/system information (and write access if 'private' is RW). "
                    "Confirmed misconfiguration, not a guess.",
                    "HIGH" if community == "private" else "MEDIUM"))
        except Exception:
            pass
        finally:
            if sock is not None:
                sock.close()
    return attrs


# ─── HTTP reachability / auth state ──────────────────────────────────────────────

def probe_http_auth_state(host: str, port: int, scheme: str = "http",
                          timeout: float = 4.0) -> list[ServiceAttribute]:
    """Is the web root open (200) or auth-gated (401/403/login redirect)?"""
    import urllib.request, urllib.error  # noqa: PLC0415
    attrs: list[ServiceAttribute] = []
    try:
        url = f"{scheme}://{host}:{port}/"
        req = urllib.request.Request(url, headers={"User-Agent": "NetLogic/2.0"})
        status, hdrs, body_head = None, {}, ""
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                body_head = resp.read(512).decode("utf-8", errors="replace").lower()
        except urllib.error.HTTPError as e:
            status = e.code
            hdrs = {k.lower(): v for k, v in (e.headers or {}).items()}
    except Exception:
        return attrs

    if status is None:
        return attrs
    if status in (401, 407) or "www-authenticate" in hdrs:
        state, detail, sev = "auth_required", \
            f"Web root returns HTTP {status} with authentication challenge — surface is auth-gated.", "INFO"
    elif status == 403:
        state, detail, sev = "forbidden", \
            "Web root returns HTTP 403 — access controlled; vulnerable paths may not be reachable unauthenticated.", "INFO"
    elif status in (301, 302, 303, 307, 308) and any(
            k in (hdrs.get("location", "") or "").lower() for k in ("login", "signin", "auth", "sso")):
        state, detail, sev = "login_redirect", \
            "Web root redirects to a login page — surface is auth-gated.", "INFO"
    elif status == 200:
        state, detail, sev = "open", \
            "Web root is openly reachable (HTTP 200, no auth) — unauthenticated attack surface is live.", "LOW"
    else:
        state, detail, sev = f"http_{status}", f"Web root returns HTTP {status}.", "INFO"
    attrs.append(ServiceAttribute(port, scheme, "http_auth_state", state, detail, sev))
    return attrs


# ─── Orchestrator ────────────────────────────────────────────────────────────────

def enumerate_services(target: str, ports, timeout: float = 4.0) -> ServiceEnumResult:
    """Run protocol-specific exploitability probes against the open ports found."""
    result = ServiceEnumResult(target=target)
    open_ports = [(p.port, (getattr(p, "service", "") or "").lower(),
                   getattr(p, "tls", False)) for p in (ports or [])
                  if getattr(p, "state", "open") == "open"]

    for port, service, tls in open_ports:
        try:
            if port == 22 or "ssh" in service:
                result.attributes += probe_ssh(target, port, timeout)
            elif port == 445 or service in ("smb", "microsoft-ds", "netbios-ssn"):
                result.attributes += probe_smb(target, port, timeout)
            elif port == 3389 or "rdp" in service or "ms-wbt" in service:
                result.attributes += probe_rdp(target, port, timeout)
            elif service in ("http", "https", "http-alt", "https-alt") or port in (80, 443, 8080, 8443):
                scheme = "https" if (tls or port in (443, 8443)) else "http"
                result.attributes += probe_http_auth_state(target, port, scheme, timeout)
        except Exception:
            continue

    # SNMP is UDP, so it won't appear in the TCP open-port loop above. Probe it only
    # when the scan actually surfaced port 161 (by number or by service name) — we do
    # NOT blindly UDP-probe every target, which would be slow (timeouts) and noisy.
    snmp_present = any(
        getattr(p, "port", None) == 161
        or "snmp" in (getattr(p, "service", "") or "").lower()
        for p in (ports or [])
    )
    if snmp_present:
        result.attributes += probe_snmp(target, 161, timeout)

    return result
