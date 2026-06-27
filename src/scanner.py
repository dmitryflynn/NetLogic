"""
NetLogic - Core Scanner Engine
Performs active port scanning, service fingerprinting, and banner grabbing.
"""

import socket
import ssl
import concurrent.futures
import itertools
import re
import sys
import subprocess
import time
from dataclasses import dataclass, field, asdict
from typing import Optional
import ipaddress

# Hard cap on hosts enumerated from a CIDR. Prevents a huge range (e.g. /8 or /0)
# from materializing millions/billions of host strings and exhausting agent memory
# (a DoS vector). 65,536 = an IPv4 /16, generous for enterprise subnet sweeps.
MAX_CIDR_HOSTS = 65_536


# ─── Data Models ────────────────────────────────────────────────────────────────

@dataclass
class ServiceBanner:
    raw: str
    product: Optional[str] = None
    version: Optional[str] = None
    extra: Optional[str] = None

@dataclass
class PortResult:
    port: int
    protocol: str
    state: str            # open / closed / filtered
    service: Optional[str] = None
    banner: Optional[ServiceBanner] = None
    tls: bool = False
    tls_cert_cn: Optional[str] = None
    response_time_ms: float = 0.0
    protocol_fingerprint: Optional[str] = None  # UDP protocol detection (DNS, SNMP, etc.)
    detection_confidence: str = "low"  # high / medium / low - confidence in service detection

@dataclass
class HostResult:
    target: str
    ip: Optional[str] = None
    hostname: Optional[str] = None
    ttl: Optional[int] = None
    os_guess: Optional[str] = None
    ports: list[PortResult] = field(default_factory=list)
    scan_duration_s: float = 0.0
    timestamp: str = ""

# ─── Service Probe Library ───────────────────────────────────────────────────────

SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-alt", 8443: "https-alt",
    9200: "elasticsearch", 27017: "mongodb", 11211: "memcached",
    2181: "zookeeper", 6443: "k8s-api", 2376: "docker",
    2375: "docker-api", 2379: "etcd", 2380: "etcd",
    3000: "grafana",    5601: "kibana", 5672: "amqp",
    5984: "couchdb",    7474: "neo4j-http", 8200: "vault",
    8300: "consul-rpc", 8500: "consul-http", 8983: "solr",
    9090: "prometheus", 9092: "kafka", 9300: "elasticsearch",
    15672: "rabbitmq-mgmt",
    # ── Long-tail, CVE-heavy services (probed under the 'full' preset) ──
    111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 389: "ldap",
    587: "smtp", 636: "ldaps", 873: "rsync", 1099: "java-rmi",
    1723: "pptp", 2049: "nfs", 3260: "iscsi", 5060: "sip",
    5555: "adb", 5985: "winrm", 5986: "winrm-https", 6000: "x11",
    6667: "irc", 7001: "weblogic", 8009: "ajp", 8089: "splunkd",
    8081: "http-alt", 8088: "http-alt", 8161: "activemq", 8888: "http-alt",
    9000: "http-alt", 9001: "http-alt", 9091: "http-alt", 9418: "git",
    10000: "webmin", 10250: "kubelet", 50000: "sap", 50070: "hadoop-namenode",
}

HTTP_PROBE = (
    b"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NetLogic/2.0\r\n"
    b"Accept: */*\r\nConnection: close\r\n\r\n"
)

PROBES = {
    "http":    HTTP_PROBE,
    "ftp":     None,        # Server sends a banner on connect — just listen.
    "ssh":     None,
    "smtp":    b"HELO netlogic.local\r\n",
    "pop3":    None,
    "imap":    None,
    "redis":   b"INFO server\r\n",
    "mysql":   None,        # MySQL sends its handshake greeting first — listen, don't poke.
    "postgresql": b"\x00\x00\x00\x08\x04\xd2\x16\x2f", # SSLRequest
    "mongodb": b"\x41\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00"
               b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    "memcached":       b"version\r\n",
    "zookeeper":       b"srvr\r\n",
    "docker-api":      b"GET /version HTTP/1.0\r\nHost: {host}\r\n\r\n",
}

# Services that speak HTTP and must receive an HTTP probe to reveal a Server
# header. The default port→service map gives many of these non-"http" names
# (http-alt on 8080, dashboards, APIs); without this set those ports return no
# banner, the version stays unknown, and CVE correlation is silently skipped.
HTTP_SERVICES = {
    "http", "https", "http-alt", "https-alt", "grafana", "kibana",
    "prometheus", "consul-http", "k8s-api", "elasticsearch", "couchdb",
    "solr", "neo4j-http", "vault", "rabbitmq-mgmt",
    # Long-tail admin panels / APIs that speak HTTP — probe for a Server header
    # so a product/version (and thus CVE correlation) can be recovered.
    "weblogic", "activemq", "splunkd", "webmin", "kubelet", "hadoop-namenode",
    "winrm", "winrm-https",
}

# Ports that are TLS-wrapped by default — banner grabbing MUST go through an SSL
# handshake. The previous code sent a plaintext probe to these and read back
# encrypted bytes, so HTTPS services never yielded a parseable banner.
TLS_PORTS = {443, 8443, 993, 995, 465, 636, 5671, 5986, 9200, 9043, 4443}


def _select_probe(service_name: str) -> Optional[bytes]:
    """Return the byte probe to send for a service, or None to just listen."""
    if service_name in HTTP_SERVICES:
        return HTTP_PROBE
    return PROBES.get(service_name)

def parse_banner(raw: str, service: str) -> ServiceBanner:
    """Extract product/version using centralized heuristic analysis."""
    b = ServiceBanner(raw=raw[:4096])
    
    # 1. Use the highly accurate correlator engine to extract accurate product/version globally
    from src.cve_correlator import extract_product_version
    prod, ver = extract_product_version(b.raw)
    
    if prod:
        b.product = prod
        b.version = ver
        return b
        
    # 2. HTTP/Web Specific Deep Analysis (Fallback if global patterns didn't catch it)
    if service in ("http", "https", "http-alt", "https-alt") or "HTTP/" in raw:
        m = re.search(r"^Server:\s*([^\r\n]+)", raw, re.I | re.M)
        if m:
            b.product = m.group(1).strip()
            if "/" in b.product:
                parts = b.product.split("/", 1)
                b.product = parts[0].strip()
                # Version is the first token after the slash; drop trailing OS /
                # comment noise, e.g. "2.4.41 (Ubuntu)" → "2.4.41", so exact CVE
                # version matching isn't defeated by the appended platform string.
                ver_tok = parts[1].strip()
                b.version = ver_tok.split()[0] if ver_tok else None
        
        if not b.version:
            m = re.search(r"^X-Powered-By:\s*([^\r\n]+)", raw, re.I | re.M)
            if m:
                b.extra = f"framework:{m.group(1).strip()}"
                vm = re.search(r"/([\d.]+)", m.group(1))
                if vm: b.version = vm.group(1)
            
            m = re.search(r"^X-Generator:\s*([^\r\n]+)", raw, re.I | re.M)
            if m:
                b.product = b.product or "cms"
                vm = re.search(r"([\d.]+)", m.group(1))
                if vm: b.version = vm.group(1)

    if b.product == "http" and b.extra and "framework:" in b.extra:
        b.product = b.extra.split(":")[1].split("/")[0]

    return b


def _snmp_sysdescr(resp: bytes) -> Optional[str]:
    """Pull sysDescr.0 out of an SNMP GET-RESPONSE. sysDescr is the value (an
    OCTET STRING) immediately after OID 1.3.6.1.2.1.1.1.0 — it carries the exact
    device/OS/version string ("Cisco IOS … Version 15.1", "Linux host 5.4.0 …"),
    which is version-confirmed CVE fuel. Minimal BER walk; fails soft to None."""
    oid = bytes.fromhex("06082b06010201010100")          # 1.3.6.1.2.1.1.1.0
    i = resp.find(oid)
    if i == -1:
        return None
    j = i + len(oid)
    if j + 1 >= len(resp) or resp[j] != 0x04:             # need tag + length byte; value must be OCTET STRING
        return None
    ln = resp[j + 1]
    start = j + 2
    if ln & 0x80:                                         # long-form length
        nbytes = ln & 0x7F
        if j + 2 + nbytes > len(resp):
            return None
        ln = int.from_bytes(resp[j + 2:j + 2 + nbytes], "big")
        start = j + 2 + nbytes
    if ln < 0 or ln > len(resp):                          # bogus length → ignore
        return None
    val = resp[start:start + ln]
    try:
        text = val.decode("utf-8", errors="replace").strip()
    except Exception:
        return None
    return text or None


def probe_udp_protocol(host: str, port: int, timeout: float = 2.0) -> Optional[tuple[str, Optional[str]]]:
    """Probe a UDP port for protocol fingerprinting.

    Returns (protocol, detail) or None. `detail` carries extracted intel when the
    service leaks it — SNMP sysDescr (device/OS/version), SSDP SERVER string — so
    the caller can feed it to version/CVE correlation; None otherwise.
    """
    # NetBIOS Name Service node-status request ("*" wildcard) — a response reveals
    # the Windows hostname/domain (great OS/identity signal).
    _NBNS = (b"\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20"
             + b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + b"\x00\x00\x21\x00\x01")
    # SSDP/UPnP discovery — a response exposes the device/SERVER string (IoT/UPnP CVEs).
    _SSDP = (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
             b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n')
    probes = {
        161: (b"\x30\x3a\x02\x01\x00\x04\x06public\xa0\x2c\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x17\x30\x15\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00", "snmp"),
        53: (b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x02com\x00\x00\x01\x00\x01", "dns"),
        123: (b"\x23\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "ntp"),
        137: (_NBNS, "netbios"),
        1900: (_SSDP, "ssdp"),
    }

    if port not in probes:
        return None

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        data, proto = probes[port]
        sock.sendto(data, (host, port))

        try:
            resp, _ = sock.recvfrom(2048)
            if len(resp) > 0:
                if port == 161 and resp[0] == 0x30:  # SNMP response starts with SEQUENCE
                    return ("snmp", _snmp_sysdescr(resp))
                elif port == 53 and len(resp) >= 2:  # DNS response
                    return ("dns", None)
                elif port == 123 and len(resp) >= 4:  # NTP response
                    return ("ntp", None)
                elif port == 137 and len(resp) >= 12:  # NBNS node-status reply
                    return ("netbios", None)
                elif port == 1900 and (b"HTTP" in resp[:8] or b"SERVER" in resp.upper()):
                    # Pull the SERVER: header (device/version) out of the SSDP reply.
                    detail = None
                    for line in resp.split(b"\r\n"):
                        if line[:7].upper() == b"SERVER:":
                            detail = line[7:].decode("utf-8", errors="replace").strip() or None
                            break
                    return ("ssdp", detail)
        except socket.timeout:
            pass
    except Exception:
        pass
    finally:
        if sock is not None:
            sock.close()
    return None


def _read_banner(sock, service_name: str, host: str, timeout: float) -> bytes:
    """Send the service probe (if any) and collect the response from an open socket.

    Partial data is preserved: many services (SSH, FTP, SMTP, MySQL, ...) send one
    banner line on connect and then wait for the client. The follow-up recv() times
    out by design, so the timeout must NOT discard banner bytes already collected.
    """
    chunks = []
    try:
        probe = _select_probe(service_name)
        if probe:
            probe_data = probe.replace(b"{host}", host.encode()) if b"{host}" in probe else probe
            sock.sendall(probe_data)
        sock.settimeout(timeout)
        total = 0
        while True:
            try:
                data = sock.recv(1024)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
            total += len(data)
            if total > 8192:
                break
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    return b"".join(chunks)


def _read_banner_tls(host: str, port: int, service_name: str, timeout: float):
    """TLS handshake, capture cert CN, then grab a banner over the encrypted channel.

    Returns (handshake_ok, common_name, raw_banner_bytes).
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cn = None
                cert = tls_sock.getpeercert()
                if cert:
                    for entry in cert.get("subject", []):
                        for key, val in entry:
                            if key == "commonName":
                                cn = val
                # Only send a probe if this service expects one (HTTP). TLS-wrapped
                # mail services (imaps/pop3s) greet on connect — just listen.
                probe = _select_probe(service_name)
                chunks = []
                try:
                    if probe:
                        probe_data = probe.replace(b"{host}", host.encode()) if b"{host}" in probe else probe
                        tls_sock.sendall(probe_data)
                    tls_sock.settimeout(timeout)
                    total = 0
                    while True:
                        try:
                            data = tls_sock.recv(1024)
                        except socket.timeout:
                            break
                        if not data:
                            break
                        chunks.append(data)
                        total += len(data)
                        if total > 8192:
                            break
                except OSError:
                    pass
                return True, cn, b"".join(chunks)
    except Exception:
        return False, None, b""


def probe_port(host: str, port: int, timeout: float = 2.0) -> PortResult:
    """Connect to a port, identify service, grab banner (TLS-aware)."""
    t0 = time.perf_counter()
    result = PortResult(port=port, protocol="tcp", state="closed")
    service_name = SERVICE_MAP.get(port, "unknown")

    # Confirm the port is open with a plain TCP connect.
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except (ConnectionRefusedError, ConnectionResetError):
        result.state = "closed"
        return result
    except (socket.timeout, TimeoutError):
        result.state = "filtered"
        return result
    except OSError:
        result.state = "closed"
        return result

    result.state = "open"
    result.service = service_name
    result.response_time_ms = round((time.perf_counter() - t0) * 1000, 2)

    raw_banner = b""
    if port in TLS_PORTS:
        # Known TLS port: redo the connection through SSL.
        try:
            sock.close()
        except OSError:
            pass
        tls_ok, cn, raw_banner = _read_banner_tls(host, port, service_name, timeout)
        if tls_ok:
            result.tls = True
            result.tls_cert_cn = cn
        else:
            # TLS failed but the port is open — fall back to plaintext.
            try:
                sock = socket.create_connection((host, port), timeout=timeout)
                raw_banner = _read_banner(sock, service_name, host, timeout)
            except OSError:
                raw_banner = b""
            finally:
                try:
                    sock.close()
                except OSError:
                    pass
    else:
        raw_banner = _read_banner(sock, service_name, host, timeout)
        try:
            sock.close()
        except OSError:
            pass
        # An HTTP-ish port that returned nothing in plaintext may be HTTPS on a
        # nonstandard port — retry through TLS before giving up.
        if not raw_banner and service_name in HTTP_SERVICES:
            tls_ok, cn, tls_raw = _read_banner_tls(host, port, service_name, timeout)
            if tls_ok:
                result.tls = True
                result.tls_cert_cn = cn
                raw_banner = tls_raw

        # Generic HTTP second-chance: a port that opened but stayed silent to a
        # plain listen is very often a web server on a non-standard port waiting
        # for a request. Send an HTTP probe (then HTTPS) to recover a Server
        # header → product/version → CVE correlation that would otherwise be
        # missed. Only fires when nothing was learned, so it adds no cost to
        # already-identified services.
        if not raw_banner and service_name not in HTTP_SERVICES:
            try:
                s2 = socket.create_connection((host, port), timeout=timeout)
                raw_banner = _read_banner(s2, "http", host, timeout)
                try:
                    s2.close()
                except OSError:
                    pass
            except OSError:
                raw_banner = b""
            if raw_banner and b"HTTP/" in raw_banner[:64].upper():
                result.service = "http"          # reclassify: it speaks HTTP
                service_name = "http"
            elif not raw_banner:
                tls_ok, cn, tls_raw = _read_banner_tls(host, port, "http", timeout)
                if tls_ok and tls_raw and b"HTTP/" in tls_raw[:64].upper():
                    result.tls = True
                    result.tls_cert_cn = cn
                    result.service = "https"
                    service_name = "https"
                    raw_banner = tls_raw

    if raw_banner:
        try:
            banner_text = raw_banner.decode("utf-8", errors="replace")
            result.banner = parse_banner(banner_text, service_name)
        except Exception:
            pass

    # Service detection confidence — aligned with the correlator's HIGH/MEDIUM/LOW:
    #   high   = banner gave us a product AND a version (exact CVE matching possible)
    #   medium = banner gave a product, or at least some response came back
    #   low    = nothing answered; service is only a port-number guess
    if result.banner and result.banner.product and result.banner.version:
        result.detection_confidence = "high"
    elif result.banner and (result.banner.product or result.banner.raw.strip()):
        result.detection_confidence = "medium"
    else:
        result.detection_confidence = "low"

    return result


# ─── TTL → OS Estimation ────────────────────────────────────────────────────────

def guess_os_from_ttl(ttl: Optional[int]) -> Optional[str]:
    if ttl is None:
        return None
    if ttl <= 64:
        return "Linux/Unix"
    if ttl <= 128:
        return "Windows"
    if ttl <= 255:
        return "Network Device (Cisco/HP)"
    return None


def get_ttl(host: str, timeout: float = 2.0) -> Optional[int]:
    """Best-effort TTL from a single system ping, used to estimate the host OS.

    Returns the observed TTL (already decremented by network hops) or None if the
    host doesn't answer ICMP / ping is unavailable. Degrades gracefully — a None
    just means os_guess stays unknown, never an error.
    """
    if sys.platform.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(int(max(1.0, timeout) * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(max(1.0, timeout))), host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
        out = f"{proc.stdout or ''}{proc.stderr or ''}"
        m = re.search(r"ttl[=\s]*(\d+)", out, re.IGNORECASE)
        if m:
            return int(m.group(1))
    except (subprocess.TimeoutExpired, OSError, ValueError):
        pass
    return None


# ─── Main Scan Orchestrator ──────────────────────────────────────────────────────

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
    5601, 5672, 5984, 6379, 6443, 7474, 8080, 8200, 8443, 8500, 8983,
    9090, 9200, 9300, 9092, 11211, 15672, 2181, 2375, 2376, 2379, 3000,
    27017,
]

# The 'full' preset — a thorough, CVE-relevant superset of COMMON_PORTS covering
# the long tail of commonly-exposed, vulnerability-heavy services (RPC/NFS, LDAP,
# RMI, AJP/Tomcat, WebLogic, WinRM, alt-HTTP admin panels, big-data/orchestration
# endpoints, …). De-duplicated (dict.fromkeys preserves order) so no port is
# scanned/reported twice.
EXTENDED_PORTS = list(dict.fromkeys(
    COMMON_PORTS
    + list(range(8000, 8010))                      # common alt-HTTP block
    + [
        # legacy / infra
        111, 137, 139, 389, 512, 513, 514, 587, 631, 636, 873,
        1080, 1099, 1723, 2049, 3260, 4443, 4444, 5000, 5060, 5555,
        5985, 5986, 6000, 6667,
        # app servers & admin panels (CVE-dense)
        7001, 7002, 8009, 8081, 8088, 8089, 8161, 8888, 9000, 9001,
        9043, 9060, 9091, 9418, 9999, 10000, 10250, 50000, 50070,
    ]
))


def resolve_target(target: str) -> tuple[str, Optional[str]]:
    """Return (ip, hostname)."""
    try:
        ip = socket.gethostbyname(target)
        hostname = target if ip != target else None
        return ip, hostname
    except socket.gaierror:
        return target, None


def scan_host(target: str, ports: list[int] = None, max_workers: int = 100,
              timeout: float = 2.0, on_open_port=None) -> HostResult:
    """Full host scan: resolve → ping → parallel port scan.

    on_open_port: optional callback(PortResult) invoked as each open port is found,
    so callers (e.g. the GUI bridge) can stream results live.
    """
    if ports is None:
        ports = EXTENDED_PORTS
    # De-dup so a port passed twice isn't scanned, streamed, and CVE-correlated twice.
    ports = list(dict.fromkeys(ports))

    start = time.time()
    ip, hostname = resolve_target(target)

    result = HostResult(
        target=target,
        ip=ip,
        hostname=hostname,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )

    # Parallel port scan
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(probe_port, ip, port, timeout): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            port_result = future.result()
            if port_result.state == "open":
                result.ports.append(port_result)
                if on_open_port is not None:
                    try:
                        on_open_port(port_result)
                    except Exception:
                        pass

    # UDP protocol fingerprinting (DNS, NTP, SNMP, NetBIOS, SSDP/UPnP). Probed in
    # parallel so broader UDP coverage doesn't serialize a timeout per port.
    udp_ports = [53, 123, 161, 137, 1900]
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(udp_ports)) as udp_exec:
        udp_futs = {udp_exec.submit(probe_udp_protocol, ip, p, timeout): p for p in udp_ports}
        for fut in concurrent.futures.as_completed(udp_futs):
            up = udp_futs[fut]
            try:
                res = fut.result()
            except Exception:
                res = None
            if res:
                proto, detail = res
                pr = PortResult(
                    port=up, protocol="udp", state="open",
                    service=proto, protocol_fingerprint=(detail or proto),
                )
                # Leaked device/OS/version intel (SNMP sysDescr, SSDP SERVER) →
                # parse it as a banner so CVE correlation can version-match it.
                if detail:
                    try:
                        pr.banner = parse_banner(detail, proto)
                        if pr.banner and pr.banner.product and pr.banner.version:
                            pr.detection_confidence = "high"
                        elif pr.banner and pr.banner.product:
                            pr.detection_confidence = "medium"
                    except Exception:
                        pass
                result.ports.append(pr)

    result.ports.sort(key=lambda p: p.port)
    # Only fingerprint the OS of hosts that are actually up (avoids a ping timeout
    # per dead host in CIDR sweeps).
    if result.ports:
        result.ttl = get_ttl(ip, timeout=timeout)
        result.os_guess = guess_os_from_ttl(result.ttl)
    result.scan_duration_s = round(time.time() - start, 2)

    return result


def scan_cidr(cidr: str, **kwargs) -> list[HostResult]:
    """Scan every host in a CIDR block to discover network structure and devices."""
    # Resolve hostname to IP first in case the user provided a domain
    base_target = cidr.split('/')[0]
    mask = cidr.split('/')[1] if '/' in cidr else "24"
    
    ip, _ = resolve_target(base_target)
    cidr = f"{ip}/{mask}"
        
    network = ipaddress.ip_network(cidr, strict=False)
    # Bounded enumeration: islice over the .hosts() GENERATOR so an oversized
    # range never builds a giant in-memory list (OOM/DoS). The API layer rejects
    # oversized CIDRs up front with a clear error; this caps the CLI path too.
    hosts = [str(h) for h in itertools.islice(network.hosts(), MAX_CIDR_HOSTS)]

    # Bound total concurrency. Each scan_host spawns its OWN per-port thread pool,
    # so the live thread/socket count is outer_workers × inner_workers. With the
    # old 32 outer × default 100 inner that was ~3,200 threads — enough to exhaust
    # file descriptors and fail on a /24. Cap the inner pool for CIDR sweeps and
    # keep the product bounded (≈16 × 40 = 640).
    kwargs["max_workers"] = min(kwargs.get("max_workers", 40) or 40, 40)
    outer = min(16, max(1, len(hosts)))

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=outer) as executor:
        futures = {executor.submit(scan_host, h, **kwargs): h for h in hosts}
        for future in concurrent.futures.as_completed(futures):
            try:
                r = future.result()
            except Exception:
                continue   # a single host failing must not abort the whole sweep
            if r.ports:   # only include live hosts
                results.append(r)
    return results


def to_dict(result: HostResult) -> dict:
    return asdict(result)


def _tcp_send_recv(host: str, port: int, data: bytes, timeout: float = 3.0, recv: int = 4096):
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            if data:
                sock.sendall(data)
            sock.settimeout(timeout)
            return sock.recv(recv)
    except Exception:
        return None
