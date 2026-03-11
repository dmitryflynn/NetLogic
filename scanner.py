"""
NetRecon - Core Scanner Engine
Performs active port scanning, service fingerprinting, and banner grabbing.
"""

import socket
import ssl
import concurrent.futures
import json
import re
import struct
import time
from dataclasses import dataclass, field, asdict
from typing import Optional
import ipaddress


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
}

PROBES = {
    "http":    b"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    "ftp":     None,   # banner grab only
    "ssh":     None,
    "smtp":    None,
    "pop3":    None,
    "imap":    None,
    "redis":   b"INFO server\r\n",
    "mysql":   None,
    "mongodb": b"\x41\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00"
               b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
}

VERSION_PATTERNS = [
    (r"SSH-(\S+)", "ssh"),
    (r"220[- ](\S+\s+\S+)", "smtp"),
    (r"Server:\s*([^\r\n]+)", "http"),
    (r"redis_version:(\S+)", "redis"),
    (r"(\d+\.\d+\.\d+)-MariaDB", "mysql"),
    (r"OpenSSH[_\s]([\d.]+[p\d]*)", "ssh"),
    (r"vsftpd\s+([\d.]+)", "ftp"),
    (r"ProFTPD\s+([\d.]+)", "ftp"),
]


def parse_banner(raw: str, service: str) -> ServiceBanner:
    """Extract product/version from raw banner text."""
    b = ServiceBanner(raw=raw[:512])
    for pattern, svc in VERSION_PATTERNS:
        m = re.search(pattern, raw, re.IGNORECASE)
        if m:
            b.version = m.group(1).strip()
            b.product = svc
            break
    # HTTP-specific
    if "Server:" in raw:
        m = re.search(r"Server:\s*([^\r\n]+)", raw)
        if m:
            b.product = m.group(1).strip()
    return b


def tls_probe(host: str, port: int, timeout: float = 3.0):
    """Attempt TLS handshake, return (success, common_name)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                cn = None
                if cert:
                    for field in cert.get("subject", []):
                        for key, val in field:
                            if key == "commonName":
                                cn = val
                return True, cn
    except Exception:
        return False, None


def probe_port(host: str, port: int, timeout: float = 2.0) -> PortResult:
    """Connect to a port, identify service, grab banner."""
    t0 = time.perf_counter()
    result = PortResult(port=port, protocol="tcp", state="closed")
    service_name = SERVICE_MAP.get(port, "unknown")

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        result.state = "open"
        result.service = service_name
        result.response_time_ms = (time.perf_counter() - t0) * 1000

        raw_banner = b""
        try:
            probe = PROBES.get(service_name)
            if probe:
                probe_data = probe.replace(b"{host}", host.encode()) if b"{host}" in probe else probe
                sock.sendall(probe_data)
            sock.settimeout(2.0)
            raw_banner = sock.recv(4096)
        except Exception:
            pass
        sock.close()

        if raw_banner:
            result.banner = parse_banner(raw_banner.decode("utf-8", errors="replace"), service_name)

        # TLS detection
        if port in (443, 8443, 993, 995, 465) or (not raw_banner and port > 0):
            tls_ok, cn = tls_probe(host, port)
            if tls_ok:
                result.tls = True
                result.tls_cert_cn = cn

    except (ConnectionRefusedError, OSError):
        result.state = "closed"
    except socket.timeout:
        result.state = "filtered"

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


def ping_host(host: str, timeout: float = 2.0) -> Optional[int]:
    """ICMP echo using raw socket — requires root. Fallback to connect-ping."""
    try:
        # Try a cheap TCP connect-based liveness check on port 80 or 443
        for port in (80, 443, 22, 3389):
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    return None   # alive but no TTL
            except (ConnectionRefusedError, OSError):
                return None       # port refused = host alive
            except socket.timeout:
                continue
    except Exception:
        pass
    return None


# ─── Main Scan Orchestrator ──────────────────────────────────────────────────────

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 9200, 27017, 11211, 2181, 6443, 2376,
]

EXTENDED_PORTS = COMMON_PORTS + list(range(8000, 8010)) + [4443, 9000, 9090, 9300, 10250]


def resolve_target(target: str) -> tuple[str, Optional[str]]:
    """Return (ip, hostname)."""
    try:
        ip = socket.gethostbyname(target)
        hostname = target if ip != target else None
        return ip, hostname
    except socket.gaierror:
        return target, None


def scan_host(target: str, ports: list[int] = None, max_workers: int = 100,
              timeout: float = 2.0) -> HostResult:
    """Full host scan: resolve → ping → parallel port scan."""
    if ports is None:
        ports = EXTENDED_PORTS

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

    result.ports.sort(key=lambda p: p.port)
    result.scan_duration_s = round(time.time() - start, 2)
    result.os_guess = guess_os_from_ttl(result.ttl)

    return result


def scan_cidr(cidr: str, **kwargs) -> list[HostResult]:
    """Scan every host in a CIDR block (e.g. 192.168.1.0/24)."""
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in network.hosts()]
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        futures = {executor.submit(scan_host, h, **kwargs): h for h in hosts}
        for future in concurrent.futures.as_completed(futures):
            r = future.result()
            if r.ports:   # only include live hosts
                results.append(r)
    return results


def to_dict(result: HostResult) -> dict:
    return asdict(result)
