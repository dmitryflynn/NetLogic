"""
NetLogic - Core Scanner Engine
Performs active port scanning, service fingerprinting, and banner grabbing.
"""

import socket
import ssl
import concurrent.futures
import json
import re
import sys
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
    2375: "docker-api", 2379: "etcd", 2380: "etcd",
    3000: "grafana",    5601: "kibana", 5672: "amqp",
    5984: "couchdb",    7474: "neo4j-http", 8200: "vault",
    8300: "consul-rpc", 8500: "consul-http", 8983: "solr",
    9090: "prometheus", 9092: "kafka", 9300: "elasticsearch",
    15672: "rabbitmq-mgmt",
}

PROBES = {
    "http":    b"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NetLogic/2.0\r\nConnection: close\r\n\r\n",
    "ftp":     None,   
    "ssh":     None,
    "smtp":    b"HELO netlogic.local\r\n",
    "pop3":    None,
    "imap":    None,
    "redis":   b"INFO server\r\n",
    "mysql":   b"\x00\x00\x00\x01", # Trigger error to see version in error msg
    "postgresql": b"\x00\x00\x00\x08\x04\xd2\x16\x2f", # SSLRequest
    "mongodb": b"\x41\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00"
               b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    "memcached":       b"version\r\n",
    "zookeeper":       b"srvr\r\n",
    "docker-api":      b"GET /version HTTP/1.0\r\nHost: {host}\r\n\r\n",
}

VERSION_PATTERNS = [
    # Multi-line/complex SSH
    (r"SSH-[21]\.\d+-OpenSSH[_\s]([\d.]+[p\d]*)", "openssh"),
    (r"SSH-(\S+)", "ssh"),
    # HTTP Side-channels
    (r"Server:\s*([^\r\n]+)", "http"),
    (r"X-Powered-By:\s*([^\r\n]+)", "web-framework"),
    (r"X-AspNet-Version:\s*([\d.]+)", "asp.net"),
    (r"X-Generator:\s*([^\r\n]+)", "cms"),
    # Databases
    (r"(\d+\.\d+\.\d+)-MariaDB", "mariadb"),
    (r"(\d+\.\d+\.\d+)-MySQL", "mysql"),
    (r"mysql_native_password", "mysql"), # Heuristic: if no version but this string, it's MySQL
    (r"PostgreSQL.*([\d.]+)", "postgresql"),
    # Others
    (r"redis_version:(\S+)", "redis"),
    (r"vsftpd\s+([\d.]+)", "vsftpd"),
    (r"ProFTPD\s+([\d.]+)", "proftpd"),
    (r"Pure-FTPd\s+([\d.]+)", "pure-ftpd"),
    (r"Zookeeper version:\s*([\d.]+)", "zookeeper"),
]


def parse_banner(raw: str, service: str) -> ServiceBanner:
    """Extract product/version using multi-layered heuristic analysis."""
    b = ServiceBanner(raw=raw[:4096]) # Increased capture for deep response analysis
    
    # 1. HTTP/Web Specific Deep Analysis
    if service in ("http", "https", "http-alt", "https-alt") or "HTTP/" in raw:
        # Check standard Server header first
        m = re.search(r"^Server:\s*([^\r\n]+)", raw, re.I | re.M)
        if m:
            b.product = m.group(1).strip()
            # Split product from version if possible (e.g. Apache/2.4.41)
            if "/" in b.product:
                parts = b.product.split("/", 1)
                b.product = parts[0].strip()
                b.version = parts[1].strip()
        
        # 2. Side-channel Inference (Fallback if Server is generic or missing)
        if not b.version:
            # Check Framework headers
            m = re.search(r"^X-Powered-By:\s*([^\r\n]+)", raw, re.I | re.M)
            if m:
                b.extra = f"framework:{m.group(1).strip()}"
                # Many frameworks include versions here
                vm = re.search(r"/([\d.]+)", m.group(1))
                if vm: b.version = vm.group(1)
            
            # Check CMS markers
            m = re.search(r"^X-Generator:\s*([^\r\n]+)", raw, re.I | re.M)
            if m:
                b.product = b.product or "cms"
                vm = re.search(r"([\d.]+)", m.group(1))
                if vm: b.version = vm.group(1)

    # 3. Global Regex Library
    for pattern, product in VERSION_PATTERNS:
        m = re.search(pattern, raw, re.I)
        if m:
            # If the regex has a capture group, use it as the version
            try:
                b.version = b.version or m.group(1).strip()
            except IndexError:
                pass
            b.product = b.product or product
            break
            
    # 4. Accuracy Refinement: If product is "http" but we have better info, prefer it
    if b.product == "http" and b.extra and "framework:" in b.extra:
        b.product = b.extra.split(":")[1].split("/")[0]

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
                    for entry in cert.get("subject", []):
                        for key, val in entry:
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
            sock.settimeout(timeout)
            
            # Robust collection of banner data
            chunks = []
            while True:
                data = sock.recv(1024)
                if not data: break
                chunks.append(data)
                if len(b"".join(chunks)) > 4096: break
            raw_banner = b"".join(chunks)
        except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
            pass
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except:
                pass

        if raw_banner:
            try:
                banner_text = raw_banner.decode("utf-8", errors="replace")
                result.banner = parse_banner(banner_text, service_name)
            except Exception:
                pass

    except (ConnectionRefusedError, OSError):
        result.state = "closed"
    except (socket.timeout, TimeoutError):
        result.state = "filtered"
    except Exception:
        result.state = "closed"

    # TLS detection - only for open ports that might have TLS
    if result.state == "open":
        if port in (443, 8443, 993, 995, 465, 636, 5671, 5986):
            try:
                tls_ok, cn = tls_probe(host, port, timeout=timeout)
                if tls_ok:
                    result.tls = True
                    result.tls_cert_cn = cn
            except Exception:
                pass

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
    5601, 5672, 5984, 6379, 6443, 7474, 8080, 8200, 8443, 8500, 8983,
    9090, 9200, 9300, 9092, 11211, 15672, 2181, 2375, 2376, 2379, 3000,
    27017,
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
    """Scan every host in a CIDR block to discover network structure and devices."""
    # Resolve hostname to IP first in case the user provided a domain
    base_target = cidr.split('/')[0]
    mask = cidr.split('/')[1] if '/' in cidr else "24"
    
    ip, _ = resolve_target(base_target)
    cidr = f"{ip}/{mask}"
        
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
