"""
NetLogic - Service Misconfiguration Prober
Checks for unauthenticated access, default credentials, and dangerous service
exposures across discovered open ports. All probes are safe and read-only.
"""

import socket
import json
import base64
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Optional


# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class ServiceFinding:
    service: str
    port: int
    severity: str           # CRITICAL / HIGH / MEDIUM / LOW
    title: str
    detail: str
    evidence: str = ""
    remediation: str = ""

@dataclass
class ServiceProbeResult:
    target: str
    findings: list[ServiceFinding] = field(default_factory=list)
    probes_run: int = 0


# ─── Low-level Helpers ────────────────────────────────────────────────────────

def _tcp_send_recv(host: str, port: int, data: bytes, timeout: float = 3.0, recv: int = 4096) -> Optional[bytes]:
    """Open TCP connection, send data, return response bytes."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            if data:
                sock.sendall(data)
            sock.settimeout(timeout)
            return sock.recv(recv)
    except Exception:
        return None


def _http_get(host: str, port: int, path: str = "/", scheme: str = "http",
              timeout: float = 4.0, headers: dict = None) -> Optional[tuple]:
    """HTTP GET — returns (status_code, headers_dict, body_str) or None on error."""
    try:
        url = f"{scheme}://{host}:{port}{path}"
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(16384).decode("utf-8", errors="replace")
            return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        try:
            body = e.read(4096).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return e.code, dict(e.headers), body
    except Exception:
        return None


# ─── Service-Specific Checks ─────────────────────────────────────────────────

def check_redis_noauth(host: str, port: int = 6379, timeout: float = 3.0) -> Optional[ServiceFinding]:
    """Redis: unauthenticated access allows full data read/write and code execution."""
    resp = _tcp_send_recv(host, port, b"INFO server\r\n", timeout)
    if not resp:
        return None
    text = resp.decode("utf-8", errors="replace")
    if "redis_version" in text:
        version = next((ln.split(":", 1)[1].strip() for ln in text.splitlines()
                        if ln.startswith("redis_version:")), "")
        return ServiceFinding(
            service="redis", port=port, severity="CRITICAL",
            title="Redis — No Authentication Required",
            detail=(f"Redis {version} is fully accessible without a password. "
                    "Attackers can read/write all data, load modules for RCE, or use SLAVEOF for lateral movement."),
            evidence=f"INFO server returned redis_version:{version}",
            remediation="Set 'requirepass' in redis.conf; bind to 127.0.0.1; use Redis 6+ ACLs."
        )
    if b"NOAUTH" in resp:
        return None  # Auth enforced
    return None


def check_memcached_noauth(host: str, port: int = 11211, timeout: float = 3.0) -> Optional[ServiceFinding]:
    """Memcached: no auth, used in record-breaking DDoS amplification attacks."""
    resp = _tcp_send_recv(host, port, b"version\r\n", timeout)
    if resp and resp.strip().startswith(b"VERSION"):
        version = resp.decode("utf-8", errors="replace").strip().split()[-1]
        return ServiceFinding(
            service="memcached", port=port, severity="CRITICAL",
            title="Memcached — Exposed Without Authentication",
            detail=(f"Memcached {version} has no authentication. Full cache read/write access. "
                    "Memcached is the primary vector for UDP amplification DDoS (51,000× amplification)."),
            evidence=f"'version' command returned: VERSION {version}",
            remediation="Bind to 127.0.0.1; use firewall rules; enable SASL authentication; disable UDP."
        )
    return None


def check_mongodb_noauth(host: str, port: int = 27017, timeout: float = 3.0) -> Optional[ServiceFinding]:
    """MongoDB: wire protocol isMaster query to detect unauthenticated access."""
    # Minimal OP_QUERY packet for {isMaster: 1} against admin.$cmd
    bson_doc = b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"
    header = (
        b"\x00\x00\x00\x00"   # messageLength — filled in below
        b"\x01\x00\x00\x00"   # requestID
        b"\x00\x00\x00\x00"   # responseTo
        b"\xd4\x07\x00\x00"   # opCode 2004 OP_QUERY
        b"\x00\x00\x00\x00"   # flags
        b"admin.$cmd\x00"      # collection name
        b"\x00\x00\x00\x00"   # numberToSkip
        b"\x01\x00\x00\x00"   # numberToReturn (-1 or 1)
    ) + bson_doc
    import struct
    packet = struct.pack("<I", len(header) + 4) + header[4:]
    # Simpler: just use the full packet with length pre-calculated
    full_len = 4 + len(header)
    packet = struct.pack("<I", full_len) + header

    resp = _tcp_send_recv(host, port, packet, timeout, recv=1024)
    if resp and len(resp) > 20:
        text = resp.decode("utf-8", errors="replace")
        if any(kw in text for kw in ("ismaster", "isWritablePrimary", "maxBsonObjectSize", "localTime")):
            return ServiceFinding(
                service="mongodb", port=port, severity="CRITICAL",
                title="MongoDB — Unauthenticated Access",
                detail="MongoDB is responding to wire protocol commands without authentication. "
                       "Full database read/write access possible across all collections.",
                evidence=f"isMaster OP_QUERY received valid response ({len(resp)} bytes)",
                remediation="Launch mongod with --auth; configure users; bind to 127.0.0.1; use TLS."
            )
    return None


def check_elasticsearch_noauth(host: str, port: int = 9200, timeout: float = 4.0) -> Optional[ServiceFinding]:
    """Elasticsearch: cluster and index enumeration without credentials."""
    result = _http_get(host, port, "/", timeout=timeout)
    if not result:
        return None
    status, hdrs, body = result
    if status == 401:
        return None
    if status == 200 and ("cluster_name" in body or "elasticsearch" in body.lower()):
        cluster_name = version = ""
        try:
            data = json.loads(body)
            cluster_name = data.get("cluster_name", "")
            version = data.get("version", {}).get("number", "")
        except Exception:
            pass
        # Check if we can list indices
        idx = _http_get(host, port, "/_cat/indices?v", timeout=timeout)
        has_indices = idx and idx[0] == 200 and len(idx[2].strip()) > 5
        return ServiceFinding(
            service="elasticsearch", port=port, severity="CRITICAL",
            title="Elasticsearch — Open Access (No Authentication)",
            detail=(f"Elasticsearch cluster '{cluster_name}' v{version} is open without authentication. "
                    f"{'Index listing accessible. ' if has_indices else ''}"
                    "Full data exfiltration and arbitrary document write possible."),
            evidence=f"GET / → HTTP 200; cluster_name={cluster_name!r}; indices accessible={has_indices}",
            remediation="Enable xpack.security.enabled=true; configure TLS and user roles; restrict to private network."
        )
    return None


def check_couchdb_noauth(host: str, port: int = 5984, timeout: float = 4.0) -> Optional[ServiceFinding]:
    """CouchDB: check for unauthenticated admin API access."""
    result = _http_get(host, port, "/_all_dbs", timeout=timeout)
    if not result:
        return None
    status, _, body = result
    if status == 401:
        return None
    if status == 200 and body.strip().startswith("["):
        try:
            dbs = json.loads(body)
            db_count = len(dbs)
            db_sample = dbs[:4]
        except Exception:
            db_count, db_sample = 0, []
        return ServiceFinding(
            service="couchdb", port=port, severity="CRITICAL",
            title="CouchDB — Unauthenticated Admin Access",
            detail=f"CouchDB /_all_dbs accessible without credentials. "
                   f"{db_count} database(s) visible: {', '.join(str(d) for d in db_sample)}.",
            evidence=f"GET /_all_dbs → HTTP 200 with {db_count} databases",
            remediation="Set require_valid_user=true in local.ini; create admin credentials; restrict network access."
        )
    return None


def check_docker_noauth(host: str, port: int = 2375, timeout: float = 4.0) -> Optional[ServiceFinding]:
    """Docker daemon TCP socket — unauthenticated access = full host takeover."""
    result = _http_get(host, port, "/version", timeout=timeout)
    if not result:
        return None
    status, _, body = result
    if status == 200 and ("ApiVersion" in body or "Version" in body):
        engine_ver = api_ver = ""
        try:
            data = json.loads(body)
            engine_ver = data.get("Version", "")
            api_ver = data.get("ApiVersion", "")
        except Exception:
            pass
        return ServiceFinding(
            service="docker-api", port=port, severity="CRITICAL",
            title="Docker API — Unauthenticated TCP Exposure",
            detail=(f"Docker Engine {engine_ver} (API {api_ver}) TCP socket is exposed without TLS or auth. "
                    "Full container lifecycle control. Trivial host escape via privileged container mount."),
            evidence="GET /version returned Docker engine version without credentials",
            remediation="Never expose Docker API on TCP without mutual TLS; use Unix socket (/var/run/docker.sock) only."
        )
    return None


def check_kubernetes_noauth(host: str, port: int = 6443, timeout: float = 4.0) -> Optional[ServiceFinding]:
    """Kubernetes API server — anonymous auth bypass."""
    for scheme in ("https", "http"):
        result = _http_get(host, port, "/api", scheme=scheme, timeout=timeout)
        if not result:
            continue
        status, _, body = result
        if status == 401 or status == 403:
            return None  # Auth enforced
        if status == 200 and ("serverAddressByClientCIDRs" in body or "versions" in body or "v1" in body):
            return ServiceFinding(
                service="k8s-api", port=port, severity="CRITICAL",
                title="Kubernetes API — Anonymous Access Enabled",
                detail="Kubernetes API server allows unauthenticated /api access. "
                       "Cluster topology enumeration possible; may lead to full cluster compromise via RBAC misconfiguration.",
                evidence=f"GET {scheme}://{host}:{port}/api → HTTP 200 with API version list",
                remediation="Set --anonymous-auth=false on kube-apiserver; enforce RBAC; require client certificates."
            )
    return None


def check_etcd_noauth(host: str, port: int = 2379, timeout: float = 4.0) -> Optional[ServiceFinding]:
    """etcd: holds Kubernetes secrets, certificates, and all cluster state."""
    for path in ("/v2/keys", "/v3/cluster/member/list", "/health"):
        result = _http_get(host, port, path, timeout=timeout)
        if not result:
            continue
        status, _, body = result
        if status == 401:
            return None
        if status == 200 and body.strip():
            return ServiceFinding(
                service="etcd", port=port, severity="CRITICAL",
                title="etcd — Unauthenticated Key-Value Access",
                detail=f"etcd API accessible without auth via {path}. "
                       "Contains Kubernetes secrets, service account tokens, certificates, and full cluster state.",
                evidence=f"GET {path} → HTTP 200",
                remediation="Enable --client-cert-auth and --peer-client-cert-auth; use TLS; restrict network access."
            )
    return None


def check_consul_noauth(host: str, port: int = 8500, timeout: float = 4.0) -> Optional[ServiceFinding]:
    """Consul: service mesh control plane with full ACL bypass."""
    result = _http_get(host, port, "/v1/catalog/services", timeout=timeout)
    if not result:
        return None
    status, _, body = result
    if status == 403:
        return None
    if status == 200 and body.strip().startswith("{"):
        try:
            services = json.loads(body)
            svc_count = len(services)
            svc_sample = list(services.keys())[:5]
        except Exception:
            svc_count, svc_sample = 0, []
        return ServiceFinding(
            service="consul-http", port=port, severity="HIGH",
            title="Consul — Unauthenticated API Access",
            detail=f"Consul HTTP API accessible without ACL tokens. "
                   f"{svc_count} registered service(s): {', '.join(svc_sample)}. "
                   "Service mesh topology and health status exposed; possible secrets via KV store.",
            evidence=f"GET /v1/catalog/services → HTTP 200 with {svc_count} services",
            remediation="Enable ACL system (acl.enabled=true); generate management tokens; require tokens for all API calls."
        )
    return None


def check_prometheus_noauth(host: str, port: int = 9090, timeout: float = 4.0) -> Optional[ServiceFinding]:
    """Prometheus: unauthenticated metric and target exposure."""
    result = _http_get(host, port, "/metrics", timeout=timeout)
    if result and result[0] == 200:
        body = result[2]
        if "# HELP" in body or "# TYPE" in body:
            metric_count = body.count("# HELP")
            return ServiceFinding(
                service="prometheus", port=port, severity="MEDIUM",
                title="Prometheus — Unauthenticated /metrics Exposure",
                detail=(f"Prometheus /metrics endpoint publicly accessible ({metric_count} metric families). "
                        "May expose internal hostnames, IP addresses, credentials in labels, business KPIs, and infrastructure topology."),
                evidence=f"GET /metrics → HTTP 200 with {metric_count} metric families",
                remediation="Add authentication via reverse proxy (nginx basic auth + SSL); use --web.config.file; restrict by IP."
            )
    # Check admin API separately
    targets = _http_get(host, port, "/api/v1/targets", timeout=timeout)
    if targets and targets[0] == 200 and "activeTargets" in targets[2]:
        return ServiceFinding(
            service="prometheus", port=port, severity="HIGH",
            title="Prometheus — Unauthenticated Admin API (/api/v1/targets)",
            detail="Prometheus admin API is accessible without authentication. "
                   "Internal scrape targets, job names, and network topology exposed.",
            evidence="GET /api/v1/targets → HTTP 200 with target list",
            remediation="Restrict Prometheus admin API; add authentication proxy; firewall to monitoring VLAN only."
        )
    return None


def check_vault_noauth(host: str, port: int = 8200, timeout: float = 4.0) -> Optional[ServiceFinding]:
    """HashiCorp Vault: detect initialization/seal status — critical for secret management."""
    result = _http_get(host, port, "/v1/sys/health", timeout=timeout)
    if not result:
        return None
    status, _, body = result
    # Vault returns various codes depending on state
    if status not in (200, 429, 472, 473, 501, 503):
        return None
    initialized = sealed = None
    version = ""
    try:
        data = json.loads(body)
        initialized = data.get("initialized")
        sealed = data.get("sealed")
        version = data.get("version", "")
    except Exception:
        pass

    if initialized is False:
        return ServiceFinding(
            service="vault", port=port, severity="CRITICAL",
            title="Vault — Not Initialized (Completely Unprotected)",
            detail="HashiCorp Vault is network-exposed and not yet initialized. "
                   "An attacker can initialize Vault, capture the unseal keys, and control all future secrets.",
            evidence="GET /v1/sys/health: initialized=false",
            remediation="Initialize Vault immediately; restrict access to management networks only; audit with Vault audit backend."
        )
    if initialized and sealed is False:
        return ServiceFinding(
            service="vault", port=port, severity="HIGH",
            title=f"Vault — Unsealed and Exposed (v{version})",
            detail=f"HashiCorp Vault v{version} is unsealed and network-accessible. "
                   "While auth is required for secrets, exposure indicates poor network segmentation.",
            evidence=f"GET /v1/sys/health: initialized=true, sealed=false, version={version}",
            remediation="Restrict Vault listener to private management networks; enforce TLS with mutual auth."
        )
    return None


def check_rabbitmq_default_creds(host: str, port: int = 15672, timeout: float = 4.0) -> Optional[ServiceFinding]:
    """RabbitMQ management: try default guest:guest credentials."""
    cred_b64 = base64.b64encode(b"guest:guest").decode()
    result = _http_get(host, port, "/api/overview", timeout=timeout,
                       headers={"Authorization": f"Basic {cred_b64}"})
    if not result:
        return None
    status, _, body = result
    if status == 200 and "rabbitmq_version" in body:
        version = product = ""
        try:
            data = json.loads(body)
            version = data.get("rabbitmq_version", "")
            product = data.get("product_name", "RabbitMQ")
        except Exception:
            pass
        return ServiceFinding(
            service="rabbitmq-mgmt", port=port, severity="CRITICAL",
            title=f"RabbitMQ — Default Credentials (guest:guest)",
            detail=(f"{product} {version} management interface authenticated with default guest:guest. "
                    "Full broker control: read/publish all queues, create admin users, execute policies."),
            evidence="GET /api/overview with Authorization: Basic guest:guest → HTTP 200",
            remediation="Delete or disable the guest user; create named admin accounts; restrict management port to admin VLANs."
        )
    return None


def check_influxdb_noauth(host: str, port: int = 8086, timeout: float = 4.0) -> Optional[ServiceFinding]:
    """InfluxDB: unauthenticated time-series data access."""
    # Ping first to confirm it's InfluxDB
    ping = _http_get(host, port, "/ping", timeout=timeout)
    if not ping or ping[0] != 204:
        return None
    # Try querying without credentials
    query = _http_get(host, port, "/query?q=SHOW+DATABASES&db=_internal", timeout=timeout)
    if query and query[0] == 200 and "results" in query[2]:
        return ServiceFinding(
            service="influxdb", port=port, severity="HIGH",
            title="InfluxDB — Unauthenticated Query Access",
            detail="InfluxDB HTTP API is accessible without authentication. "
                   "Time-series data readable; may contain monitoring metrics, sensor data, or business telemetry.",
            evidence="GET /query?q=SHOW+DATABASES → HTTP 200 with database list",
            remediation="Enable auth-enabled=true in influxdb.conf; create admin user before enabling auth."
        )
    return None


def check_ftp_anonymous(host: str, port: int = 21, timeout: float = 5.0) -> Optional[ServiceFinding]:
    """FTP: attempt anonymous login — common misconfiguration enabling data exfiltration."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            sock.sendall(b"USER anonymous\r\n")
            resp1 = sock.recv(1024).decode("utf-8", errors="replace")
            if resp1.startswith("331"):
                sock.sendall(b"PASS anonymous@netlogic.scan\r\n")
                resp2 = sock.recv(1024).decode("utf-8", errors="replace")
                if resp2.startswith("230"):
                    return ServiceFinding(
                        service="ftp", port=port, severity="HIGH",
                        title="FTP — Anonymous Login Enabled",
                        detail="FTP server accepts anonymous login. Unauthenticated users can download files "
                               "and potentially upload malicious content or overwrite existing files.",
                        evidence=f"USER anonymous / PASS anonymous@... → 230 Login successful | Banner: {banner[:60]}",
                        remediation="Disable anonymous FTP; use SFTP/FTPS instead; apply strict directory permissions."
                    )
            elif resp1.startswith("230"):
                return ServiceFinding(
                    service="ftp", port=port, severity="CRITICAL",
                    title="FTP — Anonymous Login Without Password",
                    detail="FTP server accepts anonymous login with no password required.",
                    evidence=f"USER anonymous → 230 (no password prompt) | Banner: {banner[:60]}",
                    remediation="Disable anonymous FTP access immediately."
                )
    except Exception:
        pass
    return None


def check_http_admin_panels(host: str, port: int, scheme: str = "http",
                             timeout: float = 4.0) -> list[ServiceFinding]:
    """Probe well-known admin panel and sensitive file paths on HTTP services."""
    findings = []

    targets = [
        # (path, label, severity, body_keywords_that_confirm)
        ("/.env",                 "Environment File",            "CRITICAL", ["PASSWORD", "SECRET", "API_KEY", "DB_"]),
        ("/.env.backup",          "Backup Env File",             "CRITICAL", ["PASSWORD", "SECRET", "DB_"]),
        ("/.git/config",          "Git Config Exposure",         "HIGH",     ["[core]", "[remote"]),
        ("/wp-config.php.bak",    "WordPress Config Backup",     "CRITICAL", ["DB_PASSWORD", "AUTH_KEY"]),
        ("/wp-config.php~",       "WordPress Config (tilde bak)","CRITICAL", ["DB_PASSWORD", "AUTH_KEY"]),
        ("/config.php.bak",       "PHP Config Backup",           "HIGH",     ["password", "mysql", "db_"]),
        ("/database.yml",         "Rails Database Config",       "HIGH",     ["password:", "adapter:"]),
        ("/application.properties","Spring App Config",          "HIGH",     ["password", "datasource"]),
        ("/application.yml",      "Spring Config (YAML)",        "HIGH",     ["password", "datasource"]),
        ("/settings.py",          "Django Settings",             "HIGH",     ["SECRET_KEY", "PASSWORD"]),
        ("/server-status",        "Apache Server-Status",        "MEDIUM",   ["Apache", "requests currently"]),
        ("/server-info",          "Apache Server-Info",          "MEDIUM",   ["Apache", "Module"]),
        ("/manager/html",         "Tomcat Manager",              "HIGH",     []),
        ("/host-manager/html",    "Tomcat Host Manager",         "HIGH",     []),
        ("/jmx-console",          "JBoss JMX Console",           "CRITICAL", ["JMX", "MBean"]),
        ("/web-console",          "JBoss Web Console",           "CRITICAL", ["jboss", "JBoss"]),
        ("/adminer.php",          "Adminer DB Tool",             "HIGH",     ["Adminer", "adminer"]),
        ("/phpmyadmin",           "phpMyAdmin",                  "HIGH",     ["phpMyAdmin", "pma_"]),
        ("/pma",                  "phpMyAdmin (alt path)",       "HIGH",     ["phpMyAdmin", "pma_"]),
        ("/actuator",             "Spring Actuator Root",        "HIGH",     ["links", "self", "actuator"]),
        ("/actuator/env",         "Spring Actuator /env",        "CRITICAL", ["propertySources", "systemEnvironment"]),
        ("/actuator/heapdump",    "Spring Actuator /heapdump",   "CRITICAL", []),
        ("/actuator/httptrace",   "Spring Actuator /httptrace",  "MEDIUM",   ["traces", "request"]),
        ("/actuator/mappings",    "Spring Actuator /mappings",   "MEDIUM",   ["mappings", "dispatcherServlets"]),
        ("/swagger-ui.html",      "Swagger UI",                  "LOW",      ["swagger", "Swagger"]),
        ("/swagger-ui/",          "Swagger UI (v3)",             "LOW",      ["swagger", "Swagger"]),
        ("/api-docs",             "OpenAPI Docs",                "LOW",      ["swagger", "openapi", "paths"]),
        ("/v2/api-docs",          "Swagger v2 Docs",             "LOW",      ["swagger", "paths", "definitions"]),
        ("/graphql",              "GraphQL Endpoint",            "MEDIUM",   []),
        ("/api/graphql",          "GraphQL (alt)",               "MEDIUM",   []),
        ("/__debug__/",           "Django Debug Toolbar",        "HIGH",     ["djdt", "Django"]),
        ("/trace",                "Spring Trace Endpoint",       "MEDIUM",   ["timestamp", "info"]),
    ]

    for path, label, base_sev, keywords in targets:
        result = _http_get(host, port, path, scheme=scheme, timeout=timeout)
        if not result:
            continue
        status, hdrs, body = result
        # Only care about 200, 401 (for auth-protected panels)
        if status == 404 or status in (301, 302, 303, 307, 308):
            continue
        if status not in (200, 401, 403):
            continue

        if status in (401, 403) and path not in ("/manager/html", "/host-manager/html",
                                                   "/jmx-console", "/web-console"):
            continue  # Auth is enforced — expected

        # Confirm by body keywords
        if keywords:
            body_lower = body.lower()
            confirmed = any(kw.lower() in body_lower for kw in keywords)
        else:
            confirmed = status == 200 and len(body) > 20

        if not confirmed and base_sev in ("CRITICAL", "HIGH"):
            continue  # False positive prevention — require content confirmation

        sev = base_sev
        if path == "/.env" and status == 200:
            has_creds = any(kw.lower() in body.lower() for kw in ["password", "secret", "key", "token"])
            sev = "CRITICAL" if has_creds else "MEDIUM"
            detail = ("Environment file is publicly accessible and contains sensitive values." if has_creds
                      else "Environment file is publicly accessible (no obvious credentials detected).")
        elif path == "/actuator/heapdump" and status == 200:
            detail = ("Spring Boot /actuator/heapdump endpoint accessible. JVM heap dump download gives "
                      "attackers memory analysis capability to extract credentials, session tokens, and encryption keys.")
        elif path in ("/manager/html", "/host-manager/html"):
            if status == 200:
                sev = "CRITICAL"
                detail = f"Tomcat {label} accessible without authentication. WAR deployment = full server code execution."
            else:
                detail = f"Tomcat {label} exists and is protected by Basic auth — susceptible to brute-force."
        else:
            detail = f"{label} is accessible at {path}."
            if path == "/.git/config":
                detail += " Git repository may be fully downloadable via /.git/ path traversal."
            elif "graphql" in path:
                detail += " Run introspection query (__schema) to enumerate full API schema."

        findings.append(ServiceFinding(
            service=f"http", port=port,
            severity=sev, title=f"{label} Exposed",
            detail=detail,
            evidence=f"GET {path} → HTTP {status} ({len(body)} bytes)",
            remediation=f"Restrict access to {path}; require authentication; add to deny rules in web server config."
        ))

    return findings


# ─── Main Probe Orchestrator ──────────────────────────────────────────────────

_PORT_CHECKS = {
    6379:  ("redis",            check_redis_noauth),
    11211: ("memcached",        check_memcached_noauth),
    27017: ("mongodb",          check_mongodb_noauth),
    9200:  ("elasticsearch",    check_elasticsearch_noauth),
    5984:  ("couchdb",          check_couchdb_noauth),
    2375:  ("docker-api",       check_docker_noauth),
    6443:  ("k8s-api",          check_kubernetes_noauth),
    2379:  ("etcd",             check_etcd_noauth),
    8500:  ("consul-http",      check_consul_noauth),
    9090:  ("prometheus",       check_prometheus_noauth),
    8200:  ("vault",            check_vault_noauth),
    15672: ("rabbitmq-mgmt",    check_rabbitmq_default_creds),
    8086:  ("influxdb",         check_influxdb_noauth),
    21:    ("ftp",              check_ftp_anonymous),
}

_HTTP_SERVICES = {
    "http", "https", "http-alt", "https-alt", "grafana", "kibana",
    "consul-http", "vault", "prometheus", "rabbitmq-mgmt", "solr",
    "neo4j-http", "couchdb", "influxdb",
}

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def probe_services(target: str, ports: list, timeout: float = 4.0) -> ServiceProbeResult:
    """
    Run misconfiguration and exposure checks against all discovered open ports.
    `ports` is a list of PortResult objects from scanner.py.
    """
    result = ServiceProbeResult(target=target)
    seen_ports = set()
    http_ports_probed = set()

    for port_result in ports:
        port = port_result.port
        service = port_result.service or ""

        # Port-based service checks
        if port in _PORT_CHECKS and port not in seen_ports:
            _, check_fn = _PORT_CHECKS[port]
            seen_ports.add(port)
            result.probes_run += 1
            finding = check_fn(target, port, timeout=timeout)
            if finding:
                result.findings.append(finding)

        # Service-name-based fallback for non-standard ports
        for std_port, (svc_name, check_fn) in _PORT_CHECKS.items():
            if service == svc_name and port != std_port and port not in seen_ports:
                seen_ports.add(port)
                result.probes_run += 1
                finding = check_fn(target, port, timeout=timeout)
                if finding:
                    result.findings.append(finding)
                break

        # HTTP admin panel probing
        if service in _HTTP_SERVICES and port not in http_ports_probed:
            scheme = "https" if (port_result.tls or port in (443, 8443, 8444)) else "http"
            http_findings = check_http_admin_panels(target, port, scheme=scheme, timeout=timeout)
            result.findings.extend(http_findings)
            result.probes_run += len(http_findings) + 1
            http_ports_probed.add(port)

    result.findings.sort(key=lambda f: _SEV_ORDER.get(f.severity, 5))
    return result
