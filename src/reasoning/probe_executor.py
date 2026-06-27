"""
ProbeExecutor — real, read-only network execution for the Phase 3 kernel.

See the Phase 3 Activation plan §1. The ExecutionKernel orchestrates and validates; this is
the one component that actually touches the network, and it does so ONLY through existing,
read-only sensor backends (header audit, TLS, DNS, banner grab, web/stack fingerprint). It
maps a validated `ProbeSpec` (carrying its primitive name in `request_spec`) to a sensor call
and returns a structured `ExecutionResult`. Every backend is bounded and fail-soft; nothing
here writes, authenticates, brute-forces, or exploits.
"""
from __future__ import annotations

import logging
import time

from src.reasoning.probe_plan import ProbeSpec
from src.reasoning.trace import ExecutionResult

log = logging.getLogger("netlogic.reasoning.executor")


class ProbeExecutor:
    """Callable `(ProbeSpec) -> ExecutionResult`. Read-only sensor backends only."""

    def __call__(self, spec: ProbeSpec) -> ExecutionResult:
        primitive = str((spec.request_spec or {}).get("primitive", "")).lower()
        host = spec.target_host
        port = int(spec.target_port or 0)
        timeout = float(spec.timeout_s or 5.0)
        started = time.time()
        try:
            if not host:
                return ExecutionResult(success=False, error="no target host")
            if primitive in ("http_head", "http_get"):
                result = self._http(host, port, spec.tls, timeout)
            elif primitive == "tls_connect":
                result = self._tls(host, port or 443)
            elif primitive == "dns_lookup":
                result = self._dns(host)
            elif primitive in ("service_banner", "port_scan"):
                result = self._banner(host, port, timeout)
            elif primitive in ("web_fingerprint", "stack_fingerprint"):
                result = self._web(host, port, spec.tls)
            else:
                result = ExecutionResult(success=False,
                                         error=f"no read-only backend for primitive {primitive!r}")
        except Exception as exc:  # noqa: BLE001 — a backend error is a failed probe, not a crash
            result = ExecutionResult(success=False, error=str(exc))
        result.latency_ms = round((time.time() - started) * 1000, 1)
        return result

    # ── Read-only backends ────────────────────────────────────────────────────────
    @staticmethod
    def _http(host: str, port: int, tls: bool, timeout: float) -> ExecutionResult:
        from src.header_audit import fetch_headers  # noqa: PLC0415
        scheme = "https" if tls or port in (443, 8443) else "http"
        netloc = host if port in (0, 80, 443) else f"{host}:{port}"
        headers, status = fetch_headers(f"{scheme}://{netloc}/", timeout=timeout)
        if status in (None, -1) and not headers:
            return ExecutionResult(success=False, error="no HTTP response", status_code=status)
        server = headers.get("server") or headers.get("Server") or ""
        return ExecutionResult(success=True, status_code=status, data=dict(headers),
                               evidence=f"HTTP {status} server={server}".strip())

    @staticmethod
    def _tls(host: str, port: int) -> ExecutionResult:
        from src.tls_analyzer import probe_protocols  # noqa: PLC0415
        supported, deprecated = probe_protocols(host, port)
        if not supported and not deprecated:
            return ExecutionResult(success=False, error="no TLS handshake")
        return ExecutionResult(success=True,
                               data={"protocols": supported, "deprecated": deprecated},
                               evidence=f"TLS supported={','.join(supported)}")

    @staticmethod
    def _dns(host: str) -> ExecutionResult:
        from src.dns_security import check_spf  # noqa: PLC0415
        spf = check_spf(host)
        record = getattr(spf, "record", "") or ""
        present = bool(getattr(spf, "present", False) or record)
        return ExecutionResult(success=present, data={"spf": record},
                               evidence=f"SPF: {record}" if record else "no SPF record")

    @staticmethod
    def _banner(host: str, port: int, timeout: float) -> ExecutionResult:
        from src.scanner import probe_port  # noqa: PLC0415
        pr = probe_port(host, port or 0, timeout=timeout)
        state = getattr(pr, "state", "")
        banner = getattr(getattr(pr, "banner", None), "raw", "") or ""
        return ExecutionResult(success=(state == "open"),
                               data={"state": state, "service": getattr(pr, "service", "")},
                               evidence=(banner[:300] or f"port {port} {state}"))

    @staticmethod
    def _web(host: str, port: int, tls: bool) -> ExecutionResult:
        from src.web_fingerprint import fingerprint_web  # noqa: PLC0415
        scheme = "https" if tls or port in (443, 8443) else "http"
        fp = fingerprint_web(host, port or (443 if scheme == "https" else 80), scheme=scheme)
        techs = getattr(fp, "technologies", None) or getattr(fp, "generator", "") or ""
        return ExecutionResult(success=bool(techs), data={"fingerprint": str(techs)[:500]},
                               evidence=f"web fingerprint: {str(techs)[:200]}")
