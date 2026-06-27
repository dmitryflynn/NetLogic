"""Executes verification tests against a target host:port and captures evidence."""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class VerificationResult:
    cve_id: str
    host: str
    port: int
    protocol: str
    success: bool
    status_code: Optional[int] = None
    response_body: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    evidence: str = ""
    duration_ms: float = 0.0
    error: str = ""


def _build_http_request(method: str, path: str, host: str, headers: Optional[dict[str, str]] = None,
                        body: Optional[str] = None) -> bytes:
    req = f"{method} {path} HTTP/1.0\r\nHost: {host}\r\n"
    if headers:
        for k, v in headers.items():
            req += f"{k}: {v}\r\n"
    if body:
        req += f"Content-Length: {len(body.encode())}\r\n"
    req += "Connection: close\r\n\r\n"
    if body:
        req += body
    return req.encode()


def _parse_http_response(raw: bytes) -> tuple[Optional[int], dict[str, str], str]:
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        text = raw.decode("latin-1", errors="replace")
    status = None
    headers: dict[str, str] = {}
    body = ""

    lines = text.split("\r\n")
    for i, line in enumerate(lines):
        if i == 0 and line.startswith("HTTP/"):
            parts = line.split(" ", 2)
            if len(parts) >= 2:
                try:
                    status = int(parts[1])
                except ValueError:
                    pass
        elif ":" in line and i > 0:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
        elif line == "" and i > 0:
            body = "\r\n".join(lines[i + 1:])
            break

    return status, headers, body


def _tcp_send_recv(host: str, port: int, payload: bytes, timeout: float = 5.0,
                   use_tls: bool = False) -> tuple[Optional[bytes], float, str]:
    start = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    tls.settimeout(timeout)
                    tls.sendall(payload)
                    resp = tls.recv(65536)
            else:
                sock.settimeout(timeout)
                sock.sendall(payload)
                resp = sock.recv(65536)
        elapsed = (time.time() - start) * 1000
        return resp, elapsed, ""
    except socket.timeout:
        return None, (time.time() - start) * 1000, "timeout"
    except ConnectionRefusedError:
        return None, (time.time() - start) * 1000, "connection refused"
    except Exception as e:
        return None, (time.time() - start) * 1000, str(e)[:120]


def run_test(plan: dict, host: str) -> VerificationResult:
    """Execute a single verification plan against *host*.

    *plan* is a dict from the AI planner with keys:
      cve_id, protocol, method, path, headers, body, expected_status, expected_body_patterns
    """
    cve_id = plan.get("cve_id", "unknown")
    port = plan.get("port", 80)
    use_tls = plan.get("tls", False)
    method = plan.get("method", "GET")
    path = plan.get("path", "/")
    headers = plan.get("headers") or {}
    body = plan.get("body")

    result = VerificationResult(cve_id=cve_id, host=host, port=port,
                                protocol="https" if use_tls else "http")

    payload = _build_http_request(method, path, host, headers, body)
    raw, elapsed, err = _tcp_send_recv(host, port, payload, use_tls=use_tls)
    result.duration_ms = elapsed

    if err:
        result.error = err
        if err == "connection refused":
            result.evidence = f"Port {port} closed — service may not be running"
        else:
            result.evidence = f"Test failed: {err}"
        return result

    if raw is None:
        result.evidence = "No response received"
        return result

    status, resp_headers, resp_body = _parse_http_response(raw)
    result.status_code = status
    result.response_headers = resp_headers
    result.response_body = resp_body[:2000]

    # Build evidence string
    ev = f"{method} {path} → HTTP {status}"
    if resp_headers.get("content-length"):
        ev += f" ({resp_headers['content-length']}b)"
    result.evidence = ev

    # Check expected status
    expected_statuses = plan.get("expected_status") or []
    expected_patterns = plan.get("expected_body_patterns") or []

    if expected_statuses:
        if status in expected_statuses:
            result.success = True
            result.evidence += f" — hit expected status {status}"
        else:
            result.success = False
            result.evidence += f" — expected status {expected_statuses}, got {status}"
    else:
        # No expected status specified — non-404 is suspicious
        if status and status not in (404,):
            result.success = True
            result.evidence += f" — non-404 response ({status}) may indicate exposure"

    # Check body patterns
    if expected_patterns and result.success:
        body_lower = resp_body.lower()
        matched = [p for p in expected_patterns if p.lower() in body_lower]
        if matched:
            result.evidence += f" — body matched patterns: {matched}"
        else:
            result.success = False
            result.evidence += " — no expected body patterns matched"

    return result
