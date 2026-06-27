"""
NetLogic — Request correlation ID + structured audit logging middleware.

Every request receives a unique X-Request-ID header (echoed back in the
response).  Security-sensitive events (token exchanges, registrations, job
creation) are logged as structured JSON lines to the `netlogic.audit` logger
so they can be shipped to a SIEM without parsing free-form text.

Usage
─────
    from api.middleware.audit import AuditMiddleware
    app.add_middleware(AuditMiddleware)

    # In a route to record a security event:
    from api.middleware.audit import audit_log
    audit_log("token_exchange", org_id=org_id, ip=request.client.host)
"""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone

# Control characters (incl. newline / carriage return) that must never appear
# verbatim in a log value: they enable log-injection / forged-record attacks
# when records are read by line-oriented tooling. We strip the C0 range plus
# DEL and the C1 range.
_CONTROL_CHARS = {c: None for c in range(0x20)}
_CONTROL_CHARS.update({c: None for c in range(0x7F, 0xA0)})
# Keep ordinary horizontal tab — it is benign and useful in messages.
_CONTROL_CHARS.pop(0x09, None)

# Hard cap on a single field's length to bound log/SIEM payload size from
# attacker-controlled fields (e.g. a giant target/hostname).
_MAX_FIELD_LEN = 1024


def _sanitize(value):
    """Recursively strip control chars from user-controlled log values."""
    if isinstance(value, str):
        cleaned = value.translate(_CONTROL_CHARS)
        if len(cleaned) > _MAX_FIELD_LEN:
            cleaned = cleaned[:_MAX_FIELD_LEN] + "...[truncated]"
        return cleaned
    if isinstance(value, dict):
        return {_sanitize(k): _sanitize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize(v) for v in value]
    return value

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# ── Context variable so routes can read the current request_id ────────────────
_request_id_var: ContextVar[str] = ContextVar("request_id", default="")

_audit_log = logging.getLogger("netlogic.audit")


def audit_log(event: str, severity: str = "info", **kwargs) -> None:
    """Emit a structured audit log line for a security-relevant event."""
    record = {
        "event":      _sanitize(event),
        "severity":    _sanitize(severity),
        "request_id": _sanitize(_request_id_var.get("")),
        "ts":         time.time(),
        "iso_timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname":   os.getenv("HOSTNAME", "unknown"),
        **{_sanitize(k): _sanitize(v) for k, v in kwargs.items()},
    }

    # Log to appropriate level based on severity
    if severity == "critical":
        _audit_log.critical(json.dumps(record))
    elif severity == "error":
        _audit_log.error(json.dumps(record))
    elif severity == "warning":
        _audit_log.warning(json.dumps(record))
    else:
        _audit_log.info(json.dumps(record))

    # Send to SIEM if configured. Defense-in-depth: only ship over http(s) so a
    # mistyped/hostile endpoint (file://, gopher://, …) can never be handed to
    # urlopen and turned into a local-file read / SSRF primitive.
    siem_endpoint = os.getenv("NETLOGIC_SIEM_ENDPOINT")
    if siem_endpoint and siem_endpoint.strip().lower().startswith(("http://", "https://")):
        _send_to_siem(record, siem_endpoint.strip())


# SIEM shipping uses ONE long-lived worker draining a bounded queue, rather than
# spawning a thread per audit event (a thread-exhaustion vector under a log
# flood). The queue caps memory; when full, records are dropped and counted.
_SIEM_QUEUE_MAX = 1000
_siem_queue: "queue.Queue | None" = None
_siem_lock = threading.Lock()
_siem_dropped = 0


def _siem_worker(q: "queue.Queue") -> None:
    """Drain audit records and ship them over one reused HTTP connection."""
    log = logging.getLogger("netlogic.audit")
    try:
        import requests  # noqa: PLC0415
        session = requests.Session()

        def _post(url, body):
            session.post(url, json=body, timeout=5)
    except Exception:
        import urllib.request  # noqa: PLC0415

        def _post(url, body):
            req = urllib.request.Request(
                url, data=json.dumps(body, default=str).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            urllib.request.urlopen(req, timeout=5).close()

    while True:
        record, endpoint = q.get()
        try:
            _post(endpoint, record)
        except Exception as e:
            log.error("Failed to send to SIEM: %s", e)
        finally:
            q.task_done()


def _ensure_siem_worker() -> "queue.Queue":
    """Lazily start the single SIEM worker thread. Returns its queue."""
    global _siem_queue
    if _siem_queue is None:
        with _siem_lock:
            if _siem_queue is None:
                q: "queue.Queue" = queue.Queue(maxsize=_SIEM_QUEUE_MAX)
                threading.Thread(target=_siem_worker, args=(q,),
                                 name="netlogic-siem", daemon=True).start()
                _siem_queue = q
    return _siem_queue


def _send_to_siem(record: dict, endpoint: str) -> None:
    """Enqueue an audit record for the background SIEM worker (non-blocking).

    Bounded queue + one worker thread: never blocks the request path and never
    spawns unbounded threads. A full queue drops the record (counted) instead.
    """
    global _siem_dropped
    q = _ensure_siem_worker()
    try:
        q.put_nowait((record, endpoint))
    except queue.Full:
        _siem_dropped += 1
        if _siem_dropped % 100 == 1:
            logging.getLogger("netlogic.audit").warning(
                "SIEM queue full — dropped %d audit record(s) total", _siem_dropped)


class AuditMiddleware(BaseHTTPMiddleware):
    """
    1. Generates or propagates a unique X-Request-ID for every request.
    2. Logs every request/response pair at DEBUG level with timing.
    3. Sets the request_id context variable so routes can call audit_log().
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        # The inbound X-Request-ID is attacker-controlled and gets both echoed
        # into a response header and written to logs, so sanitize control chars
        # (CR/LF -> header/log injection) and cap its length.
        raw_req_id = request.headers.get("X-Request-ID")
        if raw_req_id:
            req_id = _sanitize(raw_req_id)[:128].strip() or uuid.uuid4().hex
        else:
            req_id = uuid.uuid4().hex
        _request_id_var.set(req_id)

        start = time.monotonic()
        response = await call_next(request)
        elapsed_ms = round((time.monotonic() - start) * 1000, 1)

        response.headers["X-Request-ID"] = req_id

        logging.getLogger("netlogic.access").debug(
            json.dumps({
                "method":     _sanitize(request.method),
                "path":       _sanitize(request.url.path),
                "status":     response.status_code,
                "elapsed_ms": elapsed_ms,
                "request_id": req_id,
                "ip":         request.client.host if request.client else "",
            })
        )

        return response
