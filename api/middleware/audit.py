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
import time
import uuid
from contextvars import ContextVar

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# ── Context variable so routes can read the current request_id ────────────────
_request_id_var: ContextVar[str] = ContextVar("request_id", default="")

_audit_log = logging.getLogger("netlogic.audit")


def audit_log(event: str, **kwargs) -> None:
    """Emit a structured audit log line for a security-relevant event."""
    record = {
        "event":      event,
        "request_id": _request_id_var.get(""),
        "ts":         time.time(),
        **kwargs,
    }
    _audit_log.info(json.dumps(record))


class AuditMiddleware(BaseHTTPMiddleware):
    """
    1. Generates or propagates a unique X-Request-ID for every request.
    2. Logs every request/response pair at DEBUG level with timing.
    3. Sets the request_id context variable so routes can call audit_log().
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        req_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        _request_id_var.set(req_id)

        start = time.monotonic()
        response = await call_next(request)
        elapsed_ms = round((time.monotonic() - start) * 1000, 1)

        response.headers["X-Request-ID"] = req_id

        logging.getLogger("netlogic.access").debug(
            json.dumps({
                "method":     request.method,
                "path":       request.url.path,
                "status":     response.status_code,
                "elapsed_ms": elapsed_ms,
                "request_id": req_id,
                "ip":         request.client.host if request.client else "",
            })
        )

        return response
