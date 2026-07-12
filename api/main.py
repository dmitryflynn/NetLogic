"""
NetLogic API — FastAPI application entry point.

Launched by `netlogic --gui`, which serves this app (API + the built React
dashboard) and opens the browser. That is the supported way to run the web app;
this module is not meant to be started directly.

Interactive docs available at http://localhost:8000/docs
"""

from __future__ import annotations

import os
import sys
import threading
import webbrowser
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

# ── Path bootstrap ────────────────────────────────────────────────────────────
# Ensure the project root (parent of api/) is on sys.path so that `from src.x`
# imports work regardless of the working directory used to launch uvicorn.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# ── Dashboard paths ───────────────────────────────────────────────────────────
_DIST_DIR   = Path(_PROJECT_ROOT) / "dashboard" / "dist"
_INDEX_HTML = _DIST_DIR / "index.html"

# ── Deferred imports (after path bootstrap) ───────────────────────────────────
from api.routes import auth, health, jobs, agents, license as license_route, settings as settings_route  # noqa: E402
from api.middleware.audit import AuditMiddleware  # noqa: E402


# ── Security-headers middleware ────────────────────────────────────────────────

# ── Request size limiting middleware ────────────────────────────────────────────

class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Limit request body size to prevent DoS attacks."""

    CONTENT_LENGTH_LIMIT = 10 * 1024 * 1024  # 10MB

    async def dispatch(self, request: Request, call_next) -> Response:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > self.CONTENT_LENGTH_LIMIT:
                    from fastapi.responses import JSONResponse
                    return JSONResponse(
                        {"detail": "Request body too large (max 10MB)"},
                        status_code=413,
                    )
            except ValueError:
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    {"detail": "Invalid Content-Length header."},
                    status_code=400,
                )
        elif request.method in ("POST", "PUT", "PATCH"):
            body = await request.body()
            if len(body) > self.CONTENT_LENGTH_LIMIT:
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    {"detail": "Request body too large (max 10MB)"},
                    status_code=413,
                )
        return await call_next(request)

# ── License gate middleware ───────────────────────────────────────────────────

# Paths that are always accessible even without a valid license.
_LICENSE_FREE = {"/health", "/v1/health", "/docs", "/redoc", "/openapi.json"}


class LicenseMiddleware(BaseHTTPMiddleware):
    """Block all /v1/ routes (except /v1/license) when no valid license is present."""

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        if path in _LICENSE_FREE or not path.startswith("/v1/") or path.startswith("/v1/license"):
            return await call_next(request)
        from api.auth.license import license_manager  # noqa: PLC0415
        if not license_manager.is_licensed:
            from fastapi.responses import JSONResponse  # noqa: PLC0415
            return JSONResponse(
                {
                    "detail": "No valid license. Activate at POST /v1/license/activate.",
                    "code": "license_required",
                },
                status_code=402,
            )
        return await call_next(request)


# ── Security headers middleware ────────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach defensive HTTP headers to every response."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-XSS-Protection", "1; mode=block")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        # HSTS: force HTTPS for a year incl. subdomains. Safe to send unconditionally
        # — browsers ignore it over plain HTTP (dev/localhost) and only honor it on a
        # secure connection, so it protects production (TLS, often proxy-terminated)
        # without affecting local HTTP use.
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=()",
        )

        # Enhanced CSP for HTML responses vs API responses
        if not response.headers.get("Content-Security-Policy"):
            ct = response.headers.get("content-type", "")
            if "text/html" in ct:
                # CSP for the dashboard. Must allow Clerk (clerk-js loads from the
                # Frontend API at *.clerk.accounts.dev / *.clerk.com, talks to it via
                # connect-src, serves avatars from img.clerk.com, uses a blob worker,
                # and runs Cloudflare Turnstile in a frame for bot detection). The
                # browser enforces the INTERSECTION of this header and index.html's
                # <meta> CSP, so the two MUST stay in sync.
                response.headers["Content-Security-Policy"] = (
                    "default-src 'self'; "
                    "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' "
                    "https://*.clerk.accounts.dev https://*.clerk.com https://challenges.cloudflare.com; "
                    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                    "img-src 'self' data: https:; "
                    "font-src 'self' data: https://fonts.gstatic.com; "
                    "connect-src 'self' ws://localhost:* wss://localhost:* "
                    "https://*.clerk.accounts.dev https://*.clerk.com https://clerk-telemetry.com; "
                    "worker-src 'self' blob:; "
                    "frame-src 'self' https://*.clerk.accounts.dev https://challenges.cloudflare.com; "
                    "frame-ancestors 'none'; "
                    "base-uri 'self'; "
                    "form-action 'self';"
                )
            else:
                # Strict CSP for API responses
                response.headers["Content-Security-Policy"] = "default-src 'none'"
        return response


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup / shutdown hooks."""
    # ── Production secret hardening ───────────────────────────────────────────
    # Refuse to boot with a missing/weak admin key or JWT secret when running in
    # production. Gated on NETLOGIC_ENV so dev/test/CI are unaffected. The
    # validators raise RuntimeError (never sys.exit), so a misconfigured prod
    # deploy fails fast with a clear error instead of silently serving with a
    # forgeable/default credential.
    import logging  # noqa: PLC0415
    _startup_log = logging.getLogger("netlogic.api")
    if os.environ.get("NETLOGIC_ENV", "").lower() in ("production", "prod"):
        from api.auth.api_keys import require_strong_admin_key  # noqa: PLC0415
        from api.auth.jwt_handler import require_strong_jwt_secret  # noqa: PLC0415
        require_strong_admin_key()
        require_strong_jwt_secret()
        # Multi-tenant prod must have the at-rest encryption key for per-org API
        # keys — fail fast rather than 503 on the first key save.
        from api import db as _db  # noqa: PLC0415
        if _db.is_enabled():
            from api.crypto import require_secrets_key  # noqa: PLC0415
            require_secrets_key()
        _startup_log.info("Production secret validation passed.")

    # Apply Postgres migrations when a database is configured (no-op otherwise).
    from api import db  # noqa: PLC0415
    if db.is_enabled():
        try:
            applied = db.apply_migrations()
            if applied:
                _startup_log.info("Applied DB migrations: %s", ", ".join(applied))
            else:
                _startup_log.info("Database connected; schema up to date.")
        except Exception:
            _startup_log.exception("DB migration failed at startup.")
            raise
        # Warm the job cache from Postgres now that scan_jobs exists. (The
        # job_manager singleton is built at import time, before migrations — so
        # its Postgres cache-load is deferred to here.)
        try:
            from api.jobs.manager import job_manager  # noqa: PLC0415
            job_manager.warm_cache()
        except Exception:
            _startup_log.exception("Job cache warm failed at startup.")

    # Pre-warm the storage directory so the first request is fast.
    from api.storage.json_store import JsonScanStore, SCANS_DIR  # noqa: PLC0415
    JsonScanStore(SCANS_DIR)

    # Start the built-in local scan agent so scans work without any external agent.
    from api.agents.local_agent import start as start_local_agent  # noqa: PLC0415
    start_local_agent(org_id="")

    # Open the web dashboard in the default browser unless suppressed.
    # Set NETLOGIC_NO_BROWSER=1 for headless / Docker / CI environments.
    if _INDEX_HTML.exists() and not os.environ.get("NETLOGIC_NO_BROWSER"):
        port = int(os.environ.get("NETLOGIC_PORT", "8000"))
        url  = f"http://localhost:{port}"
        # Small delay lets uvicorn finish binding before the browser hits it.
        threading.Timer(1.2, webbrowser.open, args=(url,)).start()

    yield

    # Shutdown — mark any still-running jobs as failed so they don't get
    # stuck in "running" state after a restart.
    import logging  # noqa: PLC0415
    from api.jobs.manager import job_manager  # noqa: PLC0415
    _log = logging.getLogger("netlogic.api")
    _log.info("NetLogic API shutting down — draining in-flight jobs...")
    for job in list(job_manager._jobs.values()):
        if job.status in ("running", "queued"):
            job.status = "failed"
            job.error = "Scan interrupted by server shutdown."
            import time as _time  # noqa: PLC0415
            job.completed_at = _time.time()
            job_manager.persist_job(job)
    _log.info("NetLogic API shutdown complete.")


# ── Application factory ───────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title="NetLogic API",
        description=(
            "Cloud-Native Attack Surface Mapper & Vulnerability Correlator.\n\n"
            "**Phase 3** — Multi-tenancy + JWT Auth.\n\n"
            "Every job and agent is scoped to an organisation.  API consumers "
            "exchange an API key for a short-lived JWT via `POST /auth/token`; "
            "the JWT's `org_id` claim enforces data isolation across all "
            "endpoints.  Remote scan agents continue to authenticate with their "
            "own registration tokens on the agent-facing endpoints."
        ),
        version="3.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # ── Audit / correlation IDs ───────────────────────────────────────────────
    app.add_middleware(AuditMiddleware)

    # ── Request size limiting ─────────────────────────────────────────────────
    app.add_middleware(RequestSizeLimitMiddleware)

    # ── License gate (outermost — runs before auth) ───────────────────────────
    app.add_middleware(LicenseMiddleware)

    # ── Security headers ──────────────────────────────────────────────────────
    app.add_middleware(SecurityHeadersMiddleware)

    # ── Origin check (CSRF defense-in-depth) ───────────────────────────────────
    # Reject state-changing requests whose Origin header does not match the
    # configured CORS origins. This is defense-in-depth: the real protection
    # is Bearer token auth, but a valid Origin check prevents CSRF even against
    # endpoints that lack Authorization checks (e.g. future public endpoints).

    class OriginCheckMiddleware(BaseHTTPMiddleware):
        """Block POST/PUT/DELETE without a matching Origin header."""

        async def dispatch(self, request: Request, call_next) -> Response:
            if request.method in ("POST", "PUT", "DELETE"):
                origin = request.headers.get("origin", "")
                # Same-origin requests have no Origin header (browser omits it)
                # or the origin matches the configured allowed list.
                if origin and allowed_origins and origin not in allowed_origins:
                    from fastapi.responses import JSONResponse
                    return JSONResponse(
                        {"detail": "Origin not allowed."}, status_code=403,
                    )
            return await call_next(request)

    app.add_middleware(OriginCheckMiddleware)

    # ── CORS ──────────────────────────────────────────────────────────────────
    # SECURITY: Default to empty list (CORS disabled) instead of wildcard
    # Wildcard CORS enables CSRF attacks and data exposure
    raw_origins = os.environ.get("NETLOGIC_CORS_ORIGINS", "")

    # Log warning if CORS not properly configured in production
    if not raw_origins.strip():
        import logging
        logging.warning("NETLOGIC_CORS_ORIGINS not set - CORS disabled for security")
        allowed_origins = []
    else:
        allowed_origins = [o.strip() for o in raw_origins.split(",") if o.strip()]

    # Only allow credentials with specific origins (never with wildcard)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=len(allowed_origins) > 0,
        allow_methods=["GET", "POST", "PUT", "DELETE"],  # Restrict methods
        allow_headers=["Authorization", "Content-Type"],  # Restrict headers
        expose_headers=["Content-Type", "Cache-Control"],
        max_age=600,  # Cache preflight requests for 10 minutes
    )

    # ── API routers ───────────────────────────────────────────────────────────
    # Health stays at /health for Docker probes + backwards compat; also at /v1/health.
    app.include_router(health.router)
    app.include_router(health.router,        prefix="/v1")
    app.include_router(license_route.router, prefix="/v1")
    app.include_router(auth.router,          prefix="/v1")
    app.include_router(jobs.router,          prefix="/v1")
    app.include_router(agents.router,        prefix="/v1")

    app.include_router(settings_route.router, prefix="/v1")

    # ── React dashboard static files ──────────────────────────────────────────
    # Serve the compiled Vite assets only when the dashboard has been built.
    if _DIST_DIR.exists():
        assets_dir = _DIST_DIR / "assets"
        if assets_dir.exists():
            app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

        # SPA catch-all — everything that isn't an API route returns index.html
        # so that React Router handles client-side navigation.
        #
        # index.html MUST NOT be cached: it names the current hashed JS/CSS bundle,
        # so a cached copy pins the client to a stale build (the bug where the
        # desktop kept loading an old bundle and 401'd on every request). The
        # hashed /assets are content-addressed and remain freely cacheable.
        @app.get("/{full_path:path}", include_in_schema=False)
        async def serve_spa(full_path: str) -> FileResponse:
            return FileResponse(
                str(_INDEX_HTML),
                headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
            )

    else:
        # Dashboard not built — fall back to API info at root.
        @app.get("/", include_in_schema=False)
        async def root() -> dict:
            return {
                "service": "NetLogic API",
                "version": "3.0.0",
                "docs": "/docs",
                "health": "/health",
                "auth": "/auth/token",
                "note": "Run `npm run build` inside dashboard/ to enable the web UI.",
            }

    return app


# Module-level app instance used by uvicorn.
app = create_app()
