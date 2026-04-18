"""
NetLogic API — FastAPI application entry point.

Run with:
    uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

Or via Docker:
    docker build -t netlogic-api . && docker run -p 8000:8000 netlogic-api

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
from api.routes import auth, health, jobs, agents, license as license_route  # noqa: E402
from api.middleware.audit import AuditMiddleware  # noqa: E402


# ── Security-headers middleware ────────────────────────────────────────────────

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
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=()",
        )
        # CSP: API-only responses don't need script/style allowances.
        # The React SPA sets its own CSP via <meta> in index.html.
        if not response.headers.get("Content-Security-Policy"):
            ct = response.headers.get("content-type", "")
            if "text/html" not in ct:
                response.headers["Content-Security-Policy"] = "default-src 'none'"
        return response


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup / shutdown hooks."""
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

    # ── License gate (outermost — runs before auth) ───────────────────────────
    app.add_middleware(LicenseMiddleware)

    # ── Security headers ──────────────────────────────────────────────────────
    app.add_middleware(SecurityHeadersMiddleware)

    # ── CORS ──────────────────────────────────────────────────────────────────
    raw_origins = os.environ.get("NETLOGIC_CORS_ORIGINS", "*")
    allowed_origins = (
        ["*"] if raw_origins.strip() == "*"
        else [o.strip() for o in raw_origins.split(",") if o.strip()]
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=raw_origins.strip() != "*",
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["Content-Type", "Cache-Control"],
    )

    # ── API routers ───────────────────────────────────────────────────────────
    # Health stays at /health for Docker probes + backwards compat; also at /v1/health.
    app.include_router(health.router)
    app.include_router(health.router,        prefix="/v1")
    app.include_router(license_route.router, prefix="/v1")
    app.include_router(auth.router,          prefix="/v1")
    app.include_router(jobs.router,          prefix="/v1")
    app.include_router(agents.router,        prefix="/v1")

    # ── React dashboard static files ──────────────────────────────────────────
    # Serve the compiled Vite assets only when the dashboard has been built.
    if _DIST_DIR.exists():
        assets_dir = _DIST_DIR / "assets"
        if assets_dir.exists():
            app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

        # SPA catch-all — everything that isn't an API route returns index.html
        # so that React Router handles client-side navigation.
        @app.get("/{full_path:path}", include_in_schema=False)
        async def serve_spa(full_path: str) -> FileResponse:
            return FileResponse(str(_INDEX_HTML))

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
