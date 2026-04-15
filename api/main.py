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
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# ── Path bootstrap ────────────────────────────────────────────────────────────
# Ensure the project root (parent of api/) is on sys.path so that `from src.x`
# imports work regardless of the working directory used to launch uvicorn.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# ── Deferred imports (after path bootstrap) ───────────────────────────────────
from api.routes import health, jobs  # noqa: E402


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup / shutdown hooks."""
    # Startup — pre-warm the storage directory so the first request is fast.
    from api.storage.json_store import JsonScanStore, SCANS_DIR  # noqa: PLC0415
    JsonScanStore(SCANS_DIR)  # creates directory if absent

    yield

    # Shutdown — gracefully drain in-flight scans.
    # The ThreadPoolExecutor will wait for running threads when the process
    # exits; no explicit shutdown needed here for Phase 1.


# ── Application factory ───────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title="NetLogic API",
        description=(
            "Cloud-Native Attack Surface Mapper & Vulnerability Correlator.\n\n"
            "Phase 1 REST layer — wraps the NetLogic scan engine as a stateless "
            "HTTP service with Server-Sent Events streaming."
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # ── CORS ──────────────────────────────────────────────────────────────────
    # Default: allow all origins (convenient for local development and the
    # React dashboard running on a different port).  Override via env var in
    # production:  NETLOGIC_CORS_ORIGINS="https://app.example.com"
    raw_origins = os.environ.get("NETLOGIC_CORS_ORIGINS", "*")
    allowed_origins = (
        ["*"] if raw_origins.strip() == "*"
        else [o.strip() for o in raw_origins.split(",") if o.strip()]
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=raw_origins.strip() != "*",  # credentials require explicit origins
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["Content-Type", "Cache-Control"],
    )

    # ── Routers ───────────────────────────────────────────────────────────────
    app.include_router(health.router)
    app.include_router(jobs.router)

    # ── Root redirect ─────────────────────────────────────────────────────────
    @app.get("/", include_in_schema=False)
    async def root() -> dict:
        return {
            "service": "NetLogic API",
            "version": "1.0.0",
            "docs": "/docs",
            "health": "/health",
        }

    return app


# Module-level app instance used by uvicorn.
app = create_app()
