# ── NetLogic — single-image SaaS (API + built dashboard) ──────────────────────
#
# One container serves both the FastAPI backend and the compiled React dashboard
# (api/main.py mounts dashboard/dist as the SPA). Multi-tenant sync ("log in from
# any device, see your data") requires this image deployed once against a shared
# Postgres + a stable NETLOGIC_SECRETS_KEY.
#
# Build (bake the PUBLIC Clerk key — it is not a secret):
#   docker build --build-arg VITE_CLERK_PUBLISHABLE_KEY=pk_live_xxx -t netlogic .
# Run the full stack:
#   docker compose up -d --build
#
# VITE_API_URL is intentionally left empty so the dashboard calls the API at its
# own origin (/v1). One origin, no app-level CORS to configure.

# ── Stage 1: build the dashboard ──────────────────────────────────────────────
FROM node:20-slim AS dashboard
WORKDIR /app/dashboard

# Public, build-time values. Vite inlines them into the bundle.
ARG VITE_CLERK_PUBLISHABLE_KEY=""
ARG VITE_API_URL=""
ENV VITE_CLERK_PUBLISHABLE_KEY=${VITE_CLERK_PUBLISHABLE_KEY}
ENV VITE_API_URL=${VITE_API_URL}

COPY dashboard/package.json dashboard/package-lock.json ./
RUN npm ci
COPY dashboard/ ./
RUN npm run build   # → /app/dashboard/dist

# ── Stage 2: the API image ────────────────────────────────────────────────────
FROM python:3.11-slim

# openssl for the TLS analyser; ca-certificates for HTTPS calls.
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements-api.txt .
RUN pip install --no-cache-dir -r requirements-api.txt

# Application code, then the freshly built dashboard from stage 1.
COPY . .
COPY --from=dashboard /app/dashboard/dist ./dashboard/dist

ENV PYTHONUNBUFFERED=1
ENV NETLOGIC_NO_BROWSER=1
# Same-origin app; override only if you serve the dashboard from another host.
ENV NETLOGIC_CORS_ORIGINS="*"

EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
