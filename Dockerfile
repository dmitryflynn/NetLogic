# ── NetLogic API — Docker image ───────────────────────────────────────────────
#
# Build:  docker build -t netlogic-api .
# Run:    docker run -p 8000:8000 netlogic-api
# Dev:    docker run -p 8000:8000 -v $(pwd):/app netlogic-api
#
# The image bundles the full project so the scan engine (src/) is available to
# the API layer without any extra setup.  The NVD cache is stored inside the
# container at /root/.netlogic/; mount a volume there for persistence:
#   docker run -p 8000:8000 -v netlogic-cache:/root/.netlogic netlogic-api

FROM python:3.11-slim

# ── System dependencies ───────────────────────────────────────────────────────
# openssl is used by the TLS analyser; ca-certificates by urllib HTTPS calls.
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies ───────────────────────────────────────────────────────
WORKDIR /app
COPY requirements-api.txt .
RUN pip install --no-cache-dir -r requirements-api.txt

# ── Application code ──────────────────────────────────────────────────────────
COPY . .

# ── Runtime configuration ─────────────────────────────────────────────────────
ENV PYTHONUNBUFFERED=1
# Allow overriding CORS origins at runtime:
#   docker run -e NETLOGIC_CORS_ORIGINS="https://app.example.com" ...
ENV NETLOGIC_CORS_ORIGINS="*"

EXPOSE 8000

# Run with 1 worker per CPU core; override with --workers N if needed.
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
