# NetLogic

**Cloud-Native Attack Surface Mapper & Vulnerability Correlator**

NetLogic is a professional-grade network security platform combining active port scanning, service fingerprinting, CVE correlation, SSL/TLS analysis, HTTP security auditing, DNS/email security assessment, subdomain takeover detection, passive OSINT, and active vulnerability probing — all accessible from a web dashboard, a remote agent network, a desktop app, or directly via CLI.

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](https://github.com/dmitryflynn/netlogic/blob/main/LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/dmitryflynn/netlogic)
[![CVE Source: NVD](https://img.shields.io/badge/CVEs-NVD%20Live%20API-orange)](https://nvd.nist.gov/)

---

## Features

| Module | Description |
|---|---|
| **Port Scanner** | TCP connect scan with 43–58 ports, 22 service probes, banner grabbing |
| **CVE Correlator** | NVD API v2.0 + SQLite VDB + 192 offline signatures; EPSS enrichment |
| **TLS Analyzer** | Protocol versions, weak ciphers, POODLE/BEAST/CRIME/DROWN, cert expiry |
| **HTTP Header Audit** | HSTS, CSP, X-Frame-Options, CORS, cookie flags; 0–100 score |
| **Stack Fingerprint** | CMS, framework, cloud provider, CDN, WAF detection |
| **DNS Security** | SPF, DKIM, DMARC, DNSSEC, zone transfer, spoofability score |
| **Passive OSINT** | CT logs, DoH DNS, ASN lookup — no direct target contact |
| **Service Prober** | Unauthenticated Redis/Mongo/ES/Docker/K8s/etcd, 33 admin paths |
| **Takeover Detector** | CT subdomain discovery + 25 provider fingerprints |
| **Nuclei Scanner** | 13k+ community-maintained templates (CVE, tech, exposure, misconfig) — MIT license |
| **Fusion Pipeline** | Multi-sensor signal gate → AI adjudication → attack graph → unified markdown report |
| **Web Fingerprint** | Favicon hash, JS secrets, version markers, exposed files, default lander detection |
| **AI Analysis** | OpenAI / Anthropic / OpenRouter / Ollama — per-scan config, token-streaming SSE |

---

## Deployment Modes

| Mode | Description |
|---|---|
| **SaaS / Web** | FastAPI controller + React dashboard. Scans run on registered remote agents — the server never touches your network. |
| **Remote Agent** | `netlogic_agent.py` polls the controller, runs scans on its local network, and streams results back in real time. |
| **Desktop App** | Electron GUI bundles the Python engine locally. Built for Windows via NSIS installer; no server needed. |
| **CLI** | `netlogic <target>` — zero third-party dependencies, pure Python 3.9+ stdlib. |

---

## Quick Start

### Web Dashboard (SaaS mode)

```bash
# 1. Install API dependencies
pip install -r requirements-api.txt

# 2. Start the controller (auto-opens browser at http://localhost:8000)
uvicorn api.main:app --host 0.0.0.0 --port 8000

# 3. Create an API key for your organisation
curl -X POST http://localhost:8000/auth/keys \
     -H "X-Admin-Key: $NETLOGIC_ADMIN_KEY" \
     -H "Content-Type: application/json" \
     -d '{"org_id": "acme"}'

# 4. Exchange it for a JWT
curl -X POST http://localhost:8000/auth/token \
     -H "Content-Type: application/json" \
     -d '{"api_key": "<key-from-step-3>"}'
```

Set `NETLOGIC_NO_BROWSER=1` to suppress the auto-open in headless / CI environments.

### With Docker

```bash
docker compose up --build
# Dashboard at http://localhost:8000
```

The compose file also provisions a PostgreSQL for persistent multi-tenant auth. Set `NETLOGIC_DATABASE_URL=` (empty) to run purely in-memory.

### Remote Agent

```bash
# First run — registers with the controller and saves credentials
python netlogic_agent.py \
    --controller http://your-controller:8000 \
    --api-key <api-key>

# Subsequent runs (credentials loaded from ~/.netlogic/agent.json)
python netlogic_agent.py --controller http://your-controller:8000
```

Credentials are stored at `~/.netlogic/agent.json` with `0o600` permissions (owner read/write only).

### CLI (local, no server)

```bash
pip install -e .
netlogic scanme.nmap.org --full
```

Or without installation:

```bash
python netlogic.py scanme.nmap.org --full
```

---

## CLI Usage

```bash
# Quick scan — 43 ports, CVE correlation
netlogic scanme.nmap.org

# Full scan with HTML report
netlogic example.com --full --report html --out ./reports

# AI analysis with streaming output
netlogic example.com --ai --ai-provider openrouter --ai-key $KEY --ai-model anthropic/claude-sonnet-4

# Active probing: unauthenticated services, default creds, CVE confirmation
netlogic 10.0.0.5 --probe

# Deep TLS + header audit
netlogic example.com --tls --headers

# CIDR block sweep
netlogic 192.168.1.0/24 --cidr --report json --out ./reports

# Only CRITICAL + HIGH CVEs
netlogic example.com --min-cvss 7.0

# Extended port range (58 ports)
netlogic 10.0.0.5 --ports full

# Custom port list
netlogic 10.0.0.5 --ports custom=22,80,443,8080,9200

# NVD API key for 10× faster rate limits
netlogic example.com --nvd-key YOUR_KEY

# AI analysis with OpenAI, Anthropic, Kimi, or Qwen
netlogic example.com --ai --ai-provider openai --ai-key YOUR_KEY --ai-model gpt-4o-mini
netlogic example.com --ai --ai-provider anthropic --ai-key YOUR_KEY
netlogic example.com --ai --ai-provider kimi --ai-key YOUR_KEY
netlogic example.com --ai --ai-provider qwen --ai-key YOUR_KEY --ai-model qwen-plus
netlogic example.com --ai --ai-provider gemini --ai-key YOUR_KEY --ai-model gemini-2.0-flash
```

---

## Fusion Pipeline

NetLogic's core innovation is a **sensors → gate → AI adjudication → synthesis** pipeline that replaces a monolithic AI call with a precision funnel:

```
Raw scan artifacts (ports, banners, probes, TLS, DNS, …)
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│  SENSORS  (evidence-producing)                                │
│  • NVD/OSV correlation  • Nuclei (13k+ templates)           │
│  • TLS analyzer         • Web fingerprint                   │
│  • Service prober       • Exposure context                  │
│  • Probe-confirmed      • CISA KEV / EPSS                   │
└──────────────────────────────┬───────────────────────────────┘
    │ signals (typed, with provenance + reliability)
    ▼
┌──────────────────────────────────────────────────────────────┐
│  GATE  (deterministic agreement)                              │
│  • Confirmed: 2+ independent sources or pinned (KEV/probe)   │
│  • Discarded: lone low-reliability, low-impact signal        │
│  • Gray band: everything else → costs an AI token            │
│  Invariant: pinned CRITICALs can NEVER be discarded          │
└──────────────────────────────┬───────────────────────────────┘
    │ gray-band verdicts only
    ▼
┌──────────────────────────────────────────────────────────────┐
│  AI ADJUDICATION  (label-stripped, disconfirmation-forced)   │
│  • Model sees only raw evidence — no sensor names            │
│  • Must rule out benign explanations before calling real     │
│  • Can never discard a high/critical gray item               │
│  • Also DISCOVERS new issues from host context               │
└──────────────────────────────┬───────────────────────────────┘
    │ all verdicts (confirmed + potential + discarded)
    ▼
┌──────────────────────────────────────────────────────────────┐
│  SYNTHESIS  (attack graph + full report)                     │
│  • Deterministic reachability graph over confirmed findings  │
│  • LLM narrates attack chains ONLY along real edges          │
│  • 6-section unified analysis: Executive Summary, Key       │
│    Findings, Attack Chains, Beyond Known CVEs, False         │
│    Positives, Remediation                                    │
│  • Output streamed token-by-token via SSE (no 99% hang)      │
└──────────────────────────────────────────────────────────────┘
    │ ai_analysis markdown + beyond_cves list
    ▼
  Dashboard / CLI / Export
```

**Key properties:**
- **AI cost proportional to ambiguity**, not asset count — the gate settles the certain cases deterministically
- **Zero false-negative on criticals** enforced in code (not prompt): pinned KEV/probe-confirmed findings survive any AI verdict
- **Fail-soft**: AI outage degrades gray band to "potential" (reported, needs verification) — scan never breaks
- **Tech-stack binding**: LLM forbidden from suggesting CMS-specific remediation unless framework confirmed in evidence
- **Default lander detection**: bare hosting-provider pages don't trigger hallucinated application advice

---

## Streamed AI Analysis

When an AI provider is configured, the synthesis LLM response is streamed token-by-token. The backend emits progressive `"ai"` SSE events every ~80 characters, so the dashboard markdown panel populates incrementally instead of freezing at 99% while waiting for the full LLM response.

Supported providers: `openai`, `anthropic`, `openrouter`, `kimi`, `qwen`, `groq`, `gemini`, `ollama`, `custom` (any OpenAI-compatible endpoint).

---

## Nuclei Integration

NetLogic ships an optional integration with [Nuclei](https://github.com/projectdiscovery/nuclei) (MIT license — safe for commercial SaaS), running 13k+ community-maintained templates across tags:

| Tag | Templates | Purpose |
|---|---|---|
| `cve` | ~4,259 | Known CVE checks |
| `tech` | ~947 | Technology fingerprinting |
| `exposure` | ~1,449 | Leaked configs, open buckets, debug endpoints |
| `config` | — | Misconfiguration detection |
| `misconfig` | ~979 | Security misconfiguration checks |

Install Nuclei via your package manager:
```bash
# Windows (scoop)
scoop install nuclei

# macOS (homebrew)
brew install nuclei

# Linux (go)
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Nuclei results feed into the Fusion pipeline as typed signals alongside banner correlations, probes, and TLS data — the gate treats them as one independent corroboration source.

---

## CVE Coverage

### Primary: SQLite VDB (offline, fast)
- Pre-populated SQLite database with CPE→CVE mappings for 100+ products
- Lookups are local — no network call, no rate limits
- Synced from NVD + OSV with incremental updates

### Secondary: NVD API v2.0 (live fallback)
- Live lookup for any product/version not in the VDB
- 192 offline signatures for air-gapped / NVD-unreachable environments
- NVD API key for 10× faster rate limits

### Enrichment
- **CISA KEV** — CVEs actively exploited in the wild, flagged as urgent
- **EPSS** — Exploit Prediction Scoring System (0–1), reprioritizes by real-world exploitation likelihood
- **Metasploit / public exploit** tracking — 88 CVEs with confirmed PoCs

---

## Environment Variables

### Controller

| Variable | Default | Description |
|---|---|---|
| `NETLOGIC_JWT_SECRET` | `changeme-in-production` | HS256 signing secret — **must be overridden** (32+ chars) |
| `NETLOGIC_JWT_EXPIRY` | `3600` | JWT lifetime in seconds |
| `NETLOGIC_ADMIN_KEY` | `admin-changeme` | Admin credential for key management — **override in production** |
| `NETLOGIC_API_KEYS` | _(empty)_ | Seed keys: `key1:org1,key2:org2,...` |
| `NETLOGIC_CORS_ORIGINS` | `*` | Comma-separated allowed origins, or `*` |
| `NETLOGIC_PORT` | `8000` | Port reported to the browser auto-open |
| `NETLOGIC_NO_BROWSER` | _(unset)_ | Set to `1` to disable browser auto-open |
| `NETLOGIC_OIDC_ISSUER` | _(unset)_ | Clerk Frontend API URL → enables human login via OIDC |
| `NETLOGIC_DATABASE_URL` | _(unset)_ | PostgreSQL URL for persistent multi-tenant auth |
| `NETLOGIC_SECRETS_KEY` | _(unset)_ | Fernet key for encrypting org API keys at rest (required with DB) |
| `NETLOGIC_AGENT_TOKEN_MAX_AGE` | `604800` | Agent token lifetime in seconds (7 days) |
| `NETLOGIC_AGENT_PENDING_CAP` | `50` | Max queued tasks per agent |
| `NETLOGIC_MAX_AGENTS_PER_ORG` | `100` | Max registered agents per organisation |
| `NETLOGIC_AI_PROVIDER` | `openrouter` | AI provider: `openrouter`, `openai`, `anthropic`, `kimi`, `qwen`, `groq`, `gemini`, `ollama`, or `custom` |
| `NETLOGIC_AI_API_KEY` | _(empty)_ | Default AI API key. Provider-specific vars also work: `OPENROUTER_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `KIMI_API_KEY`, `MOONSHOT_API_KEY`, `DASHSCOPE_API_KEY` |
| `NETLOGIC_AI_MODEL` | provider default | Optional model id. For OpenRouter, use the exact provider/model id |
| `NETLOGIC_AI_BASE_URL` | provider default | Custom OpenAI-compatible base URL |

### Agent

| Variable | Default | Description |
|---|---|---|
| `NETLOGIC_CONTROLLER` | `http://localhost:8000` | Controller base URL |
| `NETLOGIC_API_KEY` | _(unset)_ | API key for first-time registration |

---

## API Reference

### Authentication

All endpoints (except `POST /auth/token`) require `Authorization: Bearer <jwt>`.

```
POST   /auth/token           Exchange API key → JWT
POST   /auth/keys            Create API key for an org (X-Admin-Key required)
GET    /auth/keys            List API keys, masked (admin only)
DELETE /auth/keys/{key}      Revoke an API key (admin only)
```

### Jobs

```
POST   /jobs                 Submit a scan job → {job_id, status: "queued"}
GET    /jobs                 List recent jobs for your org
GET    /jobs/{id}            Job status + result counts
GET    /jobs/{id}/stream     Live SSE stream of scan events (including streaming AI tokens)
POST   /jobs/{id}/cancel     Cancel a queued/running job
DELETE /jobs/{id}            Remove a job record
```

**POST /jobs body:**

```json
{
  "target": "example.com",
  "ports": "quick",
  "do_tls": false,
  "do_headers": false,
  "do_stack": false,
  "do_dns": false,
  "do_osint": false,
  "do_probe": false,
  "do_takeover": false,
  "do_full": false,
  "cidr": false,
  "timeout": 2.0,
  "threads": 100,
  "min_cvss": 4.0,
  "agent_id": null,
  "do_ai": false,
  "ai_provider": "openrouter",
  "ai_key": null,
  "ai_model": null
}
```

`ports`: `"quick"` (43 ports) | `"full"` (58 ports) | `"custom=22,80,443"`  
`agent_id`: route the job to a specific agent; omit to auto-assign.  
`do_ai` / `ai_*`: per-scan AI analysis override (takes precedence over server defaults).

### Agents (controller-side management)

```
GET    /agents               List all agents with live status
GET    /agents/{id}          Agent detail
DELETE /agents/{id}          Deregister an agent
```

### Agent protocol (used by `netlogic_agent.py`)

```
POST   /agents/register                        Register → {agent_id, token}
POST   /agents/{id}/heartbeat                  Keep-alive (every 25 s)
GET    /agents/{id}/tasks                      Poll for pending jobs
POST   /agents/{id}/tasks/{job_id}/events      Stream scan events (max 500/batch)
POST   /agents/{id}/tasks/{job_id}/complete    Mark job done or failed
```

Agent endpoints authenticate with the one-time registration token (`Bearer <token>`), not a JWT.

### System

```
GET    /health               Service status + uptime
GET    /docs                 Interactive OpenAPI docs
```

---

## Architecture

```
netlogic/
│
├── netlogic.py                  ← CLI entry point
├── netlogic_agent.py            ← Remote agent runner (stdlib-only)
│
├── src/                         ← Scan engine (zero third-party deps)
│   ├── scanner.py               ← TCP scanner, 22 service probes, banner grabbing
│   ├── engine.py                ← Orchestrator: runs all modules + fusion pipeline
│   ├── cve_correlator.py        ← CVE correlation: NVD + 192 offline sigs
│   ├── nvd_lookup.py            ← NIST NVD API v2.0 client, disk cache, CISA KEV
│   ├── epss.py                  ← EPSS enrichment (FIRST.org API, 24h cache)
│   ├── vdb_engine.py            ← SQLite-based local vulnerability database
│   ├── vdb_syncer.py            ← Incremental VDB sync from NVD + OSV
│   ├── service_prober.py        ← Unauthenticated access, default creds, admin paths
│   ├── vuln_prober.py           ← CVE-specific safe active probes
│   ├── osint.py                 ← DNS/DoH, CT logs, ASN lookup
│   ├── tls_analyzer.py          ← SSL/TLS deep analysis
│   ├── header_audit.py          ← HTTP security header audit
│   ├── stack_fingerprint.py     ← CMS, framework, cloud, CDN, WAF detection
│   ├── web_fingerprint.py       ← Body hashing, favicon mmh3, version markers
│   ├── dns_security.py          ← SPF, DKIM, DMARC, DNSSEC, zone transfer
│   ├── takeover.py              ← Subdomain takeover (25 providers)
│   ├── json_bridge.py           ← Streaming JSON events for Electron / agent
│   ├── scan_diff.py             ← Per-target change tracking across scans
│   ├── reporter.py              ← Terminal, JSON, HTML output
│   │
│   ├── fusion/                  ← Precision funnel (sensors → gate → AI → synthesis)
│   │   ├── signals.py           ← Signal schema (evidence+provenance)
│   │   ├── gate.py              ← Deterministic agreement gate
│   │   ├── adjudicator.py       ← AI adjudication (gray band only)
│   │   ├── synthesis.py         ← Attack graph + 6-section report generation
│   │   ├── ai.py                ← Model adapter: buffered + streaming completers
│   │   ├── engine_bridge.py     ← Converts scan artifacts → signals → verdicts
│   │   ├── benchmark.py         ← Off-pipeline benchmark harness
│   │   ├── cassette.py          ← Record/replay for offline testing
│   │   ├── corpus.py            ← Test corpus
│   │   ├── sensors/             ← Evidence-producing sensor adapters
│   │   │   ├── nuclei.py        ← Nuclei JSONL → Signal conversion
│   │   │   └── wappalyzer.py    ← Wappalyzer tech-detection → Signal conversion
│   │   └── data/                ← Test fixtures
│   │
│   └── external/                ← Third-party tool wrappers
│       └── nuclei_runner.py     ← Nuclei binary wrapper (MIT license)
│
├── api/                         ← FastAPI controller
│   ├── main.py                  ← App factory, static SPA serving, middleware
│   ├── cli.py                   ← Typer CLI entry point for `netlogic` command
│   ├── auth/
│   │   ├── jwt_handler.py       ← HS256 JWT (stdlib-only, alg enforcement)
│   │   ├── api_keys.py          ← In-memory API key store
│   │   ├── oidc.py              ← Clerk OIDC / JWKS verification
│   │   ├── rate_limit.py        ← Sliding-window rate limiter (per-IP / per-agent)
│   │   └── dependencies.py      ← require_org FastAPI dependency
│   ├── agents/
│   │   └── registry.py          ← Agent registry (token expiry, pending cap)
│   ├── jobs/
│   │   ├── manager.py           ← In-memory + JSON-file + Postgres job store
│   │   └── executor.py          ← SaaS dispatcher (never runs scans locally)
│   ├── middleware/
│   │   └── audit.py             ← X-Request-ID correlation + audit log
│   ├── models/
│   │   ├── scan_request.py      ← Pydantic ScanRequest (ipaddress validation)
│   │   └── agent.py             ← AgentRegistration with size constraints
│   ├── routes/
│   │   ├── auth.py              ← /auth/*
│   │   ├── jobs.py              ← /jobs/*
│   │   ├── agents.py            ← /agents/*
│   │   └── health.py            ← /health
│   └── storage/
│       └── json_store.py        ← Scan persistence (10 MB cap, 500 file cap)
│
├── dashboard/                   ← React SPA (Vite + TypeScript + Tailwind)
│   └── src/
│       ├── api/                 ← REST + SSE client hooks
│       ├── components/          ← StatusBadge, PortTable, VulnCard, ScanFeed, Markdown
│       ├── pages/               ← Dashboard, NewScan, ScanDetail, Agents, Login
│       └── store/               ← Zustand auth store
│
└── electron/                    ← Desktop app (Node + Electron)
    ├── main.js                  ← BrowserWindow (sandbox, contextIsolation, no nodeIntegration)
    └── preload.js               ← Sandboxed IPC bridge
```

### SaaS Dispatch Flow

```
Browser / curl
    │  POST /jobs  (JWT)
    ▼
FastAPI Controller
    │  creates ScanJob{status: queued}
    │  try_dispatch_queued() — dispatch lock prevents races
    │       ↓ if agent online & idle
    │  assign_task(agent_id, job_id)
    ▼
netlogic_agent.py  (runs on your network)
    │  GET /agents/{id}/tasks  → receives job config
    │  runs src/json_bridge.run_streaming_scan()
    │  POST /agents/{id}/tasks/{job_id}/events  (batched, ≤ 500/req)
    │  POST /agents/{id}/tasks/{job_id}/complete
    ▼
Browser SSE (GET /jobs/{id}/stream)
    └─ live events replayed to dashboard
       Fusion pipeline results streamed as typed events:
       • "fusion" — adjudicated findings (confirmed / potential / discarded)
       • "ai" — streaming markdown tokens (progressive, ~80 char batches)
       • "ai" (final) — complete markdown + beyond_cves array
```

---

## Security Architecture

### Authentication
- **API keys** — long-lived org credentials, stored in-memory (seed via `NETLOGIC_API_KEYS`), or persisted in PostgreSQL
- **JWT** — HS256, stdlib-only; `alg` field enforced before signature verification (prevents `alg=none` attack); startup warning if secret is weak or < 32 chars
- **Clerk OIDC** — human logins via Clerk-issued session JWTs, verified against public JWKS (no Clerk secret key needed server-side)
- **Agent tokens** — SHA-256 hashed in registry, expire after `NETLOGIC_AGENT_TOKEN_MAX_AGE`; stored at `~/.netlogic/agent.json` with `0o600` permissions

### Rate Limiting (sliding window, in-memory)

| Endpoint | Limit |
|---|---|
| `POST /auth/token` | 10 / minute / IP |
| `POST /agents/register` | 5 / hour / IP |
| `POST /agents/{id}/heartbeat` | 3 / minute / agent |
| `POST /agents/{id}/tasks/{id}/events` | 60 / minute / agent, max 500 events/batch |
| `POST /jobs` | 30 / minute / org |

### Multi-tenancy
Every job, agent, and API key is scoped to an `org_id`. Cross-org lookups return 404 (not 403) to prevent enumeration.

### HTTP Security Headers
Applied by `SecurityHeadersMiddleware` to every response:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: geolocation=(), microphone=(), camera=()`
- `Content-Security-Policy: default-src 'none'` (API JSON responses)

### Content Security Policy (dashboard)
Set via `<meta http-equiv="Content-Security-Policy">` in `index.html`:
- `script-src 'self'` — no inline scripts, no CDN script injection
- `style-src 'self' 'unsafe-inline'` — Tailwind requires inline styles
- `connect-src 'self'` — SSE and API calls to same origin only
- `frame-ancestors 'none'` — clickjacking prevention

### Audit Logging
`AuditMiddleware` emits structured JSON lines to the `netlogic.audit` logger for:
- `token_exchange_ok` / `token_exchange_failed` / `token_rate_limited`
- `agent_registered` / `agent_deregistered`
- `job_created` / `job_cancelled`

Every request receives a unique `X-Request-ID` header for correlation.

### Secret Sealing
When PostgreSQL persistence is enabled, org-specific LLM API keys are encrypted at rest using Fernet (symmetric) before storage. The server returns HTTP 503 if a key is submitted without `NETLOGIC_SECRETS_KEY` configured.

### Input Validation
- Targets validated with Python's `ipaddress` module (IP / CIDR) then RFC 1123 label regex — no ReDoS-prone patterns
- Agent `hostname` max 255 chars; tags max 20 pairs × 64 chars; capabilities max 32 items
- Scan JSON files capped at 10 MB each; max 500 files loaded on startup

---

## CI / Testing

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run all tests
python -m pytest

# Security gates
bandit -r src/ api/
pip-audit -r requirements-api.txt
```

- **1000+ pytest cases** covering every scan module, fusion pipeline, API routes, auth, rate limiting, multi-tenancy, SSRF/CIDR boundaries, and production-readiness
- CI pipeline in `.github/workflows/ci.yml` runs tests, Bandit SAST, and `pip-audit` dependency CVE checks

---

## Legal Notice

> **NetLogic is intended for authorized security assessments, penetration testing, and network administration only.**
> Scanning or probing hosts without explicit written permission is illegal in most jurisdictions.
> The author assumes no liability for unauthorized use.

---

## License

MIT © 2026 Dmitry Flynn — See [LICENSE](https://github.com/dmitryflynn/netlogic/blob/main/LICENSE)
