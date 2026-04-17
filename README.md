# NetLogic

**Cloud-Native Attack Surface Mapper & Vulnerability Correlator**

NetLogic is a professional-grade network security platform combining active port scanning, service fingerprinting, CVE correlation, SSL/TLS analysis, HTTP security auditing, DNS/email security assessment, subdomain takeover detection, passive OSINT, and active vulnerability probing — all accessible from a web dashboard, a remote agent network, or a standalone desktop app.

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](https://github.com/dmitryflynn/netlogic/blob/main/LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/dmitryflynn/netlogic)
[![CVE Source: NVD](https://img.shields.io/badge/CVEs-NVD%20Live%20API-orange)](https://nvd.nist.gov/)

---

## Deployment Modes

| Mode | Description |
|---|---|
| **SaaS / Web** | FastAPI controller + React dashboard. Scans run on registered remote agents — the server never touches your network. |
| **Remote Agent** | `netlogic_agent.py` polls the controller, runs scans on its local network, and streams results back in real time. |
| **Desktop App** | Electron GUI bundles the Python engine locally. Built for Windows via NSIS installer; no server needed. |
| **CLI** | `netlogic.py` — zero third-party dependencies, pure Python 3.9+ stdlib. |

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
git clone https://github.com/dmitryflynn/netlogic.git
cd netlogic
python netlogic.py scanme.nmap.org --full
```

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
| `NETLOGIC_AGENT_TOKEN_MAX_AGE` | `604800` | Agent token lifetime in seconds (7 days) |
| `NETLOGIC_AGENT_PENDING_CAP` | `50` | Max queued tasks per agent |
| `NETLOGIC_MAX_AGENTS_PER_ORG` | `100` | Max registered agents per organisation |

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
GET    /jobs/{id}/stream     Live SSE stream of scan events
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
  "agent_id": null
}
```

`ports`: `"quick"` (43 ports) | `"full"` (58 ports) | `"custom=22,80,443"`  
`agent_id`: route the job to a specific agent; omit to auto-assign.

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
├── netlogic.py                  ← CLI entry point
├── netlogic_agent.py            ← Remote agent runner (stdlib-only)
│
├── src/                         ← Scan engine (zero third-party deps)
│   ├── scanner.py               ← TCP scanner, 22 service probes, banner grabbing
│   ├── cve_correlator.py        ← CVE correlation: NVD + 192 offline sigs
│   ├── nvd_lookup.py            ← NIST NVD API v2.0 client, disk cache, CISA KEV
│   ├── service_prober.py        ← Unauthenticated access, default creds, admin paths
│   ├── vuln_prober.py           ← CVE-specific safe active probes
│   ├── osint.py                 ← DNS/DoH, CT logs, ASN lookup
│   ├── tls_analyzer.py          ← SSL/TLS deep analysis
│   ├── header_audit.py          ← HTTP security header audit
│   ├── stack_fingerprint.py     ← CMS, framework, cloud, CDN, WAF detection
│   ├── dns_security.py          ← SPF, DKIM, DMARC, DNSSEC, zone transfer
│   ├── takeover.py              ← Subdomain takeover (25 providers)
│   ├── reporter.py              ← Terminal, JSON, HTML output
│   └── json_bridge.py           ← Streaming JSON events for Electron / agent
│
├── api/                         ← FastAPI controller
│   ├── main.py                  ← App factory, static SPA serving, middleware
│   ├── auth/
│   │   ├── jwt_handler.py       ← HS256 JWT (stdlib-only, alg enforcement)
│   │   ├── api_keys.py          ← In-memory API key store
│   │   ├── rate_limit.py        ← Sliding-window rate limiter (per-IP / per-agent)
│   │   └── dependencies.py      ← require_org FastAPI dependency
│   ├── agents/
│   │   └── registry.py          ← Agent registry (token expiry, pending cap)
│   ├── jobs/
│   │   ├── manager.py           ← In-memory + JSON-file job store
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
│       ├── components/          ← StatusBadge, PortTable, VulnCard, ScanFeed, Layout
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
```

---

## Security Architecture

### Authentication
- **API keys** — long-lived org credentials, stored in-memory (seed via `NETLOGIC_API_KEYS`)
- **JWT** — HS256, stdlib-only; `alg` field enforced before signature verification (prevents `alg=none` attack); startup warning if secret is weak or < 32 chars
- **Agent tokens** — SHA-256 hashed in registry, expire after 7 days (`NETLOGIC_AGENT_TOKEN_MAX_AGE`); stored at `~/.netlogic/agent.json` with `0o600` permissions

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

### Input Validation
- Targets validated with Python's `ipaddress` module (IP / CIDR) then RFC 1123 label regex — no ReDoS-prone patterns
- Agent `hostname` max 255 chars; tags max 20 pairs × 64 chars; capabilities max 32 items
- Scan JSON files capped at 10 MB each; max 500 files loaded on startup

### Electron Desktop
- `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`
- All renderer↔main IPC goes through typed `preload.js` bridge

---

## Scan Modules

| Flag | Module | What it does |
|---|---|---|
| _(default)_ | Port scanner | TCP connect scan, 22 service probes, CVE correlation via NVD |
| `--tls` / `do_tls` | TLS analyzer | Protocol versions, weak ciphers, POODLE/BEAST/CRIME/DROWN, cert expiry |
| `--headers` / `do_headers` | Header audit | HSTS, CSP, X-Frame-Options, CORS, cookie flags; 0–100 score |
| `--stack` / `do_stack` | Stack fingerprint | CMS, framework, cloud provider, CDN, WAF detection |
| `--dns` / `do_dns` | DNS security | SPF, DKIM, DMARC, DNSSEC, zone transfer, spoofability score |
| `--osint` / `do_osint` | Passive OSINT | CT logs, DoH DNS, ASN lookup — no direct target contact |
| `--probe` / `do_probe` | Service prober | Unauthenticated Redis/Mongo/ES/Docker/K8s/etcd, 33 admin paths |
| `--takeover` / `do_takeover` | Takeover detector | CT subdomain discovery + 25 provider fingerprints |
| `--full` / `do_full` | All modules | Enables every module above |

---

## CLI Usage

```bash
# Quick scan — 43 ports, CVE correlation
python netlogic.py scanme.nmap.org

# Full scan with HTML report
python netlogic.py example.com --full --report html --out ./reports

# Active probing: unauthenticated services, default creds, CVE confirmation
python netlogic.py 10.0.0.5 --probe

# Deep TLS + header audit
python netlogic.py example.com --tls --headers

# CIDR block sweep
python netlogic.py 192.168.1.0/24 --cidr --report json --out ./reports

# Only CRITICAL + HIGH CVEs
python netlogic.py example.com --min-cvss 7.0

# Extended port range (58 ports)
python netlogic.py 10.0.0.5 --ports full

# Custom port list
python netlogic.py 10.0.0.5 --ports custom=22,80,443,8080,9200

# NVD API key for 10× faster rate limits
python netlogic.py example.com --nvd-key YOUR_KEY
```

### Remote Agent CLI

```bash
python netlogic_agent.py \
    --controller http://localhost:8000 \
    --api-key <key> \
    --name my-agent-01 \
    --tags env=prod region=us-east-1 \
    --concurrency 2 \
    --poll-interval 5

# Options
--controller URL    Controller base URL (or $NETLOGIC_CONTROLLER)
--api-key KEY       API key for first-time registration (or $NETLOGIC_API_KEY)
--name HOSTNAME     Override reported hostname (default: system hostname)
--tags KEY=VALUE    Arbitrary metadata tags
--state FILE        Credential file path (default: ~/.netlogic/agent.json)
--concurrency N     Max parallel scans (default: 1)
--poll-interval N   Task poll interval in seconds (default: 5)
--verbose           Debug logging
```

---

## CVE Coverage

### Via Live NVD API (101 product mappings — always current)

OpenSSH, Apache HTTPD, Nginx, Microsoft IIS, PHP, WordPress, Drupal, Joomla, Apache Tomcat, Spring Framework, Log4j, Grafana, Kibana, Confluence, Jira, Jenkins, Redis, MongoDB, Elasticsearch, CouchDB, Memcached, HashiCorp Vault, Consul, etcd, RabbitMQ, InfluxDB, Prometheus, Solr, MinIO, Docker daemon, Kubernetes API, vsftpd, ProFTPD, Samba, OpenSSL, Exim, Splunk, Exchange, vCenter — and live NVD fallback for any product/version.

### CISA KEV + Exploit Tracking
- Flags CVEs actively exploited in the wild (CISA KEV catalog)
- 52 CVEs with confirmed Metasploit modules
- 88 CVEs with public exploits / PoCs
- 192 offline signatures for air-gapped / NVD-unreachable environments

---

## Legal Notice

> **NetLogic is intended for authorized security assessments, penetration testing, and network administration only.**
> Scanning or probing hosts without explicit written permission is illegal in most jurisdictions.
> The author assumes no liability for unauthorized use.

---

## License

MIT © 2026 Dmitry Flynn — See [LICENSE](https://github.com/dmitryflynn/netlogic/blob/main/LICENSE)
