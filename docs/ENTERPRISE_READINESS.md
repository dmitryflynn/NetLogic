# NetLogic — Enterprise Readiness & Security Posture

This document is the security brief for (a) the operator deploying NetLogic, (b)
enterprise buyers' security questionnaires (SIG/CAIQ), and (c) an external
penetration-test firm scoping an engagement. Every control below maps to code
and to an automated test/gate — claims are grounded, not aspirational.

> Status summary: code-level hardening complete and CI-gated (771 tests + live
> Postgres integration green). The two items that **must** be done against your
> deployed infrastructure — an independent third-party pen-test and a
> production-scale soak test — are listed in the Pre-Launch Checklist and are
> the operator's responsibility (they cannot be performed from the codebase).

---

## 1. Architecture & trust boundaries

- **API** (FastAPI, `api/`) — stateless request handlers; single source of truth
  for auth and tenancy. Runs single-worker today; multi-worker is viable on the
  Postgres backend (shared state).
- **Scan engine** (`src/`) — zero third-party deps; performs the actual scanning.
- **Agents** (`api/agents/`) — execute scans. A built-in in-process agent serves
  desktop/single-tenant; the distributed agent fleet is the multi-tenant tier.
  **Trust boundary:** agents run on operator (or customer) infrastructure and
  send packets outward — see §5 (scanning authorization) and the SSRF note.
- **Storage** — in-memory + JSON files (desktop) OR Postgres (multi-tenant,
  durable). Selected by `NETLOGIC_DATABASE_URL`.

## 2. Authentication & authorization

| Control | Implementation | Test/gate |
|---|---|---|
| API-key → short-lived JWT exchange | `api/auth/jwt_handler.py` (HS256, constant-time compare, 1h TTL) | `test_auth_security.py` |
| Human login via Clerk OIDC | `api/auth/oidc.py` (RS256 + JWKS, alg pinned) | `test_oidc.py` (alg-confusion rejected) |
| Every request carries an org_id | `require_org` raises 401 if absent | `test_auth_multitenancy.py` |
| Multi-tenant isolation (no IDOR) | `job_manager.get/list` return 404 on org mismatch | pen-test (cross-org → 404), DB-path verified |
| Admin endpoints gated | strong-admin-key required; fail-closed | `test_auth_security.py` |
| Brute-force protection | IP rate-limit + fail-limit + ban list (`api/auth/rate_limit.py`) | pen-test |

## 3. Data protection

- **Per-org LLM API keys encrypted at rest** — Fernet (AES-128-CBC + HMAC) via
  `api/crypto.py`, master key `NETLOGIC_SECRETS_KEY`. Keys are write-only over
  the API (masked hints only). Verified in a live DB (ciphertext ≠ plaintext).
- **API keys hashed at rest** (sha256); plaintext shown once.
- **Fail-closed**: in production with a DB configured, the server refuses to boot
  without `NETLOGIC_SECRETS_KEY` (`api/crypto.require_secrets_key`).

## 4. Application hardening

- **Input validation** (`api/models/scan_request.py`): targets validated
  (hostname/IP/CIDR); **ssh_user/ssh_key reject option-injection** (`-oProxyCommand`
  → 422); **CIDR bounded to ≤65 536 hosts** (anti-OOM-DoS); ports de-duplicated +
  length-capped; timeout/threads/cvss range-bounded.
- **Security response headers** (`SecurityHeadersMiddleware`): HSTS,
  X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy,
  CSP (HTML + strict API).
- **CORS** defaults to disabled (no wildcard).
- **No secret leakage** in logs/responses; errors return controlled messages (no
  stack traces); SIEM webhook restricted to http(s).
- **Subprocess calls** use argv lists (no shell); SQL fully parameterized.

## 5. Scanning authorization (operator decision)

NetLogic does **not** currently gate which targets a tenant may scan (a prior
DNS-verification gate was removed by product decision). For multi-tenant SaaS the
operator should decide a policy before launch:
- An **attestation + audit** model (caller affirms authorization, logged), and/or
- Blocking the operator's **own** link-local/cloud-metadata ranges
  (`169.254.0.0/16`) so a tenant can't pivot through a shared agent to the
  operator's IMDS credentials. **(Recommended; not yet implemented.)**

## 6. Validation evidence (this engineering cycle)

- **771 unit/integration tests + 3 live-DB tests** green.
- **Live Postgres**: migrations apply, durable jobs persist and **survive a
  server restart** (validated in `NETLOGIC_ENV=production`).
- **Active pen-test** (running instance): 14/14 — auth bypass, forged/`alg=none`
  tokens, cross-org IDOR, ssh/CIDR/shell/oversized injection, malformed JSON,
  info disclosure — all defended.
- **SAST** (`bandit --severity-level high`): 0 high.
- **Dependency CVEs** (`pip-audit`, `npm audit --omit=dev`): 0.
- **Concurrency stress**: no races/deadlocks/cross-org leakage.
- **CI gates** (`.github/workflows/ci.yml`): live-Postgres integration job + SAST
  + dependency audit run on every push/PR.

## 7. Production configuration (required)

```
NETLOGIC_ENV=production
NETLOGIC_DATABASE_URL=postgresql://USER:PASS@HOST:5432/DB
NETLOGIC_SECRETS_KEY=<Fernet key>          # python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
NETLOGIC_JWT_SECRET=<32+ random chars>     # python -c "import secrets; print(secrets.token_hex(32))"
NETLOGIC_ADMIN_KEY=<32+ random chars>      # python -c "import secrets; print(secrets.token_urlsafe(32))"
NETLOGIC_CORS_ORIGINS=https://app.your-domain.com
```
In production mode the server fail-fast-validates all of the above at startup.

## 8. Pre-launch checklist (operator / external)

- [ ] Deploy to staging with the §7 config; run `pytest` against it (the live
      integration tests exercise the real DB).
- [ ] **Commission an independent third-party penetration test** of the deployed
      instance. Scope: §1 architecture; focus on §2 authz/tenancy, §4 input
      surface, §5 scanning authorization, and the agent trust boundary. Provide
      two test orgs to verify isolation.
- [ ] **Soak/load test at production scale** (multi-instance, real DB).
- [ ] Decide and implement the §5 scanning-authorization policy.
- [ ] Configure backups/PITR for Postgres; confirm migrations run on deploy.
- [ ] Penetration-test findings triaged and remediated → launch sign-off.
