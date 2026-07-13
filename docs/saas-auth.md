# NetLogic SaaS Authentication — Design & Migration Plan

**Decisions (locked):** managed IdP for human logins · user accounts · PostgreSQL
as the system of record. Programmatic access keeps the in-house, now-hashed
API-key model.

This document is the contract for the migration. Code lands in phases; the schema
(`db/migrations/0001_init_auth.sql`) is the foundation.

---

## 1. Two credential planes

NetLogic has two distinct callers, and conflating them is how SaaS auth gets
insecure. We keep them separate:

| Plane | Who | Credential | Lifetime | Verified by |
|---|---|---|---|---|
| **Human** | dashboard users | IdP session → OIDC JWT | minutes (refreshed by IdP) | IdP JWKS (RS256) |
| **Programmatic** | agents, CI, API clients | API key `nl_live_…` | long-lived, revocable | sha256 lookup in Postgres |

Both resolve to the **same authorization primitive we already have**: an
`org_id`, consumed by `require_org`. That's the key insight — the new IdP path
plugs into existing tenant isolation instead of replacing it.

## 2. Request flows

**Human login**
```
Browser → IdP hosted login (password / MFA / passkey — IdP owns this)
       → IdP issues OIDC ID/access token (RS256, signed by IdP)
       → dashboard sends it as Bearer to NetLogic API
       → API verifies signature via IdP JWKS, checks iss/aud/exp
       → map token.sub → users.idp_subject → org_memberships → org_id (+ role)
```

**Programmatic**
```
Client → Bearer nl_live_<key>
       → API sha256(key) → api_keys (active, not revoked/expired) → org_id
       → update last_used_at  (sharing/abuse signal)
```

`require_org` becomes a thin dispatcher: if the Bearer is a NetLogic API key
prefix, take the key path; otherwise treat it as an IdP JWT and verify via JWKS.
Both return `(org_id, role, principal)`.

## 3. Why a managed IdP (and which)

For a security product, login compromise is catastrophic, and password storage,
MFA, passkeys, account recovery, brute-force/breach detection, and session
management are exactly the things you do **not** want to hand-roll. The backend
stays **IdP-agnostic** — it only verifies OIDC tokens via JWKS — so any of these
work with the same code, configured by issuer + audience:

- **Clerk** — fastest to ship; MFA, passkeys, orgs built in. Recommended for launch.
- **Auth0** — mature, enterprise-ready, great OIDC conformance.
- **WorkOS** — best if enterprise **SSO/SAML** becomes a near-term paid feature.

All three issue standard OIDC RS256 tokens with a JWKS endpoint, so switching is
a config change, not a rewrite.

## 4. Dependencies to add (`requirements-api.txt`)

```
psycopg[binary]==3.*      # PostgreSQL driver
PyJWT[crypto]==2.*        # RS256/JWKS verification of IdP tokens (pulls `cryptography`)
```

The core scan engine (`src/`) stays zero-dependency; these are API-layer only.
The existing stdlib HS256 handler stays for now (internal/local desktop tokens);
IdP tokens use PyJWT because RS256 needs real RSA verification.

## 5. Phased rollout (each phase ships independently, tests green)

1. **Schema + repository layer.** `0001_init_auth.sql` + a `Repository`
   interface with a Postgres implementation. Migrate `ApiKeyStore` to read/write
   `api_keys` (hashed — already done in-memory), add `last_used_at`. Keep the
   JSON/in-memory store behind the same interface for local/desktop + tests.
2. **OIDC verification.** `verify_idp_token()` — fetch & cache JWKS, verify
   RS256 signature, validate `iss`/`aud`/`exp`/`nbf`. Config:
   `NETLOGIC_OIDC_ISSUER`, `NETLOGIC_OIDC_AUDIENCE`, `NETLOGIC_OIDC_JWKS_URL`.
3. **User provisioning + `require_org` dispatcher.** On first valid IdP token,
   upsert `users`, attach to an org via `org_memberships`. Routes get `org_id`
   exactly as today, plus `role` for RBAC.
4. **Dashboard login.** Swap the API-key paste screen for the IdP login widget;
   keep API-key entry as a fallback for programmatic/agent setup.
5. **Hardening for "unsharable"** (see §6).
6. **Cutover.** Provision per-org slugs, migrate existing keys into `api_keys`,
   retire `NETLOGIC_API_KEYS` env seeding in production.

## 6. "Unsharable & super secure" — the concrete checklist

A bearer string can't be made physically unsharable, so the bar is: **short blast
radius + detectable + instantly revocable.**

- [ ] Human sessions short-lived (IdP access tokens ~5–15 min) + IdP refresh.
- [ ] **MFA / passkeys** enforced at the IdP (free with the providers above).
- [ ] API keys: `nl_live_` prefix, **hashed at rest** (done), shown once,
      per-key `last_used_at` + last-used IP for sharing detection, rotation,
      instant revoke (`revoked_at`).
- [ ] `jti` **revocation denylist** (`revoked_tokens`) for logout-everywhere /
      leaked-token kill switch before natural expiry.
- [ ] Per-credential **rate limits** (already have the limiter; key it per
      api_key_id / user as well as per IP).
- [ ] All secrets from a **secrets manager / KMS** in prod, never env files;
      desktop secrets.json moves to OS keystore (DPAPI/Keychain/libsecret).
- [ ] Audit every auth event to `audit_log` (we already emit these; persist them).
- [ ] TLS-only, HSTS, secure cookies if any; tokens never in URLs/logs
      (we already stopped putting the API key in the JWT `sub`).

## 7. What I need from you to wire phases 2–4

1. **Which IdP** (Clerk / Auth0 / WorkOS) — then its **issuer URL**, **audience**,
   and **JWKS URL** (all non-secret, safe to share).
2. A **Postgres connection string** (`NETLOGIC_DATABASE_URL`) for a dev DB, or
   confirmation to target a local Docker Postgres for development.
3. Approval to add the two dependencies in §4.

With those, I can build phases 1–3 behind a `NETLOGIC_AUTH_BACKEND` flag so the
current API-key flow keeps working untouched until you flip it.
