-- NetLogic SaaS — initial auth & tenancy schema (PostgreSQL)
-- =============================================================================
-- Target: managed IdP for human logins (users.idp_subject links to the IdP),
-- Postgres as the system of record for tenants, users, memberships, API keys,
-- and audit. Human sessions are owned by the IdP; we only verify its tokens and
-- map them onto an org via memberships. Programmatic access keeps the in-house
-- API-key model — now persisted and hashed at rest.
--
-- Apply:  psql "$NETLOGIC_DATABASE_URL" -f db/migrations/0001_init_auth.sql
--   or:   handled automatically at API startup by api/db.py:apply_migrations()
-- (The Python runner wraps each migration in its own transaction, so no
-- BEGIN/COMMIT here — keep statements bare and semicolon-terminated.)
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid()

-- ── Organizations (tenants) ─────────────────────────────────────────────────
CREATE TABLE organizations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        TEXT NOT NULL UNIQUE,                 -- url-safe tenant id used in JWT org_id claim
    name        TEXT NOT NULL,
    plan        TEXT NOT NULL DEFAULT 'free',         -- free | pro | plaid (agents tier)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT organizations_slug_fmt CHECK (slug ~ '^[A-Za-z0-9._-]{1,64}$')
);

-- ── Users (one row per human; identity owned by the IdP) ─────────────────────
CREATE TABLE users (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    idp_subject    TEXT NOT NULL UNIQUE,              -- the IdP token `sub` claim — the join key
    email          TEXT NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT false,
    name           TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at  TIMESTAMPTZ
);
-- Case-insensitive unique email without requiring the citext extension.
CREATE UNIQUE INDEX users_email_lower_uq ON users (lower(email));

-- ── Org membership + role (a user may belong to several orgs) ────────────────
CREATE TABLE org_memberships (
    org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id)         ON DELETE CASCADE,
    role       TEXT NOT NULL DEFAULT 'member'
               CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id)
);
CREATE INDEX org_memberships_user_idx ON org_memberships (user_id);

-- ── API keys (programmatic access) — HASHED at rest ──────────────────────────
-- Mirrors the in-process ApiKeyStore but durable and per-org. The plaintext is
-- shown once at creation; only sha256(key) is stored. key_prefix is the
-- non-secret display hint (e.g. "nl_live_a1b2c3d4"). scopes is forward-looking
-- (least-privilege keys) even though launch uses full-org keys.
CREATE TABLE api_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    key_hash    TEXT NOT NULL UNIQUE,                 -- sha256 hex of the full key
    key_prefix  TEXT NOT NULL,                        -- non-secret display hint
    name        TEXT,
    scopes      TEXT[] NOT NULL DEFAULT '{}',
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,                          -- abuse/sharing detection
    expires_at  TIMESTAMPTZ,                           -- NULL = no expiry
    revoked_at  TIMESTAMPTZ                            -- NULL = active
);
CREATE INDEX api_keys_org_idx ON api_keys (org_id);
-- Fast "active key" lookups (revoked/expired keys excluded at the query).
CREATE INDEX api_keys_active_idx ON api_keys (key_hash) WHERE revoked_at IS NULL;

-- ── Token revocation denylist (emergency / logout-everywhere) ────────────────
-- IdP tokens are short-lived, but a jti denylist lets us hard-revoke a leaked
-- session before it expires. Rows are purged after expires_at.
CREATE TABLE revoked_tokens (
    jti        TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── Audit log (security events; append-only) ─────────────────────────────────
CREATE TABLE audit_log (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    org_id      UUID REFERENCES organizations(id) ON DELETE SET NULL,
    actor       TEXT,                                  -- user_id, 'system', or 'anonymous'
    event       TEXT NOT NULL,                         -- auth_success, key_revoked, ...
    severity    TEXT NOT NULL DEFAULT 'info'
                CHECK (severity IN ('info', 'warning', 'error', 'critical')),
    ip          INET,
    request_id  TEXT,
    detail      JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_log_org_ts_idx ON audit_log (org_id, ts DESC);
CREATE INDEX audit_log_event_idx  ON audit_log (event, ts DESC);
