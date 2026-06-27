-- ── Per-org AI / fusion provider settings (multi-tenant key isolation) ───────
-- Each organisation stores its OWN LLM credentials, encrypted at rest. This
-- replaces the process-global env/secrets.json key that leaked across tenants:
-- a scan now resolves the key for the org that owns the job, never a shared one.
--
--   • role          — 'ai' (report writer) or 'fusion' (gray-band adjudicator).
--                     Two independent provider/key/model triples per org; fusion
--                     falls back to the org's 'ai' row when it has none.
--   • key_ciphertext — Fernet-sealed (AES-128-CBC + HMAC) bytes. The plaintext
--                     key is NEVER stored; it is decrypted in-process only at
--                     scan time. Sealed with the NETLOGIC_SECRETS_KEY master key.
--   • key_hint      — non-secret masked display ("sk-o…7c36") for the dashboard.
CREATE TABLE org_ai_settings (
    org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role          TEXT NOT NULL CHECK (role IN ('ai', 'fusion')),
    provider      TEXT NOT NULL DEFAULT 'openrouter',
    model         TEXT,
    base_url      TEXT,
    key_ciphertext BYTEA,                                 -- Fernet-sealed; NULL = no key set
    key_hint      TEXT,                                   -- non-secret masked display hint
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, role)
);
