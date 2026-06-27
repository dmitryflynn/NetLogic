-- ── Durable scan jobs (multi-tenant, survives restart + horizontal scale) ───
-- The in-memory JobManager + per-file JSON store is fine for single-tenant
-- desktop, but for enterprise SaaS jobs must be durable in shared storage:
-- survive a restart, be visible across multiple API instances, and never be
-- silently dropped by the in-memory 500-job cap. The full job record is kept
-- as JSONB (same shape as ScanJob.to_dict); org_id / status / target / created
-- are denormalized columns for indexed, org-scoped listing.
CREATE TABLE scan_jobs (
    job_id      UUID PRIMARY KEY,
    org_id      TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL,
    target      TEXT,
    record      JSONB NOT NULL,                       -- full ScanJob.to_dict()
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Org-scoped "most recent jobs" listing (the dashboard's primary query).
CREATE INDEX scan_jobs_org_created_idx ON scan_jobs (org_id, created_at DESC);
