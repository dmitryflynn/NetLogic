-- ── Persistent reasoning state (Phase 1) ──────────────────────────────────────
-- The hierarchical ReasoningState (WorldModel/InvestigationState/ExecutionState +
-- EvidenceGraph) is built passively per scan and stored here so it survives restarts
-- and enables post-scan analysis, UI replay (temporal edges + structured explanations),
-- resumable scans, and scan-over-time change detection. The full state is kept as JSONB
-- (ReasoningState.to_dict()); job_id / org_id / target / schema_version are denormalized
-- for indexed, org-scoped lookup and future migrations.
CREATE TABLE reasoning_state (
    job_id          UUID PRIMARY KEY,
    org_id          TEXT NOT NULL DEFAULT '',
    target          TEXT,
    schema_version  INTEGER NOT NULL DEFAULT 1,
    state           JSONB NOT NULL,                     -- full ReasoningState.to_dict()
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Org-scoped "most recent reasoning states for a target" (change detection + history).
CREATE INDEX reasoning_state_org_target_idx ON reasoning_state (org_id, target, created_at DESC);
