-- BAS approvals back the two-person rule enforced at the HTTP boundary
-- (`sx-api::controller::bas`). Each row records ONE approver attesting
-- to ONE technique inside a specific engagement. The `safe_interactive`
-- (and future `active_exploit`) mode requires >= 2 distinct approver
-- emails for a given (engagement_id, technique_id) tuple.
--
-- Tenant isolation follows the same Row-Level Security pattern as the
-- other tenant-scoped tables: RLS is enabled + FORCED, and a
-- `tenant_isolation_bas_approvals` policy keys off the
-- `app.current_tenant_id` GUC set by `TenantContext::apply`.

CREATE TABLE bas_approvals (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    engagement_id   UUID NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    technique_id    TEXT NOT NULL CHECK (length(technique_id) BETWEEN 1 AND 64),
    approver_email  TEXT NOT NULL CHECK (length(approver_email) BETWEEN 3 AND 320),
    reason          TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 1024),
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Idempotency: a given approver may only sign off on a given
    -- (engagement, technique) pair once. The adapter relies on this
    -- constraint to surface duplicates as a 409 Conflict.
    UNIQUE (engagement_id, technique_id, approver_email)
);

CREATE INDEX bas_approvals_tenant_idx
    ON bas_approvals (tenant_id);
CREATE INDEX bas_approvals_engagement_idx
    ON bas_approvals (tenant_id, engagement_id);
CREATE INDEX bas_approvals_engagement_technique_idx
    ON bas_approvals (tenant_id, engagement_id, technique_id);
CREATE INDEX bas_approvals_recorded_idx
    ON bas_approvals (tenant_id, recorded_at DESC);

-- Row-Level Security: same pattern as every other tenant-scoped table.
ALTER TABLE bas_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE bas_approvals FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_bas_approvals ON bas_approvals
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
