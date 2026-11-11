-- P1-012 copilot human-in-loop approval gate.
--
-- Every state-changing action the AI Copilot wants to take is materialised
-- as a row here in `pending` status; a reviewer flips it to `approved` or
-- `rejected` via the `POST /v1/copilot/approvals/{token}/decide` endpoint.
-- Auto-expiry is enforced at read time, but `expires_at` is still stored
-- so a background sweep (or an audit query) can spot stale entries.
--
-- Tenant isolation follows the same Row-Level Security pattern as every
-- other tenant-scoped table: RLS is enabled + FORCED, and a
-- `tenant_isolation_copilot_approvals` policy keys off the
-- `app.current_tenant_id` GUC set by `TenantContext::apply`.

CREATE TABLE copilot_approvals (
    token        UUID PRIMARY KEY,
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Full proposed action body (kind discriminator + variant-specific
    -- payload). The crate keeps the variant set open-ended, so JSONB
    -- lets the schema evolve without future ALTER TABLEs.
    action       JSONB NOT NULL,
    -- 'pending' | 'approved' | 'rejected' | 'expired'. The CHECK
    -- constraint matches the on-wire `ApprovalStatus::as_str()` values.
    status       TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
    proposed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at   TIMESTAMPTZ NULL,
    decided_by   TEXT NULL CHECK (decided_by IS NULL OR length(decided_by) BETWEEN 1 AND 320),
    reason       TEXT NULL CHECK (reason IS NULL OR length(reason) BETWEEN 1 AND 1024),
    expires_at   TIMESTAMPTZ NOT NULL
);

CREATE INDEX copilot_approvals_tenant_idx
    ON copilot_approvals (tenant_id);
CREATE INDEX copilot_approvals_tenant_status_idx
    ON copilot_approvals (tenant_id, status);
CREATE INDEX copilot_approvals_tenant_proposed_idx
    ON copilot_approvals (tenant_id, proposed_at DESC);
CREATE INDEX copilot_approvals_tenant_expires_idx
    ON copilot_approvals (tenant_id, expires_at);

-- Row-Level Security: same pattern as every other tenant-scoped table.
ALTER TABLE copilot_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE copilot_approvals FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_copilot_approvals ON copilot_approvals
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
