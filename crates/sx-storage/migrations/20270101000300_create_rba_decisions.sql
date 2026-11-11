-- Risk-Based Authentication decision audit table (P1-003).
--
-- Persistent audit of every decision emitted by the RBA engine —
-- whether the engine allowed, asked for step-up MFA, or blocked the
-- login. The row is written by the engine after EACH evaluate() call,
-- even on `allow`, so the SOC can reconstruct what the engine saw at
-- decision time.
--
-- ## Columns
--
-- * `id`        — uuid of the decision; primary key.
-- * `tenant_id` — uuid of the tenant the decision belongs to. Tenant
--                 isolation is enforced via Row-Level Security.
-- * `user_id`   — uuid of the user, NULL when the credential lookup
--                 itself failed and the engine still wrote an audit
--                 row.
-- * `ip`        — caller IP. Stored as `INET` so the column accepts
--                 both v4 and v6.
-- * `score`     — composite 0-100 risk score the engine produced.
-- * `action`    — one of `allow`, `step_up_mfa`, `block` (CHECK
--                 enforced).
-- * `signals`   — JSONB bundle of the per-signal sub-scores + raw
--                 inputs.
-- * `decided_at` — wall-clock timestamp of the decision.
--
-- ## Indexes
--
-- The hot read path is `WHERE tenant_id = $1 ORDER BY decided_at DESC
-- LIMIT N` (the dashboard's "last N decisions" view), so we keep one
-- composite descending index on `(tenant_id, decided_at DESC)`.
--
-- ## Row-Level Security
--
-- ENABLED + FORCED to match every other tenant-scoped table in the
-- platform. The policy keys off the `app.current_tenant_id` GUC set
-- by `TenantContext::apply` at the start of every repository
-- transaction.

CREATE TABLE rba_decisions (
    id           UUID PRIMARY KEY,
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id      UUID,
    ip           INET NOT NULL,
    score        INTEGER NOT NULL CHECK (score >= 0 AND score <= 100),
    action       TEXT NOT NULL CHECK (action IN ('allow', 'step_up_mfa', 'block')),
    signals      JSONB NOT NULL DEFAULT '{}'::jsonb,
    decided_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX rba_decisions_tenant_decided_idx
    ON rba_decisions (tenant_id, decided_at DESC);
CREATE INDEX rba_decisions_tenant_action_idx
    ON rba_decisions (tenant_id, action);

ALTER TABLE rba_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE rba_decisions FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_rba_decisions
    ON rba_decisions
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
