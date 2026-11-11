-- Per-tenant composite risk-scoring weights (P1-014).
--
-- Carries the six `w_*` weights that previously lived only in the
-- process-wide `risk.weights` config section. When a row exists for a
-- given tenant, the scorer uses those weights in place of the
-- platform-wide defaults; otherwise it falls back to the YAML / env
-- values loaded at boot.
--
-- The cross-field invariant — "weights MUST sum to 1.0 +/- 0.01" — is
-- enforced in three places (Rust validator, this DB CHECK, and the API
-- handler) so a row that violates it cannot reach the scorer:
--   * `weights_sum_in_range` below ensures the database refuses any
--     INSERT/UPDATE that lands outside `[0.99, 1.01]`,
--   * `crates/sx-config/src/schema/risk_weights.rs::check_invariants`
--     enforces the same band in Rust,
--   * the API handler validates before either of the above is reached.
--
-- Tenant isolation follows the same Row-Level Security pattern as every
-- other tenant-scoped table: RLS is ENABLED + FORCED, and a
-- `tenant_isolation_tenant_risk_weights` policy keys off the
-- `app.current_tenant_id` GUC set by `TenantContext::apply`.

CREATE TABLE tenant_risk_weights (
    tenant_id          UUID PRIMARY KEY,
    w_severity         NUMERIC(4,3) NOT NULL,
    w_exploit          NUMERIC(4,3) NOT NULL,
    w_exposure         NUMERIC(4,3) NOT NULL,
    w_criticality      NUMERIC(4,3) NOT NULL,
    w_business_impact  NUMERIC(4,3) NOT NULL,
    w_chain            NUMERIC(4,3) NOT NULL,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT weights_sum_in_range CHECK (
        (w_severity+w_exploit+w_exposure+w_criticality+w_business_impact+w_chain) BETWEEN 0.99 AND 1.01
    )
);
ALTER TABLE tenant_risk_weights ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_risk_weights FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_tenant_risk_weights ON tenant_risk_weights
    USING (tenant_id = app_current_tenant())
    WITH CHECK (tenant_id = app_current_tenant());
