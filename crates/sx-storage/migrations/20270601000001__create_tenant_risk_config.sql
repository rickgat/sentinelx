-- P1-014 — Per-tenant risk-model tuning (full sparse override row).
--
-- `tenant_risk_weights` (20260815) carries only the composite weight
-- override. P1-014 extends the per-tenant tuning surface with the four
-- score-band thresholds (`low`, `med`, `high`, `crit`) so an operator
-- can re-bucket the `0..=100` composite score independently of the
-- weight vector.
--
-- A single sparse row per tenant is the on-the-wire shape. Each of the
-- ten fields is independently nullable so the operator can tune one
-- knob without restating every other dial.
--
-- Invariants:
--
-- * When the six `w_*` weights are all NOT NULL their sum lands in
--   `[0.99, 1.01]` — same window as `tenant_risk_weights.weights_sum_in_range`.
--   The DB CHECK is "all-or-nothing" because the platform default is
--   what fills in the gaps at merge time, and we cannot evaluate the
--   sum against a default at the SQL layer.
-- * When all four thresholds are NOT NULL they MUST be strictly
--   monotonic ascending — `low < med < high < crit`.
-- * Every threshold MUST lie in `[0, 100]` individually.
--
-- The Rust validator (`sx_config::schema::tenant_risk`) enforces the
-- same invariants on the override **before** any SQL roundtrip; the DB
-- checks below are belt-and-braces so a manual UPDATE never installs a
-- vector the scorer would reject.
--
-- Tenant isolation follows the same Row-Level Security pattern as
-- `tenant_risk_weights`: RLS is ENABLED + FORCED, and a policy keys
-- off the `app.current_tenant_id` GUC set by `TenantContext::apply`.

CREATE TABLE tenant_risk_config (
    tenant_id          UUID PRIMARY KEY,

    -- Sparse weights (NULL = inherit platform default).
    w_severity         NUMERIC(4,3),
    w_exploit          NUMERIC(4,3),
    w_exposure         NUMERIC(4,3),
    w_criticality      NUMERIC(4,3),
    w_business_impact  NUMERIC(4,3),
    w_chain            NUMERIC(4,3),

    -- Sparse thresholds (NULL = inherit platform default).
    band_low           NUMERIC(5,2),
    band_med           NUMERIC(5,2),
    band_high          NUMERIC(5,2),
    band_crit          NUMERIC(5,2),

    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- "All weights or none" — partial sparsity within the weight vector
    -- is forbidden because a half-set vector cannot pass the sum
    -- invariant against a defaults-only complement at the SQL layer.
    CONSTRAINT weights_all_or_none CHECK (
        (
            w_severity IS NULL AND w_exploit IS NULL AND w_exposure IS NULL
            AND w_criticality IS NULL AND w_business_impact IS NULL AND w_chain IS NULL
        ) OR (
            w_severity IS NOT NULL AND w_exploit IS NOT NULL AND w_exposure IS NOT NULL
            AND w_criticality IS NOT NULL AND w_business_impact IS NOT NULL AND w_chain IS NOT NULL
        )
    ),

    -- Sum invariant — only evaluated when every weight is present.
    CONSTRAINT weights_sum_in_range CHECK (
        w_severity IS NULL OR (
            (w_severity + w_exploit + w_exposure + w_criticality + w_business_impact + w_chain)
                BETWEEN 0.99 AND 1.01
        )
    ),

    -- Same all-or-nothing rule for thresholds — a half-set band vector
    -- cannot be monotone-checked against a defaults-only complement.
    CONSTRAINT thresholds_all_or_none CHECK (
        (
            band_low IS NULL AND band_med IS NULL
            AND band_high IS NULL AND band_crit IS NULL
        ) OR (
            band_low IS NOT NULL AND band_med IS NOT NULL
            AND band_high IS NOT NULL AND band_crit IS NOT NULL
        )
    ),

    -- Strict monotone ascending — only evaluated when every threshold
    -- is present.
    CONSTRAINT thresholds_monotone CHECK (
        band_low IS NULL OR (
            band_low < band_med AND band_med < band_high AND band_high < band_crit
        )
    ),

    -- Range invariant on every threshold.
    CONSTRAINT band_low_range  CHECK (band_low  IS NULL OR (band_low  BETWEEN 0 AND 100)),
    CONSTRAINT band_med_range  CHECK (band_med  IS NULL OR (band_med  BETWEEN 0 AND 100)),
    CONSTRAINT band_high_range CHECK (band_high IS NULL OR (band_high BETWEEN 0 AND 100)),
    CONSTRAINT band_crit_range CHECK (band_crit IS NULL OR (band_crit BETWEEN 0 AND 100))
);

ALTER TABLE tenant_risk_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_risk_config FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_tenant_risk_config ON tenant_risk_config
    USING (tenant_id = app_current_tenant())
    WITH CHECK (tenant_id = app_current_tenant());
