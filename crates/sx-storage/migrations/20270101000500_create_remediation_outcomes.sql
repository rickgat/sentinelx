-- P1-011: Remediation outcomes + regression tracking.
--
-- Two tables. `remediation_outcomes` records every (open -> closed)
-- transition together with how the closure was driven (auto-patch,
-- manual-patch, risk-accepted, ...) and the time-to-remediate in whole
-- seconds. `regression_events` records detection of a fresh finding on
-- the same `(asset_id, check_id)` pair inside the lookback window.
--
-- Both tables are tenant-scoped and protected by the standard RLS policy
-- keyed on `app_current_tenant()`.

CREATE TABLE remediation_outcomes (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id        TEXT NOT NULL CHECK (length(asset_id) BETWEEN 1 AND 256),
    check_id        TEXT NOT NULL CHECK (length(check_id) BETWEEN 1 AND 128),
    finding_id      UUID NOT NULL,
    method          TEXT NOT NULL CHECK (method IN (
        'auto-patch',
        'manual-patch',
        'risk-accepted',
        'false-positive',
        'config-change',
        'unspecified'
    )),
    severity        TEXT NOT NULL CHECK (severity IN (
        'info',
        'low',
        'medium',
        'high',
        'critical'
    )),
    opened_at       TIMESTAMPTZ NOT NULL,
    closed_at       TIMESTAMPTZ NOT NULL,
    ttr_seconds     BIGINT NOT NULL CHECK (ttr_seconds >= 0)
);

CREATE INDEX remediation_outcomes_tenant_idx
    ON remediation_outcomes (tenant_id);
CREATE INDEX remediation_outcomes_lookup_idx
    ON remediation_outcomes (tenant_id, asset_id, check_id, closed_at DESC);
CREATE INDEX remediation_outcomes_closed_at_idx
    ON remediation_outcomes (tenant_id, closed_at DESC);

ALTER TABLE remediation_outcomes ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_outcomes FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_remediation_outcomes ON remediation_outcomes
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());

-- regression_events references the prior outcome via FK so a tenant
-- delete cascades cleanly. Regressions outside the configured window
-- are never inserted by the service layer (the lookback bound lives in
-- `sx_remediation::service::outcomes`).

CREATE TABLE regression_events (
    id                UUID PRIMARY KEY,
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id          TEXT NOT NULL CHECK (length(asset_id) BETWEEN 1 AND 256),
    check_id          TEXT NOT NULL CHECK (length(check_id) BETWEEN 1 AND 128),
    prior_outcome_id  UUID NOT NULL REFERENCES remediation_outcomes(id) ON DELETE CASCADE,
    new_finding_id    UUID NOT NULL,
    detected_at       TIMESTAMPTZ NOT NULL,
    gap_seconds       BIGINT NOT NULL CHECK (gap_seconds >= 0)
);

CREATE INDEX regression_events_tenant_idx
    ON regression_events (tenant_id);
CREATE INDEX regression_events_detected_idx
    ON regression_events (tenant_id, detected_at DESC);
CREATE INDEX regression_events_lookup_idx
    ON regression_events (tenant_id, asset_id, check_id, detected_at DESC);

ALTER TABLE regression_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE regression_events FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_regression_events ON regression_events
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
