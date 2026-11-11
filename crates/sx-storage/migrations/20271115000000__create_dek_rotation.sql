-- DEK rotation per-tenant operational tables (CRIT-003).
--
-- Two tables back the periodic re-encryption job that runs in
-- `sx-secrets::dek_rotation`:
--
--   * `dek_rotation_progress` — one row per *active* rotation, holding
--     the checkpoint (`last_processed_row_id`) plus running counters
--     and lifecycle status. The PRIMARY KEY is `(tenant_id,
--     target_dek_version)` so a tenant may have at most one row per
--     target version at a time; the application enforces the "at most
--     one IN-PROGRESS row per tenant" rule via the unique partial
--     index below.
--
--   * `dek_rotation_policy` — one row per tenant carrying the
--     operator-configured cadence in days and the wall-clock stamp of
--     the most recently completed rotation. The scheduler reads this
--     table every 6h and enqueues a rotation when
--     `now() - last_rotated_at >= cadence_days`.
--
-- Tenant isolation: both tables follow the platform RLS pattern —
-- ENABLED + FORCED row-level security keyed on the
-- `app.current_tenant_id` GUC set by the secrets adapter at the start
-- of every repository transaction. The scheduler is the only caller
-- that bypasses the GUC (it explicitly LISTS tenant policies); it
-- runs under a service role that has `BYPASSRLS` set on the dedicated
-- `dek_rotation_scheduler` connection — see the runbook.

CREATE TABLE dek_rotation_progress (
    tenant_id               UUID        NOT NULL,
    target_dek_version      INTEGER     NOT NULL CHECK (target_dek_version >= 0),
    -- Opaque cursor: the highest `(table_name, row_id)` pair the job
    -- has finished re-encrypting. Encoded as TEXT so different visitors
    -- can use different primary-key shapes (UUID, BIGINT, composite).
    -- NULL means "no rows processed yet".
    last_processed_row_id   TEXT,
    -- Snapshotted at job start. Counters are best-effort estimates
    -- for operator dashboards; they may drift slightly if rows are
    -- inserted mid-rotation.
    total_rows              BIGINT      NOT NULL DEFAULT 0
                                CHECK (total_rows >= 0),
    processed_rows          BIGINT      NOT NULL DEFAULT 0
                                CHECK (processed_rows >= 0),
    started_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_checkpoint_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Lifecycle: pending → in_progress → (completed | failed | cancelled).
    -- Failure budget exhaustion / KMS error transitions to `failed`;
    -- the CLI `--cancel` path transitions to `cancelled`.
    status                  TEXT        NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending', 'in_progress',
                                                  'completed', 'failed',
                                                  'cancelled')),
    -- Operator-facing redacted error message on `failed`. NULL otherwise.
    last_error              TEXT,

    PRIMARY KEY (tenant_id, target_dek_version)
);

CREATE INDEX dek_rotation_progress_tenant_status_idx
    ON dek_rotation_progress (tenant_id, status);

-- At most one IN-PROGRESS row per tenant. Backstops the per-tenant
-- backpressure that the scheduler enforces in-process.
CREATE UNIQUE INDEX dek_rotation_progress_tenant_inprogress_uniq
    ON dek_rotation_progress (tenant_id)
    WHERE status IN ('pending', 'in_progress');

ALTER TABLE dek_rotation_progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE dek_rotation_progress FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_dek_rotation_progress
    ON dek_rotation_progress
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());

CREATE TABLE dek_rotation_policy (
    tenant_id           UUID        PRIMARY KEY,
    -- Default 365 days, PCI tenants 90. The application enforces the
    -- semantic; the DB only enforces a sane range.
    cadence_days        INTEGER     NOT NULL DEFAULT 365
                            CHECK (cadence_days BETWEEN 1 AND 3650),
    -- Wall-clock stamp of the most recently *completed* rotation.
    -- NULL when no rotation has ever finished for this tenant.
    last_rotated_at     TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE dek_rotation_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE dek_rotation_policy FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_dek_rotation_policy
    ON dek_rotation_policy
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
