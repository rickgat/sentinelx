-- Report schedules persist the cron-driven report-email pipeline backing
-- the `sx-report::scheduler` module (P2-001 MVP).
--
-- Each row is the authoritative description of *what* to render
-- (engagement + format), *when* to render it next (`next_run_at`), and
-- *who* receives the artefact (`recipients`). The orchestrator polls
-- this table once per minute, dispatches every row whose
-- `next_run_at <= NOW()` AND `enabled = TRUE`, and rewrites
-- `last_run_at` + `next_run_at` after a successful send.
--
-- Tenant isolation follows the same Row-Level Security pattern as every
-- other tenant-scoped table: RLS is enabled + FORCED, and a
-- `tenant_isolation_report_schedules` policy keys off the
-- `app.current_tenant_id` GUC set by `TenantContext::apply`.

CREATE TABLE report_schedules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    engagement_id   UUID,
    format          TEXT NOT NULL,
    cron_expr       TEXT NOT NULL,
    recipients      JSONB NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    last_run_at     TIMESTAMPTZ,
    last_status     TEXT,
    next_run_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX report_schedules_tenant_idx ON report_schedules (tenant_id);
CREATE INDEX report_schedules_due_idx ON report_schedules (next_run_at)
    WHERE enabled = TRUE;

ALTER TABLE report_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE report_schedules FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_report_schedules ON report_schedules
    USING (tenant_id = app_current_tenant())
    WITH CHECK (tenant_id = app_current_tenant());
