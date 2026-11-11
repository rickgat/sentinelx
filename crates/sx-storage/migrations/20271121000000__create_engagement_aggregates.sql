-- Durable store for the sx-engagement authorization aggregate.
--
-- The engagement authorization gate (ValidateScanRequestUseCase) reads the
-- rich `sx_engagement::model::Engagement` aggregate — status, scope,
-- Rules-of-Engagement time window, intensity ceiling, and approvals — which
-- is a different, broader shape than the legacy `engagements` table
-- (20260101000005, the sx-core model used by `sx_storage`'s own repository,
-- not wired into the monolith). The composition root previously bound the
-- engagement port to an in-memory repository, so engagements (and therefore
-- every active Rules-of-Engagement authorization) were lost on restart and
-- invisible across instances.
--
-- This table persists the aggregate verbatim as JSONB, keyed by
-- `(tenant_id, engagement_id)`, with scalar projections (`name`, `status`,
-- timestamps) for listing/ordering without deserialising every document —
-- the same lossless-aggregate pattern as `pentest_runs`.
--
-- RLS: ENABLED + FORCED, keyed on `app_current_tenant()` set by
-- `TenantContext::apply`, matching every other tenant-scoped table.

CREATE TABLE engagement_aggregates (
    tenant_id      UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    engagement_id  UUID        NOT NULL,
    name           TEXT        NOT NULL DEFAULT '',
    status         TEXT        NOT NULL DEFAULT 'draft',
    aggregate      JSONB       NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, engagement_id)
);

CREATE INDEX engagement_aggregates_tenant_status_idx
    ON engagement_aggregates (tenant_id, status);

ALTER TABLE engagement_aggregates ENABLE ROW LEVEL SECURITY;
ALTER TABLE engagement_aggregates FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_engagement_aggregates
    ON engagement_aggregates
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
