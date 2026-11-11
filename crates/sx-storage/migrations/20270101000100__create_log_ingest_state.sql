-- OCSF log-ingest tenant status table (P0-003).
--
-- The MVP keeps the actual events in an in-memory ring buffer owned by
-- `sx_log_ingest::LogIngestService` (per-tenant cap 10_000 events). The
-- per-tenant status row persisted here is the durable surface that the
-- future ClickHouse-backed pipeline will join against:
--
--   * `last_event_at` — the upstream timestamp of the most-recent
--                       accepted event. Used by the dashboard to render
--                       freshness ("last event 2m ago") and by the SOC
--                       correlator to gate stale-tenant alarms.
--   * `event_count`   — monotonically-increasing tally of accepted
--                       events. Lets billing + capacity reporting derive
--                       per-tenant ingestion volume without scanning the
--                       (eventually huge) event store.
--
-- RLS is enabled and forced so every read/write must run under a
-- session that has executed `SET app.tenant_id = '...'`. The policy
-- mirrors the canonical `app_current_tenant()` predicate used by every
-- other tenant-scoped table in the schema.

CREATE TABLE log_ingest_status (
    tenant_id      UUID PRIMARY KEY,
    last_event_at  TIMESTAMPTZ,
    event_count    BIGINT NOT NULL DEFAULT 0 CHECK (event_count >= 0),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE log_ingest_status ENABLE ROW LEVEL SECURITY;
ALTER TABLE log_ingest_status FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_log_ingest_status ON log_ingest_status
    USING (tenant_id = app_current_tenant())
    WITH CHECK (tenant_id = app_current_tenant());
