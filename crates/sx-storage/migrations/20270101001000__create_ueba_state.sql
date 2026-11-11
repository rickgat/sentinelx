-- UEBA (User & Entity Behavioural Analytics) state tables — P2-005.
--
-- Two tenant-scoped tables back the UEBA pipeline:
--
--   * `ueba_baselines`  — per-user behavioural roll-up (login-hour
--                         histogram, /16 IP prefixes, accessed assets).
--                         Composite primary key `(tenant_id, user_id)`.
--   * `ueba_anomalies`  — append-only audit of every triggered anomaly,
--                         one row per detection.
--
-- Both tables have Row-Level Security ENABLED + FORCED with a
-- `tenant_id = app_current_tenant()` policy so a misconfigured
-- application cannot leak cross-tenant data even if the WHERE clause
-- is dropped from a query.
--
-- The Postgres adapter that backs these tables is deferred — the MVP
-- ships with the in-memory `InMemoryUebaService` and these tables wait
-- for a future agent to plug them behind a real
-- `PgUebaRepository`. The migration is registered now so the schema
-- snapshots used by integration tests already carry it.

-- ---------------------------------------------------------------------
-- ueba_baselines
-- ---------------------------------------------------------------------
--
-- One row per `(tenant_id, user_id)` carrying the bounded baseline.
--
-- Columns:
--
-- * `tenant_id`         — uuid of the tenant; composite PK part.
-- * `user_id`           — uuid of the subject; composite PK part.
-- * `login_hour_counts` — exactly 24 entries, indexed by UTC hour-of-day.
--                         The Rust-side `update_baseline_from_event`
--                         enforces the bound; the CHECK below replicates
--                         it at the DB layer.
-- * `ip_prefixes`       — JSONB object `{ "<prefix>": <hit_count>, … }`,
--                         capped at 100 entries by the application.
-- * `accessed_assets`   — JSONB object `{ "<asset_id>": <hit_count>, … }`,
--                         capped at 100 entries by the application.
-- * `updated_at`        — wall-clock timestamp of the most recent fold.

CREATE TABLE ueba_baselines (
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id           UUID NOT NULL,
    login_hour_counts INTEGER[] NOT NULL DEFAULT ARRAY[
        0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0
    ]::INTEGER[],
    ip_prefixes       JSONB NOT NULL DEFAULT '{}'::jsonb,
    accessed_assets   JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id),
    CONSTRAINT ueba_baselines_hour_buckets_card
        CHECK (array_length(login_hour_counts, 1) = 24)
);

CREATE INDEX ueba_baselines_tenant_updated_idx
    ON ueba_baselines (tenant_id, updated_at DESC);

ALTER TABLE ueba_baselines ENABLE ROW LEVEL SECURITY;
ALTER TABLE ueba_baselines FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_ueba_baselines
    ON ueba_baselines
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());

-- ---------------------------------------------------------------------
-- ueba_anomalies
-- ---------------------------------------------------------------------
--
-- Append-only audit table — one row per detected anomaly.
--
-- Columns:
--
-- * `id`           — uuid of the anomaly; primary key.
-- * `tenant_id`    — uuid of the owning tenant; RLS keys off this column.
-- * `user_id`      — uuid of the subject the anomaly is attributed to.
-- * `event_id`     — uuid of the originating event when known; NULL when
--                    the event was not stamped with one upstream.
-- * `score`        — aggregate anomaly score; `REAL` so the column can
--                    accept the per-dimension max produced by the engine.
-- * `dimensions`   — JSONB array of `{dimension, score, reason}` records
--                    as returned by `detect_anomaly`.
-- * `severity`     — coarse severity bucket; matches `Severity::as_str()`.
-- * `detected_at`  — wall-clock detection timestamp.

CREATE TABLE ueba_anomalies (
    id           UUID PRIMARY KEY,
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id      UUID NOT NULL,
    event_id     UUID NULL,
    score        REAL NOT NULL,
    dimensions   JSONB NOT NULL DEFAULT '[]'::jsonb,
    severity     TEXT NOT NULL CHECK (severity IN (
        'critical', 'high', 'medium', 'low', 'info'
    )),
    detected_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ueba_anomalies_tenant_detected_idx
    ON ueba_anomalies (tenant_id, detected_at DESC);
CREATE INDEX ueba_anomalies_tenant_user_idx
    ON ueba_anomalies (tenant_id, user_id);

ALTER TABLE ueba_anomalies ENABLE ROW LEVEL SECURITY;
ALTER TABLE ueba_anomalies FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_ueba_anomalies
    ON ueba_anomalies
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
