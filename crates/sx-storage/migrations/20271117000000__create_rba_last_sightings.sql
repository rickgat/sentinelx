-- RBA last-sighting tracker for the impossible-travel signal (LOW-005,
-- HIGH-001 follow-up).
--
-- The HIGH-001 impossible-travel detector keeps the *last observed*
-- `(lat, lon, at)` per `(tenant_id, user_id)` and computes a great-
-- circle distance + implied speed on every subsequent login. Until this
-- migration that ledger lived in process memory (`DashMap<(tenant,
-- user), LastSighting>`), which means a restart of `sx-monolith` lost
-- every sighting → for ~hours/days post-restart the signal silently
-- downgrades to "no opinion" until every user re-logs in.
--
-- This table is the persistent backing store consumed by
-- `PgTravelStore` in `crates/sx-rba/src/signals/travel_pg.rs`.
--
-- ## Columns
--
-- * `tenant_id` — uuid of the tenant; tenant-scoped via RLS.
-- * `user_id`   — uuid of the end user the sighting belongs to.
-- * `lat`       — last observed latitude in decimal degrees (WGS-84).
-- * `lon`       — last observed longitude in decimal degrees (WGS-84).
-- * `at`        — wall-clock time the sighting was recorded at.
--
-- ## Cardinality
--
-- Exactly one row per `(tenant_id, user_id)`. The primary key enforces
-- that invariant and is also the hot read path (`SELECT ... WHERE
-- tenant_id = $1 AND user_id = $2`).
--
-- ## Row-Level Security
--
-- ENABLED + FORCED to match every other tenant-scoped table. The policy
-- keys off `app_current_tenant()` set by `TenantContext::apply` / the
-- inline `SET LOCAL` shim in `PgTravelStore`. Even the table owner is
-- subject to the policy because FORCE is set.

CREATE TABLE rba_last_sightings (
    tenant_id UUID             NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id   UUID             NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    lat       DOUBLE PRECISION NOT NULL CHECK (lat BETWEEN -90.0 AND 90.0),
    lon       DOUBLE PRECISION NOT NULL CHECK (lon BETWEEN -180.0 AND 180.0),
    at        TIMESTAMPTZ      NOT NULL,
    PRIMARY KEY (tenant_id, user_id)
);

ALTER TABLE rba_last_sightings ENABLE ROW LEVEL SECURITY;
ALTER TABLE rba_last_sightings FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_rba_last_sightings
    ON rba_last_sightings
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
