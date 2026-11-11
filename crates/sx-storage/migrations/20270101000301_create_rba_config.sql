-- Per-tenant Risk-Based Authentication configuration (P1-003).
--
-- One row per tenant carrying the engine thresholds, signal weights,
-- and business-hours window. When a row is absent the engine falls
-- back to the platform defaults (`RbaConfig::default`) so the table is
-- safe to be empty.
--
-- ## Columns
--
-- * `tenant_id`            — uuid of the tenant (primary key).
-- * `allow_threshold`      — scores strictly below this allow without
--                            friction.
-- * `block_threshold`      — scores at-or-above this block hard.
-- * `weights`              — JSONB bundle of the per-signal weights
--                            (`w_ip_geo`, `w_velocity`,
--                            `w_business_hours`). Stored as JSONB so
--                            additional signals can be tuned in
--                            without a schema migration.
-- * `business_tz`          — IANA timezone name (`UTC`, `Europe/Berlin`,
--                            ...).
-- * `business_hours_start` — local hour business hours begin, `0..=23`.
-- * `business_hours_end`   — local hour business hours end (exclusive),
--                            `0..=23`.
-- * `updated_at`           — timestamp of the last write — used by the
--                            dashboard to surface "last tuned by".
--
-- ## Cross-field invariants
--
-- * `allow_threshold < block_threshold` is enforced by the Rust
--   validator (`RbaConfig::validate`) and the API surface. We replicate
--   the threshold range check at the database layer so a buggy admin
--   tool cannot install a row outside `[0, 100]`.
-- * `business_hours_start < business_hours_end` is enforced by the
--   Rust validator. We leave the DB-level invariant off because the
--   range CHECK already pins the legal values and the engine treats a
--   bad row as "default".
--
-- ## Row-Level Security
--
-- ENABLED + FORCED to match every other tenant-scoped table.

CREATE TABLE rba_config (
    tenant_id            UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    allow_threshold      INTEGER NOT NULL DEFAULT 30
                         CHECK (allow_threshold >= 0 AND allow_threshold <= 100),
    block_threshold      INTEGER NOT NULL DEFAULT 70
                         CHECK (block_threshold >= 0 AND block_threshold <= 100),
    weights              JSONB   NOT NULL
                         DEFAULT '{"w_ip_geo":0.4,"w_velocity":0.4,"w_business_hours":0.2}'::jsonb,
    business_tz          TEXT    NOT NULL DEFAULT 'UTC'
                         CHECK (length(business_tz) BETWEEN 1 AND 64),
    business_hours_start INTEGER NOT NULL DEFAULT 9
                         CHECK (business_hours_start >= 0 AND business_hours_start <= 23),
    business_hours_end   INTEGER NOT NULL DEFAULT 18
                         CHECK (business_hours_end   >= 0 AND business_hours_end   <= 23),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT rba_thresholds_band CHECK (allow_threshold < block_threshold)
);

ALTER TABLE rba_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE rba_config FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_rba_config
    ON rba_config
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
