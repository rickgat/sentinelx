-- RBA known-device fingerprint ledger (HIGH-001).
--
-- One row per `(tenant_id, user_id, fp_hash)` triple. The RBA engine
-- consults this table for the device-fingerprint signal: a hit lowers
-- the per-attempt risk sub-score, a miss raises it (first-seen device),
-- and an explicit revocation locks the row to the maximum sub-score.
--
-- ## Columns
--
-- * `tenant_id`  — uuid of the tenant; tenant-scoped via RLS.
-- * `user_id`    — uuid of the end user the fingerprint belongs to.
-- * `fp_hash`    — opaque SHA-256 hex of (UA + Accept headers + cookie)
--                  computed by the client. Treated as opaque by the
--                  engine; never decomposed.
-- * `first_seen` — wall-clock time the fingerprint was first observed.
-- * `last_seen`  — wall-clock time of the most recent observation
--                  (updated on every successful login).
-- * `revoked_at` — non-NULL when the operator or end-user has revoked
--                  the device. NULL while the fingerprint is "active".
-- * `revoke_reason` — free-text audit hint (`operator`, `lost_device`,
--                  `compromise`, ...) carried into the IR pipeline.
--
-- ## Cross-field invariants
--
-- * `first_seen <= last_seen` enforced by CHECK.
-- * `revoked_at IS NULL OR revoked_at >= first_seen` enforced by CHECK.
-- * `(tenant_id, user_id, fp_hash)` is unique — there is exactly one
--   row per fingerprint triple, NOT one row per login.
--
-- ## Row-Level Security
--
-- ENABLED + FORCED to match every other tenant-scoped table. The policy
-- keys off `app_current_tenant()` set by `TenantContext::apply`.
--
-- ## Indexes
--
-- The hot read path is the engine's `lookup(tenant, user, fp_hash)`
-- which the PRIMARY KEY already covers. A secondary index on
-- `(tenant_id, user_id)` supports the dashboard's "all my devices"
-- list view without a sequential scan.

CREATE TABLE rba_known_devices (
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id       UUID NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    fp_hash       TEXT NOT NULL CHECK (length(fp_hash) BETWEEN 16 AND 128),
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at    TIMESTAMPTZ,
    revoke_reason TEXT CHECK (revoke_reason IS NULL OR length(revoke_reason) BETWEEN 1 AND 128),
    PRIMARY KEY (tenant_id, user_id, fp_hash),
    CONSTRAINT rba_kd_seen_ordered  CHECK (first_seen <= last_seen),
    CONSTRAINT rba_kd_revoke_after_seen CHECK (revoked_at IS NULL OR revoked_at >= first_seen)
);

CREATE INDEX rba_known_devices_tenant_user_idx
    ON rba_known_devices (tenant_id, user_id);

ALTER TABLE rba_known_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE rba_known_devices FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_rba_known_devices
    ON rba_known_devices
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
