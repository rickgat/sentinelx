-- Device-trust + posture (P2-008).
--
-- Registered as:
--   * M36_DEVICE_POSTURE_POLICY    — per-tenant declarative posture policy.
--   * M37_DEVICE_POSTURE_SNAPSHOTS — per-session observed posture snapshots.
--
-- ## Tenant isolation
--
-- Both tables follow the standard RLS pattern used throughout the
-- platform: ENABLED + FORCED row-level security keyed on the
-- `app.current_tenant_id` GUC set by the storage layer at the start of
-- every repository transaction (see `20260101000010_enable_rls.sql`).
--
-- ## Storage shape
--
-- * `device_posture_policy` holds **one** row per tenant. The policy
--   itself is a JSONB document so future rule extensions land without a
--   migration. The shape is owned by `sx_device_trust::PosturePolicy`.
--
-- * `device_posture_snapshots` records a posture observation each time
--   the API middleware decodes a posture JWT. Snapshots are retained for
--   audit + dashboard surfacing; an out-of-band janitor job (TBD) will
--   prune entries older than the retention window.

CREATE TABLE device_posture_policy (
    tenant_id   UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    policy      JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE device_posture_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_posture_policy FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_device_posture_policy
    ON device_posture_policy
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());

CREATE TABLE device_posture_snapshots (
    id           UUID PRIMARY KEY,
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id      UUID NOT NULL,
    session_id   UUID NOT NULL,
    status       TEXT NOT NULL
                      CHECK (status IN ('trusted', 'untrusted', 'stale')),
    claims       JSONB NOT NULL,
    reasons      JSONB NOT NULL DEFAULT '[]'::JSONB,
    observed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX device_posture_snapshots_tenant_observed_idx
    ON device_posture_snapshots (tenant_id, observed_at DESC);
CREATE INDEX device_posture_snapshots_tenant_session_idx
    ON device_posture_snapshots (tenant_id, session_id);
CREATE INDEX device_posture_snapshots_tenant_user_idx
    ON device_posture_snapshots (tenant_id, user_id);

ALTER TABLE device_posture_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_posture_snapshots FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_device_posture_snapshots
    ON device_posture_snapshots
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
