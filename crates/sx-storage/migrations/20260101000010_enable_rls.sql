-- Row-Level Security policies. Every tenant-scoped table is gated on
-- `current_setting('app.current_tenant_id', true)` which the storage
-- layer sets via `set_config(..., true)` (transaction-local) at the
-- start of every repository transaction.
--
-- `tenants` and `cves` are NOT under RLS:
--   - `tenants` is the authority itself (platform-admin only).
--   - `cves` is shared reference data.

ALTER TABLE users               ENABLE ROW LEVEL SECURITY;
ALTER TABLE roles               ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_roles          ENABLE ROW LEVEL SECURITY;
ALTER TABLE engagements         ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets              ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings            ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log           ENABLE ROW LEVEL SECURITY;

-- Defence in depth: also FORCE row level security so that even table
-- owners obey the policy. Without this, ROLE-postgres connections
-- would bypass it.
ALTER TABLE users               FORCE ROW LEVEL SECURITY;
ALTER TABLE roles               FORCE ROW LEVEL SECURITY;
ALTER TABLE user_roles          FORCE ROW LEVEL SECURITY;
ALTER TABLE engagements         FORCE ROW LEVEL SECURITY;
ALTER TABLE assets              FORCE ROW LEVEL SECURITY;
ALTER TABLE findings            FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_log           FORCE ROW LEVEL SECURITY;

-- A tiny helper to centralise the tenant predicate. Returns NULL when
-- the GUC is unset, which causes the policy below to reject all rows.
CREATE OR REPLACE FUNCTION app_current_tenant() RETURNS UUID
LANGUAGE sql
STABLE
AS $$
    SELECT NULLIF(current_setting('app.current_tenant_id', true), '')::uuid;
$$;

CREATE POLICY tenant_isolation_users ON users
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());

CREATE POLICY tenant_isolation_roles ON roles
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());

CREATE POLICY tenant_isolation_user_roles ON user_roles
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());

CREATE POLICY tenant_isolation_engagements ON engagements
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());

CREATE POLICY tenant_isolation_assets ON assets
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());

CREATE POLICY tenant_isolation_findings ON findings
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());

CREATE POLICY tenant_isolation_audit_log ON audit_log
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
