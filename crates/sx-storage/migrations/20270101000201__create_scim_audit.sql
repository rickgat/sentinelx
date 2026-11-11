-- SCIM 2.0 provisioning audit log (P0-005).
--
-- Every CREATE / UPDATE / DELETE the SCIM provisioner performs lands one
-- row here. The HTTP controller and the in-memory adapter share the
-- same projection so the future Postgres-backed adapter can flush these
-- rows without changing the wire format.
--
-- `payload` carries the JSON shape SCIM clients sent, minus any
-- sensitive sub-attributes the adapter is configured to strip
-- (`password`, recovery codes, etc.). The column is `JSONB` so SOC
-- queries can pattern-match on action / user / mutation type.
--
-- Tenant isolation follows the standard Row-Level Security pattern.

CREATE TABLE scim_audit (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    scim_user_id    TEXT NULL,
    action          TEXT NOT NULL
        CHECK (action IN (
            'create_user',
            'replace_user',
            'delete_user',
            'create_group'
        )),
    payload         JSONB NOT NULL,
    ts              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX scim_audit_tenant_id_idx ON scim_audit (tenant_id);
CREATE INDEX scim_audit_ts_idx ON scim_audit (ts DESC);
CREATE INDEX scim_audit_scim_user_id_idx ON scim_audit (scim_user_id);
CREATE INDEX scim_audit_payload_gin_idx ON scim_audit USING GIN (payload);

ALTER TABLE scim_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_audit FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_scim_audit ON scim_audit
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
