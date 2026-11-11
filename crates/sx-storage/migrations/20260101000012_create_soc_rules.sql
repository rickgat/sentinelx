-- SOC rules let operators author detection logic without redeploying.
-- Each row is a single rule keyed by `(tenant_id, rule_id)` so a tenant
-- can rev a rule independently and reuse the same `rule_id` across
-- tenants. The match condition is captured as JSONB (`when_json`) and
-- evaluated at the SOC engine layer; the storage layer treats it as an
-- opaque envelope.
--
-- Tenant isolation follows the same Row-Level Security pattern as the
-- other tenant-scoped tables: RLS is enabled + FORCED, and a
-- `tenant_isolation_soc_rules` policy keys off the
-- `app.current_tenant_id` GUC set by `TenantContext::apply`.

CREATE TABLE soc_rules (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id         TEXT NOT NULL CHECK (length(rule_id) BETWEEN 1 AND 128),
    name            TEXT CHECK (name IS NULL OR length(name) BETWEEN 1 AND 256),
    severity        TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    when_json       JSONB NOT NULL,
    throttle_secs   INTEGER CHECK (throttle_secs IS NULL OR throttle_secs >= 0),
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- A given `rule_id` is unique within a tenant. The adapter relies
    -- on this constraint to drive `ON CONFLICT` upserts.
    UNIQUE (tenant_id, rule_id)
);

CREATE INDEX soc_rules_tenant_idx
    ON soc_rules (tenant_id);
CREATE INDEX soc_rules_tenant_enabled_idx
    ON soc_rules (tenant_id, enabled)
    WHERE enabled = TRUE;
CREATE INDEX soc_rules_tenant_severity_idx
    ON soc_rules (tenant_id, severity);

-- Row-Level Security: same pattern as every other tenant-scoped table.
ALTER TABLE soc_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE soc_rules FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_soc_rules ON soc_rules
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
