-- Per-tenant Falco rule allow/deny overrides (HIGH-006).
--
-- Falco emits a fixed catalogue of rules ("Terminal shell in container",
-- "Write below etc", ...) plus a free-form `output_fields` map. A noisy
-- ruleset can flood a tenant with low-value alerts; conversely a
-- high-value finding may need to be escalated above Falco's stamped
-- priority. HIGH-006 introduces a per-tenant override table the
-- `sx-runtime` event normaliser consults *before* mapping an alert into
-- a finding.
--
-- ## Columns
--
-- * `tenant_id`  — uuid of the tenant; tenant-scoped via RLS.
-- * `rule_name`  — Falco rule name, mirrored verbatim from `rule` on the
--                  alert wire (case-sensitive).
-- * `subkey`     — within-rule discriminator. The runtime evaluator
--                  encodes "this override applies to every subkey under
--                  this rule" as the literal `'*'` (`SUBKEY_WILDCARD`)
--                  so the primary key remains non-nullable and the
--                  ingest hot path can do a straight equality lookup.
-- * `action`     — one of `allow`, `deny`, `escalate`, `downgrade`.
--                  `allow` is a no-op today (reserved for a future
--                  allow-list mode), `deny` suppresses the alert,
--                  `escalate`/`downgrade` shift severity one tier and
--                  saturate at the ladder ends.
-- * `reason`     — operator-supplied justification persisted into every
--                  override audit row (`sx_audit::AuditSink`).
-- * `set_by`     — uuid of the operator who last touched the row.
-- * `set_at`     — wall-clock of the last mutation.
--
-- ## Cross-field invariants
--
-- * `action IN ('allow','deny','escalate','downgrade')` enforced by
--   CHECK so a malformed adapter cannot persist an unknown action.
-- * `length(rule_name) BETWEEN 1 AND 256` and `length(subkey)
--   BETWEEN 1 AND 128` cap pathological inputs.
-- * `(tenant_id, rule_name, subkey)` is the primary key — exactly one
--   row per (rule, subkey) per tenant.
--
-- ## Row-Level Security
--
-- ENABLED + FORCED to match every other tenant-scoped table. The
-- policy keys off `app_current_tenant()` set by the application's
-- `TenantContext::apply` shim. `FORCE` is critical: the runtime
-- ingestion path runs as the application DB role, never the table
-- owner, so the policy is non-bypassable.
--
-- ## Indexes
--
-- The hot read path is the ingest evaluator's `list_for_tenant` which
-- the PRIMARY KEY (`tenant_id` first) already covers. A secondary
-- index on `(tenant_id, rule_name)` accelerates the dashboard's
-- per-rule drill-down without a sequential scan over the whole tenant
-- partition.

CREATE TABLE falco_rule_overrides (
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_name  TEXT NOT NULL CHECK (length(rule_name) BETWEEN 1 AND 256),
    subkey     TEXT NOT NULL CHECK (length(subkey) BETWEEN 1 AND 128),
    action     TEXT NOT NULL CHECK (action IN ('allow', 'deny', 'escalate', 'downgrade')),
    reason     TEXT NOT NULL DEFAULT '' CHECK (length(reason) <= 1024),
    set_by     UUID NOT NULL,
    set_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, rule_name, subkey)
);

CREATE INDEX falco_rule_overrides_tenant_rule_idx
    ON falco_rule_overrides (tenant_id, rule_name);

ALTER TABLE falco_rule_overrides ENABLE ROW LEVEL SECURITY;
ALTER TABLE falco_rule_overrides FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_falco_rule_overrides
    ON falco_rule_overrides
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
