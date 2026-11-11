-- P3-004: In-app IR playbooks (NIST SP 800-61 Rev 2).
--
-- Two tables. `ir_incidents` holds one row per live incident together
-- with the cloned step list (status / owner / reason / evidence) as a
-- JSONB document — the per-incident step set is bounded and small (the
-- four built-in playbooks ship 12-16 steps each), so a JSONB column
-- avoids a wide third table while still letting us index by tenant.
-- `ir_step_audit` is an append-only audit row per legal state-machine
-- transition. Both tables are tenant-scoped and protected by the
-- standard RLS policy keyed on `app_current_tenant()`.

CREATE TABLE ir_incidents (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    playbook_id     TEXT NOT NULL CHECK (length(playbook_id) BETWEEN 1 AND 64),
    state           TEXT NOT NULL CHECK (state IN (
        'open',
        'in_progress',
        'contained',
        'closed'
    )),
    title           TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 256),
    severity        TEXT CHECK (severity IS NULL OR length(severity) BETWEEN 1 AND 32),
    steps           JSONB NOT NULL DEFAULT '[]'::jsonb,
    opened_at       TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX ir_incidents_tenant_idx
    ON ir_incidents (tenant_id);
CREATE INDEX ir_incidents_lookup_idx
    ON ir_incidents (tenant_id, opened_at DESC);
CREATE INDEX ir_incidents_state_idx
    ON ir_incidents (tenant_id, state, updated_at DESC);

ALTER TABLE ir_incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE ir_incidents FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_ir_incidents ON ir_incidents
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());

-- Append-only audit trail. One row per legal step / incident-state
-- transition. References the parent incident via FK so a tenant delete
-- cascades the audit rows cleanly.

CREATE TABLE ir_step_audit (
    id                    UUID PRIMARY KEY,
    tenant_id             UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    incident_id           UUID NOT NULL REFERENCES ir_incidents(id) ON DELETE CASCADE,
    kind                  TEXT NOT NULL CHECK (kind IN (
        'step_status_changed',
        'step_owner_changed',
        'evidence_attached',
        'incident_state_changed'
    )),
    step_id               TEXT CHECK (step_id IS NULL OR length(step_id) BETWEEN 1 AND 128),
    actor                 TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 256),
    from_status           TEXT CHECK (from_status IS NULL OR from_status IN (
        'todo', 'in_progress', 'done', 'skipped'
    )),
    to_status             TEXT CHECK (to_status IS NULL OR to_status IN (
        'todo', 'in_progress', 'done', 'skipped'
    )),
    from_incident_state   TEXT CHECK (from_incident_state IS NULL OR from_incident_state IN (
        'open', 'in_progress', 'contained', 'closed'
    )),
    to_incident_state     TEXT CHECK (to_incident_state IS NULL OR to_incident_state IN (
        'open', 'in_progress', 'contained', 'closed'
    )),
    note                  TEXT CHECK (note IS NULL OR length(note) BETWEEN 1 AND 2048),
    at                    TIMESTAMPTZ NOT NULL
);

CREATE INDEX ir_step_audit_tenant_idx
    ON ir_step_audit (tenant_id);
CREATE INDEX ir_step_audit_incident_idx
    ON ir_step_audit (tenant_id, incident_id, at DESC);
CREATE INDEX ir_step_audit_kind_idx
    ON ir_step_audit (tenant_id, kind, at DESC);

ALTER TABLE ir_step_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE ir_step_audit FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_ir_step_audit ON ir_step_audit
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
