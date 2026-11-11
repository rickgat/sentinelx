-- Hash-chained audit log. Each tenant has its own monotonically
-- increasing sequence (`seq`). `prev_hash` and `hash` form a tamper-
-- evident chain — any retroactive edit invalidates every hash from
-- that row onwards.

CREATE TABLE audit_log (
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    seq           BIGINT NOT NULL,
    ts            TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor         JSONB NOT NULL,
    action        TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 128),
    resource_kind TEXT NOT NULL CHECK (length(resource_kind) BETWEEN 1 AND 64),
    resource_id   TEXT NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 256),
    before        JSONB,
    after         JSONB,
    request_id    TEXT NOT NULL DEFAULT '',
    -- 32-byte SHA-256 of the previous row's `hash` for this tenant.
    -- NULL only for the first row in the chain.
    prev_hash     BYTEA CHECK (prev_hash IS NULL OR length(prev_hash) = 32),
    -- 32-byte SHA-256 of (prev_hash || canonical-json(row)).
    hash          BYTEA NOT NULL CHECK (length(hash) = 32),
    PRIMARY KEY (tenant_id, seq)
);

-- Per-tenant sequence integrity: there is exactly one row at any seq
-- for a given tenant (enforced by PK), and seq increments monotonically
-- (enforced by application code).
CREATE INDEX audit_log_tenant_ts_idx ON audit_log (tenant_id, ts DESC);
CREATE INDEX audit_log_tenant_action_idx ON audit_log (tenant_id, action);
CREATE INDEX audit_log_tenant_resource_idx
    ON audit_log (tenant_id, resource_kind, resource_id);
CREATE INDEX audit_log_request_idx ON audit_log (request_id)
    WHERE request_id <> '';
