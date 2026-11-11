-- CRIT-006 — TSA fallback + retry queue (multi-TSA + circuit breaker).
--
-- Two tables.
--
-- 1. `audit_tsa_config` — per-tenant primary + backup TSA endpoints,
--    each with its own pinned CA cert and per-request timeout.
-- 2. `audit_anchor_queue` — per-tenant retry queue. When the fallback
--    cascade fails the orchestrator pushes the (Merkle root, window,
--    chain_hashes) blob here; a separate retryer tick walks the queue
--    every minute and retries inside the 24h window. Past the window
--    the row flips to `exhausted` and a CRITICAL
--    `audit.anchor.queue_exhausted` event is emitted.
--
-- Engineering bar:
--   * `payload_bytes` and `chain_hashes` are BYTEA / BYTEA[] — no raw
--     bytes on the wire.
--   * Both tables are tenant-scoped and protected by the standard RLS
--     policy keyed on `app_current_tenant()`.

-- ---------------------------------------------------------------------
-- audit_tsa_config — multi-TSA configuration per tenant.
-- ---------------------------------------------------------------------

CREATE TABLE audit_tsa_config (
    tenant_id            UUID PRIMARY KEY,
    primary_tsa_url      TEXT NOT NULL CHECK (length(primary_tsa_url) BETWEEN 1 AND 1024),
    primary_ca_pem       TEXT NOT NULL CHECK (length(primary_ca_pem) BETWEEN 1 AND 16384),
    primary_label        TEXT CHECK (primary_label IS NULL OR length(primary_label) BETWEEN 1 AND 64),
    primary_timeout_ms   INTEGER NOT NULL DEFAULT 30000
        CHECK (primary_timeout_ms BETWEEN 100 AND 600000),
    -- Backups stored as a JSONB array of {url, ca_pem, label, timeout_ms}
    -- objects. Keeping them in one row simplifies the per-tenant lookup
    -- to a single SELECT.
    backups              JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(backups) = 'array' AND jsonb_array_length(backups) <= 8),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE audit_tsa_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_tsa_config FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_audit_tsa_config ON audit_tsa_config
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());

-- ---------------------------------------------------------------------
-- audit_anchor_queue — pending retries.
-- ---------------------------------------------------------------------

CREATE TABLE audit_anchor_queue (
    queue_id            UUID PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    window_start        TIMESTAMPTZ NOT NULL,
    window_end          TIMESTAMPTZ NOT NULL,
    audit_seq_from      BIGINT NOT NULL CHECK (audit_seq_from >= 0),
    audit_seq_to        BIGINT NOT NULL CHECK (audit_seq_to >= audit_seq_from),
    merkle_root         BYTEA NOT NULL CHECK (octet_length(merkle_root) = 32),
    -- Chain hashes stored as a BYTEA array so the retryer can re-run
    -- the Merkle pipeline byte-for-byte without re-reading the audit
    -- log. Capped at 8192 hashes (the largest reasonable window).
    chain_hashes        BYTEA[] NOT NULL CHECK (cardinality(chain_hashes) <= 8192),
    queued_at           TIMESTAMPTZ NOT NULL,
    attempts            INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    status              TEXT NOT NULL CHECK (status IN ('pending', 'recovered', 'exhausted')),
    last_failure_reason TEXT NOT NULL CHECK (length(last_failure_reason) BETWEEN 0 AND 2048),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX audit_anchor_queue_tenant_idx
    ON audit_anchor_queue (tenant_id);
CREATE INDEX audit_anchor_queue_pending_idx
    ON audit_anchor_queue (tenant_id, status, queued_at DESC)
    WHERE status = 'pending';
CREATE INDEX audit_anchor_queue_global_pending_idx
    ON audit_anchor_queue (status, queued_at DESC)
    WHERE status = 'pending';

ALTER TABLE audit_anchor_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_anchor_queue FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_audit_anchor_queue ON audit_anchor_queue
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
