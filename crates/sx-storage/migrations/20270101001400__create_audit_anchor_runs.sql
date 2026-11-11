-- External audit-chain anchor runs (P1-015 — per-spec table).
--
-- Each row is one *anchoring run* — the orchestrator periodically
-- (default 1 h, configurable per-tenant) snapshots the tenant's audit
-- hash-chain into a SHA-256 Merkle root, submits that root to an
-- RFC 3161 TSA, verifies the reply against the operator-pinned per-
-- tenant CA cert, and stores the resulting (verified) row here.
--
-- This table is *not* the same as `audit_anchor_external` (created in
-- migration `20261015000000_…`). That earlier table stores the
-- low-level submission record — one row per published anchor across
-- *any* anchor pipeline (today TSA + blockchain-stub). `audit_anchor_runs`
-- is the higher-level *scheduler* view the API surface lists and
-- re-verifies; it maps 1:1 to the per-spec columns the P1-015 ticket
-- enumerates: `run_id`, `tenant_id`, `merkle_root`, `tsa_serial`,
-- `tsa_genTime`, `anchored_at`, `payload_bytes`.
--
-- ## Storage notes
--
-- - `merkle_root` is a 32-byte BYTEA (raw SHA-256 digest).
-- - `tsa_serial` is the TSA-issued serial number stored as TEXT so we
--   can preserve the operator's preferred rendering (decimal vs hex)
--   without committing to a numeric range; TSA serials are opaque to
--   us.
-- - `tsa_gen_time` is the `genTime` extracted from the TSA reply, in
--   UTC; this is *not* the wall-clock time the row was inserted
--   (that's `anchored_at`).
-- - `payload_bytes` is the verbatim TSA reply blob. Engineering bar:
--   the raw bytes NEVER appear on the wire or in any log line — the
--   API surface exposes only `payload_size_bytes`.
--
-- ## Multi-tenancy
--
-- Row-Level Security is enabled + FORCED. Every read or write must
-- key off the `tenant_id` GUC set by `TenantContext::apply` — there
-- is no superuser exception. The cross-tenant verify-reject test
-- (`run_once_with_*` in `crates/sx-audit/tests/anchor_run_tsa.rs`)
-- exercises the same invariant at the application layer.

CREATE TABLE audit_anchor_runs (
    run_id          UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    merkle_root     BYTEA NOT NULL,
    tsa_serial      TEXT NOT NULL,
    tsa_gen_time    TIMESTAMPTZ NOT NULL,
    anchored_at     TIMESTAMPTZ NOT NULL,
    payload_bytes   BYTEA NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT audit_anchor_runs_merkle_root_len
        CHECK (octet_length(merkle_root) = 32),
    CONSTRAINT audit_anchor_runs_payload_nonempty
        CHECK (octet_length(payload_bytes) > 0)
);

-- Newest-first list lookup: the `GET /v1/audit/anchors` endpoint pages
-- by `anchored_at DESC` per tenant. Composite index keeps the planner
-- on an index-only scan for the typical "last N runs" query.
CREATE INDEX audit_anchor_runs_tenant_anchored_idx
    ON audit_anchor_runs (tenant_id, anchored_at DESC);

ALTER TABLE audit_anchor_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_anchor_runs FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_audit_anchor_runs ON audit_anchor_runs
    USING (tenant_id = app_current_tenant())
    WITH CHECK (tenant_id = app_current_tenant());
