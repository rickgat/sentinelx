-- Durable store for the tamper-evident audit trail (sx-audit `AuditEntry`).
--
-- The composition root bound the audit trail to an in-memory buffer, so every
-- audit entry — and the per-tenant SHA-256 hash chain that makes the log
-- tamper-evident — was lost on a monolith restart (and invisible across
-- instances). When `database.enabled` the trail is persisted here instead,
-- and the hash chain resumes seamlessly across a restart: the recorder reads
-- `last_entry_for_tenant` (now from this table) and chains the next entry
-- onto the persisted head.
--
-- The full `AuditEntry` (actor, action, before/after, prev_hash, hash, HMAC
-- chain anchors) is stored losslessly as JSONB keyed by `(tenant_id, seq)`,
-- with a `ts` projection for ordering. The per-tenant monotonic-`seq`
-- invariant is enforced by the `(tenant_id, seq)` primary key (plus the
-- recorder's per-tenant read-then-append mutex within a process).
--
-- This is deliberately a NEW table, not the legacy columnar `audit_log`
-- (20260101000009): that table is `sx_storage`'s own older audit model and
-- lacks the HMAC chain-anchor fields the current `sx_audit::AuditEntry`
-- carries. Storing the aggregate verbatim keeps the chain bytes exact.
--
-- The audit search/export surface is cross-tenant (an admin view gated by the
-- `audit:read` RBAC permission), so reads span every tenant. The table is
-- therefore intentionally NOT under tenant RLS; the per-tenant sink methods
-- (append / last-entry / read-range) carry an explicit `tenant_id` predicate.

CREATE TABLE audit_entries (
    tenant_id   UUID        NOT NULL,
    seq         BIGINT      NOT NULL,
    ts          TIMESTAMPTZ NOT NULL,
    aggregate   JSONB       NOT NULL,
    PRIMARY KEY (tenant_id, seq)
);

-- Cross-tenant ordering for the admin search/export surface.
CREATE INDEX audit_entries_ts_idx ON audit_entries (ts);
