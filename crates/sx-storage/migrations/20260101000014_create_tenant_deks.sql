-- Per-tenant Data Encryption Key (DEK) storage.
--
-- One row per tenant holds the KMS-wrapped DEK along with the metadata
-- needed for rotation and audit. The plaintext form of the DEK is
-- *never* persisted: it is dropped immediately after the in-memory
-- crypto operation that minted it. Only the KMS-wrapped ciphertext
-- survives here.
--
-- `crypto_erase_tenant` (in `sx-secrets::shred`) deletes the row so the
-- wrapped form is gone forever; because the KMS-wrapped DEK was the
-- only path back to the plaintext, all ciphertext encrypted under it
-- becomes permanently unrecoverable.
--
-- Tenant isolation follows the same Row-Level Security pattern as the
-- other tenant-scoped tables: RLS is enabled + FORCED, and a
-- `tenant_isolation_tenant_deks` policy keys off the
-- `app.current_tenant_id` GUC set by the secrets adapter at the start
-- of every transaction.

CREATE TABLE tenant_deks (
    tenant_id   UUID PRIMARY KEY,
    key_id      TEXT NOT NULL CHECK (length(key_id) BETWEEN 1 AND 256),
    version     INTEGER NOT NULL CHECK (version >= 0),
    wrapped     TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL
);

-- Row-Level Security: same pattern as every other tenant-scoped table.
ALTER TABLE tenant_deks ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_deks FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_tenant_deks ON tenant_deks
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
