-- Per-tenant SCIM 2.0 bearer tokens (P0-005).
--
-- One row per minted token. The plaintext value is returned to the
-- operator exactly once (at mint time) and dropped immediately afterwards;
-- only the SHA-256 hash is stored here. The SCIM adapter uses
-- `subtle::ConstantTimeEq` (see `services/sx-monolith/src/adapters/scim.rs`)
-- to compare incoming bearer tokens against `token_hash` without leaking
-- the matched row's position via wall-clock timing.
--
-- `last_used_at` is updated by the adapter after a successful auth and
-- is nullable so operators can identify never-used (and therefore safe
-- to revoke) tokens.
--
-- Tenant isolation follows the same Row-Level Security pattern as every
-- other tenant-scoped table.

CREATE TABLE scim_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    token_hash      BYTEA NOT NULL CHECK (octet_length(token_hash) = 32),
    name            TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ NULL
);

CREATE INDEX scim_tokens_tenant_id_idx ON scim_tokens (tenant_id);
CREATE INDEX scim_tokens_token_hash_idx ON scim_tokens (token_hash);

ALTER TABLE scim_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_tokens FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_scim_tokens ON scim_tokens
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
