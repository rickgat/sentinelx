-- FIDO2 / WebAuthn passkey credentials (P1-002).
--
-- The canonical migration lives at
--   crates/sx-storage/migrations/20270101001200__create_webauthn_credentials.sql
-- and is what the runtime applies (the monolith's sqlx::migrate!() macro
-- points at the sx-storage tree).
--
-- This file is the **owner-crate copy** referenced by the P1-002 task
-- specification (`crates/sx-iam/migrations/<ts>_webauthn.sql`). It is
-- kept byte-identical to the storage copy so the two never drift; any
-- schema edit MUST be made in both files in the same commit.

CREATE TABLE IF NOT EXISTS webauthn_tenant_rp (
    tenant_id        UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    rp_id            TEXT NOT NULL,
    rp_name          TEXT NOT NULL,
    rp_origin        TEXT NOT NULL,
    attestation      TEXT NOT NULL
                          CHECK (attestation IN ('none', 'indirect', 'direct', 'enterprise')),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE webauthn_tenant_rp ENABLE ROW LEVEL SECURITY;
ALTER TABLE webauthn_tenant_rp FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_webauthn_tenant_rp
    ON webauthn_tenant_rp
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id               UUID PRIMARY KEY,
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id          UUID NOT NULL,
    cred_id          TEXT NOT NULL,
    cred_id_bytes    BYTEA NOT NULL,
    public_key       BYTEA NOT NULL,
    aaguid           BYTEA,
    counter          INTEGER NOT NULL DEFAULT 0,
    passkey          JSONB NOT NULL,
    label            TEXT,
    attestation      TEXT NOT NULL
                          CHECK (attestation IN ('none', 'indirect', 'direct', 'enterprise')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at     TIMESTAMPTZ,
    revoked_at       TIMESTAMPTZ,
    UNIQUE (tenant_id, cred_id)
);

CREATE INDEX IF NOT EXISTS webauthn_credentials_tenant_user_idx
    ON webauthn_credentials (tenant_id, user_id)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS webauthn_credentials_tenant_cred_idx
    ON webauthn_credentials (tenant_id, cred_id);

ALTER TABLE webauthn_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE webauthn_credentials FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_webauthn_credentials
    ON webauthn_credentials
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
