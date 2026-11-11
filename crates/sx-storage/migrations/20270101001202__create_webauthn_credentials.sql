-- FIDO2 / WebAuthn passkey credentials (P1-002).
--
-- Registered as:
--   * M40_WEBAUTHN_CREDENTIALS  — per-user passkey store, tenant-scoped.
--   * M41_WEBAUTHN_TENANT_RP   — per-tenant relying-party configuration
--                                 (rp_id, rp_origin, attestation).
--
-- ## Tenant isolation
--
-- Both tables follow the platform's RLS pattern keyed on the
-- `app.current_tenant_id` GUC set by the storage layer at the start of
-- every repository transaction (see `20260101000010_enable_rls.sql`).
--
-- ## Storage shape
--
-- * `webauthn_tenant_rp` holds one row per tenant carrying the
--   relying-party configuration. `rp_id` and `rp_origin` MUST be a
--   matching pair (rp_id is an effective domain of rp_origin's host)
--   or the runtime `WebauthnService::new` call will reject the row at
--   load time.
--
-- * `webauthn_credentials` holds N rows per user — a user may register
--   multiple authenticators (e.g. one platform passkey + one roaming
--   security key). The credential ID (`cred_id`) is unique platform-wide
--   per the W3C recommendation. The `passkey` column is the full
--   `webauthn-rs` serialised `Passkey` JSON so `start_authentication`
--   can reconstitute the credential without re-deriving from the
--   individual columns.

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
    -- Raw credential ID, base64url-encoded for human-readable lookup.
    -- The full byte form is also stored verbatim in `cred_id_bytes`.
    cred_id          TEXT NOT NULL,
    cred_id_bytes    BYTEA NOT NULL,
    -- COSE-encoded public key as JSON bytes (round-tripped through
    -- webauthn-rs's serde impl so reconstruction is lossless).
    public_key       BYTEA NOT NULL,
    -- Authenticator AAGUID (16 bytes) or NULL for U2F-style devices.
    aaguid           BYTEA,
    -- Last observed signature counter; updated on every successful
    -- assertion. A regression (new < stored, or new = stored for
    -- non-zero values) is treated as a clone signal and the credential
    -- MUST be revoked (`revoked_at` populated).
    counter          INTEGER NOT NULL DEFAULT 0,
    -- Full webauthn-rs Passkey blob (JSON) so subsequent
    -- start_authentication does not need to re-derive from columns.
    passkey          JSONB NOT NULL,
    -- Human-readable label set by the user on enrolment ("YubiKey 5",
    -- "iPhone Touch ID", etc.). Optional.
    label            TEXT,
    -- Attestation level the credential was registered under.
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
