-- FIDO2 / WebAuthn passkey credentials (P1-002 — MFA, TRD §24.3).
--
-- Each row stores ONE passkey enrolled by ONE user. A user may have
-- multiple credentials (laptop + phone + hardware key); each is
-- identified to the authenticator by its raw `credential_id` (variable
-- length, up to 1023 bytes per WebAuthn L3 §5.4.4).
--
-- The verifier side (sx-iam::service::webauthn) extracts four fields
-- from the registration ceremony into this table:
--   * cred_id        — the raw CredentialID bytes (BYTEA, unique
--                      *globally* per spec, not just per tenant).
--   * public_key     — the COSE-encoded public key, JSON-serialised by
--                      the service layer (`COSEKey: Serialize`). Stored
--                      as BYTEA so the encoding can evolve without a
--                      migration.
--   * counter        — last successful signature counter. Updated on
--                      every successful authentication; strict
--                      monotonic increase enforced by
--                      `WebauthnService::finish_authentication`.
--   * aaguid         — 16-byte authenticator identifier. NULL for
--                      U2F-style devices that don't supply one.
--
-- ## Tenant isolation
--
-- The table is tenant-scoped via `tenant_id` with the same Row-Level
-- Security pattern used by `users`, `engagements`, etc. RLS is
-- ENABLED + FORCED and a `tenant_isolation_user_webauthn_credentials`
-- policy keys off the `app.current_tenant_id` GUC set by the storage
-- layer at the start of every repository transaction.
--
-- ## Uniqueness
--
-- * `(tenant_id, cred_id)` — a credential ID may only be registered
--   once within a tenant. We do not constrain cross-tenant uniqueness
--   at the DB layer (RLS would already prevent a cross-tenant lookup);
--   the WebAuthn spec only requires uniqueness within the relying
--   party, which here corresponds to a tenant.
-- * `(tenant_id, user_id, name)` — a user cannot have two credentials
--   with the same human label (`name`, e.g. "YubiKey 5C", "iPhone").

CREATE TABLE user_webauthn_credentials (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id)   ON DELETE CASCADE,

    -- Raw CredentialID. WebAuthn L3 §5.4.4 caps this at 1023 bytes.
    cred_id         BYTEA NOT NULL
                          CHECK (octet_length(cred_id) BETWEEN 1 AND 1023),

    -- COSE-encoded public key as serialised by the service layer.
    -- The exact encoding (JSON vs. CBOR) is opaque to the DB; we only
    -- guarantee it round-trips through `WebauthnService::finish_*`.
    public_key      BYTEA NOT NULL
                          CHECK (octet_length(public_key) BETWEEN 1 AND 4096),

    -- Last verified signature counter. The service enforces strict
    -- monotonic increase per W3C §7.2 step 21.
    counter         BIGINT NOT NULL DEFAULT 0
                           CHECK (counter >= 0 AND counter <= 4294967295),

    -- 16-byte AAGUID — NULL when the authenticator does not supply one.
    aaguid          BYTEA
                          CHECK (aaguid IS NULL OR octet_length(aaguid) = 16),

    -- Human-readable credential nickname surfaced in the dashboard
    -- ("YubiKey 5C", "Pixel 9", ...). Tenant-scoped uniqueness per
    -- user keeps the picker unambiguous.
    name            TEXT NOT NULL
                          CHECK (length(name) BETWEEN 1 AND 128),

    -- Authenticator transports advertised by the device (usb, nfc, ble,
    -- internal, hybrid). Stored as a sorted TEXT[] so the dashboard can
    -- pick the right icon. Optional — synced passkeys may omit it.
    transports      TEXT[] NOT NULL DEFAULT '{}',

    -- Backup-eligibility & backup-state flags from the authenticator
    -- data, recorded at registration. Used by risk scoring to flag
    -- non-backed-up hardware keys as single-points-of-failure.
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state    BOOLEAN NOT NULL DEFAULT FALSE,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ,

    UNIQUE (tenant_id, cred_id),
    UNIQUE (tenant_id, user_id, name)
);

CREATE INDEX user_webauthn_credentials_tenant_user_idx
    ON user_webauthn_credentials (tenant_id, user_id);
CREATE INDEX user_webauthn_credentials_tenant_cred_idx
    ON user_webauthn_credentials (tenant_id, cred_id);
CREATE INDEX user_webauthn_credentials_tenant_last_used_idx
    ON user_webauthn_credentials (tenant_id, last_used_at DESC NULLS LAST);

-- Row-Level Security: same pattern as every other tenant-scoped table
-- (see `20260101000010_enable_rls.sql` for the `app_current_tenant()`
-- helper).
ALTER TABLE user_webauthn_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_webauthn_credentials FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_user_webauthn_credentials
    ON user_webauthn_credentials
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
