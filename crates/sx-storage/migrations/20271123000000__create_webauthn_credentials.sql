-- Durable store for registered FIDO2 / WebAuthn passkeys.
--
-- The composition root bound the WebAuthn credential repository to an
-- in-memory `Vec<StoredCredential>`, so every user's registered passkey —
-- public key, signature counter, attestation and the opaque webauthn-rs
-- `Passkey` blob needed to reconstruct a login ceremony — was lost on a
-- monolith restart. A passkey-only user was then locked out until they
-- re-enrolled a credential. This table persists them.
--
-- The full `sx_iam::model::webauthn::StoredCredential` aggregate is stored
-- losslessly as JSONB, keyed by `(tenant_id, cred_id)`, with scalar
-- projections (`user_id`, `revoked_at`, `created_at`) so `list_active` can
-- filter + order without deserialising every row — the same lossless-aggregate
-- pattern as `pentest_runs` and `engagement_aggregates`.
--
-- RLS: ENABLED + FORCED, keyed on `app_current_tenant()` set by
-- `TenantContext::apply`, matching every other tenant-scoped table.

CREATE TABLE webauthn_credentials (
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    cred_id     TEXT        NOT NULL,
    user_id     UUID        NOT NULL,
    revoked_at  TIMESTAMPTZ,
    aggregate   JSONB       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, cred_id)
);

-- `list_active(tenant_id, user_id)` scans active credentials for one user.
CREATE INDEX webauthn_credentials_active_idx
    ON webauthn_credentials (tenant_id, user_id)
    WHERE revoked_at IS NULL;

ALTER TABLE webauthn_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE webauthn_credentials FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_webauthn_credentials
    ON webauthn_credentials
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
