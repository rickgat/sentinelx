-- Per-tenant outbound webhook HMAC signing-key history (MED-003).
--
-- One row per `(tenant_id, kid)` pair. The rotator schedules a new row
-- every `RotationPolicy::cadence` (default 90 days). The verifier
-- endpoint accepts every row whose `(activated_at <= now()) AND
-- (retired_at IS NULL OR retired_at > now())`, so both the previous and
-- the freshly-minted key remain valid throughout the 7-day grace
-- window.
--
-- ## Columns
--
-- * `tenant_id`     — uuid of the tenant; tenant-scoped via FORCE-RLS.
-- * `kid`           — short, opaque key identifier emitted in the
--                     `X-SentinelX-Kid` header on every signed payload.
--                     Generated as `kid_<8-hex>` so it fits in HTTP
--                     headers without escaping.
-- * `secret_enc`    — envelope-encrypted HMAC secret (ciphertext from
--                     `sx_secrets::EnvelopeKeyManager`). Plaintext is
--                     32 random bytes from `OsRng`; we never store the
--                     plaintext.
-- * `created_at`    — wall-clock time the row was minted.
-- * `activated_at`  — moment the key first becomes a signing candidate.
--                     The newest active key is the primary signer; the
--                     verifier additionally accepts every other
--                     non-retired key for the grace window.
-- * `retired_at`    — moment the key stops being accepted. NULL until
--                     the rotator cutover. After `retired_at` the
--                     verifier rejects requests signed with this `kid`.
--
-- ## Cross-field invariants
--
-- * `created_at <= activated_at` enforced by CHECK.
-- * `retired_at IS NULL OR retired_at >= activated_at` enforced by CHECK.
-- * `(tenant_id, kid)` is unique — there is exactly one row per
--   `(tenant, kid)` pair.
--
-- ## Row-Level Security
--
-- ENABLED + FORCED to match every other tenant-scoped table. The policy
-- keys off `app_current_tenant()` so a cross-tenant write or read
-- silently returns zero rows / fails the INSERT check.
--
-- ## Indexes
--
-- The hot read path is the signer's "pick latest active key for tenant"
-- and the verifier's "find by (tenant_id, kid)". The primary key
-- already covers point lookups; the secondary index on
-- `(tenant_id, activated_at DESC)` supports the signer's "latest" query
-- without a sort.

CREATE TABLE webhook_signing_keys (
    tenant_id     UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kid           TEXT         NOT NULL CHECK (length(kid) BETWEEN 4 AND 64),
    secret_enc    TEXT         NOT NULL CHECK (length(secret_enc) BETWEEN 1 AND 4096),
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    activated_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    retired_at    TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, kid),
    CONSTRAINT webhook_keys_activated_after_created
        CHECK (created_at <= activated_at),
    CONSTRAINT webhook_keys_retired_after_activated
        CHECK (retired_at IS NULL OR retired_at >= activated_at)
);

CREATE INDEX webhook_signing_keys_tenant_activated_idx
    ON webhook_signing_keys (tenant_id, activated_at DESC);

ALTER TABLE webhook_signing_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_signing_keys FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_webhook_signing_keys
    ON webhook_signing_keys
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
