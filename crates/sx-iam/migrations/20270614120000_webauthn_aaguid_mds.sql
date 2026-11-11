-- HIGH-002 — WebAuthn AAGUID blocklist + FIDO MDS3 metadata service.
--
-- Two new tables on top of the P1-002 schema:
--
--   * `webauthn_mds_metadata` — cached FIDO Alliance MDS3 entries,
--     keyed by AAGUID. Refreshed by the in-process MdsFetcher
--     (default weekly).
--   * `webauthn_aaguid_policy` — per-tenant per-AAGUID allow/block
--     decision rows. The presence of any `allow` row for a tenant
--     flips the tenant into "allowlist-only" mode (default-deny for
--     unmentioned AAGUIDs).
--
-- Both tables are tenant-aware (the policy table directly; the MDS
-- table is cross-tenant by design — the FIDO catalogue is global —
-- so RLS does not apply to it).
--
-- This file is the **owner-crate copy** referenced by the HIGH-002
-- task specification. The canonical migration the runtime applies
-- lives at:
--     crates/sx-storage/migrations/20270614120000__create_webauthn_aaguid_mds.sql
-- and is kept byte-identical to this file.

CREATE TABLE IF NOT EXISTS webauthn_mds_metadata (
    aaguid                  UUID PRIMARY KEY,
    authenticator_name      TEXT NOT NULL,
    authenticator_version   TEXT NOT NULL,
    certification_level     TEXT NOT NULL,
    last_updated            TIMESTAMPTZ NOT NULL DEFAULT now(),
    raw_blob                JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS webauthn_mds_metadata_last_updated_idx
    ON webauthn_mds_metadata (last_updated);

CREATE TABLE IF NOT EXISTS webauthn_aaguid_policy (
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    aaguid     UUID NOT NULL,
    action     TEXT NOT NULL CHECK (action IN ('allow', 'block')),
    reason     TEXT NOT NULL,
    set_by     UUID NOT NULL,
    set_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, aaguid)
);

CREATE INDEX IF NOT EXISTS webauthn_aaguid_policy_tenant_idx
    ON webauthn_aaguid_policy (tenant_id);

ALTER TABLE webauthn_aaguid_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE webauthn_aaguid_policy FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_webauthn_aaguid_policy
    ON webauthn_aaguid_policy
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
