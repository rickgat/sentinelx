-- SAML 2.0 per-tenant Identity Provider configuration (P0-004).
--
-- One row per tenant. Holds the IdP's `EntityID`, single-sign-on +
-- optional single-logout URLs, the IdP's X.509 signing certificate
-- (PEM-encoded), and the chosen signing algorithm. The SAML SP adapter
-- (`services/sx-monolith/src/adapters/saml.rs`) loads the row keyed by
-- `tenant_id` at ACS time and uses it to verify the embedded
-- `<ds:Signature>` over the `<saml:Assertion>` subtree.
--
-- ## Tenant isolation
--
-- Standard ENABLED + FORCED row-level security keyed on the
-- `app.current_tenant_id` GUC set by the storage layer at the start of
-- every repository transaction (see `20260101000010_enable_rls.sql`).
-- This keeps tenant A's IdP config invisible to tenant B even if a
-- shared service-role connection forgets to filter on `tenant_id`.
--
-- ## Storage shape
--
-- * `entity_id` — the IdP's `EntityID` (used to match incoming responses'
--   `<saml:Issuer>`).
-- * `sso_url` — the IdP's `SingleSignOnService` endpoint. The SP redirects
--   the user agent here on the AuthN-request leg.
-- * `slo_url` — optional `SingleLogoutService` endpoint. Tenants that
--   leave this NULL get a 422 from `GET /v1/auth/saml/logout`.
-- * `x509_cert_pem` — PEM-encoded IdP signing certificate. We do NOT
--   normalise to DER on disk because (a) PEM is what every operator
--   uploads from their IdP admin console and (b) the verifier already
--   accepts both PEM and SPKI shapes.
-- * `signing_algo` — `sha1`, `sha256`, or `sha384`. SHA-1 is retained
--   only because some legacy ADFS deployments still emit it; new tenants
--   should pick SHA-256.

CREATE TABLE saml_idp_config (
    tenant_id        UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    entity_id        TEXT NOT NULL
                          CHECK (length(entity_id) BETWEEN 1 AND 1024),
    sso_url          TEXT NOT NULL
                          CHECK (sso_url ~* '^https?://'),
    slo_url          TEXT NULL
                          CHECK (slo_url IS NULL OR slo_url ~* '^https?://'),
    x509_cert_pem    TEXT NOT NULL
                          CHECK (length(x509_cert_pem) BETWEEN 64 AND 16384),
    signing_algo     TEXT NOT NULL DEFAULT 'sha256'
                          CHECK (signing_algo IN ('sha1', 'sha256', 'sha384')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX saml_idp_config_entity_id_idx ON saml_idp_config (entity_id);

ALTER TABLE saml_idp_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_idp_config FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_saml_idp_config ON saml_idp_config
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
