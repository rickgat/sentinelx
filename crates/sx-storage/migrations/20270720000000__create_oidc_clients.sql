-- OIDC confidential-client registry (MED-004).
--
-- One row per `(tenant_id, client_id)`. The token endpoint
-- (`POST /v1/oauth/token`) validates `client_secret_jwt` assertions
-- against this table; the admin endpoint
-- (`POST /v1/admin/oidc/clients/{client_id}/rotate-secret`) moves the
-- current secret into `previous_secret` and stamps a new live secret.
--
-- ## Columns
--
-- * `id`                   — surrogate uuid primary key.
-- * `tenant_id`            — owning tenant (RLS).
-- * `client_id`            — opaque, customer-facing identifier.
-- * `auth_method`          — one of `client_secret_basic`,
--                            `client_secret_post`, `client_secret_jwt`.
--                            MED-004 only ships `client_secret_jwt`
--                            validation; the others are reserved.
-- * `secret_envelope`      — envelope-encrypted bytes of the live secret
--                            (DEK-wrapped via `sx-secrets`). Opaque to
--                            this table.
-- * `previous_secret_envelope` — envelope-encrypted bytes of the
--                            previous secret retained for the rotation
--                            grace window. `NULL` outside rotation.
-- * `previous_expires_at`  — wall-clock the previous secret stops
--                            being accepted. `NULL` outside rotation.
-- * `rotated_at`           — wall-clock of the most recent rotation
--                            (populated on initial creation as well).
-- * `created_at`           — wall-clock of row insertion.
--
-- ## Row-Level Security
--
-- ENABLED + FORCED matching every other tenant-scoped table. Policy
-- keys off `app_current_tenant()` set by `TenantContext::apply`.
--
-- ## Indexes
--
-- The hot read path is `WHERE tenant_id = $1 AND client_id = $2` which
-- the UNIQUE constraint covers. A secondary index on `(tenant_id,
-- rotated_at)` supports the rotation scheduler's "find clients older
-- than cadence" sweep.

CREATE TABLE oidc_clients (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id                   TEXT NOT NULL CHECK (length(client_id) BETWEEN 1 AND 128),
    auth_method                 TEXT NOT NULL CHECK (auth_method IN
                                    ('client_secret_basic',
                                     'client_secret_post',
                                     'client_secret_jwt')),
    secret_envelope             BYTEA NOT NULL CHECK (length(secret_envelope) BETWEEN 1 AND 4096),
    previous_secret_envelope    BYTEA CHECK (previous_secret_envelope IS NULL
                                    OR length(previous_secret_envelope) BETWEEN 1 AND 4096),
    previous_expires_at         TIMESTAMPTZ,
    rotated_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, client_id),
    CONSTRAINT oidc_clients_previous_pair CHECK (
        (previous_secret_envelope IS NULL AND previous_expires_at IS NULL)
        OR (previous_secret_envelope IS NOT NULL AND previous_expires_at IS NOT NULL)
    ),
    CONSTRAINT oidc_clients_rotated_after_creation CHECK (rotated_at >= created_at)
);

CREATE INDEX oidc_clients_tenant_rotated_idx
    ON oidc_clients (tenant_id, rotated_at);

ALTER TABLE oidc_clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE oidc_clients FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_oidc_clients
    ON oidc_clients
    USING       (tenant_id = app_current_tenant())
    WITH CHECK  (tenant_id = app_current_tenant());
