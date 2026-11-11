-- Users belong to exactly one tenant. Email is case-insensitive
-- (CITEXT) and unique per tenant.

CREATE TABLE users (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email           CITEXT NOT NULL CHECK (length(email) BETWEEN 3 AND 320),
    password_hash   TEXT NOT NULL CHECK (length(password_hash) BETWEEN 1 AND 1024),
    display_name    TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    mfa_enrolled    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);

CREATE INDEX users_tenant_idx ON users (tenant_id);
CREATE INDEX users_tenant_email_idx ON users (tenant_id, email);
CREATE INDEX users_tenant_created_idx ON users (tenant_id, created_at);
