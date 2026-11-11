-- Durable store for SCIM 2.0 bearer tokens.
--
-- The composition root bound SCIM bearer tokens to an in-memory map, so
-- every tenant's provisioning token — the credential an external IdP uses
-- to push users/groups via SCIM — was lost on a monolith restart, silently
-- breaking the provisioning integration until an admin re-minted a token.
-- This table persists them (the hash only; the plaintext is returned once
-- at mint time and never stored).
--
-- The full `TokenRow` lifecycle aggregate (SHA-256 hash, scopes, created/
-- activated/expires/retired/revoked/last-used timestamps) is stored as JSONB,
-- keyed by the token `id`, with:
--   * `token_hash` (bytea, UNIQUE) — the indexed exact-match lookup for
--     `authenticate`, which runs before any tenant is known;
--   * `tenant_id` — per-tenant listing / rotation / revoke filters.
--
-- Keyed by a globally-unique token id + hash, and `authenticate` has no
-- tenant context, so — like `mfa_enrollments` — this table is intentionally
-- NOT under tenant RLS. Isolation is by the explicit `tenant_id` filter the
-- lifecycle methods (list/rotate/revoke) already enforce, plus the
-- unguessable 256-bit token the hash is derived from.

CREATE TABLE scim_tokens (
    id          TEXT        PRIMARY KEY,
    tenant_id   TEXT        NOT NULL,
    token_hash  BYTEA       NOT NULL UNIQUE,
    aggregate   JSONB       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-tenant listing (list_tokens / rotate / revoke scope checks).
CREATE INDEX scim_tokens_tenant_idx ON scim_tokens (tenant_id);
