-- Durable store for SCIM 2.0 provisioned Users and Groups.
--
-- The composition root bound the SCIM provisioner to an in-memory map, so
-- every SCIM-provisioned user and group — pushed by an external IdP — was
-- lost on a monolith restart (and invisible across instances). This pairs
-- with the durable SCIM bearer-token store (`scim_tokens`): together they
-- make the SCIM integration survive a restart end to end.
--
-- Each resource is stored losslessly as JSONB (the `ScimUser` / `ScimGroup`
-- aggregate, including `meta`) keyed by `(tenant_id, id)`, with a
-- `resource_name` column (`userName` / `displayName`) carrying a
-- case-insensitive UNIQUE index so the RFC 7644 §3.3 duplicate-name 409 is
-- enforced in the database. User soft-delete (`active = false`) keeps the
-- row, so a deprovisioned name stays reserved — matching the in-memory store.
--
-- Keyed by a globally-unique resource id and filtered explicitly by
-- `tenant_id` on every query, these tables are intentionally NOT under
-- tenant RLS (same rationale as `mfa_enrollments` / `scim_tokens`);
-- isolation is by the explicit `tenant_id` predicate.

CREATE TABLE scim_users (
    tenant_id      TEXT        NOT NULL,
    id             TEXT        NOT NULL,
    resource_name  TEXT        NOT NULL,
    aggregate      JSONB       NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);

-- RFC 7644 §3.3: `userName` is unique per tenant, case-insensitive.
CREATE UNIQUE INDEX scim_users_tenant_name_idx
    ON scim_users (tenant_id, lower(resource_name));

CREATE TABLE scim_groups (
    tenant_id      TEXT        NOT NULL,
    id             TEXT        NOT NULL,
    resource_name  TEXT        NOT NULL,
    aggregate      JSONB       NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);

-- `displayName` is unique per tenant, case-insensitive.
CREATE UNIQUE INDEX scim_groups_tenant_name_idx
    ON scim_groups (tenant_id, lower(resource_name));
