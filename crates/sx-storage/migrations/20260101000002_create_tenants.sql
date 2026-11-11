-- `tenants` is the root of multi-tenancy. It is intentionally not
-- under RLS: it is the authority that other tables key off of. Only
-- platform-administrator code paths reach this table.

CREATE TABLE tenants (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 256),
    slug        CITEXT NOT NULL UNIQUE CHECK (length(slug) BETWEEN 1 AND 64),
    tier        TEXT NOT NULL CHECK (tier IN ('starter', 'growth', 'enterprise')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at  TIMESTAMPTZ
);

-- Partial index over active tenants for fast slug lookups in the hot
-- path (login / API onboarding).
CREATE INDEX tenants_active_slug_idx
    ON tenants (slug)
    WHERE deleted_at IS NULL;
