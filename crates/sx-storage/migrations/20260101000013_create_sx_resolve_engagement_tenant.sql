-- `sx_resolve_engagement_tenant(UUID)` — the canonical
-- engagement → tenant resolver.
--
-- Adapters (notably `PgApprovalAdapter` in `sx-monolith`) bridge a
-- tenant-less HTTP port to a tenant-scoped storage repository, which
-- means they need to look up the owning `tenant_id` for an
-- `engagement_id` before they have a `TenantContext` to set
-- `app.current_tenant_id`. RLS would otherwise hide the row.
--
-- Historically the adapter worked around this with `SET LOCAL
-- row_security = off`, which only succeeds on superuser / BYPASSRLS
-- roles. That is acceptable for dev/CI but inappropriate for
-- production hardening.
--
-- This `SECURITY DEFINER` function solves the same problem without
-- relaxing RLS on the caller's session: the function executes with
-- the privileges of its owner (the migration runner, which is the
-- table owner), so RLS does not apply to the lookup, while the
-- caller's session keeps RLS enforced for everything else.
--
-- The function returns a single `tenant_id` (a UUID, not a row) so
-- the bypass cannot leak any other column through the function
-- surface.
--
-- Search path is pinned to `public` so a caller cannot shadow
-- `engagements` via a malicious schema on `search_path`.
--
-- NOTE on grants: the workspace does not provision a dedicated
-- application role in its migrations (see
-- `20260101000001_init_extensions.sql`). To keep the function
-- usable by whichever role the pool happens to connect as in dev,
-- CI, and production, EXECUTE is granted to PUBLIC. The function
-- only returns the `tenant_id` column of a single row keyed by
-- primary key, so this grant does not widen the surface beyond
-- what the adapter already needs.

CREATE OR REPLACE FUNCTION sx_resolve_engagement_tenant(engagement UUID)
RETURNS UUID
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT tenant_id FROM engagements WHERE id = engagement;
$$;

-- Lock the grant surface down before re-granting to the intended
-- audience. The workspace migrations do not create a dedicated
-- `sentinelx` role, so we fall back to a PUBLIC EXECUTE grant; see
-- the header comment for the rationale.
REVOKE ALL ON FUNCTION sx_resolve_engagement_tenant(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sx_resolve_engagement_tenant(UUID) TO PUBLIC;
