-- Allow wildcard segments in `permissions.name` (IAM Postgres RBAC fix).
--
-- The domain permission model (sx-core) supports wildcard grants such as
-- `*:*` (the bootstrap admin role) and `pentest:*`, matched case-by-case by
-- the wildcard-aware `require_permission` check. The original CHECK only
-- admitted concrete `resource:action` names, so wildcard permissions could
-- not be persisted — which is why the Postgres-backed user repository
-- silently dropped the bootstrap admin's `*:*` role and every DB-backed user
-- logged in with an empty permissions claim (every authorised endpoint 403).
--
-- Relax the constraint so each segment is either a concrete identifier or a
-- single `*`. Concrete names keep their original shape; `*` is now allowed.
-- No existing deployment has applied the RBAC tables with data (the Postgres
-- path could not boot before the migration-version-collision fix), so this
-- is a forward-only tightening of capability.

ALTER TABLE permissions DROP CONSTRAINT permissions_name_check;

ALTER TABLE permissions
    ADD CONSTRAINT permissions_name_check
    CHECK (name ~ '^([a-z][a-z0-9_]*|\*):([a-z][a-z0-9_]*|\*)$');
