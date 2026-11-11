-- MED-005 — SCIM token rotation + scoped tokens.
--
-- Extends the P0-005 `scim_tokens` table with the four columns required by
-- the rotation state machine:
--
--   scopes        JSONB  array of canonical wire scope strings
--                        (e.g. `["scim:users:read", "scim:users:write"]`).
--                        Default `[]` means default-deny — the token
--                        authenticates but authorises nothing. The
--                        application layer enforces non-empty mint
--                        (`InMemoryScim::mint_token` rejects empty
--                        scopes), so existing rows that pre-date this
--                        migration default to default-deny too.
--
--   activated_at  TIMESTAMPTZ when the token first became authoritative.
--                 In practice equal to `created_at` for fresh mints; the
--                 column is split out so a future "stage then activate"
--                 rotation strategy can reuse the same schema.
--
--   expires_at    TIMESTAMPTZ end of the rotation cadence. NULL on
--                 pre-existing rows means "no cadence enforced yet" —
--                 the application MUST treat NULL as expired-on-startup
--                 (back-fill is operator-driven via the rotate API).
--
--   retired_at    TIMESTAMPTZ end of the grace window after a rotation.
--                 NULL while the token is the live authority; set to
--                 `rotation_at + grace_window` on rotation.
--
--   revoked_at    TIMESTAMPTZ explicit revocation timestamp. Once set,
--                 the token returns 401 immediately and unconditionally.
--
-- ROW-LEVEL SECURITY
--
-- Inherits the FORCE-RLS policy installed in the P0-005 migration. No
-- schema change is needed here — `ALTER TABLE` does not relax RLS.

ALTER TABLE scim_tokens
    ADD COLUMN IF NOT EXISTS scopes       JSONB        NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS activated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS expires_at   TIMESTAMPTZ  NULL,
    ADD COLUMN IF NOT EXISTS retired_at   TIMESTAMPTZ  NULL,
    ADD COLUMN IF NOT EXISTS revoked_at   TIMESTAMPTZ  NULL;

-- A token is "live" when revoked_at IS NULL and (retired_at IS NULL OR
-- retired_at > NOW()). This expression is intentionally not pushed into
-- a generated column — the SCIM adapter computes status at read time
-- via `TokenRow::status_at` so the wall clock stays a single source of
-- truth across in-memory + Postgres implementations.

-- Index acceleration for the rotation scheduler's "due soon" query.
CREATE INDEX IF NOT EXISTS scim_tokens_expires_at_idx
    ON scim_tokens (expires_at)
    WHERE expires_at IS NOT NULL;

-- Index acceleration for the lifecycle audit query
-- (`SELECT ... WHERE retired_at < NOW() OR revoked_at IS NOT NULL`).
CREATE INDEX IF NOT EXISTS scim_tokens_lifecycle_idx
    ON scim_tokens (retired_at, revoked_at);

-- Belt-and-braces: keep the FORCE-RLS guarantee even if the next admin
-- pushes a destructive `ALTER TABLE`. This is a no-op when the bit is
-- already set, but documents the invariant.
ALTER TABLE scim_tokens FORCE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- SCIM audit log — extend the action whitelist for the new lifecycle
-- events (`mint_token`, `rotate_token`, `revoke_token`, `scope_violation`).
-- ---------------------------------------------------------------------------

-- Drop and re-create the check constraint atomically. CHECK constraints
-- are not nameable in `ALTER TABLE ADD CONSTRAINT IF NOT EXISTS` on
-- vanilla Postgres < 15, so we wrap in a DO block that no-ops when the
-- constraint already carries the extended set.
DO $$
BEGIN
    -- Drop the legacy constraint if present. The exact name depends on
    -- the migration runner (sqlx names it `scim_audit_action_check`).
    IF EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'scim_audit_action_check'
    ) THEN
        ALTER TABLE scim_audit DROP CONSTRAINT scim_audit_action_check;
    END IF;

    ALTER TABLE scim_audit
        ADD CONSTRAINT scim_audit_action_check
        CHECK (action IN (
            'create_user',
            'replace_user',
            'delete_user',
            'create_group',
            'mint_token',
            'rotate_token',
            'revoke_token',
            'scope_violation'
        ));
END
$$;
