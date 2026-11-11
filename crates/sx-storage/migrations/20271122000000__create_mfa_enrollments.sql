-- Durable MFA/TOTP enrolment store.
--
-- The composition root bound MFA to an in-memory map, so every user's TOTP
-- secret + recovery-code hashes were lost on a monolith restart (all users
-- forced to re-enrol 2FA). This table persists them.
--
-- Keyed by `user_id` alone: the `MfaPort` is tenant-less (enroll/verify/
-- status/disable take only a user id), and a user id is a globally-unique
-- UUID, so there is no cross-tenant key collision. Every access is an exact
-- `WHERE user_id = $1` lookup. There is therefore no tenant GUC to key an
-- RLS policy on, so this table is intentionally NOT under tenant RLS (unlike
-- the tenant-scoped tables); isolation is by the unique user-id key.
--
-- The enrolment aggregate (secret, verified flag, last_verified_at, recovery
-- hashes) is stored as JSONB — a lossless mirror of the in-memory shape.

CREATE TABLE mfa_enrollments (
    user_id     UUID        PRIMARY KEY,
    enrollment  JSONB       NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
