-- Postgres extensions used across the schema.
-- pgcrypto: gen_random_uuid() (defence-in-depth UUID source; we mint
--           UUIDv7 in the app layer but still rely on pgcrypto for
--           random salt / fallback ids in audit columns).
-- citext:   case-insensitive text type used for `users.email`,
--           `tenants.slug`, and other natural keys.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;
