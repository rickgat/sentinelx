-- SentinelX local-multiregion: primary init.
--
-- Runs once on first container boot via the postgres image's
-- /docker-entrypoint-initdb.d hook.
--
-- Responsibilities:
--   1. Create a replication role consumed by pg_standby (pg_basebackup).
--   2. Create a physical replication slot so the standby can resume after
--      a brief disconnect without losing WAL.
--
-- The replication credentials are pinned to the literals below to keep
-- this file static and idempotent. They are matched verbatim by
-- pg_standby/standby-entrypoint.sh. Override via .env if you need to
-- rotate them.

DO
$$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'replicator') THEN
        CREATE ROLE replicator
            WITH REPLICATION LOGIN PASSWORD 'sentinelx-replica-pw';
    END IF;
END
$$;

SELECT pg_create_physical_replication_slot('sx_standby_slot')
WHERE NOT EXISTS (
    SELECT 1 FROM pg_replication_slots WHERE slot_name = 'sx_standby_slot'
);
