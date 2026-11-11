#!/usr/bin/env bash
# SentinelX local-multiregion: pg_standby bootstrap.
#
# Strategy (Postgres 16):
#   1. If PGDATA already contains a base backup (re-run case), skip step 2.
#   2. Otherwise:
#       a. Wait for pg_primary to accept connections.
#       b. pg_basebackup from pg_primary into PGDATA.
#       c. Touch standby.signal (Pg 12+ replaces recovery.conf).
#       d. Write primary_conninfo / primary_slot_name into postgresql.auto.conf.
#   3. Exec postgres in hot-standby mode.
#
# The primary_conninfo is built from the docker-compose-injected env vars
# but defaults match init.sql literals so the file works standalone too.

set -euo pipefail

PG_PRIMARY_HOST="${PG_PRIMARY_HOST:-pg_primary}"
PG_PRIMARY_PORT="${PG_PRIMARY_PORT:-5432}"
PG_REPL_USER="${PG_REPL_USER:-replicator}"
PG_REPL_PASSWORD="${PG_REPL_PASSWORD:-sentinelx-replica-pw}"
PG_REPL_SLOT="${PG_REPL_SLOT:-sx_standby_slot}"

# The postgres:16-alpine image always sets PGDATA via its base image; default
# matches the upstream value.
PGDATA="${PGDATA:-/var/lib/postgresql/data}"

mkdir -p "${PGDATA}"
chown -R postgres:postgres "${PGDATA}" || true
chmod 0700 "${PGDATA}" || true

if [ ! -s "${PGDATA}/PG_VERSION" ]; then
    echo "==> pg_standby: empty PGDATA; running pg_basebackup against ${PG_PRIMARY_HOST}:${PG_PRIMARY_PORT}"

    # Wait for the primary to accept TCP.
    DEADLINE=$(( $(date +%s) + 120 ))
    until PGPASSWORD="${PG_REPL_PASSWORD}" pg_isready \
            -h "${PG_PRIMARY_HOST}" -p "${PG_PRIMARY_PORT}" \
            -U "${PG_REPL_USER}" >/dev/null 2>&1; do
        if [ "$(date +%s)" -gt "${DEADLINE}" ]; then
            echo "FATAL: primary did not become ready within 120s" >&2
            exit 1
        fi
        sleep 2
    done

    # Run the base backup as the postgres user so file ownership is right.
    su -s /bin/sh postgres -c "
        PGPASSWORD='${PG_REPL_PASSWORD}' pg_basebackup \
            -h '${PG_PRIMARY_HOST}' -p '${PG_PRIMARY_PORT}' \
            -U '${PG_REPL_USER}' \
            -D '${PGDATA}' \
            -Fp -Xs -P -R \
            -S '${PG_REPL_SLOT}'
    "

    # pg_basebackup -R already creates standby.signal and writes
    # primary_conninfo into postgresql.auto.conf; the lines below are
    # defensive (older clients).
    if [ ! -f "${PGDATA}/standby.signal" ]; then
        su -s /bin/sh postgres -c "touch '${PGDATA}/standby.signal'"
    fi

    if ! grep -q '^primary_slot_name' "${PGDATA}/postgresql.auto.conf" 2>/dev/null; then
        echo "primary_slot_name = '${PG_REPL_SLOT}'" \
            | su -s /bin/sh postgres -c "tee -a '${PGDATA}/postgresql.auto.conf' >/dev/null"
    fi
else
    echo "==> pg_standby: PGDATA already initialised; skipping base backup."
fi

# Hand off to the postgres image's standard entrypoint (handles user-switch,
# args, signals).
exec docker-entrypoint.sh postgres \
    -c hot_standby=on \
    -c listen_addresses='*'
