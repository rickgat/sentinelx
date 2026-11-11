#!/usr/bin/env bash
# Appends a host-replication line so the pg_standby container can run
# pg_basebackup against this primary as the `replicator` role.
#
# Runs once on first boot via /docker-entrypoint-initdb.d. After this
# hook, postgres restarts and the new pg_hba lines take effect.
set -euo pipefail

PGDATA="${PGDATA:-/var/lib/postgresql/data}"
HBA="${PGDATA}/pg_hba.conf"

if ! grep -q '^host[[:space:]]\+replication[[:space:]]\+replicator' "${HBA}"; then
    {
        echo ""
        echo "# SentinelX local-multiregion: allow streaming replication from pg_standby."
        echo "host    replication     replicator      0.0.0.0/0       md5"
        echo "host    all             all             0.0.0.0/0       md5"
    } >> "${HBA}"
fi
