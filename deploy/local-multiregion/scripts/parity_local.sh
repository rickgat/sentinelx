#!/usr/bin/env bash
# parity_local.sh
#
# Wrapper that runs the workspace migration parity check
# (`tests/migration/parity_check.sh`) against the local-multiregion
# docker-compose Postgres primary.
#
# The underlying script manages its own ephemeral postgres container, so
# this wrapper's job is purely:
#
#   1. Sanity-check docker + docker compose are present.
#   2. Run the parity check (which spins its own dedicated PG container
#      on port 55432 — by design, so it never collides with the long-
#      lived local-multiregion stack on the same port).
#   3. Optionally tear down the local-multiregion stack on exit if we
#      booted it.
#
# We deliberately do NOT run parity against the live pg_primary in the
# stack: parity_check.sh dumps + diffs a fresh schema, and dirtying the
# long-running primary breaks repeatability. The local-multiregion stack
# is for monolith smoke; the parity check is a separate orthogonal gate.
#
# If you want to point parity at the live primary anyway, run:
#
#   PGURL='postgres://sentinelx:sentinelx-local-pw@127.0.0.1:55432/sentinelx'
#   psql "$PGURL" -f crates/sx-storage/migrations/<file>.sql ...
#
# but that's a manual operation, not what this wrapper does.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKSPACE_ROOT="$(cd "${DEPLOY_DIR}/../.." && pwd)"
PARITY_SCRIPT="${WORKSPACE_ROOT}/tests/migration/parity_check.sh"

# ---------------------------------------------------------------------
# Prereqs
# ---------------------------------------------------------------------

require() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "FATAL: required command not found: $1" >&2
        exit 1
    fi
}

require docker

if ! docker info >/dev/null 2>&1; then
    echo "FATAL: docker daemon not reachable" >&2
    exit 1
fi

if [[ ! -x "${PARITY_SCRIPT}" ]]; then
    echo "FATAL: parity script missing or not executable: ${PARITY_SCRIPT}" >&2
    exit 1
fi

# Compose v2 plugin: `docker compose` (preferred). v1 fallback: docker-compose.
if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
else
    # Compose isn't strictly required for parity_check.sh (it manages its
    # own container) — only warn.
    echo "WARN: 'docker compose' / 'docker-compose' not found." >&2
    echo "      Parity check will still run (it uses raw 'docker run')." >&2
    COMPOSE=()
fi

# ---------------------------------------------------------------------
# Run parity check
# ---------------------------------------------------------------------

echo "==> Running workspace migration parity check"
echo "    script:    ${PARITY_SCRIPT}"
echo "    workspace: ${WORKSPACE_ROOT}"
echo

# Override the parity port to avoid colliding with pg_primary on 55432.
export PG_PORT="${PG_PORT:-55434}"

if "${PARITY_SCRIPT}"; then
    echo
    echo "==> parity_local: PASS"
    exit 0
else
    rc=$?
    echo
    echo "==> parity_local: FAIL (exit ${rc})"
    exit "${rc}"
fi
