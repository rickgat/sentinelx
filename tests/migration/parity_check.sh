#!/usr/bin/env bash
# tests/migration/parity_check.sh
#
# Migration parity gate (TOP5-#4).
#
# Spins a fresh Postgres 16 container, applies every migration under
# `crates/sx-storage/migrations` forward, dumps the schema, and (when
# downgrade migrations exist) tests the round-trip. The script exits
# non-zero with a diff if the round-trip produces a non-byte-identical
# schema; the absence of downgrade migrations is recorded but is NOT a
# fail condition (the current workspace ships forward-only migrations
# by policy — see `docs/RDBMS.md:1972`).
#
# Usage:
#   tests/migration/parity_check.sh
#
# Prereqs (verified at startup):
#   - docker reachable (`docker info`)
#   - sqlx-cli installed (`cargo install sqlx-cli --no-default-features --features postgres`)
#   - or fall back to the workspace runner if sqlx-cli is absent
#
# Exit codes:
#   0  parity verified, or forward-only with no round-trip to compare
#   1  prereq missing
#   2  migration apply failed
#   3  schema dump failed
#   4  parity diff non-empty (downgrade->upgrade is not idempotent)
#
# This script is intentionally docker-only (no docker-compose) so it
# runs anywhere a CI runner can pull `postgres:16-alpine`.

set -euo pipefail

# ---------------------------------------------------------------------
# Configuration (env overrides)
# ---------------------------------------------------------------------

readonly PG_IMAGE="${PG_IMAGE:-postgres:16-alpine}"
readonly PG_PASSWORD="${PG_PASSWORD:-sentinelx-parity-pw}"
readonly PG_USER="${PG_USER:-sentinelx}"
readonly PG_DB="${PG_DB:-sentinelx_parity}"
readonly PG_PORT="${PG_PORT:-55432}"

readonly WORKDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MIGRATIONS_DIR="${WORKDIR}/crates/sx-storage/migrations"
readonly TMPDIR="$(mktemp -d -t sx-migration-parity.XXXXXX)"

readonly CONTAINER_NAME="sx-parity-pg-$$"

# ---------------------------------------------------------------------
# Cleanup trap — always destroy the container + tmpdir
# ---------------------------------------------------------------------

cleanup() {
  local exit_code=$?
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  rm -rf "${TMPDIR}"
  exit "${exit_code}"
}
trap cleanup EXIT

# ---------------------------------------------------------------------
# Prereq verification
# ---------------------------------------------------------------------

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "FATAL: required command not found: $1" >&2
    exit 1
  fi
}

require_cmd docker
require_cmd diff

if ! docker info >/dev/null 2>&1; then
  echo "FATAL: docker daemon not reachable" >&2
  exit 1
fi

if [[ ! -d "${MIGRATIONS_DIR}" ]]; then
  echo "FATAL: migrations directory missing: ${MIGRATIONS_DIR}" >&2
  exit 1
fi

# Inventory + classify migrations.
mapfile -t FORWARD_FILES < <(find "${MIGRATIONS_DIR}" -maxdepth 1 -type f -name '*.sql' | sort)
DOWN_FILES=()
for f in "${FORWARD_FILES[@]}"; do
  base="$(basename "${f}")"
  case "${base}" in
    *.down.sql) DOWN_FILES+=("${f}") ;;
  esac
done

FORWARD_ONLY_COUNT="${#FORWARD_FILES[@]}"
DOWN_COUNT="${#DOWN_FILES[@]}"

echo "==> Migration inventory"
echo "    Forward .sql files : ${FORWARD_ONLY_COUNT}"
echo "    Down  .down.sql    : ${DOWN_COUNT}"

# Tool choice: prefer sqlx-cli (it's what `cargo` uses in CI). Fall back
# to `psql` apply (works because every migration in this workspace is
# pure SQL — no sqlx-specific syntax extensions).
if command -v sqlx >/dev/null 2>&1; then
  RUNNER=sqlx
  echo "==> Using sqlx-cli for migration apply"
else
  RUNNER=psql
  echo "==> sqlx-cli not present; falling back to psql apply"
  require_cmd psql
fi

# ---------------------------------------------------------------------
# Start Postgres
# ---------------------------------------------------------------------

echo "==> Starting Postgres container (${PG_IMAGE}) on port ${PG_PORT}"
docker run -d --rm \
  --name "${CONTAINER_NAME}" \
  -e "POSTGRES_USER=${PG_USER}" \
  -e "POSTGRES_PASSWORD=${PG_PASSWORD}" \
  -e "POSTGRES_DB=${PG_DB}" \
  -p "${PG_PORT}:5432" \
  "${PG_IMAGE}" >/dev/null

# Wait for postgres to accept connections.
export PGPASSWORD="${PG_PASSWORD}"
DEADLINE=$(($(date +%s) + 60))
until docker exec "${CONTAINER_NAME}" pg_isready -U "${PG_USER}" -d "${PG_DB}" >/dev/null 2>&1; do
  if [[ $(date +%s) -gt ${DEADLINE} ]]; then
    echo "FATAL: postgres did not become ready in 60s" >&2
    exit 2
  fi
  sleep 1
done

readonly DB_URL="postgres://${PG_USER}:${PG_PASSWORD}@127.0.0.1:${PG_PORT}/${PG_DB}"

# ---------------------------------------------------------------------
# apply_migrations <db_url>
# ---------------------------------------------------------------------

apply_migrations() {
  local db_url="$1"
  if [[ "${RUNNER}" == "sqlx" ]]; then
    sqlx migrate run --source "${MIGRATIONS_DIR}" --database-url "${db_url}"
  else
    for f in "${FORWARD_FILES[@]}"; do
      # Skip already-classified down migrations.
      case "$(basename "${f}")" in
        *.down.sql) continue ;;
      esac
      psql "${db_url}" -v ON_ERROR_STOP=1 -f "${f}" >/dev/null
    done
  fi
}

# ---------------------------------------------------------------------
# Pass 1 — clean DB, forward
# ---------------------------------------------------------------------

echo "==> Pass 1: applying all migrations forward"
if ! apply_migrations "${DB_URL}"; then
  echo "FATAL: pass-1 migration apply failed" >&2
  exit 2
fi

echo "==> Dumping schema (pass 1)"
if ! docker exec "${CONTAINER_NAME}" pg_dump \
    --schema-only --no-owner --no-acl \
    -U "${PG_USER}" "${PG_DB}" > "${TMPDIR}/schema.pass1.sql"; then
  echo "FATAL: pg_dump (pass 1) failed" >&2
  exit 3
fi

PASS1_LINES=$(wc -l < "${TMPDIR}/schema.pass1.sql" | tr -d ' ')
echo "    pass 1 schema: ${PASS1_LINES} lines"

# ---------------------------------------------------------------------
# Pass 2 — downgrade (if available) then forward again
# ---------------------------------------------------------------------

if [[ "${DOWN_COUNT}" -eq 0 ]]; then
  echo "==> No down migrations detected; workspace is forward-only by policy."
  echo "    See docs/RDBMS.md (migration policy) — recorded, not a fail."
  echo
  echo "PARITY CHECK PASSED (forward-only mode)"
  echo
  echo "Artefacts retained:"
  echo "    ${TMPDIR}/schema.pass1.sql"
  # Do not delete tmpdir on success-without-roundtrip; the operator
  # may want to diff against a future migration baseline.
  trap - EXIT
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  exit 0
fi

echo "==> Pass 2: applying down migrations (reverse alphabetical), then re-applying forward"
# Apply down migrations in reverse order.
for ((i=${#DOWN_FILES[@]}-1; i>=0; i--)); do
  psql "${DB_URL}" -v ON_ERROR_STOP=1 -f "${DOWN_FILES[i]}" >/dev/null
done

# Re-apply forward.
if ! apply_migrations "${DB_URL}"; then
  echo "FATAL: pass-2 re-apply failed" >&2
  exit 2
fi

echo "==> Dumping schema (pass 2)"
if ! docker exec "${CONTAINER_NAME}" pg_dump \
    --schema-only --no-owner --no-acl \
    -U "${PG_USER}" "${PG_DB}" > "${TMPDIR}/schema.pass2.sql"; then
  echo "FATAL: pg_dump (pass 2) failed" >&2
  exit 3
fi

PASS2_LINES=$(wc -l < "${TMPDIR}/schema.pass2.sql" | tr -d ' ')
echo "    pass 2 schema: ${PASS2_LINES} lines"

# ---------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------

echo "==> Diffing schemas"
if diff -u "${TMPDIR}/schema.pass1.sql" "${TMPDIR}/schema.pass2.sql" > "${TMPDIR}/schema.diff"; then
  echo
  echo "PARITY CHECK PASSED (round-trip byte-identical)"
  echo
  trap - EXIT
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  rm -rf "${TMPDIR}"
  exit 0
fi

echo
echo "PARITY CHECK FAILED — schemas differ after down/up round-trip" >&2
echo "Diff retained at: ${TMPDIR}/schema.diff" >&2
echo
cat "${TMPDIR}/schema.diff" >&2

# Leave tmpdir alone so the operator can inspect.
trap - EXIT
docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
exit 4
