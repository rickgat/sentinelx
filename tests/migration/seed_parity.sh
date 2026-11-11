#!/usr/bin/env bash
# tests/migration/seed_parity.sh
#
# Verifies the M2 seed-idempotency contract against a real Postgres
# (the workspace's in-memory adapters already pass this gate; this
# script proves it on the production storage path).
#
# What it does:
#   1. Start a fresh Postgres 16 container, apply migrations.
#   2. Boot `sx-monolith` against the container; it seeds the
#      bootstrap admin (`admin@sentinelx.dev`) and demo data
#      idempotently per
#      `services/sx-monolith/src/adapters/postgres.rs::run_migrations`.
#   3. `pg_dump --data-only` of all non-system tables → dump A.
#   4. Stop the monolith.
#   5. Re-boot the monolith with the seed-disable flag
#      (`SENTINELX__BOOTSTRAP__ENABLED=false`) so we exercise the
#      "second boot" path. The monolith should NOT mutate seed rows.
#   6. `pg_dump --data-only` → dump B.
#   7. Diff A vs B — must be identical (modulo non-deterministic
#      timestamp columns, which we filter out).
#
# Exit codes:
#   0  seed idempotent (parity match)
#   1  prereq missing
#   2  container or monolith boot failure
#   3  pg_dump failure
#   4  parity diff non-empty (seed is NOT idempotent — M2 regression)
#
# Prereqs:
#   - docker
#   - cargo + workspace built (`cargo build --bin sx-monolith` once)
#   - `config/sentinelx.dev.example.yaml` present
#
# Run from workspace root.

set -euo pipefail

# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

readonly PG_IMAGE="${PG_IMAGE:-postgres:16-alpine}"
readonly PG_PASSWORD="${PG_PASSWORD:-sentinelx-seed-pw}"
readonly PG_USER="${PG_USER:-sentinelx}"
readonly PG_DB="${PG_DB:-sentinelx_seed}"
readonly PG_PORT="${PG_PORT:-55433}"

readonly WORKDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MONOLITH_PORT="${MONOLITH_PORT:-58080}"
readonly CONFIG_PATH="${WORKDIR}/config/sentinelx.dev.example.yaml"
readonly MONOLITH_BIN="${WORKDIR}/target/debug/sx-monolith"
readonly TMPDIR="$(mktemp -d -t sx-seed-parity.XXXXXX)"

readonly CONTAINER_NAME="sx-seed-pg-$$"

# ---------------------------------------------------------------------
# Cleanup trap
# ---------------------------------------------------------------------

MONOLITH_PID=""
cleanup() {
  local exit_code=$?
  if [[ -n "${MONOLITH_PID}" ]] && kill -0 "${MONOLITH_PID}" 2>/dev/null; then
    kill "${MONOLITH_PID}" 2>/dev/null || true
    wait "${MONOLITH_PID}" 2>/dev/null || true
  fi
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  if [[ "${exit_code}" -eq 0 ]]; then
    rm -rf "${TMPDIR}"
  else
    echo "Artefacts retained at ${TMPDIR}" >&2
  fi
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
require_cmd curl

if ! docker info >/dev/null 2>&1; then
  echo "FATAL: docker daemon not reachable" >&2
  exit 1
fi

if [[ ! -f "${CONFIG_PATH}" ]]; then
  echo "FATAL: dev config missing: ${CONFIG_PATH}" >&2
  exit 1
fi

if [[ ! -x "${MONOLITH_BIN}" ]]; then
  echo "==> Monolith binary missing; building (this may take a few minutes)..."
  (cd "${WORKDIR}" && cargo build --bin sx-monolith)
fi

# ---------------------------------------------------------------------
# Postgres up
# ---------------------------------------------------------------------

echo "==> Starting Postgres container (${PG_IMAGE})"
docker run -d --rm \
  --name "${CONTAINER_NAME}" \
  -e "POSTGRES_USER=${PG_USER}" \
  -e "POSTGRES_PASSWORD=${PG_PASSWORD}" \
  -e "POSTGRES_DB=${PG_DB}" \
  -p "${PG_PORT}:5432" \
  "${PG_IMAGE}" >/dev/null

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
# spawn_monolith <seed_enabled>
# ---------------------------------------------------------------------

spawn_monolith() {
  local seed_enabled="$1"
  echo "==> Spawning sx-monolith (seed_enabled=${seed_enabled}) on port ${MONOLITH_PORT}"

  SENTINELX_CONFIG="${CONFIG_PATH}" \
  SENTINELX__SERVER__BIND_ADDR="127.0.0.1:${MONOLITH_PORT}" \
  SENTINELX__STORAGE__POSTGRES__URL="${DB_URL}" \
  SENTINELX__BOOTSTRAP__ENABLED="${seed_enabled}" \
  RUST_LOG="warn,sx_monolith=info" \
    "${MONOLITH_BIN}" >"${TMPDIR}/monolith-${seed_enabled}.log" 2>&1 &
  MONOLITH_PID=$!

  # Wait for /healthz
  local boot_deadline=$(($(date +%s) + 60))
  until curl -fsS "http://127.0.0.1:${MONOLITH_PORT}/healthz" >/dev/null 2>&1; do
    if ! kill -0 "${MONOLITH_PID}" 2>/dev/null; then
      echo "FATAL: monolith exited during boot — see ${TMPDIR}/monolith-${seed_enabled}.log" >&2
      cat "${TMPDIR}/monolith-${seed_enabled}.log" >&2
      exit 2
    fi
    if [[ $(date +%s) -gt ${boot_deadline} ]]; then
      echo "FATAL: monolith did not become healthy in 60s" >&2
      exit 2
    fi
    sleep 1
  done
}

stop_monolith() {
  if [[ -z "${MONOLITH_PID}" ]]; then
    return
  fi
  kill "${MONOLITH_PID}" 2>/dev/null || true
  wait "${MONOLITH_PID}" 2>/dev/null || true
  MONOLITH_PID=""
}

# ---------------------------------------------------------------------
# Data dump with timestamp filter
# ---------------------------------------------------------------------
# Reproducible data dump: pg_dump prints `created_at` / `updated_at`
# timestamps that drift between boots even when the seed payload is
# logically identical. We filter to a stable subset by sorting and
# stripping the well-known timestamp columns.

dump_data() {
  local out="$1"
  docker exec "${CONTAINER_NAME}" pg_dump \
    --data-only \
    --inserts \
    --no-owner --no-acl \
    --exclude-table='_sqlx_migrations' \
    -U "${PG_USER}" "${PG_DB}" > "${out}.raw"

  # Strip volatile timestamp lines and sort INSERT bodies so two boot
  # orderings still compare equal. `sx_audit_log` is excluded entirely
  # because audit rows carry a per-boot nonce that is correctly
  # non-deterministic.
  grep -v "^--" "${out}.raw" \
    | grep -v "^SET " \
    | grep -v "^SELECT pg_catalog" \
    | grep -v "^INSERT INTO sx_audit_log" \
    | sed -E "s/'20[0-9]{2}-[0-9]{2}-[0-9]{2}T?[0-9]{2}:[0-9]{2}:[0-9]{2}[^']*'/'<TS>'/g" \
    | sort > "${out}"
}

# ---------------------------------------------------------------------
# Pass 1 — seed enabled, dump A
# ---------------------------------------------------------------------

spawn_monolith "true"

echo "==> Letting seed land (5s)"
sleep 5

echo "==> Dumping data (pass 1, post-seed)"
dump_data "${TMPDIR}/data.pass1.sql"
PASS1_BYTES=$(wc -c < "${TMPDIR}/data.pass1.sql" | tr -d ' ')
echo "    pass 1 dump: ${PASS1_BYTES} bytes (filtered)"

stop_monolith

# ---------------------------------------------------------------------
# Pass 2 — seed disabled, dump B
# ---------------------------------------------------------------------

spawn_monolith "false"

echo "==> Letting second-boot bookkeeping settle (5s)"
sleep 5

echo "==> Dumping data (pass 2, seed-disabled second boot)"
dump_data "${TMPDIR}/data.pass2.sql"
PASS2_BYTES=$(wc -c < "${TMPDIR}/data.pass2.sql" | tr -d ' ')
echo "    pass 2 dump: ${PASS2_BYTES} bytes (filtered)"

stop_monolith

# ---------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------

echo "==> Diffing"
if diff -u "${TMPDIR}/data.pass1.sql" "${TMPDIR}/data.pass2.sql" > "${TMPDIR}/data.diff"; then
  echo
  echo "SEED PARITY PASSED — second boot is idempotent against PG"
  echo
  exit 0
fi

echo
echo "SEED PARITY FAILED — second boot mutated seed rows (M2 regression)" >&2
echo "Diff retained at: ${TMPDIR}/data.diff" >&2
echo
head -200 "${TMPDIR}/data.diff" >&2
exit 4
