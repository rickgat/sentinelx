#!/usr/bin/env bash
# shellcheck shell=bash
#
# integration-smoke.sh - end-to-end integration smoke for SentinelX.
#
# Workflow:
#   1. docker compose up -d postgres redis      (with healthchecks)
#   2. cargo test --workspace -- --ignored      (live Postgres + Redis tests)
#   3. cargo run -p sx-monolith (background)    (HTTP API foreground in CI)
#   4. tests/integration/smoke.sh               (curl-based 5-step smoke)
#   5. tear down: kill monolith + docker compose down
#
# Usage:
#   scripts/integration-smoke.sh                # full run + teardown
#   scripts/integration-smoke.sh --keep-up      # leave containers running
#   scripts/integration-smoke.sh --no-cargo     # skip the --ignored cargo run
#   scripts/integration-smoke.sh --no-monolith  # skip booting the monolith
#   scripts/integration-smoke.sh --help
#
# Environment overrides:
#   POSTGRES_USER      (default sentinelx)
#   POSTGRES_PASSWORD  (default sentinelx_dev)
#   POSTGRES_DB        (default sentinelx)
#   POSTGRES_HOST_PORT (default 5432)
#   REDIS_PASSWORD     (default sentinelx_dev)
#   REDIS_HOST_PORT    (default 6379)
#   SX_HTTP_PORT       (default 8080)
#   SX_METRICS_PORT    (default 9090)
#   SX_BOOTSTRAP_TENANT_ID (default 00000000-0000-0000-0000-000000000001)
#   SX_BOOTSTRAP_EMAIL     (default admin@example.invalid)
#   SX_BOOTSTRAP_PASSWORD  (default sentinelx-admin-pw)
#   SX_HEALTH_TIMEOUT      (default 60 - seconds to wait for monolith)
#
# Linting: shellcheck ./scripts/integration-smoke.sh

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

KEEP_UP=0
RUN_CARGO=1
RUN_MONOLITH=1

log()  { printf '[smoke] %s\n' "$*"; }
warn() { printf '[smoke] WARN: %s\n' "$*" >&2; }
err()  { printf '[smoke] ERROR: %s\n' "$*" >&2; }

usage() {
    sed -n '2,33p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --keep-up)     KEEP_UP=1 ;;
            --no-cargo)    RUN_CARGO=0 ;;
            --no-monolith) RUN_MONOLITH=0 ;;
            --help|-h)     usage; exit 0 ;;
            *)             err "unknown arg: $1"; usage; exit 64 ;;
        esac
        shift
    done
}

require_tools() {
    for bin in docker curl jq; do
        if ! command -v "${bin}" >/dev/null 2>&1; then
            err "${bin} is required on PATH"
            exit 127
        fi
    done
    if ! docker compose version >/dev/null 2>&1; then
        err "'docker compose' subcommand missing (install compose v2 plugin)"
        exit 127
    fi
}

export_env() {
    : "${POSTGRES_USER:=sentinelx}"
    : "${POSTGRES_PASSWORD:=sentinelx_dev}"
    : "${POSTGRES_DB:=sentinelx}"
    : "${POSTGRES_HOST_PORT:=5432}"
    : "${REDIS_PASSWORD:=sentinelx_dev}"
    : "${REDIS_HOST_PORT:=6379}"
    : "${SX_HTTP_PORT:=8080}"
    : "${SX_METRICS_PORT:=9090}"
    : "${SX_BOOTSTRAP_TENANT_ID:=00000000-0000-0000-0000-000000000001}"
    : "${SX_BOOTSTRAP_EMAIL:=admin@example.invalid}"
    : "${SX_BOOTSTRAP_PASSWORD:=sentinelx-admin-pw}"
    : "${SX_HEALTH_TIMEOUT:=60}"

    # A precomputed Argon2id PHC for the password `sentinelx-admin-pw`.
    # Generated once and pinned so the smoke does not need a hashing helper
    # at runtime. Regenerate with `cargo run -p sx-cli -- hash-password` if
    # the default password is changed.
    : "${SX_BOOTSTRAP_ADMIN_PASSWORD_PHC:=\$argon2id\$v=19\$m=19456,t=2,p=1\$c2VudGluZWx4c21va2VzYWx0\$jR3CmU4PqJtmCaP9WzkAyMnLpRkr7q2ETkU+/wjpVK0}"

    TEST_DATABASE_URL="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:${POSTGRES_HOST_PORT}/${POSTGRES_DB}?sslmode=disable"
    SX_TEST_REDIS_URL="redis://:${REDIS_PASSWORD}@127.0.0.1:${REDIS_HOST_PORT}/0"

    # SENTINELX__* overrides feed sx-config; SX_* are read by smoke.sh.
    export POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB POSTGRES_HOST_PORT
    export REDIS_PASSWORD REDIS_HOST_PORT
    export SX_HTTP_PORT SX_METRICS_PORT
    export SX_BOOTSTRAP_TENANT_ID SX_BOOTSTRAP_EMAIL SX_BOOTSTRAP_PASSWORD
    export SX_HEALTH_TIMEOUT
    export TEST_DATABASE_URL SX_TEST_REDIS_URL
    export SENTINELX__DATABASE__URL="${TEST_DATABASE_URL}"
    export SENTINELX__DATABASE__ENABLED=true
    export SENTINELX__DATABASE__MIGRATE_ON_START=true
    export SENTINELX__REDIS__URL="${SX_TEST_REDIS_URL}"
    export SENTINELX__REDIS__ENABLED=true
    export SENTINELX__SERVER__BIND_ADDR="127.0.0.1:${SX_HTTP_PORT}"
    export SENTINELX__METRICS__BIND_ADDR="127.0.0.1:${SX_METRICS_PORT}"
    export SENTINELX__BOOTSTRAP__ENABLED=true
    export SENTINELX__BOOTSTRAP__ADMIN_TENANT_ID="${SX_BOOTSTRAP_TENANT_ID}"
    export SENTINELX__BOOTSTRAP__ADMIN_EMAIL="${SX_BOOTSTRAP_EMAIL}"
    export SENTINELX__BOOTSTRAP__ADMIN_PASSWORD_PHC="${SX_BOOTSTRAP_ADMIN_PASSWORD_PHC}"
}

wait_health() {
    local name="$1" timeout="$2"
    log "waiting up to ${timeout}s for ${name} to report healthy"
    local elapsed=0
    while [ "${elapsed}" -lt "${timeout}" ]; do
        if docker compose ps "${name}" 2>/dev/null | grep -q "(healthy)"; then
            log "${name} is healthy"
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    err "${name} did not become healthy in ${timeout}s"
    docker compose logs --tail=50 "${name}" >&2 || true
    return 1
}

start_infra() {
    cd "${REPO_ROOT}"
    log "starting postgres + redis via docker compose"
    docker compose up -d postgres redis
    wait_health postgres 60
    wait_health redis 30
}

run_ignored_tests() {
    [ "${RUN_CARGO}" -eq 1 ] || { log "--no-cargo: skipping cargo --ignored tests"; return 0; }
    cd "${REPO_ROOT}"
    log "running ignored live-deps tests: cargo test --workspace -- --ignored"
    cargo test --workspace --no-fail-fast -- --ignored
}

MONOLITH_PID=0
start_monolith() {
    [ "${RUN_MONOLITH}" -eq 1 ] || { log "--no-monolith: skipping monolith boot"; return 0; }
    cd "${REPO_ROOT}"
    log "building + launching sx-monolith on 127.0.0.1:${SX_HTTP_PORT}"
    cargo build -p sx-monolith --release
    cargo run -p sx-monolith --release >/tmp/sx-monolith.log 2>&1 &
    MONOLITH_PID=$!
    log "monolith pid: ${MONOLITH_PID}"

    local elapsed=0
    while [ "${elapsed}" -lt "${SX_HEALTH_TIMEOUT}" ]; do
        if curl -fsS "http://127.0.0.1:${SX_HTTP_PORT}/healthz" >/dev/null 2>&1; then
            log "monolith /healthz is up after ${elapsed}s"
            return 0
        fi
        if ! kill -0 "${MONOLITH_PID}" 2>/dev/null; then
            err "monolith process died — tail of /tmp/sx-monolith.log:"
            tail -n 80 /tmp/sx-monolith.log >&2 || true
            return 1
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    err "monolith did not pass /healthz within ${SX_HEALTH_TIMEOUT}s"
    tail -n 80 /tmp/sx-monolith.log >&2 || true
    return 1
}

run_smoke() {
    [ "${RUN_MONOLITH}" -eq 1 ] || { log "--no-monolith: skipping HTTP smoke"; return 0; }
    log "running HTTP smoke: tests/integration/smoke.sh"
    # Invoked via `bash` so the smoke does not depend on the file having
    # the executable bit set in the working copy (CI may check it out via
    # `actions/checkout` which preserves the mode from index).
    SX_BASE_URL="http://127.0.0.1:${SX_HTTP_PORT}" \
        bash "${REPO_ROOT}/tests/integration/smoke.sh"
}

teardown() {
    local code=$?
    if [ "${MONOLITH_PID}" -gt 0 ] && kill -0 "${MONOLITH_PID}" 2>/dev/null; then
        log "stopping monolith pid ${MONOLITH_PID}"
        kill "${MONOLITH_PID}" 2>/dev/null || true
        wait "${MONOLITH_PID}" 2>/dev/null || true
    fi
    if [ "${KEEP_UP}" -eq 0 ]; then
        log "stopping docker compose stack (volumes kept)"
        ( cd "${REPO_ROOT}" && docker compose down ) || true
    else
        log "--keep-up: leaving containers running"
    fi
    if [ "${code}" -ne 0 ]; then
        err "smoke FAILED (exit ${code})"
    else
        log "smoke OK"
    fi
    exit "${code}"
}

main() {
    parse_args "$@"
    require_tools
    export_env
    trap teardown EXIT INT TERM
    start_infra
    run_ignored_tests
    start_monolith
    run_smoke
}

main "$@"
