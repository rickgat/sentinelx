#!/usr/bin/env bash
# shellcheck shell=bash
#
# local-dev-pg.sh — boot SentinelX against the LIVE Postgres adapter.
#
# Thin wrapper around `docker-compose up -d postgres` + `cargo run -p
# sx-monolith --release`. Idempotent: re-running while the database is
# already up is a no-op for the infra layer and re-launches the monolith.
#
# Unlike `scripts/local-dev.sh` which boots in fully in-memory mode (with
# Redis + telemetry sidecars), this script:
#   1. brings up only Postgres,
#   2. waits for it to report healthy,
#   3. generates a per-boot Argon2id PHC for the bootstrap admin password,
#   4. exports `SENTINELX__DATABASE__ENABLED=true` plus the seed env vars,
#   5. exec's `cargo run -p sx-monolith --release` in the foreground.
#
# The PHC is regenerated on every boot so the password never has to be
# carried in source control. Login credentials are emitted before exec so
# the operator can curl `/v1/auth/login` right away.
#
# Usage:
#   scripts/local-dev-pg.sh           # bring up Postgres + the monolith
#   scripts/local-dev-pg.sh --down    # stop the docker stack
#   scripts/local-dev-pg.sh --help    # this message
#
# Environment overrides:
#   POSTGRES_HOST_PORT (default 5432)
#   POSTGRES_USER      (default sentinelx)
#   POSTGRES_PASSWORD  (default sentinelx_dev)
#   POSTGRES_DB        (default sentinelx)
#   SX_HTTP_PORT       (default 18080)
#   ADMIN_PASSWORD     (default SentinelXDemo123!)
#
# Note: this script intentionally does NOT touch the long-lived
# in-memory monolith that the user keeps running on port 18080 outside
# of this stack. If that conflicts, override SX_HTTP_PORT.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(cd -- "${SCRIPT_DIR}/.." && pwd)

HEALTH_TIMEOUT=30

log() {
    printf '[local-dev-pg] %s\n' "$*"
}

err() {
    printf '[local-dev-pg] ERROR: %s\n' "$*" >&2
}

usage() {
    sed -n '2,40p' "$0" | sed 's/^# //; s/^#//'
}

require_docker_compose() {
    if ! command -v docker >/dev/null 2>&1; then
        err "docker is not on PATH. Install Docker Desktop or the docker CLI first."
        exit 127
    fi
    if ! docker compose version >/dev/null 2>&1; then
        err "'docker compose' subcommand is not available."
        exit 127
    fi
}

wait_for_postgres_healthy() {
    log "Waiting up to ${HEALTH_TIMEOUT}s for postgres to report healthy..."
    local elapsed=0
    while [ "${elapsed}" -lt "${HEALTH_TIMEOUT}" ]; do
        status=$(docker compose ps postgres 2>/dev/null || true)
        case "${status}" in
            *"(healthy)"*)
                log "postgres is healthy."
                return 0
                ;;
        esac
        sleep 1
        elapsed=$((elapsed + 1))
    done
    err "postgres did not become healthy within ${HEALTH_TIMEOUT}s."
    err "Recent logs:"
    docker compose logs --tail=50 postgres >&2 || true
    return 1
}

# Locate a usable PHC generator. Order of preference:
#   1. PHC_GEN env override (explicit out-of-tree cargo project)
#   2. /tmp/phc-gen (legacy ad-hoc utility, if present)
#   3. in-tree `sx-cli hash-password` (default; no external dependency)
#
# The in-tree default means a clean checkout boots without any out-of-repo
# helper. The password is piped on stdin so it never appears in the process
# argument list, and cargo's build chatter is sent to stderr so the command
# substitution below captures only the PHC string on stdout.
generate_phc() {
    local password="$1"
    if [ -n "${PHC_GEN:-}" ] && [ -d "${PHC_GEN}" ]; then
        log "Generating PHC via PHC_GEN=${PHC_GEN}..."
        ( cd "${PHC_GEN}" && cargo run --quiet -- "${password}" )
        return
    fi
    if [ -d "/tmp/phc-gen" ]; then
        log "Generating PHC via /tmp/phc-gen..."
        ( cd "/tmp/phc-gen" && cargo run --quiet -- "${password}" )
        return
    fi
    log "Generating PHC via in-tree sx-cli hash-password..." >&2
    printf '%s' "${password}" \
        | ( cd "${REPO_ROOT}" && cargo run --quiet -p sx-cli -- hash-password )
}

export_dev_env() {
    : "${POSTGRES_HOST_PORT:=5432}"
    : "${POSTGRES_USER:=sentinelx}"
    : "${POSTGRES_PASSWORD:=sentinelx_dev}"
    : "${POSTGRES_DB:=sentinelx}"
    : "${SX_HTTP_PORT:=18080}"
    : "${ADMIN_PASSWORD:=SentinelXDemo123!}"
    : "${REDIS_PASSWORD:=sentinelx_dev}"

    # Required by docker-compose.yml even though we only start postgres.
    export POSTGRES_HOST_PORT POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB
    export REDIS_PASSWORD

    SENTINELX__SERVER__BIND_ADDR="127.0.0.1:${SX_HTTP_PORT}"
    SENTINELX__DATABASE__URL="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:${POSTGRES_HOST_PORT}/${POSTGRES_DB}"
    SENTINELX__DATABASE__ENABLED="true"
    SENTINELX__DATABASE__MIGRATE_ON_START="true"

    # Redis off — the monolith runs in single-process mode against Postgres.
    SENTINELX__REDIS__URL="redis://:x@127.0.0.1:6379/0"
    SENTINELX__REDIS__ENABLED="false"

    # JWT signing key — base64 32 bytes (literal "01" * 32). Local dev only.
    SENTINELX__JWT__SIGNING_KEY="MDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDE="

    SENTINELX__IAM__ATTEMPT_EMAIL_PEPPER="local-dev-pepper-16b"

    SENTINELX__BOOTSTRAP__ENABLED="true"
    SENTINELX__BOOTSTRAP__ADMIN_TENANT_SLUG="default"
    SENTINELX__BOOTSTRAP__ADMIN_TENANT_NAME="Default Tenant"
    SENTINELX__BOOTSTRAP__ADMIN_TENANT_ID="01010101-0101-0101-0101-010101010101"
    SENTINELX__BOOTSTRAP__ADMIN_EMAIL="admin@sentinelx.dev"

    SENTINELX__TELEMETRY__LOG_FORMAT="text"

    # Use the example config as the base; env vars override every field.
    SENTINELX_CONFIG="${REPO_ROOT}/config/sentinelx.example.yaml"

    export SENTINELX_CONFIG
    export SENTINELX__SERVER__BIND_ADDR
    export SENTINELX__DATABASE__URL SENTINELX__DATABASE__ENABLED
    export SENTINELX__DATABASE__MIGRATE_ON_START
    export SENTINELX__REDIS__URL SENTINELX__REDIS__ENABLED
    export SENTINELX__JWT__SIGNING_KEY
    export SENTINELX__IAM__ATTEMPT_EMAIL_PEPPER
    export SENTINELX__BOOTSTRAP__ENABLED
    export SENTINELX__BOOTSTRAP__ADMIN_TENANT_SLUG
    export SENTINELX__BOOTSTRAP__ADMIN_TENANT_NAME
    export SENTINELX__BOOTSTRAP__ADMIN_TENANT_ID
    export SENTINELX__BOOTSTRAP__ADMIN_EMAIL
    export SENTINELX__TELEMETRY__LOG_FORMAT
}

cmd_up() {
    require_docker_compose
    cd "${REPO_ROOT}"
    export_dev_env

    log "Starting Postgres infrastructure..."
    docker compose up -d postgres
    wait_for_postgres_healthy

    log "Generating per-boot bootstrap admin PHC..."
    PHC=$(generate_phc "${ADMIN_PASSWORD}")
    if [ -z "${PHC}" ]; then
        err "PHC generator returned an empty string."
        exit 1
    fi
    export SENTINELX__BOOTSTRAP__ADMIN_PASSWORD_PHC="${PHC}"

    log ""
    log "Bootstrap admin credentials (this boot only):"
    log "  email:    admin@sentinelx.dev"
    log "  password: ${ADMIN_PASSWORD}"
    log "  tenant:   01010101-0101-0101-0101-010101010101 (slug: default)"
    log ""
    log "Launching sx-monolith on http://127.0.0.1:${SX_HTTP_PORT} ..."
    exec cargo run -p sx-monolith --release
}

cmd_down() {
    require_docker_compose
    cd "${REPO_ROOT}"
    : "${POSTGRES_PASSWORD:=sentinelx_dev}"
    : "${REDIS_PASSWORD:=sentinelx_dev}"
    export POSTGRES_PASSWORD REDIS_PASSWORD
    log "Stopping postgres container (volumes kept)..."
    docker compose stop postgres
}

main() {
    if [ "$#" -eq 0 ]; then
        cmd_up
        return
    fi
    case "$1" in
        --down|down)
            cmd_down
            ;;
        --help|-h|help)
            usage
            ;;
        *)
            err "Unknown argument: $1"
            usage
            exit 64
            ;;
    esac
}

main "$@"
