#!/usr/bin/env bash
# shellcheck shell=bash
#
# local-dev-redis.sh — boot SentinelX against the LIVE Redis adapter.
#
# Thin wrapper around `docker compose up -d redis` + `cargo run -p
# sx-monolith --release`. Idempotent: re-running while Redis is already
# up is a no-op for the infra layer and re-launches the monolith.
#
# Unlike `scripts/local-dev-pg.sh` which exercises only the Postgres
# adapter (Redis off), this script:
#   1. brings up only Redis,
#   2. waits for it to report healthy,
#   3. exports `SENTINELX__REDIS__ENABLED=true` plus the URL with
#      injected password,
#   4. exec's `cargo run -p sx-monolith --release` in the foreground.
#
# The database stays disabled by default (`SENTINELX__DATABASE__ENABLED=false`)
# so the in-memory repos boot in <100 ms while the Redis-backed
# kill-switch + login-attempt tracker are still exercised end-to-end.
#
# Usage:
#   scripts/local-dev-redis.sh           # bring up Redis + the monolith
#   scripts/local-dev-redis.sh --down    # stop the docker stack
#   scripts/local-dev-redis.sh --help    # this message
#
# Environment overrides:
#   REDIS_HOST_PORT   (default 6379)
#   REDIS_PASSWORD    (default sentinelx_dev)
#   SX_HTTP_PORT      (default 28080)
#   ADMIN_PASSWORD    (default SentinelXDemo123!)
#
# Note: SX_HTTP_PORT defaults to 28080 to avoid colliding with
#       local-dev.sh (8080) and local-dev-pg.sh (18080).

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(cd -- "${SCRIPT_DIR}/.." && pwd)

HEALTH_TIMEOUT=30

log() {
    printf '[local-dev-redis] %s\n' "$*"
}

err() {
    printf '[local-dev-redis] ERROR: %s\n' "$*" >&2
}

usage() {
    sed -n '2,30p' "$0" | sed 's/^# //; s/^#//'
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

wait_for_redis_healthy() {
    log "Waiting up to ${HEALTH_TIMEOUT}s for redis to report healthy..."
    local elapsed=0
    while [ "${elapsed}" -lt "${HEALTH_TIMEOUT}" ]; do
        status=$(docker compose ps redis 2>/dev/null || true)
        case "${status}" in
            *"(healthy)"*)
                log "redis is healthy."
                return 0
                ;;
        esac
        sleep 1
        elapsed=$((elapsed + 1))
    done
    err "redis did not become healthy within ${HEALTH_TIMEOUT}s."
    err "Recent logs:"
    docker compose logs --tail=50 redis >&2 || true
    return 1
}

export_dev_env() {
    : "${REDIS_HOST_PORT:=6379}"
    : "${REDIS_PASSWORD:=sentinelx_dev}"
    : "${SX_HTTP_PORT:=28080}"
    : "${ADMIN_PASSWORD:=SentinelXDemo123!}"
    # docker-compose.yml requires this even though we only start redis.
    : "${POSTGRES_PASSWORD:=sentinelx_dev}"

    export REDIS_HOST_PORT REDIS_PASSWORD POSTGRES_PASSWORD

    SENTINELX__SERVER__BIND_ADDR="127.0.0.1:${SX_HTTP_PORT}"

    # The whole point: Redis adapter ON.
    SENTINELX__REDIS__ENABLED="true"
    SENTINELX__REDIS__URL="redis://:${REDIS_PASSWORD}@127.0.0.1:${REDIS_HOST_PORT}/0"

    # In-memory repos — exercise Redis in isolation.
    SENTINELX__DATABASE__ENABLED="false"

    # JWT signing key — base64 32 bytes (literal "01" * 32). Local dev only.
    SENTINELX__JWT__SIGNING_KEY="MDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDE="

    SENTINELX__IAM__ATTEMPT_EMAIL_PEPPER="local-dev-pepper-16b"

    SENTINELX__BOOTSTRAP__ENABLED="false"

    SENTINELX__TELEMETRY__LOG_FORMAT="text"

    # Use the example config as the base; env vars override every field.
    SENTINELX_CONFIG="${REPO_ROOT}/config/sentinelx.example.yaml"

    export SENTINELX_CONFIG
    export SENTINELX__SERVER__BIND_ADDR
    export SENTINELX__REDIS__URL SENTINELX__REDIS__ENABLED
    export SENTINELX__DATABASE__ENABLED
    export SENTINELX__JWT__SIGNING_KEY
    export SENTINELX__IAM__ATTEMPT_EMAIL_PEPPER
    export SENTINELX__BOOTSTRAP__ENABLED
    export SENTINELX__TELEMETRY__LOG_FORMAT
}

cmd_up() {
    require_docker_compose
    cd "${REPO_ROOT}"
    export_dev_env

    log "Starting Redis infrastructure..."
    docker compose up -d redis
    wait_for_redis_healthy

    log ""
    log "Redis adapter enabled."
    log "  host    : 127.0.0.1:${REDIS_HOST_PORT}"
    log "  http    : http://127.0.0.1:${SX_HTTP_PORT}"
    log ""
    log "Launching sx-monolith ..."
    exec cargo run -p sx-monolith --release
}

cmd_down() {
    require_docker_compose
    cd "${REPO_ROOT}"
    : "${REDIS_PASSWORD:=sentinelx_dev}"
    : "${POSTGRES_PASSWORD:=sentinelx_dev}"
    export REDIS_PASSWORD POSTGRES_PASSWORD
    log "Stopping redis container (volumes kept)..."
    docker compose stop redis
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
