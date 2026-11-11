#!/usr/bin/env sh
# shellcheck shell=sh
#
# local-dev.sh — boot the SentinelX local development stack.
#
# Usage:
#   scripts/local-dev.sh           # bring up postgres/redis/jaeger/otel,
#                                  # wait for postgres healthy, then run
#                                  # `cargo run -p sx-monolith --release`
#                                  # in the foreground.
#   scripts/local-dev.sh --down    # stop + remove the docker stack
#                                  # (volumes are kept).
#   scripts/local-dev.sh --help    # this message.
#
# The script is idempotent. Re-running it when the stack is already up is
# a no-op for the infrastructure services and re-launches the monolith.
#
# Environment overrides:
#   POSTGRES_HOST_PORT (default 5432)
#   REDIS_HOST_PORT    (default 6379)
#   OTLP_GRPC_PORT     (default 4317)
#   SX_HTTP_PORT       (default 8080)
#   SX_METRICS_PORT    (default 9090)
#
# Linters: passes `shellcheck local-dev.sh` cleanly on shellcheck >= 0.9.0.
# If shellcheck is not installed, run `brew install shellcheck` (macOS) or
# `apt-get install shellcheck` (Debian/Ubuntu) to lint.

set -eu

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(cd -- "${SCRIPT_DIR}/.." && pwd)

INFRA_SERVICES="postgres redis jaeger otel-collector"
HEALTH_TIMEOUT=30

usage() {
    sed -n '2,30p' "$0" | sed 's/^# //; s/^#//'
}

log() {
    printf '[local-dev] %s\n' "$*"
}

err() {
    printf '[local-dev] ERROR: %s\n' "$*" >&2
}

require_docker_compose() {
    if ! command -v docker >/dev/null 2>&1; then
        err "docker is not on PATH. Install Docker Desktop or the docker CLI first."
        exit 127
    fi
    if ! docker compose version >/dev/null 2>&1; then
        err "'docker compose' subcommand is not available."
        err "Install the Compose v2 plugin (Docker Desktop bundles it, or 'apt-get install docker-compose-plugin')."
        exit 127
    fi
}

wait_for_postgres_healthy() {
    log "Waiting up to ${HEALTH_TIMEOUT}s for postgres to report healthy..."
    elapsed=0
    while [ "${elapsed}" -lt "${HEALTH_TIMEOUT}" ]; do
        # `docker compose ps` v2 emits a `STATUS` column where the substring
        # `(healthy)` appears once a service with a healthcheck has passed it.
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

export_dev_env() {
    # Sane localhost defaults; do NOT overwrite caller-provided values.
    : "${POSTGRES_HOST_PORT:=5432}"
    : "${POSTGRES_USER:=sentinelx}"
    : "${POSTGRES_PASSWORD:=sentinelx_dev}"
    : "${POSTGRES_DB:=sentinelx}"
    : "${REDIS_HOST_PORT:=6379}"
    : "${REDIS_PASSWORD:=sentinelx_dev}"
    : "${OTLP_GRPC_PORT:=4317}"
    : "${SX_HTTP_PORT:=8080}"
    : "${SX_METRICS_PORT:=9090}"

    SENTINELX__DATABASE__URL="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:${POSTGRES_HOST_PORT}/${POSTGRES_DB}"
    SENTINELX__REDIS__URL="redis://:${REDIS_PASSWORD}@127.0.0.1:${REDIS_HOST_PORT}/0"
    SENTINELX__TELEMETRY__OTLP_ENDPOINT="http://127.0.0.1:${OTLP_GRPC_PORT}"
    SENTINELX__SERVER__BIND_ADDR="127.0.0.1:${SX_HTTP_PORT}"
    SENTINELX__METRICS__BIND_ADDR="127.0.0.1:${SX_METRICS_PORT}"

    export POSTGRES_HOST_PORT POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB
    export REDIS_HOST_PORT REDIS_PASSWORD OTLP_GRPC_PORT
    export SX_HTTP_PORT SX_METRICS_PORT
    export SENTINELX__DATABASE__URL SENTINELX__REDIS__URL
    export SENTINELX__TELEMETRY__OTLP_ENDPOINT
    export SENTINELX__SERVER__BIND_ADDR SENTINELX__METRICS__BIND_ADDR
}

cmd_up() {
    require_docker_compose
    cd "${REPO_ROOT}"
    export_dev_env

    log "Starting infrastructure: ${INFRA_SERVICES}"
    # shellcheck disable=SC2086 # word-splitting on service list is intentional
    docker compose up -d ${INFRA_SERVICES}

    wait_for_postgres_healthy

    log "Launching sx-monolith in the foreground (Ctrl-C to stop)."
    log "  HTTP    : http://127.0.0.1:${SX_HTTP_PORT}"
    log "  Metrics : http://127.0.0.1:${SX_METRICS_PORT}/metrics"
    log "  Jaeger  : http://127.0.0.1:16686"
    exec cargo run -p sx-monolith --release
}

cmd_down() {
    require_docker_compose
    cd "${REPO_ROOT}"
    log "Stopping and removing infrastructure containers (volumes kept)."
    docker compose down
    log "Done."
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
