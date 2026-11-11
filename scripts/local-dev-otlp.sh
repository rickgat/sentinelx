#!/usr/bin/env sh
# shellcheck shell=sh
#
# local-dev-otlp.sh — boot the OTLP/Jaeger trace-sink stack and launch the
# SentinelX monolith with OTLP span export wired to localhost.
#
# This is a focused companion to scripts/local-dev.sh: it only stands up the
# tracing pipeline (otel-collector + jaeger) plus the monolith. Postgres /
# Redis are intentionally left to local-dev.sh — start that first if you
# need them, or run both scripts side by side.
#
# Usage:
#   scripts/local-dev-otlp.sh           # bring up otel-collector + jaeger,
#                                       # wait for both to report ready,
#                                       # then run
#                                       # `cargo run -p sx-monolith --release`
#                                       # in the foreground with the OTLP
#                                       # endpoint env var preset.
#   scripts/local-dev-otlp.sh --down    # stop + remove the trace stack
#                                       # (volumes are kept).
#   scripts/local-dev-otlp.sh --help    # this message.
#
# The script is idempotent — re-running it when the stack is already up is
# a no-op for the infrastructure services and re-launches the monolith.
#
# Environment overrides:
#   OTLP_GRPC_PORT     (default 4317)   gRPC OTLP receiver
#   OTLP_HTTP_PORT     (default 4318)   HTTP OTLP receiver
#   JAEGER_UI_PORT     (default 16686)  Jaeger UI
#   SX_HTTP_PORT       (default 8080)   monolith HTTP listener
#   SX_METRICS_PORT    (default 9090)   prometheus /metrics listener
#
# Linters: passes `shellcheck local-dev-otlp.sh` cleanly on shellcheck
# >= 0.9.0.

set -eu

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(cd -- "${SCRIPT_DIR}/.." && pwd)

OTLP_SERVICES="otel-collector jaeger"
HEALTH_TIMEOUT=30

usage() {
    sed -n '2,33p' "$0" | sed 's/^# //; s/^#//'
}

log() {
    printf '[local-dev-otlp] %s\n' "$*"
}

err() {
    printf '[local-dev-otlp] ERROR: %s\n' "$*" >&2
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

wait_for_service_running() {
    service_name="$1"
    log "Waiting up to ${HEALTH_TIMEOUT}s for ${service_name} to report running..."
    elapsed=0
    while [ "${elapsed}" -lt "${HEALTH_TIMEOUT}" ]; do
        status=$(docker compose ps "${service_name}" 2>/dev/null || true)
        case "${status}" in
            *"Up"*|*"running"*)
                log "${service_name} is up."
                return 0
                ;;
        esac
        sleep 1
        elapsed=$((elapsed + 1))
    done
    err "${service_name} did not become ready within ${HEALTH_TIMEOUT}s."
    err "Recent logs:"
    docker compose logs --tail=50 "${service_name}" >&2 || true
    return 1
}

export_otlp_env() {
    # Sane localhost defaults; do NOT overwrite caller-provided values.
    : "${OTLP_GRPC_PORT:=4317}"
    : "${OTLP_HTTP_PORT:=4318}"
    : "${JAEGER_UI_PORT:=16686}"
    : "${SX_HTTP_PORT:=8080}"
    : "${SX_METRICS_PORT:=9090}"

    SENTINELX__TELEMETRY__OTLP_ENDPOINT="http://127.0.0.1:${OTLP_GRPC_PORT}"
    SENTINELX__SERVER__BIND_ADDR="127.0.0.1:${SX_HTTP_PORT}"
    SENTINELX__METRICS__BIND_ADDR="127.0.0.1:${SX_METRICS_PORT}"

    export OTLP_GRPC_PORT OTLP_HTTP_PORT JAEGER_UI_PORT
    export SX_HTTP_PORT SX_METRICS_PORT
    export SENTINELX__TELEMETRY__OTLP_ENDPOINT
    export SENTINELX__SERVER__BIND_ADDR
    export SENTINELX__METRICS__BIND_ADDR
}

cmd_up() {
    require_docker_compose
    cd "${REPO_ROOT}"
    export_otlp_env

    log "Starting trace pipeline: ${OTLP_SERVICES}"
    # shellcheck disable=SC2086 # word-splitting on service list is intentional
    docker compose up -d ${OTLP_SERVICES}

    for svc in ${OTLP_SERVICES}; do
        wait_for_service_running "${svc}"
    done

    log "Launching sx-monolith with OTLP export enabled (Ctrl-C to stop)."
    log "  OTLP gRPC : 127.0.0.1:${OTLP_GRPC_PORT}"
    log "  OTLP HTTP : 127.0.0.1:${OTLP_HTTP_PORT}"
    log "  Jaeger UI : http://127.0.0.1:${JAEGER_UI_PORT}"
    log "  Monolith  : http://127.0.0.1:${SX_HTTP_PORT}"
    log "  Metrics   : http://127.0.0.1:${SX_METRICS_PORT}/metrics"
    log "  Endpoint  : ${SENTINELX__TELEMETRY__OTLP_ENDPOINT}"
    exec cargo run -p sx-monolith --release
}

cmd_down() {
    require_docker_compose
    cd "${REPO_ROOT}"
    log "Stopping and removing the OTLP trace stack (volumes kept)."
    # shellcheck disable=SC2086 # word-splitting on service list is intentional
    docker compose rm -sfv ${OTLP_SERVICES}
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
