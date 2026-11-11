#!/usr/bin/env sh
# shellcheck shell=sh
#
# dev-bootstrap.sh — seed config/sentinelx.dev.yaml from the dev example
# and print the SENTINELX_CONFIG env export that wires it up.
#
# Idempotent: if config/sentinelx.dev.yaml already exists the script
# leaves it untouched so a developer's local edits are never clobbered.
# Pass --force to overwrite anyway.
#
# Usage:
#   scripts/dev-bootstrap.sh           # copy if missing, print env
#   scripts/dev-bootstrap.sh --force   # overwrite the dev config
#   scripts/dev-bootstrap.sh --help
#
# Companion to the README quick-start: the dev example ships a verified
# Argon2id PHC for the documented credentials (`admin@sentinelx.dev` /
# `sentinelx-admin-pw`). See config/sentinelx.dev.example.yaml for the
# full per-section explainer.

set -eu

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(cd -- "${SCRIPT_DIR}/.." && pwd)

SRC="${REPO_ROOT}/config/sentinelx.dev.example.yaml"
DST="${REPO_ROOT}/config/sentinelx.dev.yaml"

usage() {
    sed -n '2,20p' "$0" | sed 's/^# //; s/^#//'
}

log() {
    printf '[dev-bootstrap] %s\n' "$*"
}

force=0
for arg in "$@"; do
    case "${arg}" in
        --force|-f) force=1 ;;
        --help|-h)  usage; exit 0 ;;
        *) printf '[dev-bootstrap] ERROR: unknown arg: %s\n' "${arg}" >&2; usage; exit 64 ;;
    esac
done

if [ ! -f "${SRC}" ]; then
    printf '[dev-bootstrap] ERROR: missing example config: %s\n' "${SRC}" >&2
    exit 1
fi

if [ -f "${DST}" ] && [ "${force}" -eq 0 ]; then
    log "${DST} already exists — leaving it alone (pass --force to overwrite)."
else
    cp "${SRC}" "${DST}"
    log "Wrote ${DST}."
fi

log "Bootstrap admin credentials baked into the config:"
log "  email    : admin@sentinelx.dev"
log "  password : sentinelx-admin-pw"
log "  tenant   : 01010101-0101-0101-0101-010101010101"
log ""
log "Export this in your shell, then start the backend:"
printf '\n  export SENTINELX_CONFIG=%s\n' "${DST}"
printf '  cargo run --release -p sx-monolith\n\n'
