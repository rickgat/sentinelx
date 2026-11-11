#!/usr/bin/env bash
# shellcheck shell=bash
#
# tests/integration/smoke.sh — five-step HTTP smoke against a live
# sx-monolith. Invoked from `scripts/integration-smoke.sh` after the
# monolith has reported `/healthz`, but also runnable standalone:
#
#   SX_BASE_URL=http://127.0.0.1:8080 tests/integration/smoke.sh
#
# Flow (each step exits non-zero on failure and tails any error envelope):
#
#   1. POST   /v1/auth/login           as bootstrap admin → access JWT
#   2. GET    /v1/findings             with admin bearer → 200 + JSON array
#   3. POST   /v1/admin/users          create analyst (random email)
#   4. POST   /v1/auth/login           as the new analyst → second JWT
#   5. GET    /v1/engagements          with analyst bearer → 200 + JSON array
#
# Environment overrides:
#   SX_BASE_URL              (default http://127.0.0.1:8080)
#   SX_BOOTSTRAP_TENANT_ID   (default 00000000-0000-0000-0000-000000000001)
#   SX_BOOTSTRAP_EMAIL       (default admin@example.invalid)
#   SX_BOOTSTRAP_PASSWORD    (default sentinelx-admin-pw)
#   SX_SMOKE_TIMEOUT         (default 15 — per-request seconds)
#
# Dependencies: bash >= 4, curl, jq.
# Linting: passes `shellcheck tests/integration/smoke.sh` cleanly.

set -euo pipefail

: "${SX_BASE_URL:=http://127.0.0.1:8080}"
: "${SX_BOOTSTRAP_TENANT_ID:=00000000-0000-0000-0000-000000000001}"
: "${SX_BOOTSTRAP_EMAIL:=admin@example.invalid}"
: "${SX_BOOTSTRAP_PASSWORD:=sentinelx-admin-pw}"
: "${SX_SMOKE_TIMEOUT:=15}"

log()  { printf '[http-smoke] %s\n' "$*" >&2; }
err()  { printf '[http-smoke] ERROR: %s\n' "$*" >&2; }

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        err "missing required tool: $1"
        exit 127
    fi
}

require_tool curl
require_tool jq

# Random suffix so re-runs against the same backend do not collide on the
# unique-email constraint enforced by sx-iam's user repository.
random_suffix() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 6
    else
        # Fallback: nanos clock truncated to 12 hex chars.
        date +%s%N | tr -d '\n' | tail -c 12
    fi
}

# curl_json METHOD PATH [BODY] [BEARER]
#
# Sends a JSON request and prints the response body on stdout. The HTTP
# status is emitted on stderr as `[http-smoke] status=NNN` and stashed in
# the global LAST_STATUS so the caller can branch on it.
LAST_STATUS=0
curl_json() {
    local method="$1" path="$2" body="${3:-}" bearer="${4:-}"
    local url="${SX_BASE_URL}${path}"
    local resp_file status_file
    resp_file="$(mktemp)"
    status_file="$(mktemp)"

    local -a args=(
        --silent --show-error
        --max-time "${SX_SMOKE_TIMEOUT}"
        -X "${method}"
        -H 'content-type: application/json'
        -H 'accept: application/json'
        -o "${resp_file}"
        -w '%{http_code}'
    )
    if [ -n "${bearer}" ]; then
        args+=(-H "authorization: Bearer ${bearer}")
    fi
    if [ -n "${body}" ]; then
        args+=(--data "${body}")
    fi
    args+=("${url}")

    curl "${args[@]}" >"${status_file}" || {
        err "curl failed for ${method} ${path}"
        rm -f "${resp_file}" "${status_file}"
        exit 1
    }
    LAST_STATUS="$(cat "${status_file}")"
    rm -f "${status_file}"
    cat "${resp_file}"
    rm -f "${resp_file}"
}

# expect_status STATUS METHOD PATH RESPONSE
expect_status() {
    local want="$1" method="$2" path="$3" resp="$4"
    if [ "${LAST_STATUS}" != "${want}" ]; then
        err "${method} ${path} expected ${want}, got ${LAST_STATUS}"
        err "response body:"
        printf '%s\n' "${resp}" >&2
        exit 1
    fi
}

# extract_access_token JSON
#
# Pulls .data.access_token from the standard ApiResponse envelope. Exits
# non-zero if the field is absent or empty so the caller can fail fast.
extract_access_token() {
    local payload="$1"
    local token
    token="$(printf '%s' "${payload}" | jq -er '.data.access_token')" || {
        err "response did not contain .data.access_token"
        printf '%s\n' "${payload}" >&2
        exit 1
    }
    printf '%s' "${token}"
}

step1_login_admin() {
    log "step 1/5: POST /v1/auth/login (bootstrap admin)"
    local body resp token
    body="$(jq -nc \
        --arg tid "${SX_BOOTSTRAP_TENANT_ID}" \
        --arg em  "${SX_BOOTSTRAP_EMAIL}" \
        --arg pw  "${SX_BOOTSTRAP_PASSWORD}" \
        '{tenant_id:$tid,email:$em,password:$pw}')"
    resp="$(curl_json POST /v1/auth/login "${body}")"
    expect_status 200 POST /v1/auth/login "${resp}"
    token="$(extract_access_token "${resp}")"
    printf '%s' "${token}"
}

step2_list_findings() {
    local bearer="$1"
    log "step 2/5: GET /v1/findings (admin bearer)"
    local resp
    resp="$(curl_json GET /v1/findings "" "${bearer}")"
    expect_status 200 GET /v1/findings "${resp}"
    # Envelope must carry a JSON array (possibly empty) under .data.
    printf '%s' "${resp}" | jq -e '.data | type == "array"' >/dev/null || {
        err "GET /v1/findings .data is not a JSON array"
        printf '%s\n' "${resp}" >&2
        exit 1
    }
}

step3_create_user() {
    local bearer="$1" new_email="$2"
    log "step 3/5: POST /v1/admin/users (create ${new_email})"
    local body resp
    body="$(jq -nc \
        --arg tid "${SX_BOOTSTRAP_TENANT_ID}" \
        --arg em  "${new_email}" \
        --arg pw  "smoke-user-pw-correct-horse" \
        '{tenant_id:$tid,email:$em,password:$pw,roles:["analyst"]}')"
    resp="$(curl_json POST /v1/admin/users "${body}" "${bearer}")"
    if [ "${LAST_STATUS}" != "200" ] && [ "${LAST_STATUS}" != "201" ]; then
        err "POST /v1/admin/users expected 200/201, got ${LAST_STATUS}"
        printf '%s\n' "${resp}" >&2
        exit 1
    fi
    printf '%s' "${resp}" | jq -e '.data.id and .data.email' >/dev/null || {
        err "create-user response missing .data.id/.data.email"
        printf '%s\n' "${resp}" >&2
        exit 1
    }
}

step4_login_new_user() {
    local new_email="$1"
    log "step 4/5: POST /v1/auth/login (new analyst)"
    local body resp token
    body="$(jq -nc \
        --arg tid "${SX_BOOTSTRAP_TENANT_ID}" \
        --arg em  "${new_email}" \
        --arg pw  "smoke-user-pw-correct-horse" \
        '{tenant_id:$tid,email:$em,password:$pw}')"
    resp="$(curl_json POST /v1/auth/login "${body}")"
    expect_status 200 POST /v1/auth/login "${resp}"
    token="$(extract_access_token "${resp}")"
    printf '%s' "${token}"
}

step5_list_engagements() {
    local bearer="$1"
    log "step 5/5: GET /v1/engagements (analyst bearer)"
    local resp
    resp="$(curl_json GET /v1/engagements "" "${bearer}")"
    expect_status 200 GET /v1/engagements "${resp}"
    printf '%s' "${resp}" | jq -e '.data | type == "array"' >/dev/null || {
        err "GET /v1/engagements .data is not a JSON array"
        printf '%s\n' "${resp}" >&2
        exit 1
    }
}

main() {
    log "base url: ${SX_BASE_URL}"
    local admin_token new_email user_token
    admin_token="$(step1_login_admin)"
    step2_list_findings "${admin_token}"
    new_email="smoke-$(random_suffix)@example.invalid"
    step3_create_user "${admin_token}" "${new_email}"
    user_token="$(step4_login_new_user "${new_email}")"
    step5_list_engagements "${user_token}"
    log "all 5 steps OK"
}

main "$@"
