#!/usr/bin/env bash
#
# QC scan simulation — exercises the operator-facing scan surface against a
# locally running monolith and asserts the SSRF guard + scan-detail
# routes added by QC-SCAN-2026-06-25-FIX behave as documented.
#
# Step 4 of the script (the SSRF-rejection cases) was added by the
# QC-SCAN-2026-06-25-FIX commit (gaps a + b closed). Step 5 covers the
# new bare-id JSON-detail route (gap c closed).
#
# Usage:
#   API=http://localhost:8080 TOKEN="bearer-jwt" ./qc_scan_simulation.sh
#
# Pre-requisites: `curl`, `jq`. The bearer must carry `scans:run` +
# `scans:read` permissions.

set -euo pipefail

API="${API:-http://localhost:8080}"
TOKEN="${TOKEN:-}"

if [[ -z "${TOKEN}" ]]; then
    echo "TOKEN env var is required (Bearer JWT with scans:run + scans:read)"
    exit 2
fi

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
hdr()   { printf '\n==== %s ====\n' "$*"; }

declare -i PASS=0
declare -i FAIL=0

expect_status() {
    # expect_status <label> <expected-status> <method> <path> [json-body]
    local label="$1" expected="$2" method="$3" path="$4" body="${5-}"
    local args=(-sS -o /dev/null -w '%{http_code}' -X "${method}" -H "Authorization: Bearer ${TOKEN}")
    if [[ -n "${body}" ]]; then
        args+=(-H 'Content-Type: application/json' --data "${body}")
    fi
    local got
    got=$(curl "${args[@]}" "${API}${path}")
    if [[ "${got}" == "${expected}" ]]; then
        green "PASS  ${label} (${method} ${path} → ${got})"
        PASS=$((PASS + 1))
    else
        red "FAIL  ${label} (${method} ${path} → ${got}, expected ${expected})"
        FAIL=$((FAIL + 1))
    fi
}

# ---------------------------------------------------------------------------
# Step 1 — happy-path scan against a benign external target.
# ---------------------------------------------------------------------------
hdr "step 1: positive control"
expect_status "scan public host" 200 POST /v1/scans/http-headers \
    '{"target":"https://example.com"}'

# ---------------------------------------------------------------------------
# Step 2 — list endpoint surfaces the just-completed scan.
# ---------------------------------------------------------------------------
hdr "step 2: list scans"
expect_status "list scans" 200 GET /v1/scans

# ---------------------------------------------------------------------------
# Step 3 — RFC 1918 internal target (allowed by the SSRF guard).
# ---------------------------------------------------------------------------
hdr "step 3: RFC 1918 (allowed)"
# A scan against 10.0.0.1 may legitimately surface a `status: error`
# record because the host is unreachable from the runner, but it must NOT
# 400 — RFC 1918 IS a legitimate scan target.
expect_status "scan rfc1918 host" 200 POST /v1/scans/http-headers \
    '{"target":"http://10.0.0.1"}'

# ---------------------------------------------------------------------------
# Step 4 — SSRF guard (QC-SCAN-2026-06-25 fixes a + b).
#
# Before the fix:
# - `file:///etc/passwd` returned 200 with `status: error` (because the
#   string-prefix-only `normalise_target` prepended `https://` to it).
# - `http://127.0.0.1:8080` was accepted (self-scan loopback).
# - `http://169.254.169.254` was accepted (AWS/GCP/Azure metadata IP).
#
# After the fix, ALL of these surface as 400 with a `ScanTargetError`
# variant message in the JSON envelope.
# ---------------------------------------------------------------------------
hdr "step 4: SSRF guard (QC-SCAN-2026-06-25 closes a + b)"
expect_status "reject file:// scheme"          400 POST /v1/scans/http-headers \
    '{"target":"file:///etc/passwd"}'
expect_status "reject gopher:// scheme"        400 POST /v1/scans/http-headers \
    '{"target":"gopher://anything"}'
expect_status "reject loopback ipv4"           400 POST /v1/scans/http-headers \
    '{"target":"http://127.0.0.1:8080"}'
expect_status "reject loopback ipv6"           400 POST /v1/scans/http-headers \
    '{"target":"http://[::1]"}'
expect_status "reject localhost (DNS-resolved loopback)" 400 POST /v1/scans/http-headers \
    '{"target":"http://localhost"}'
expect_status "reject AWS metadata IP"         400 POST /v1/scans/http-headers \
    '{"target":"http://169.254.169.254/latest/meta-data/iam"}'
expect_status "reject link-local non-metadata" 400 POST /v1/scans/http-headers \
    '{"target":"http://169.254.0.1"}'

# ---------------------------------------------------------------------------
# Step 5 — JSON scan-detail route (QC-SCAN-2026-06-25 fix c).
#
# Before the fix, `GET /v1/scans/{id}` returned 404 because only the
# SARIF-suffixed route was registered. After the fix, the unified
# dispatcher serves both routes from a single capture.
# ---------------------------------------------------------------------------
hdr "step 5: scan detail JSON + SARIF (QC-SCAN-2026-06-25 closes c)"
SCAN_ID=$(curl -sS -H "Authorization: Bearer ${TOKEN}" "${API}/v1/scans?limit=1" \
    | jq -r '.data.items[0].id // empty')
if [[ -z "${SCAN_ID}" ]]; then
    red "skip step 5: no scans recorded to fetch by id"
else
    expect_status "bare id → JSON detail" 200 GET "/v1/scans/${SCAN_ID}"
    expect_status "id.sarif → SARIF"      200 GET "/v1/scans/${SCAN_ID}.sarif"
    expect_status "unknown id → 404"      404 GET "/v1/scans/00000000-0000-0000-0000-000000000000"
fi

# ---------------------------------------------------------------------------
# Summary.
# ---------------------------------------------------------------------------
hdr "summary"
green "PASS=${PASS}"
if (( FAIL > 0 )); then
    red "FAIL=${FAIL}"
    exit 1
fi
echo "all checks passed"
