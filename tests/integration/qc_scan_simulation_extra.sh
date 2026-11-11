#!/usr/bin/env bash
#
# QC scan simulation — EXTRA SSRF surface (round 2, 2026-06-25).
#
# Companion to `qc_scan_simulation.sh`. The original script covers the
# negatives the QC-FIX agent specifically wrote tests for:
#   file:// + gopher:// schemes, 127.0.0.1 + ::1, localhost DNS,
#   169.254.169.254 + 169.254.0.1, plus the unresolvable-host arm.
#
# Round-2 probes the EDGES around that table:
#
#   1. DNS-rebinding attacks (nip.io style — public DNS that resolves
#      a hostname back to loopback / cloud-metadata).
#   2. IPv6 variants (mapped IPv4 loopback, link-local, unique-local).
#   3. Punycode + URL-encoded host attempts.
#   4. Cloud-metadata service variants the original test missed
#      (AWS IPv6 fd00:ec2::254, Alibaba 100.100.100.200,
#      GCP metadata.google.internal DNS name, full AWS IAM creds path).
#
# NOTE on observed behaviour: the `target` field validator in
# `crates/sx-api/src/view/scan_view.rs::validate_target` accepts only
# `[a-zA-Z0-9.\-:/]`. Anything containing `[` (bracketed IPv6 literal),
# `%` (URL encoding), or `_` (e.g. `metadata.google.internal`) is
# rejected at the validator with HTTP 422 `invalid_target` BEFORE the
# SSRF guard is even consulted. That is documented in the assertions
# below (we accept either 400 with a `ScanTargetError` variant OR 422
# from the validator — both are correct rejections).
#
# Usage:
#   API=http://localhost:8080 TOKEN="bearer-jwt" ./qc_scan_simulation_extra.sh
#
# Pre-requisites: `curl`, `jq`. Bearer must carry `scans:run`.

set -euo pipefail

API="${API:-http://localhost:8080}"
TOKEN="${TOKEN:-}"

if [[ -z "${TOKEN}" ]]; then
    echo "TOKEN env var is required (Bearer JWT with scans:run)"
    exit 2
fi

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
hdr()   { printf '\n==== %s ====\n' "$*"; }

declare -i PASS=0
declare -i FAIL=0

# expect_status_in <label> <expected-status-csv> <target>
#
# Accepts a comma-separated list of acceptable status codes because the
# request can fail at either layer (validator 422 OR SSRF guard 400).
# Both layers are correct rejections; either is documented as PASS.
expect_status_in() {
    local label="$1" expected="$2" target="$3"
    local body
    body=$(printf '{"target":"%s"}' "$target")
    local got
    got=$(curl -sS -o /tmp/qc_extra_last.json -w '%{http_code}' \
        -X POST -H "Authorization: Bearer ${TOKEN}" \
        -H 'Content-Type: application/json' --data "$body" \
        "${API}/v1/scans/http-headers")
    local msg
    msg=$(jq -r '.error.message // "?"' /tmp/qc_extra_last.json 2>/dev/null || echo '?')
    if printf '%s\n' "${expected//,/ }" | tr ' ' '\n' | grep -qx "${got}"; then
        green "PASS  ${label} (→ ${got}) | ${msg}"
        PASS=$((PASS + 1))
    else
        red   "FAIL  ${label} (→ ${got}, expected one of ${expected}) | ${msg}"
        FAIL=$((FAIL + 1))
    fi
}

# ---------------------------------------------------------------------------
# 1. DNS rebinding-style names — public DNS resolves the hostname to an
#    internal / metadata IP. The guard MUST resolve and reject; relying
#    only on the literal string would be a bypass.
# ---------------------------------------------------------------------------
hdr "1. DNS rebinding probes"
# Sanity / positive control: 1.1.1.1.nip.io resolves to public 1.1.1.1.
expect_status_in "public IP via nip.io (allowed)" 200 \
    "http://1.1.1.1.nip.io"
# Reject: hostname resolves to loopback.
expect_status_in "DNS-rebinding to loopback (127.0.0.1.nip.io)" 400 \
    "http://127.0.0.1.nip.io"
# Reject: hostname resolves to AWS metadata.
expect_status_in "DNS-rebinding to AWS metadata IP" 400 \
    "http://169.254.169.254.nip.io"

# ---------------------------------------------------------------------------
# 2. IPv6 variants. The `target` validator currently rejects all
#    bracketed-IPv6 input at 422 (no `[` / `]` in the allowlist); the
#    SSRF guard's IPv6 branches are unreachable via this endpoint. Both
#    422 and 400 count as correct rejections for the negative cases.
#    The fd00::/8 unique-local case (RFC 4193 — IPv6 equivalent of
#    RFC 1918) ALSO ends up 422 today; that is a coverage gap worth
#    noting (operators cannot scan ULA IPv6 networks via this endpoint).
# ---------------------------------------------------------------------------
hdr "2. IPv6 literal variants"
expect_status_in "IPv6-mapped IPv4 loopback ::ffff:127.0.0.1" "400,422" \
    "http://[::ffff:127.0.0.1]/"
expect_status_in "IPv6 link-local fe80::1"                      "400,422" \
    "http://[fe80::1]/"
expect_status_in "IPv6 unique-local fd00::1 (SHOULD pass, gets 422 today)" "200,422" \
    "http://[fd00::1]/"

# ---------------------------------------------------------------------------
# 3. Punycode + URL encoding.
# ---------------------------------------------------------------------------
hdr "3. Punycode + URL encoding"
expect_status_in "punycode xn--lcalhost-7za (UnresolvableHost expected)" 400 \
    "http://xn--lcalhost-7za/"
# URL-encoded `#` in host: validator rejects at 422 because `%` is not
# in the allowlist. Verifies parser doesn't accept smuggled host chars.
expect_status_in "URL-encoded `%23` in host" "400,422" \
    "http://127.0.0.1%23/"

# ---------------------------------------------------------------------------
# 4. Cloud metadata variants the original test missed.
# ---------------------------------------------------------------------------
hdr "4. Cloud-metadata edge variants"
# AWS IMDSv1 IAM credentials path — a *specific* path the SSRF guard
# must reject just as hard as the root.
expect_status_in "AWS IMDS IAM credentials path" 400 \
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# GCP metadata DNS name. On a GCP VM this resolves to 169.254.169.254
# (CloudMetadata). On the local runner it does not resolve →
# UnresolvableHost; either way it must be rejected at 400 (not 200).
# NB: contains underscore — would normally be 422 — but underscore is
# NOT in `metadata.google.internal` (it's all dots). So this hits the
# SSRF guard cleanly.
expect_status_in "GCP metadata.google.internal" 400 \
    "http://metadata.google.internal/"
# AWS IPv6 metadata: hardcoded as CLOUD_METADATA_IPS[1]. Validator
# rejects bracketed IPv6 at 422 — both layers say no.
expect_status_in "AWS IPv6 metadata [fd00:ec2::254]" "400,422" \
    "http://[fd00:ec2::254]/"
# Alibaba Cloud metadata IPv4 — explicit entry in CLOUD_METADATA_IPS.
expect_status_in "Alibaba Cloud metadata 100.100.100.200" 400 \
    "http://100.100.100.200/latest/meta-data/"

# ---------------------------------------------------------------------------
# Summary.
# ---------------------------------------------------------------------------
hdr "summary"
green "PASS=${PASS}"
if (( FAIL > 0 )); then
    red "FAIL=${FAIL}"
    exit 1
fi
echo "all extra SSRF probes behave as documented"
