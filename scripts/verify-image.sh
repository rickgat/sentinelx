#!/usr/bin/env bash
#
# verify-image.sh — verify a published sx-monolith image was signed by the
# SentinelX GitHub Actions release workflow, and that its CycloneDX SBOM
# attestation is intact.
#
# Usage:
#     TAG=v1.4.0 ./scripts/verify-image.sh
#     ./scripts/verify-image.sh v1.4.0
#     IMAGE=ghcr.io/sentinelx/monolith TAG=v1.4.0 ./scripts/verify-image.sh
#
# Exit codes:
#     0   both signature and SBOM attestation verified
#     1   signature failed
#     2   SBOM attestation failed
#     64  bad invocation / missing dependency
#
# Operators MUST refuse to deploy any image where this script does not exit 0.

set -Eeuo pipefail

# -----------------------------------------------------------------------------
# Config (override via env)
# -----------------------------------------------------------------------------
IMAGE="${IMAGE:-ghcr.io/sentinelx/monolith}"
IDENTITY_REGEXP="${COSIGN_IDENTITY_REGEXP:-https://github.com/sentinelx/}"
OIDC_ISSUER="${COSIGN_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

# Tag may come from $1 or $TAG. $1 wins.
TAG="${1:-${TAG:-}}"

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
log()  { printf '\033[1;34m[verify-image]\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[1;32m[ok]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; }

usage() {
    cat >&2 <<'USAGE'
verify-image.sh — verify cosign signature + CycloneDX SBOM attestation.

Usage:
    TAG=v1.4.0 ./scripts/verify-image.sh
    ./scripts/verify-image.sh v1.4.0

Env overrides:
    IMAGE                      default: ghcr.io/sentinelx/monolith
    COSIGN_IDENTITY_REGEXP     default: https://github.com/sentinelx/
    COSIGN_OIDC_ISSUER         default: https://token.actions.githubusercontent.com
USAGE
}

require() {
    local bin="$1"
    if ! command -v "$bin" >/dev/null 2>&1; then
        fail "missing required binary: $bin"
        exit 64
    fi
}

# -----------------------------------------------------------------------------
# Preflight
# -----------------------------------------------------------------------------
if [[ -z "${TAG}" ]]; then
    usage
    exit 64
fi

require cosign

REF="${IMAGE}:${TAG}"
log "image:    ${REF}"
log "identity: ${IDENTITY_REGEXP}"
log "issuer:   ${OIDC_ISSUER}"

# -----------------------------------------------------------------------------
# 1. Signature verification
# -----------------------------------------------------------------------------
log "step 1/2 — cosign verify (keyless signature)"
if cosign verify \
    "${REF}" \
    --certificate-identity-regexp "${IDENTITY_REGEXP}" \
    --certificate-oidc-issuer "${OIDC_ISSUER}" \
    >/tmp/verify-image.sig.json 2>&1; then
    ok "signature verified"
else
    fail "cosign verify failed — see output below"
    cat /tmp/verify-image.sig.json >&2 || true
    exit 1
fi

# -----------------------------------------------------------------------------
# 2. SBOM attestation verification
# -----------------------------------------------------------------------------
log "step 2/2 — cosign verify-attestation (CycloneDX SBOM)"
if cosign verify-attestation \
    "${REF}" \
    --type cyclonedx \
    --certificate-identity-regexp "${IDENTITY_REGEXP}" \
    --certificate-oidc-issuer "${OIDC_ISSUER}" \
    >/tmp/verify-image.att.json 2>&1; then
    ok "SBOM attestation verified"
else
    fail "cosign verify-attestation failed — see output below"
    cat /tmp/verify-image.att.json >&2 || true
    exit 2
fi

ok "image ${REF} is signed and SBOM-attested — safe to deploy"
exit 0
