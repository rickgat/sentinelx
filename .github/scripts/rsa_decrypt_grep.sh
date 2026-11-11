#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# LOW-001-FU3 defence-in-depth CI grep gate: RSA decrypt surface.
# ---------------------------------------------------------------------------
#
# .cargo/audit.toml carries an ACCEPTED-PERMANENT ignore for
# RUSTSEC-2023-0071 (Marvin Attack, `rsa@0.9.10`). The ignore's
# justification is that SentinelX has ZERO RSA decrypt call sites —
# only signature-verify consumers via `RsaPublicKey`. Marvin Attack
# requires an attacker-controlled decrypt oracle, so it is
# NON-APPLICABLE to our exposure surface.
#
# This script is the CI-side regression guard for that invariant. If
# any production (non-test) code under `crates/` or `services/` starts
# importing or calling an RSA private-key / decrypting-key surface, the
# gate hard-fails, forcing a re-evaluation of the ignore entry before
# the change can merge.
#
# Scope rules:
#   * Only `.rs` files under `crates/` and `services/`.
#   * Whitelist paths that are test / fuzz / bench / example harnesses:
#     `**/tests/**`, `**/fuzz/**`, `**/benches/**`, `**/examples/**`.
#     These are dev artefacts, not the production hot path. The current
#     workspace hits for `RsaPrivateKey` live entirely under
#     `crates/sx-audit/tests/` and `crates/sx-iam/tests/` — the gate
#     MUST pass on clean main.
#
# Pattern design:
#   * `RsaPrivateKey` and `DecryptingKey` are literal type names owned
#     by the `rsa` crate. We grep for them as-is.
#   * `.decrypt(` is intentionally NOT grepped directly: the workspace
#     has many legitimate non-RSA decrypt call sites (KMS providers,
#     Vault Transit, AWS KEK, DEK rotation, envelope encrypters, etc.)
#     A bare `\.decrypt\(` regex over-matches by an order of magnitude.
#     Strategy: only inspect `.decrypt(` occurrences inside files that
#     also `use rsa::` — that scopes the pattern to the rsa crate's
#     decrypt surface without false positives from other crates.
#
# Behaviour:
#   * On any match: print each offending file:line, print pointers to
#     `docs/runbooks/supply-chain.md` §6.4 (LOW-001-FU3 row) and
#     `.cargo/audit.toml`, then exit 1.
#   * On no match: print a single success line and exit 0.

set -euo pipefail

# Repo root = two levels up from this script (`.github/scripts/`).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

SEARCH_ROOTS=()
for d in crates services; do
  if [ -d "$d" ]; then
    SEARCH_ROOTS+=("$d")
  fi
done

if [ "${#SEARCH_ROOTS[@]}" -eq 0 ]; then
  echo "rsa-decrypt-surface: neither crates/ nor services/ present — nothing to scan." >&2
  exit 0
fi

# Whitelist regex — extended grep syntax, matches path segments.
WHITELIST='/(tests|fuzz|benches|examples)/'

# Type-name patterns owned by the `rsa` crate.
TYPE_PATTERN='RsaPrivateKey|DecryptingKey'

TMP="$(mktemp -t rsa-decrypt-surface.XXXXXX)"
trap 'rm -f "$TMP"' EXIT

# ---- Pass 1: literal type names ------------------------------------------------
grep -RIn --include='*.rs' -E "$TYPE_PATTERN" "${SEARCH_ROOTS[@]}" 2>/dev/null \
  | grep -Ev "$WHITELIST" >> "$TMP" || true

# ---- Pass 2: `.decrypt(` inside files that also `use rsa::` -------------------
#
# We first enumerate the (non-whitelisted) production files that pull in
# the `rsa` crate, then within only that narrow set of files search for
# a `.decrypt(` call. This keeps the gate free of AES / KMS / Vault
# false positives while still catching an `RsaPrivateKey::decrypt(...)`
# regression that snuck in without a fresh `use` line (e.g. via full-path
# `rsa::RsaPrivateKey`).
RSA_FILES="$(grep -RIl --include='*.rs' -E '(^|\W)rsa::' "${SEARCH_ROOTS[@]}" 2>/dev/null \
  | grep -Ev "$WHITELIST" || true)"

if [ -n "$RSA_FILES" ]; then
  # shellcheck disable=SC2086
  # $RSA_FILES is a newline-separated list; xargs handles quoting.
  echo "$RSA_FILES" | xargs -I{} grep -HIn -E '\.decrypt\(' "{}" 2>/dev/null \
    >> "$TMP" || true
fi

# ---- Report -------------------------------------------------------------------
if [ -s "$TMP" ]; then
  echo "✗ RSA decrypt surface detected in production code (LOW-001-FU3 regression)."
  echo ""
  echo "Offending sites:"
  # De-dupe while preserving order (some lines may be picked up by both passes).
  awk '!seen[$0]++' "$TMP"
  echo ""
  echo "Context:"
  echo "  * .cargo/audit.toml — RUSTSEC-2023-0071 ignore is gated on"
  echo "    'zero RSA decrypt call sites'. Any hit above invalidates that gate."
  echo "  * docs/runbooks/supply-chain.md §6.4 (LOW-001-FU3 row) — exposure"
  echo "    surface analysis + upstream Marvin Attack tracking."
  echo ""
  echo "Remediation options:"
  echo "  1. Remove the RSA decrypt call site (preferred — the workspace is"
  echo "     verify-only by design)."
  echo "  2. If the decrypt is genuinely required, drop RUSTSEC-2023-0071 from"
  echo "     .cargo/audit.toml, escalate to Security Eng, migrate to a"
  echo "     constant-time RSA primitive (openssl / ring), and file a follow-up"
  echo "     ticket before merging."
  exit 1
fi

echo "✓ zero RSA decrypt call sites detected"
exit 0
