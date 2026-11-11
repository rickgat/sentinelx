# Supply-Chain Hardening Runbook

> **Last reviewed:** 2026-06-15
> **Maintainer:** Security Engineering (`security-eng@sentinelx.example`)
> **Review cadence:** Quarterly
> **Classification:** Internal — Restricted
> **Tracking ticket:** LOW-001 (`docs/SPRINT_HARDENING_HANDOFF.md`)

## 1. Purpose & scope

This runbook documents the SentinelX supply-chain gates: how Rust dependency
advisories are surfaced and enforced, and how the Software Bill of Materials
(SBOM) is produced, signed, and verified for every release.

Out of scope: the container-image-level SBOM produced by `syft` (covered by
the release workflow itself) and the CVE-scanner gate (`trivy` — see
`docs/runbooks/incident-response.md`).

## 2. Targets

| Control | Target | Enforced by |
| --- | --- | --- |
| Block PR merge on any unignored RUSTSEC advisory | 100% of PRs | `.github/workflows/audit.yml` |
| Detect newly-disclosed advisories on `main` without code change | weekly | `.github/workflows/dependency-scan.yml` (cron Mon 04:00 UTC) |
| Publish CycloneDX SBOM with every tagged release | every `v*.*.*` tag | `.github/workflows/release.yml` |
| Cryptographically sign the SBOM (sigstore keyless) | every release SBOM | `cosign sign-blob` in release job |

## 3. Cargo-audit gate

### 3.1 What runs, when

- **Per-push + per-PR**: `.github/workflows/audit.yml` runs `cargo audit` with
  `--deny warnings --deny unmaintained --deny unsound --deny yanked`. The job
  reads `.cargo/audit.toml` for the workspace ignore list. **Any** advisory
  not in the ignore list fails the build.
- **Weekly cron**: `.github/workflows/dependency-scan.yml` runs the same gate
  every Monday 04:00 UTC so newly-disclosed advisories surface even when no
  PRs land.

### 3.2 Severity policy — hard-stop only

We do **not** downgrade severity. The gate is binary:

- Advisory present + not ignored → build fails.
- Advisory present + ignored in `.cargo/audit.toml` with justification → build passes.
- No advisory → build passes.

There is no "warn-only" tier. If an advisory cannot be remediated, it must
appear in the ignore list with a tracking ticket and a re-evaluation date.

### 3.3 How to ignore an advisory

Ignoring is a code change reviewed like any other. Procedure:

1. Reproduce locally:

       make audit

   Confirm the failing RUSTSEC ID and the affected dep tree:

       cargo audit --json | jq '.vulnerabilities.list[] | {id: .advisory.id, package: .package.name, dependency_tree: .package.dependencies}'

2. Decide between **remediate** and **ignore**.
   - Prefer remediation: bump the affected dep (`cargo update -p <crate>`),
     or bump the parent that pulls it. Re-run `make audit`.
   - Ignore only when remediation is blocked (upstream unfixed, in-flight,
     or the advisory does not apply to our exposure surface).

3. Add the ignore to `.cargo/audit.toml` using the template at the top of
   the file. Required fields:
   - RUSTSEC ID + affected crate@version.
   - Reason — concrete justification grounded in exposure surface (e.g.
     "we never call the affected API; documented in module X").
   - Tracking ticket in `docs/SECURITY_GAP_REMEDIATION_TASKS.md`.
   - Re-evaluation date (ISO 8601, max 90 days out).

4. Open a PR. The PR template requires two security-engineering reviewers
   for any `.cargo/audit.toml` change. The audit gate must pass with the
   new ignore in place.

5. File a tracking item linking the PR + the RUSTSEC ID so the
   re-evaluation date triggers a follow-up sweep.

### 3.4 Local sanity check

    make audit          # workspace audit using the policy
    make audit-install  # install cargo-audit if missing

## 4. SBOM generation + signing

### 4.1 What gets shipped

Every release tag (`v*.*.*`) attaches the following artifacts to the GitHub
Release (see `.github/workflows/release.yml`):

| Artifact | Purpose |
| --- | --- |
| `sbom.cyclonedx.json` | Cargo-level CycloneDX 1.4 SBOM, every workspace crate + transitive dep |
| `sbom.cyclonedx.json.sig` | sigstore signature (DER) over the SBOM |
| `sbom.cyclonedx.json.pem` | Fulcio-issued signing certificate (carries OIDC identity) |
| `sbom.cdx.json` | Container-image SBOM via `syft` (separate, complementary) |
| `checksums.txt[.sig|.pem]` | SHA-256 manifest + sigstore signature |

### 4.2 Local SBOM build

Developers can produce the same SBOM locally before tagging:

    make sbom

Output: `sbom.cyclonedx.json` in the workspace root. The Makefile installs
`cargo-cyclonedx` on demand if it is missing.

### 4.3 How releases sign

The release workflow uses **sigstore cosign keyless OIDC**: cosign mints a
short-lived signing cert from Fulcio using the GitHub-issued OIDC token of
the running workflow. No long-lived signing keys exist. The certificate is
published alongside the signature so downstream verifiers can pin the
expected workflow identity.

### 4.4 How to verify a release SBOM

Required tooling: `cosign >= v2.4.0`.

1. Download the three SBOM artifacts from the GitHub Release page:
   `sbom.cyclonedx.json`, `sbom.cyclonedx.json.sig`, `sbom.cyclonedx.json.pem`.

2. Verify (pin to the release workflow identity):

       cosign verify-blob \
         --certificate sbom.cyclonedx.json.pem \
         --signature sbom.cyclonedx.json.sig \
         --certificate-identity-regexp 'https://github\.com/.*/\.github/workflows/release\.yml@.*' \
         --certificate-oidc-issuer https://token.actions.githubusercontent.com \
         sbom.cyclonedx.json

   A successful run prints `Verified OK`. Any other output is a failure —
   treat as a potential tampered artifact and escalate per
   `docs/runbooks/incident-response.md` (supply-chain compromise track).

3. Or use the Makefile shortcut from a checked-out workspace:

       make sbom-verify SBOM_OUT=sbom.cyclonedx.json

### 4.5 What the SBOM is good for

- Auditor evidence (SOC 2 CC8.1, ISO 27001 A.8.30, EU CRA Annex I).
- Downstream consumers can match advisories against pinned deps without
  building from source.
- Incident response: when a new RUSTSEC drops, search every shipped SBOM
  for the affected crate to bracket exposure across versions.

## 5. Change log

| Date | Author | Change |
| --- | --- | --- |
| 2026-06-15 | Security Eng | Initial publication. Introduces the CI gate (`audit.yml`), the workspace ignore policy (`.cargo/audit.toml`), the cargo-level CycloneDX SBOM, and the sigstore signing flow on release. Tracks LOW-001. |
| 2026-06-16 | Security Eng | LOW-001-FU1 triage of the 29 advisories that were open when the gate landed. See §6 for the per-ID disposition table; 11 advisories remediated by dep bumps, 18 accepted-as-ignored with structured justifications and re-evaluation date 2026-12-15. |
| 2026-06-23 | Security Eng | LOW-001-FU2 + LOW-001-FU4 landed: (a) FU2 cascade rustc 1.88→1.92, AWS SDK 1.5→1.8, wasmtime 24→36 closes 10 of the 18 FU1 ignores (3 rustls-webpki, 6 wasmtime, 1 lru); (b) FU4 hickory-proto 0.24→0.26 migration closes RUSTSEC-2026-0119 (O(n²) name-compression DoS); (c) concurrent quinn-proto 0.11.14→0.11.15 (both FU2 and FU4 picked it up) closes newly-disclosed RUSTSEC-2026-0185 (stream reassembly DoS, published 2026-06-22). Ignore list down from 18 → 6. See §6.3 / §6.4 for the updated ledger. |

## 6. LOW-001-FU1 triage outcome (2026-06-16)

The initial gate landing (LOW-001) flipped the build red on 29 RUSTSEC
advisories. This section is the per-ID ledger of how each was resolved.

### 6.1 Summary

| Bucket | Count | Action |
| --- | --- | --- |
| Vulnerabilities remediated by version bump | 10 | wasmtime 26.0.1 -> 24.0.7 (10 of 16 advisories patched in the 24.x backport) |
| Vulnerabilities remediated by parent-crate bump | 1 | idna 0.5 -> 1.0 via `validator` 0.18 -> 0.20 |
| Yanked version replaced | 1 | bitflags 2.12.0 -> 2.13.0 |
| Vulnerabilities accepted-as-ignored | 10 | See §6.3 (one struck through: RUSTSEC-2026-0119 cleared by LOW-001-FU4 on 2026-06-23) |
| Unmaintained / unsound accepted-as-ignored | 7 | See §6.3 |
| **Total** | **29 → 0 open + 17 ignored** (as of 2026-06-23) | Gate green at exit 0 |

### 6.2 Dep bumps (the green column)

| Change | Affected file | RUSTSEC IDs resolved |
| --- | --- | --- |
| `wasmtime` workspace `26.0.1` → `=24.0.7` (24.x backport line, MSRV 1.78) | `Cargo.toml` workspace section, `crates/sx-plugins/src/wasm_host.rs` (`ResourceLimiter::table_growing` signature `usize`→`u32`) | RUSTSEC-2025-0046, RUSTSEC-2025-0118, RUSTSEC-2026-0020, RUSTSEC-2026-0021, RUSTSEC-2026-0085, RUSTSEC-2026-0087, RUSTSEC-2026-0091, RUSTSEC-2026-0092, RUSTSEC-2026-0093 + the prior wasmtime CVE that shipped against 26.0.1 |
| `validator` workspace `0.18` → `0.20` (idna 1.0 transitively) | `Cargo.toml` workspace section | RUSTSEC-2024-0421 (idna Punycode acceptance) + dropped RUSTSEC-2024-0370 (proc-macro-error 1.x, replaced by proc-macro-error2 — separate entry below) |
| `bitflags` `2.12.0` → `2.13.0` via `cargo update -p bitflags` | `Cargo.lock` only | yanked version replaced (no RUSTSEC ID) |

### 6.3 Accepted-as-ignored (with re-evaluation date 2026-12-15)

The structured rationale for every entry lives in `.cargo/audit.toml` as
the comment block above each `"RUSTSEC-..."` literal. Re-evaluation date
is uniformly 2026-12-15 because every ignore here is gated on one of:

1. **MSRV bump 1.88 → 1.92** (`LOW-001-FU2`) — required to take any of
   the AWS SDK or rustls modernization, which unblocks the `aws-config`
   1.8 line, `rustls-webpki` ≥ 0.103, `lru` ≥ 0.16, and the 6 wasmtime
   advisories patched only in the ≥36 line.
2. **No upstream patch** (`LOW-001-FU3`) — `rsa@0.9.10` Marvin Attack;
   the upstream `RustCrypto/rsa` crate has not shipped a constant-time
   decrypt path. We only verify with RSA (no decrypt) so the side-channel
   does not apply to our exposure surface. Re-probed 2026-06-25 against
   `rsa@0.10.0-rc.18` (latest tag): the `crypto-bigint` migration landed
   constant-time **modpow** (upstream issue #19 closed 2026-01-07), but
   the **padding** layer is still non-constant-time per upstream issue
   [#626](https://github.com/RustCrypto/RSA/issues/626) (still open
   2026-06-02). RUSTSEC-2023-0071 advisory remains `patched = []`. No
   stable 0.10 has shipped. Status stays BLOCKED.
3. **Multi-day API migration** (`LOW-001-FU4`) — `hickory-proto` 0.24 →
   0.26 changed `TokioAsyncResolver`, the `RequestHandler` trait, and
   resolver config — multi-day refactor of `sx-discovery` + `sx-collab`.
4. **Abandonware, transitive only** (`LOW-001-FU5`, `LOW-001-FU6`) — six
   unmaintained crates pulled transitively (`backoff`, `instant`, `paste`,
   `proc-macro-error2`, `rustls-pemfile` ×2). None used directly by
   `sx-*` code; each tracked against the upstream parent's planned bump.

| RUSTSEC ID | Crate@version | Class | Follow-up ticket |
| --- | --- | --- | --- |
| RUSTSEC-2023-0071 | rsa@0.9.10 | vulnerability — no patch | LOW-001-FU3 |
| ~~RUSTSEC-2026-0098~~ | ~~rustls-webpki@0.101.7~~ | ~~vulnerability — MSRV-locked~~ | ✅ closed 2026-06-23 by LOW-001-FU2 |
| ~~RUSTSEC-2026-0099~~ | ~~rustls-webpki@0.101.7~~ | ~~vulnerability — MSRV-locked~~ | ✅ closed 2026-06-23 by LOW-001-FU2 |
| ~~RUSTSEC-2026-0104~~ | ~~rustls-webpki@0.101.7~~ | ~~vulnerability — MSRV-locked~~ | ✅ closed 2026-06-23 by LOW-001-FU2 |
| ~~RUSTSEC-2026-0086~~ | ~~wasmtime@24.0.7~~ | ~~vulnerability — Winch off; MSRV-locked~~ | ✅ closed 2026-06-23 by LOW-001-FU2 |
| ~~RUSTSEC-2026-0088~~ | ~~wasmtime@24.0.7~~ | ~~vulnerability — pooling-allocator off; MSRV-locked~~ | ✅ closed 2026-06-23 by LOW-001-FU2 |
| ~~RUSTSEC-2026-0089~~ | ~~wasmtime@24.0.7~~ | ~~vulnerability — Winch off; MSRV-locked~~ | ✅ closed 2026-06-23 by LOW-001-FU2 |
| ~~RUSTSEC-2026-0094~~ | ~~wasmtime@24.0.7~~ | ~~vulnerability — Winch off; MSRV-locked~~ | ✅ closed 2026-06-23 by LOW-001-FU2 |
| ~~RUSTSEC-2026-0095~~ | ~~wasmtime@24.0.7~~ | ~~vulnerability — Winch off; MSRV-locked~~ | ✅ closed 2026-06-23 by LOW-001-FU2 |
| ~~RUSTSEC-2026-0096~~ | ~~wasmtime@24.0.7~~ | ~~vulnerability — aarch64-Cranelift; MSRV-locked~~ | ✅ closed 2026-06-23 by LOW-001-FU2 |
| ~~RUSTSEC-2026-0119~~ | ~~hickory-proto@0.24.4~~ | ~~vulnerability — multi-day migration~~ | ✅ closed 2026-06-23 by LOW-001-FU4 (hickory 0.24→0.26) |
| RUSTSEC-2025-0012 | backoff@0.4.0 | unmaintained | LOW-001-FU5 |
| RUSTSEC-2024-0384 | instant@0.1.13 | unmaintained | LOW-001-FU6 |
| RUSTSEC-2024-0436 | paste@1.0.15 | unmaintained | LOW-001-FU6 |
| RUSTSEC-2026-0173 | proc-macro-error2@2.0.1 | unmaintained | LOW-001-FU6 |
| ~~RUSTSEC-2025-0134~~ | ~~rustls-pemfile@1.0.4~~ | ~~unmaintained~~ | ✅ 1.0.4 instance dropped 2026-06-23 by LOW-001-FU2 (modern aws-smithy http client) |
| RUSTSEC-2025-0134 | rustls-pemfile@2.2.0 | unmaintained | LOW-001-FU6 — moved out of LOW-001-FU2 scope; 2.2.0 still pulled by tonic/redis/neo4rs/kube-client/axum-server |
| ~~RUSTSEC-2026-0002~~ | ~~lru@0.12.5~~ | ~~unsound — `IterMut` not invoked~~ | ✅ closed 2026-06-23 by LOW-001-FU2 |

### 6.4 Follow-up tickets created

| ID | Title | Status | Scope / resolution |
| --- | --- | --- | --- |
| LOW-001-FU2 | Workspace MSRV bump 1.88 → 1.92 + AWS SDK 1.5 → 1.8 + wasmtime 24 → 36 cascade | ✅ landed 2026-06-23 | Closed: 6 wasmtime advisories (RUSTSEC-2026-0086 / -0088 / -0089 / -0094 / -0095 / -0096), 3 rustls-webpki advisories (RUSTSEC-2026-0098 / -0099 / -0104), 1 lru advisory (RUSTSEC-2026-0002), 1 of the 2 rustls-pemfile entries (RUSTSEC-2025-0134 against 1.0.4). Also bumped quinn-proto 0.11.14 → 0.11.15 closing the newly-disclosed RUSTSEC-2026-0185 (DoS via unbounded out-of-order stream reassembly). The remaining `rustls-pemfile@2.2.0` instance is reclassified into FU6. |
| LOW-001-FU3 | RSA constant-time decrypt path (track upstream `rsa@1.x` or migrate to `openssl` primitive) | 🔒 UPSTREAM BLOCKED 2026-06-25 (0.10-rc lacks fix; next probe quarterly) | Resolves Marvin Attack RUSTSEC-2023-0071. **Probe 2026-06-25** vs `rsa@0.10.0-rc.18` (no stable 0.10 yet): constant-time **modpow** has landed (upstream issue #19 closed 2026-01-07 via `crypto-bigint` migration); constant-time **padding** has NOT — upstream issue [#626](https://github.com/RustCrypto/RSA/issues/626) "Padding implementation is not constant-time" still open (created 2026-01-07, last updated 2026-06-02). RUSTSEC-2023-0071 still has `patched = []` upstream. README at v0.10.0-rc.18 still states "This crate is vulnerable to the Marvin Attack". Workspace exposure: signature-verify-only via `RsaPublicKey` in `sx-audit/anchor_run.rs` and `sx-iam/saml/response.rs` — no `RsaPrivateKey` / decrypt call sites; Marvin Attack does not apply to our usage. Re-probe quarterly. **CI enforcement:** `.github/workflows/audit.yml` job `rsa-decrypt-surface` (script at `.github/scripts/rsa_decrypt_grep.sh`) fails on regression — any new `RsaPrivateKey` / `DecryptingKey` / `rsa` `.decrypt(` call in non-test code under `crates/` or `services/` breaks the build. |
| LOW-001-FU4 | `hickory-*` 0.24 → 0.26 migration in `sx-discovery` + `sx-collab` | ✅ landed 2026-06-23 | Closed RUSTSEC-2026-0119; workspace `hickory-{proto,resolver,server}` pinned to 0.26; `Resolver::builder_with_config` + `Metadata::response_from_request` + `hickory_server::Server` adopted. Ignore list now 18 → 6. |
| LOW-001-FU5 | `neo4rs` 0.8 → 1.x (drops `backoff`) | deferred → FU6-class | No 1.x stable upstream as of 2026-06-23, reconfirmed 2026-06-24 (`cargo search neo4rs` still returns latest stable `0.8.0`, latest pre-release `0.9.0-rc.10`; no 1.0 release line on crates.io). PO decision: wait for 1.0 stable rather than pin a pre-release to the critical-path graph driver. Reclassified into FU6-class tracking. 2026-06-25 re-probe: still blocked. **2026-07-04 re-probe** (via `crates.io/api/v1/crates/neo4rs`): `max_stable_version = 0.8.0`, `max_version = 0.9.0-rc.10` — zero net progress since 2026-06-25 probe (same rc.10, no new pre-release). Status unchanged; quarterly gate stays at 2026-09-25. Alternative-path analysis at `supply-chain-alternative-paths-2026-06-25.md` still valid. |
| LOW-001-FU6 | Drop `instant` / `paste` / `proc-macro-error2` / `rustls-pemfile@2.2.0` / `backoff` (via neo4rs 1.x) when upstream bumps land | pending | Cleanup once upstreams ship; scope widened 2026-06-23 to absorb rustls-pemfile@2.2.0 (from FU2) and backoff (from FU5 deferral). See §7 probe report for current upstream status. 2026-06-25 re-probe: still blocked. Alternative-path analysis at `supply-chain-alternative-paths-2026-06-25.md` surfaces TWO actionable sub-paths (audit-toml comment refresh for stale `paste` rationale; `rustls-pemfile` partial parent-bump cascade narrowing 6 paths → 1) — neither closes the audit-toml ignore on its own, but both are clear-cost. **2026-07-04 update**: `LOW-001-FU6-TONIC-OTEL` cascade landed (merge `d0e14ba`) — tonic 0.14 + opentelemetry 0.32; drops the tonic parent for `rustls-pemfile`. Remaining fan-in narrows further: 6 → 2 (only `neo4rs@0.8.0` + local `sx-mtls` via `rustls-native-certs`). Co-blocked on FU5. PO decision pending on alternative paths. |

### 6.5 Re-evaluation cadence

Every entry in §6.3 has `Re-evaluate by: 2026-12-15` in the audit.toml
comment. The weekly dependency-scan cron will surface ANY newly-disclosed
advisory automatically; the 2026-12-15 review is for the existing
ignores only.

When re-evaluating, the procedure is:

1. For each ignored ID, check whether the underlying constraint
   (MSRV / no-patch / refactor) still holds.
2. If the parent dep has a new minor that ships the fix at a compatible
   MSRV — bump, drop the ignore, run `make audit`.
3. If the constraint still holds — extend the re-evaluation date by at
   most 90 days AND add a one-line note to the audit.toml comment
   block citing the latest blocker (e.g. "rustc 1.92 bump deferred to
   sprint 6").

A re-evaluation that simply rolls the date forward without a fresh
blocker note is a policy violation — the gate exists to surface
abandoned ignores.

## 7. LOW-001-FU6 upstream probe 2026-06-23

This section captures a scheduled probe of the four abandonware advisories
parked under LOW-001-FU6 to determine whether any parent crate has shipped a
release that drops the unmaintained transitive — i.e. whether the FU6 ignores
can be retired without waiting for the cascading rustc / AWS SDK / rustls
modernization that LOW-001-FU2 + FU5 require.

### 7.1 Method

For each of the four advisories, `cargo tree -i <crate>` enumerated the
immediate parent(s). For each parent, the latest crates.io version was
inspected with `cargo info <parent>` and its feature list / dependency table
was compared against the currently-resolved version to determine whether the
unmaintained transitive has been dropped. Where a parent had shipped a
newer version with the transitive dropped, the dry-run criterion was:
SemVer-compatible bump only, no API breakage. A bump was treated as
landable only if it would let us drop the corresponding `.cargo/audit.toml`
ignore — partial reductions (where some but not all parents still pull the
transitive) were recorded but NOT landed, because the audit gate still
hard-fails on the surviving parent path and the bump would not retire the
ignore.

### 7.2 Per-advisory status

| RUSTSEC ID | Crate@version | Parent(s) (immediate) | Parent latest | Parent dropped bad transitive? | Action | Next check by |
|---|---|---|---|---|---|---|
| RUSTSEC-2024-0384 | `instant@0.1.13` | `backoff@0.4.0` (via `neo4rs@0.8.0`) | `backoff@0.4.0` (unchanged since 2022 — author-abandoned) | no — `backoff` has not shipped, `neo4rs@0.9.0-rc.10` (pre-release) is the upstream replacement path | waiting — co-blocked on LOW-001-FU5 (`neo4rs 0.8 → 1.x` drops `backoff` which drops `instant`) | 2026-09-23 or earlier when `neo4rs 0.9.0` ships GA |
| RUSTSEC-2024-0436 | `paste@1.0.15` | `neo4rs@0.8.0`, `wasmtime@24.0.7` | `neo4rs@0.9.0-rc.10`, `wasmtime@46.0.0` | partial — FU2 already bumped wasmtime to 36.0.11 on 2026-06-23, removing one parent; `neo4rs@0.8` remains | waiting — co-blocked on LOW-001-FU5 (`neo4rs`) | 2026-09-23 or earlier on FU5 movement |
| RUSTSEC-2026-0173 | `proc-macro-error2@2.0.1` | `validator_derive@0.20.0` (via `validator@0.20`) | `validator_derive@0.20.0` (unchanged — current stable) | no — no newer `validator` / `validator_derive` release exists; upstream has not cut a version that drops `proc-macro-error2` | waiting — no upstream movement; nothing actionable | 2026-09-23 (re-probe `cargo info validator_derive`) |
| RUSTSEC-2025-0134 | `rustls-pemfile@2.2.0` | `axum-server@0.7.3`, `kube-client@0.96.0`, `neo4rs@0.8.0`, `redis@0.27.6`, `rustls-native-certs@0.7.3` (via `neo4rs`), `tonic@0.12.3` | `axum-server@0.8.0`, `kube-client@4.0.0`, `redis@1.2.4`, `rustls-native-certs@0.8.4`, `tonic@0.14.6` | partial — `axum-server 0.8` and `tonic 0.14` no longer expose `rustls-pemfile` in their feature lists (replaced by `rustls-pki-types`). However `neo4rs@0.8.0` pulls `rustls-pemfile` AND `rustls-native-certs@0.7.3` directly; the audit-toml ignore cannot be dropped until ALL parents stop pulling it. | waiting — even bumping every bumpable parent (axum-server 0.7→0.8, tonic 0.12→0.14, kube 0.96→4.0, redis 0.27→1.x) would leave `neo4rs 0.8` as the holdout. Co-blocked on LOW-001-FU5. | 2026-09-23 or earlier on FU5 movement |

### 7.3 Why nothing landed in this probe

Every FU6 advisory is co-blocked on a heavier-weight follow-up
(FU2 = rustc 1.92 + AWS SDK / rustls 0.23, FU5 = neo4rs 0.8 → 1.x). Even
where a parent has shipped a fix-bearing release, at least one OTHER
parent that still pulls the same transitive has NOT shipped, so the
`.cargo/audit.toml` ignore cannot be retired and a partial bump would
churn the dependency graph without removing any audit-gate ignore.

Specifically (as of 2026-06-23, post-FU2 + post-FU4 merge):

- **`instant`** has exactly one parent (`backoff@0.4.0`) and that parent
  is abandoned; the only viable drop path is `neo4rs 0.8 → 0.9 / 1.x`
  (the parent of the parent), which is LOW-001-FU5 scope.
- **`paste`** had two parents (`neo4rs`, `wasmtime`). FU2 closed the
  wasmtime path by bumping to 36.0.11; `neo4rs 0.8` remains, so the
  ignore stays until FU5 moves.
- **`proc-macro-error2`** has one parent (`validator_derive 0.20`) and
  the parent has shipped no newer version. Pure upstream-waiting case.
- **`rustls-pemfile@2.2.0`** has six parents; four have newer versions
  that dropped it (`axum-server 0.8`, `tonic 0.14`, `kube 4.0`,
  `redis 1.x`), but `neo4rs 0.8` and `rustls-native-certs 0.7.3` (also
  pulled via `neo4rs`) still pull it. Co-blocked on LOW-001-FU5.

### 7.4 Out-of-band finding

The `cargo audit` run on 2026-06-23 surfaced a NEW high-severity
vulnerability:

- **RUSTSEC-2026-0185** — `quinn-proto@0.11.14` — remote memory
  exhaustion from unbounded out-of-order stream reassembly; severity
  7.5 (high); fixed in `quinn-proto >= 0.11.15`. Pulled transitively by
  `quinn 0.11.9` ← `reqwest 0.12.28`. Published 2026-06-22 (one day
  before this probe).

✅ Closed on the same day by LOW-001-FU2 + LOW-001-FU4 (both branches
landed a `cargo update -p quinn-proto` to 0.11.15). No further action.

### 7.5 Next-check cadence

All four FU6 advisories remain on their original
`Re-evaluate by: 2026-12-15` cap from §6.3. The next opportunistic
re-probe should occur:

- when LOW-001-FU5 (`neo4rs 0.8 → 1.x`) lands — that would close
  `instant` (RUSTSEC-2024-0384) and remove `neo4rs` from the
  `rustls-pemfile@2.2.0` parent list (advancing — but not closing —
  RUSTSEC-2025-0134).
- 2026-09-23, three months from this probe, as a baseline cadence
  even absent FU5 movement, to catch any `validator_derive`
  release that drops `proc-macro-error2`.

### 7.6 2026-06-25 follow-up — alternative-path analysis

The 2026-06-24 re-probe surfaced no upstream movement and the PO
escalated: rather than another "still waiting" cell in §7.2, produce a
costed-out alternative-path decision matrix. The output lives in a
companion document so that §7 stays a probe ledger and the alternatives
analysis stays evergreen:

- **[`supply-chain-alternative-paths-2026-06-25.md`](./supply-chain-alternative-paths-2026-06-25.md)**

Headline outcomes (full detail in the companion document):

- `neo4rs` 0.8 → 0.9 stable (FU5): wait remains cheapest. `neo4rs@0.9.0-rc.10`
  pin is a viable 3-4 day contingency (closes `backoff` + `instant` and
  removes one of the 6 `rustls-pemfile` parents) but PO declined twice
  on critical-path pre-release risk. `bolt-client` swap (8-12 days) and
  DIY-Bolt (25-40 days) are documented but not credible.
- `paste@1.0.15`: re-inventory confirmed **single parent** (`neo4rs`).
  `pastey@0.2.3` maintained-successor crate exists and is a credible
  `[patch.crates-io]` target, but a sharpened `audit.toml` rationale
  comment (~0.25 dev-days) is the recommended action because the
  existing rationale incorrectly names `metrics-exporter-prometheus`
  as the consumer.
- `rustls-pemfile@2.2.0`: re-probe revealed `redis@1.2.4` and
  `rustls-native-certs@0.8.4` shipped since 2026-06-23. A partial
  parent-bump cascade (axum-server 0.8 + tonic 0.14 + kube 4.0 + redis
  1.x + rustls-native-certs 0.8.4) is now 5-7 dev-days and narrows
  attack-surface from 6 paths → 1, pre-staging the FU5 unblock. Does
  NOT close the audit-toml ignore (neo4rs holdout).
- `instant` (RUSTSEC-2024-0384): zero runtime exposure (wasm-only path);
  recommend co-resolving with FU5. No independent action justified.
- `proc-macro-error2` (RUSTSEC-2026-0173): compile-time only, single
  parent (`validator_derive@0.20.0`); waiting remains cheapest.

Two actionable sub-paths surfaced that qualify the FU6 tracker row for
downgrade from 🔒 BLOCKED to 🟡 AWAITING-PO-DECISION pending the PO
choice on whether to (a) file the `audit.toml`-comment refresh and/or
(b) file a separate `LOW-001-FU7` ticket for the rustls-pemfile parent
cascade.

## 8. libxmlsec1 CVE tracking (TOP5-#1)

### 8.1 Why this section exists

TOP5-#1 (see [ADR-0022](../adr/0022-saml-xmldsig-libxmlsec1-replacement.md)
and [SX-PLAN-TOP5-001](../plans/top5-1-xmldsig-replacement.md))
replaces the hand-rolled SAML XMLDSig verifier with `libxmlsec1` via
the `sx-xmlsec` workspace crate. `libxmlsec1` is a C library tracked
**outside** the Rust ecosystem advisory pipeline:

* `cargo audit` does NOT scan it — the RUSTSEC database covers crates
  registered on crates.io only.
* `cargo deny advisories` does NOT scan it — same reason.
* Our weekly CI advisory sweep (§3) would miss any `libxmlsec1` /
  `libxml2` CVE without an explicit watch.

Without this section, a `libxmlsec1` CVE could land in upstream and
sit unreviewed in our deployed image — a near-repeat of the
"knowingly-running-with-advisories" pattern senior review §1.5
flagged for the wasmtime LOW-001-FU2 cascade. This section closes the
gap.

### 8.2 Monitoring sources

| Source | What it covers | Cadence |
|---|---|---|
| [libxmlsec1 GitHub releases](https://github.com/lsh123/xmlsec/releases) | Upstream release notes; the release-note body announces CVE fixes. | RSS / GitHub watch (release) |
| [libxml2 GitLab security advisories](https://gitlab.gnome.org/GNOME/libxml2/-/security) | libxml2 (the transitive dep that libxmlsec1 calls into). | Manual probe monthly |
| [NVD search "xmlsec1"](https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=xmlsec1) | NVD's CPE-tagged advisories for `xmlsec1`. | Manual probe monthly |
| [NVD search "libxmlsec"](https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=libxmlsec) | NVD's broader libxmlsec search (some CVEs are tagged this way). | Manual probe monthly |
| [Debian Security Tracker — libxmlsec1](https://security-tracker.debian.org/tracker/source-package/xmlsec1) | The release-image base (Debian) status for libxmlsec1; tells us if the apt-pinned version on our image is patched. | Manual probe monthly |

### 8.3 Operational SLA

* **Monthly review.** Folded into the standard supply-chain sweep
  cadence (§3.1). The reviewer opens each of the §8.2 sources, notes
  any advisory dated since the previous sweep, and records the
  outcome in the `Change log` of this runbook (§5).
* **CRIT escalation.** Any CVE class affecting our linked
  `libxmlsec1` version with severity "RCE", "signature bypass",
  "auth bypass", or "XSW bypass" is escalated to CRIT and
  page-routed to the on-call engineer, regardless of the monthly
  cadence. The §3.2 hard-stop policy applies by analogy: do not
  ship a release with an unpatched CRIT-class libxmlsec1 advisory
  unless an explicit ignore-with-re-evaluation-date is recorded
  here.
* **MED / LOW.** Aggregated into the monthly review write-up; no
  out-of-band escalation. The hand-rolled rollback path (§8.4)
  buys time if MED accumulates without an upstream fix.

### 8.4 Mitigation playbook

If a critical CVE lands against the deployed `libxmlsec1` version:

1. **Confirm exposure.** Inspect the release image's
   `dpkg -s libxmlsec1-openssl` to see the pinned version; cross-
   reference with the §8.2 advisory text.
2. **Flip the YAML knob** —
   `saml.xmldsig.verifier: handrolled` — and trigger a config
   reload (rolling restart if the deployment does not support hot
   reload). This routes the SAML SP path back through the
   hand-rolled `verify_assertion` and bypasses libxmlsec1 entirely.
   The hand-rolled path stays compileable through ADR-0022's
   rollback window (one minor release after the
   `saml.xmldsig.verifier: xmlsec1` cutover) for exactly this
   purpose.
3. **Patch upstream.** Bump the `libxmlsec1-openssl` package version
   in `deploy/Dockerfile` (apt-pin) and / or bump the
   `vendored-libxmlsec1` source tarball in `crates/sx-xmlsec/`
   (if the release image is on the vendored path).
4. **Re-cutover.** Once the patched image is deployed and the
   shadow-mode telemetry confirms zero disagreements for ≥24h,
   flip the YAML knob back to `xmlsec1` (or `shadow` first if the
   patched version is a major upgrade).
5. **Record the incident** in §5 with the CVE id, the days the
   `handrolled` fallback was active, and the disposition.

### 8.5 Cutover SLO

The "default behaviour flips from `handrolled` to `xmlsec1`"
operational decision is gated on the cutover SLO from
[SX-PLAN-TOP5-001 §2.2](../plans/top5-1-xmldsig-replacement.md):

> **Pre-cutover acceptance criterion: zero Class A or Class B
> mismatch events for 14 consecutive days against real production
> tenants.**

Class A = primary accepted, shadow rejected. Class B = primary
rejected, shadow accepted. Class C (both rejected, different
variants) is silently aggregated per the planner's §2.2 explicit
allowance — it is informational noise, not a regression signal.

The mismatch counter is
`xmldsig_shadow_mismatch_total{kind="..."}` (from
`crates/sx-xmlsec/src/dual.rs`). The corresponding `warn!` events
are `xmldsig.shadow.mismatch.both_accept_differ`,
`xmldsig.shadow.mismatch.primary_only_accept`, and
`xmldsig.shadow.mismatch.secondary_only_accept`.

The cutover decision is **the PO's**, not the SRE's. SRE provides
the SLO compliance read-out from the metric; PO signs off and a
PR flips the default to `xmlsec1` in `config/sentinelx.example.yaml`
and the production overrides.
