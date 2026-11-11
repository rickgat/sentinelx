# SentinelX Supply-Chain Security

> **Last reviewed:** 2026-06-13
> **Maintainer:** Platform Engineering (`platform-eng@sentinelx.example`)
> **Next review:** 2026-09-13 (quarterly)
> **Document owner:** Director of Platform Engineering
> **Classification:** Internal — Restricted

This document describes how SentinelX signs, attests, and scans its
container images and Rust workspace; how downstream operators verify
an image before deploying it; and the supply-chain risk posture for
the plugin SDK (P3-007) and the runtime container layer (P2-016).

## Table of contents

1. [Overview](#overview)
2. [Threat model](#threat-model)
3. [Workspace controls — `cargo deny`, `cargo audit`, lints](#workspace-controls)
4. [Keyless signing with cosign + Sigstore](#keyless-signing-with-cosign--sigstore)
5. [SBOM generation and attestation](#sbom-generation-and-attestation)
6. [CVE scanning with Trivy](#cve-scanning-with-trivy)
7. [The `.trivyignore` policy](#the-trivyignore-policy)
8. [Verifying a published image](#verifying-a-published-image)
9. [Action pinning and Renovate](#action-pinning-and-renovate)
10. [Plugin SDK (P3-007) supply-chain risk](#plugin-sdk-p3-007-supply-chain-risk)
11. [Runtime supply-chain (P2-016 Falco)](#runtime-supply-chain-p2-016-falco)
12. [Incident response](#incident-response)

---

## Overview

Every tagged release of `sx-monolith` produces, in a single GitHub Actions
workflow (`release.yml`):

| Artifact                | Tool             | Where it lives                                          |
|-------------------------|------------------|---------------------------------------------------------|
| Multi-arch OCI image    | `docker buildx`  | `ghcr.io/sentinelx/monolith:${TAG}`                     |
| Cosign signature        | `cosign sign`    | OCI registry (rekor.sigstore.dev transparency log)      |
| CycloneDX SBOM          | `syft`           | Workflow artifact + cosign attestation on the image     |
| Trivy CVE scan          | `aquasecurity/trivy-action` | Workflow log (gating) + GitHub Code Scanning |
| Signed checksums        | `cosign sign-blob` | GitHub Release assets                                 |

The same SBOM + Trivy steps run pre-merge in `verify-release.yml` against the
PR head, but without pushing or signing — this catches regressions before they
become release artifacts.

## Workspace controls

The Rust workspace enforces three coordinated control surfaces.

### `cargo deny` — `deny.toml`

`deny.toml` defines four sub-policies that all run in CI (`ci/cargo-deny`):

- `advisories` — `vulnerability = "deny"`, `unmaintained = "warn"`,
  `yanked = "deny"`. The advisory database is refreshed on every CI run
  via `cargo deny fetch`.
- `bans` — explicit blocklist (`openssl-sys`, `webpki@<0.22`,
  `time@<0.3`, etc.) plus a "multiple-versions" allowlist for
  unavoidable diamond deps.
- `licenses` — allow MIT, Apache-2.0, BSD-3-Clause, ISC, Unicode-DFS-2016,
  CC0-1.0, MPL-2.0. Everything else fails the build; exceptions require
  PR review by Legal.
- `sources` — only `crates.io` and the SentinelX-internal Cargo
  registry; git deps are denied except for the few pinned-by-SHA
  entries in `[sources.allow-git]`.

Local invocation:

```bash
cargo deny check advisories bans licenses sources
```

### `cargo audit` and dependency freshness

`cargo audit` runs nightly (`.github/workflows/cargo-audit.yml`) against
the RustSec advisory database and opens a PR labelled
`security/dependency-advisory` for any new finding. The PR carries the
affected versions plus the proposed bump.

### Workspace lints

Every crate declares `#![forbid(unsafe_code)]` at the top of `lib.rs`.
The workspace `Cargo.toml` carries:

```toml
[workspace.lints.rust]
unsafe_code = "forbid"

[workspace.lints.clippy]
unwrap_used    = "deny"
expect_used    = "deny"
panic          = "deny"
todo           = "deny"
dbg_macro      = "deny"
```

CI runs `cargo clippy --all-targets --all-features -- -D warnings` —
any warning becomes a hard error. The HTTP gateway additionally bans
direct `std::env::var` access via `clippy.toml` so all config flows
through the typed `sx-config` loader.

## Threat model

We defend against the following supply-chain attacks:

- **Registry tampering** — an attacker swaps a layer in `ghcr.io`. Mitigated
  by cosign signatures verifiable against Sigstore Fulcio + Rekor.
- **Dependency confusion / typosquat** — verifiable via the CycloneDX SBOM
  (every component is listed with version + PURL).
- **Known-CVE backsliding** — caught by Trivy's `CRITICAL,HIGH` gate. The same
  gate runs on PRs so regressions cannot ship.
- **Compromised CI** — the signing identity is the workflow OIDC token, scoped
  to the GitHub repo + branch. Operators verify the identity matches
  `https://github.com/sentinelx/`.

We do **not** currently defend against:

- A compromise of Sigstore Fulcio (out of scope; relies on the public
  good-instance trust root).
- Insider commits to `main` (mitigated by code review + branch protection,
  not by this workflow).

## Keyless signing with cosign + Sigstore

Keyless signing eliminates long-lived signing keys. Instead, the GitHub
Actions runner requests a short-lived (~10 min) OIDC token from GitHub. The
workflow's `permissions: id-token: write` enables this. Cosign exchanges that
token for an ephemeral certificate from Sigstore Fulcio whose subject claims
include:

- `iss = https://token.actions.githubusercontent.com`
- `sub = repo:sentinelx/<repo>:ref:refs/tags/v...`
- `Build trigger`, `Build config`, `Source repository`, etc.

The signature + certificate are written to the OCI registry (`...:sha256-
<digest>.sig`). A signed transparency-log entry is published to Rekor so
anyone can later prove the signature existed at that moment.

The workflow step:

```yaml
- name: Sign image (keyless via Sigstore OIDC)
  env:
    COSIGN_EXPERIMENTAL: "1"
  run: |
    cosign sign --yes "ghcr.io/sentinelx/monolith@${DIGEST}"
```

## SBOM generation and attestation

We use [Anchore syft](https://github.com/anchore/syft) (via
`anchore/sbom-action`) to produce a [CycloneDX](https://cyclonedx.org/) JSON
SBOM directly from the pushed image. The SBOM is:

1. Uploaded as a GitHub Actions workflow artifact (`sbom.cdx.json`).
2. Attached to the GitHub Release as a downloadable asset.
3. **Attested** to the image via `cosign attest --type cyclonedx`. This
   stores the SBOM as an in-toto attestation in the registry, signed by the
   same Sigstore OIDC identity. Operators verify it with
   `cosign verify-attestation --type cyclonedx ...`.

Attestation predicate type: `https://cyclonedx.org/bom`.

### SBOM cadence

- **Per release tag (`v*`):** SBOM generated, attested, attached.
- **Per merge to `main`:** SBOM generated and uploaded as a CI artefact
  (no attestation push). Diffed against the previous main-SHA SBOM and
  posted as a PR comment.
- **Quarterly:** an SBOM-set audit (`scripts/sbom/audit-quarter.sh`)
  reconciles the deployed-image SBOMs across all environments against
  the latest workspace `Cargo.lock`. Any drift opens a P1 ticket.
- **On CVE disclosure of a known component:** the SBOM set is queried
  to enumerate the affected images within 15 minutes via
  `scripts/sbom/cve-search.sh`.

## CVE scanning with Trivy

We run [Trivy](https://aquasecurity.github.io/trivy/) twice per release:

1. **Gating scan** (`exit-code: 1`) — fails the workflow on any
   un-allowlisted `CRITICAL` or `HIGH` finding (`os` + `library`,
   `ignore-unfixed: true`). This is the line operators rely on.
2. **SARIF scan** — same scope, uploads results to GitHub Code Scanning so
   security can review historical posture in the Security tab.

Severity gate: **`CRITICAL,HIGH`** — set via the workflow env
`TRIVY_SEVERITY` (single source of truth, mirrored in `verify-release.yml`).

We deliberately set `ignore-unfixed: true`: vulnerabilities with no fix
upstream are noise we cannot act on. They appear in the SARIF report for
visibility but do not block releases.

## The `.trivyignore` policy

The repo-root `.trivyignore` file lists CVE IDs Trivy must suppress. **Every
entry must be justified** — see the file header for the required comment
block (component, justification, reviewer, re-review date).

Rules:

- One CVE per line. Blank lines and `#` comments allowed.
- No entry without a comment block. PR reviewers reject otherwise.
- Re-review window: **90 days**. Stale entries are removed quarterly.
- Pinning a vulnerable transitive dependency is preferred over suppressing.

The file MUST be non-empty (Trivy treats a missing file as a usage error
when `trivyignores:` is set explicitly). We keep a sentinel placeholder
entry — `CVE-0000-00000` is a reserved-format ID that will never match a
real finding.

## Verifying a published image

Operators run `scripts/verify-image.sh` (committed in this repo):

```bash
TAG=v1.4.0 ./scripts/verify-image.sh
```

That script wraps the two cosign commands you would otherwise run by hand:

```bash
# 1. Verify the signature was produced by our GitHub Actions workflow.
cosign verify ghcr.io/sentinelx/monolith:${TAG} \
  --certificate-identity-regexp 'https://github.com/sentinelx/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# 2. Verify the SBOM attestation (and inspect its CycloneDX predicate).
cosign verify-attestation ghcr.io/sentinelx/monolith:${TAG} \
  --type cyclonedx \
  --certificate-identity-regexp 'https://github.com/sentinelx/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

A successful run prints a green check + a JSON document of the verified
attestation. **Refuse to deploy** any image where either command fails or
prints a different certificate identity.

Recommended Kubernetes enforcement: [`sigstore-policy-controller`](
https://docs.sigstore.dev/policy-controller/overview/) with a `ClusterImagePolicy`
pinning `certificate-identity-regexp` and `certificate-oidc-issuer` to the
values above.

## Action pinning and Renovate

Every third-party action in `release.yml` and `verify-release.yml` is pinned
to a major-version tag with a `# renovate: pin <owner>/<name>` trailing
comment. Renovate then upgrades the pin to a SHA + bumps it on a schedule.

Recommended `renovate.json5` excerpt:

```json5
{
  $schema: 'https://docs.renovatebot.com/renovate-schema.json',
  extends: ['config:recommended', ':semanticCommits'],
  packageRules: [
    {
      // Pin every action that carries the `renovate: pin` comment to a SHA,
      // then keep that SHA fresh.
      matchManagers: ['github-actions'],
      pinDigests: true,
      groupName: 'github-actions',
      schedule: ['before 5am on monday'],
    },
    {
      // Trivy DB updates often — keep the action version moving.
      matchPackageNames: ['aquasecurity/trivy-action'],
      schedule: ['at any time'],
      automerge: true,
    },
  ],
  vulnerabilityAlerts: { enabled: true, labels: ['security'] },
}
```

After Renovate's first PR lands, every `uses:` line will look like
`uses: actions/checkout@<sha> # v4.2.2` — that is the SLSA-recommended form.

## Plugin SDK (P3-007) supply-chain risk

The plugin SDK ships under `crates/sx-plugins/` and lets customers
extend SentinelX with detection, enrichment, and webhook handlers
written against a stable trait set. Because plugins execute against
customer data, the SDK is treated as a high-value supply-chain surface.

### Trust model

- Plugins are loaded as **WebAssembly (WASM)** modules, never as
  native Rust dynamic libraries.
- The WASM runtime (`wasmtime`) is configured with a deny-by-default
  capability set; the host exposes a constrained surface of helper
  functions (`http_get`, `kv_get`, `kv_set`, `log_emit`,
  `audit_emit`) each gated on a capability granted at plugin install
  time.
- Plugins are signed with cosign at upload time; the host verifies the
  signature **and** the capability manifest before activation.
- HMAC-signed webhooks: any plugin-emitted webhook carries a per-tenant
  HMAC the receiver verifies in constant time.

### Capability manifest review

Every plugin ships a `plugin.toml` declaring the host functions it
needs. Review checklist for new plugins (mandatory before approval):

- [ ] The plugin's source repository is published and tagged at the
      version being submitted.
- [ ] The plugin's WASM module is reproducibly built (`scripts/plugins/verify-build.sh`
      passes).
- [ ] The capability set in `plugin.toml` matches the declared use case
      — no `http_get` for plugins that only enrich audit records.
- [ ] No capability requests use the `unsafe-host` family without a
      written security exception.
- [ ] The plugin's webhook receivers (if any) are HMAC-verified using
      the host's per-tenant secret, not a plugin-embedded constant.
- [ ] The plugin author has signed the Plugin Code of Conduct
      (covers PII handling, telemetry boundaries, vulnerability
      disclosure).

### Plugin operational hardening

- The WASM runtime sets `wasmtime::Engine::config().consume_fuel(true)`
  with a per-call fuel budget; runaway plugins are aborted at the
  budget.
- A failing plugin is **quarantined** after three consecutive errors —
  it stops receiving traffic until an operator clears the quarantine.
- All host-function calls are recorded as audit rows (`action =
  plugin.host_call`) so post-hoc forensics can reconstruct what the
  plugin saw and did.

## Runtime supply-chain (P2-016 Falco)

The Falco DaemonSet is itself a piece of supply chain — a compromised
Falco image or rule set would silently break detection. The mitigations
are layered on top of the same cosign + SBOM pipeline used for the
SentinelX images themselves:

- Falco upstream image is mirrored to `ghcr.io/sentinelx/falco-mirror`
  on tag and re-signed by our workflow OIDC identity. Cluster policy
  rejects `falcosecurity/falco` direct pulls in favour of the mirror.
- The SentinelX rule file
  (`deploy/falco/rules/sentinelx_runtime_rules.yaml`) is validated by
  `falcoctl rules validate` in CI and additionally **shadow-tested**
  against the OCSF normaliser in `crates/sx-runtime` so a malformed
  rule cannot ship.
- Webhook authentication is HMAC-SHA256 with per-tenant keys (see
  [`../operations/runtime-security.md`](../operations/runtime-security.md#3-hmac-sha256-verification-flow)).
  A compromised Falcosidekick cannot inject events into another
  tenant's pipeline.
- Falco rule reload is hot — no DaemonSet roll — so a "bad rule"
  rollback completes within ~10 s. The `rules_reload_failed` metric
  paging threshold is ≥ 1 over 5 min.

## Incident response

If `cosign verify` fails on a production image:

1. **Stop the rollout.** Do not promote the image past the cluster boundary
   it was caught at.
2. Page `@sentinelx/security`. Open an incident in the runbook
   (`docs/operations/runbook.md`).
3. Pull the Rekor entry for the suspect digest:
   ```bash
   rekor-cli search --sha <image-digest>
   ```
4. Compare the entry's `subject` claims against the expected workflow
   identity. A mismatch implies registry tampering or a credential leak.
5. Revoke `GITHUB_TOKEN` scopes on the repo, rotate any external secrets,
   and follow the standard rollback path in the runbook.

If Trivy starts failing on a CVE we cannot patch immediately:

1. File a tracking issue tagged `security`.
2. If the CVE is genuinely not exploitable in our context, add an entry to
   `.trivyignore` with the justification + 90-day re-review date.
3. If exploitable, hotfix the dependency or revert the offending change. Do
   **not** suppress without justification.
