# SentinelX SBOM — Supply Chain Inventory

Generated **2026-08-04** via `syft` v1.50.0 + vulnerability-attributed via `grype` v0.116.1.

## Files

| File | Format | Size | Purpose |
|---|---|---:|---|
| `sentinelx.spdx.json` | SPDX 2.3 JSON | 4.3 MB | ISO/IEC 5962:2021 standard SBOM. Feed to enterprise SBOM tools + customer disclosures. |
| `sentinelx.cdx.json` | CycloneDX 1.6 | 2.4 MB | OWASP-native SBOM. Feed to Dependency-Track, Snyk, etc. |
| `sentinelx.syft.json` | Syft native | 3.1 MB | Complete syft output with source-location metadata for auditors. |
| `sentinelx-vulns.json` | Grype JSON | 5.6 KB | Vulnerability findings against the SBOM. **Currently: 0 findings.** |

## Package inventory

**1852 total packages** across three ecosystems:

| Ecosystem | Count | Notes |
|---|---:|---|
| Rust crates (`pkg:cargo/*`) | **1335** | Workspace + fuzz workspace + build-deps |
| npm (`pkg:npm/*`) | **410** | Next.js dashboard runtime + dev deps |
| GitHub Actions (`pkg:github/*`) | **50** | CI workflow uses |

## Verification

Reproduce this SBOM locally:

```bash
# From repo root
syft scan . \
  --exclude "./target" \
  --exclude "./web/dashboard/.next" \
  --exclude "./web/dashboard/node_modules" \
  --output spdx-json=sbom/sentinelx.spdx.json \
  --output cyclonedx-json=sbom/sentinelx.cdx.json

# Attribute vulnerabilities
grype sbom:sbom/sentinelx.spdx.json --fail-on high
```

## CI integration

`.github/workflows/audit.yml → sbom-and-grype` job runs on every push + PR:

- Generates SBOM (SPDX + CycloneDX) via syft
- Attributes vulnerabilities via grype against NVD + GHSA + RustSec
- **Fails the build on any HIGH or CRITICAL grype finding**
- Uploads SBOM as build artifact (retention: 90 days)
- Publishes grype SARIF to GitHub Code Scanning

For release engineering: attach the artifact SBOM to tagged releases so customers can validate the supply chain independently.

## Coverage relative to cargo audit

Grype attributes advisories from a broader database than cargo-audit:

- **NVD** (CVE) — full NVD feed with kernel-of-truth CVSS
- **GHSA** — GitHub Security Advisories (includes RustSec + npm + PyPI + others)
- **RustSec** — via ghsa-osv-schema mirror

Grype found **4 advisories** that cargo-audit missed on the initial scan (all now fixed):
- `GHSA-h395-gr6q-cpjc` — jsonwebtoken 9.3.1 (type confusion → auth bypass)
- `GHSA-4w2j-m93h-cj5j` — quinn-proto 0.11.14 (remote memory exhaustion)
- `GHSA-7gcf-g7xr-8hxj` — serde_with 3.20.0 (panic on empty entries)
- Plus quinn-proto duplicate from fuzz workspace

All fixed via cargo update + `jsonwebtoken 9 → 10` + `octocrab 0.42 → 0.54`.

## Historical baseline

| Date | SPDX packages | grype findings | Notes |
|---|---:|---:|---|
| 2026-08-04 (initial) | 1892 | 4 (1 High + 3 Medium) | Wave 1 assessment; jsonwebtoken 9.3.1 + quinn-proto 0.11.14 |
| 2026-08-04 (post-remediation) | **1852** | **0** | After bumping jsonwebtoken/quinn-proto/serde_with + octocrab + fuzz-workspace update. Package count dropped 40 due to `cargo machete --fix` removing unused deps. |
