# Compliance Evidence Collection Runbook (P1-004)

> **Last reviewed:** 2026-06-13
> **Maintainer:** Compliance Engineering (`compliance-eng@sentinelx.example`)
> **Next review:** 2026-09-13 (quarterly)
> **Document owner:** Director of Compliance + Director of Platform Engineering
> **Classification:** Internal — Restricted

This runbook is the canonical procedure for assembling, signing, storing
and exporting evidence bundles for SOC 2, ISO 27001:2022 and PCI DSS 4.0
audits using the **P1-004 automated evidence collector**
(`crates/sx-compliance/src/p1_004/*`).

It is paired with:

- [`docs/compliance/pci-dss-v4-mapping.md`](../compliance/pci-dss-v4-mapping.md)
  — what each PCI control means in SentinelX terms.
- [`docs/compliance/gdpr-pdp-dpia.md`](../compliance/gdpr-pdp-dpia.md) —
  privacy impact assessment + retention implications.
- [`docs/operations/gitops.md`](./gitops.md) — pipeline-level evidence
  (deploy provenance) which is harvested *alongside* the bundles described
  here.

---

## 1. Architecture in one screen

```
+----------------------+        weekly cron          +-----------------------+
| EvidenceCollection-  |<--------------------------- |  per-tenant scheduler |
| Service (sx-compl.)  |                              |  (ControlSchedule)    |
+----------+-----------+                              +-----------------------+
           |
           | EvidenceCollector::collect()
           v
+----------------------+        per-control          +-----------------------+
|  Five built-in       |                              | manifest.json +       |
|  collectors          |----+ ZIP (STORE-only) +---->| HMAC-SHA256 per file  |
+----------------------+    |                        +-----------------------+
                            |
                            | put_immutable() — refuses overwrite
                            v
+-------------------------------------------+
| WORM object store: S3 Object Lock         |
|   - mode = COMPLIANCE                     |
|   - retention = 365*7+2 days (7 years)    |
|   - key prefix = tenant/<tid>/run/<rid>/  |
+-----------------------+-------------------+
                        |
                        | metadata + signed audit row
                        v
+--------------------------+   GRC outbound (P2-009)   +-------------------+
|  Postgres evidence_runs, |--------------------------> | Vanta / Drata /   |
|  evidence_files, audit   |  exp-backoff + retry      | ServiceNow GRC    |
+--------------------------+                            +-------------------+
```

Everything above the WORM line is multi-tenant scoped — every repository
read filters on `tenant_id`; every object key carries the tenant prefix;
the HMAC key is loaded per-tenant from `sx-secrets`. Cross-tenant reads
are rejected explicitly (see `tests/p1_004_tenant_isolation.rs`).

---

## 2. Built-in collectors and their framework mappings

The MVP ships five collectors. Each is a one-shot probe of a live
control and produces a small JSON evidence payload that the bundle
exporter wraps under `manifest.json`.

| Control ID (`ControlId`)              | Probes                                                                                  | SOC 2 (TSC)        | ISO 27001:2022     | PCI DSS 4.0                    | Default cadence |
|---------------------------------------|------------------------------------------------------------------------------------------|--------------------|--------------------|--------------------------------|------------------|
| `SX-MFA-ENROLLMENT-RATE`              | `MfaEnrollmentQuery` over `iam.user` — % users with ≥ 1 WebAuthn factor (P1-002)         | CC6.1, CC6.6       | A.5.16, A.5.17     | 8.4.1, 8.4.2, 8.5.1            | Weekly           |
| `SX-AWS-IAM-PASSWORD-POLICY`          | `IamPasswordPolicyFetcher` — pulled length, history, max-age vs. policy                  | CC6.1              | A.5.17             | 8.3.6, 8.3.9                   | Weekly           |
| `SX-VAULT-SEALED-STATE`               | `VaultStatusProbe::status()` — unsealed = pass; sealed = fail                            | CC6.6, A1.2        | A.8.24             | 3.5.1, 3.6.x                   | Hourly           |
| `SX-KILL-SWITCH-TESTED-RECENTLY`      | `KillSwitchEventReader::last_trip()` ≤ 90 days                                           | CC7.3, A1.2        | A.5.30             | 12.10.1, 12.10.5               | Weekly           |
| `SX-AUDIT-CHAIN-INTEGRITY-VERIFY`     | `ChainVerifyProbe::verify()` — full Merkle walk + TSA anchor cross-check (P1-015)        | CC7.2, CC8.1       | A.8.15             | 10.2.x, 10.3.x, 10.5.x         | Daily            |

`builtin_controls()` in `crates/sx-compliance/src/p1_004/control.rs`
returns the closed set above. Adding a new collector requires:

1. Implement the `EvidenceCollector` trait
   (`fn id(&self) -> ControlId; async fn collect(&self) -> Evidence`).
2. Register it in `builtin_controls()` with the right
   `FrameworkLabel` set (`Soc2 | Iso27001 | PciDss`).
3. Pick a `ControlSchedule { kind: ScheduleKind::{Hourly|Daily|Weekly|Cron(_)} }`.

The framework labels above are wire-encoded as `soc2`, `iso27001`,
`pci_dss` — Vanta / Drata / ServiceNow ingest them verbatim via the GRC
exporter.

---

## 3. Scheduling and run cadence

The scheduler iterates `builtin_controls()` × tenants and emits a job
when `now() >= last_run_at + ControlSchedule::interval`. Jobs are
persisted as `evidence_runs` rows with state machine:

```
queued -> running -> succeeded
                  \-> failed (auto-retry up to 3 times, exp-backoff 30s/2m/10m)
```

Concrete commands:

```bash
# Show the cron the scheduler is using (effective config after env overlay)
sx-cli compliance schedule list --tenant 11111111-1111-1111-1111-111111111111

# Force-run one control out-of-cadence (audit-row signature still applied)
sx-cli compliance collect \
  --tenant 11111111-1111-1111-1111-111111111111 \
  --control SX-AUDIT-CHAIN-INTEGRITY-VERIFY
```

The HTTP equivalents are:

```http
POST /v1/compliance/evidence/collect
GET  /v1/compliance/evidence/bundles?since=2026-01-01T00:00:00Z
GET  /v1/compliance/evidence/bundles/{id}/download
```

DTOs are re-exported via `p1_004::api::{CollectEvidenceRequest,
CollectEvidenceResponse, BundleSummary, ListBundlesResponse,
DownloadBundleResponse}`.

Every successful run emits **exactly one** audit row signed by the
tenant's audit-signing key (`sx-audit::RecordAuditEventUseCase`,
`action = compliance.evidence_collected`). Failed runs emit
`action = compliance.evidence_collection_failed` with the
`P1004CollectError` discriminant attached.

---

## 4. Bundle format

The bundle is a STORE-only ZIP (no compression — byte-deterministic so
snapshot tests pass) with the following layout:

```
bundle.zip
├── manifest.json                # JSON document, see below
├── controls/
│   ├── SX-MFA-ENROLLMENT-RATE.json
│   ├── SX-AWS-IAM-PASSWORD-POLICY.json
│   ├── SX-VAULT-SEALED-STATE.json
│   ├── SX-KILL-SWITCH-TESTED-RECENTLY.json
│   └── SX-AUDIT-CHAIN-INTEGRITY-VERIFY.json
└── audit/
    └── chain-verify-<run-id>.txt    # `sx audit verify` stdout when
                                      # AUDIT-CHAIN-INTEGRITY-VERIFY runs
```

`manifest.json` schema (`BundleManifest` in
`crates/sx-compliance/src/p1_004/bundle.rs`):

```json
{
  "tenant_id": "11111111-1111-1111-1111-111111111111",
  "run_id":    "8c5f...e0",
  "generated_at": "2026-06-13T03:15:00Z",
  "generator": { "name": "sx-compliance", "version": "1.4.0" },
  "frameworks": ["soc2", "iso27001", "pci_dss"],
  "files": [
    {
      "path": "controls/SX-MFA-ENROLLMENT-RATE.json",
      "size_bytes": 481,
      "sha256":     "1f7a...",
      "hmac_sha256":"a3b8...",
      "control_id": "SX-MFA-ENROLLMENT-RATE",
      "collected_at": "2026-06-13T03:14:58Z"
    }
  ],
  "manifest_hmac_sha256": "<hmac over the canonical JSON of all fields above>"
}
```

The `hmac_sha256` per file and `manifest_hmac_sha256` over the manifest
itself both key off the tenant-scoped HMAC key fetched via
`TenantHmacKeyProvider::hmac_key(tenant_id)`. The key never leaves
`sx-secrets`; the bundle exporter receives an opaque
`secrecy::Secret<[u8; 32]>` and zeroises it on drop.

**Verification** by an auditor (offline, no SentinelX access required
beyond the manifest):

```bash
# 1. Verify each file's HMAC matches its bytes.
sx audit-bundle verify ./bundle.zip --hmac-key ./auditor-key.bin

# Exit codes: 0 ok | 2 file HMAC mismatch | 3 manifest HMAC mismatch |
#             4 missing file referenced in manifest | 5 extra file not in manifest.
```

---

## 5. WORM storage (S3 Object Lock, Compliance mode)

The `WormStore` trait (`p1_004::worm`) has a single mutating method,
`put_immutable(key, bytes, content_type, retention_days)`. The
production adapter wraps `aws-sdk-s3` with:

| Parameter                       | Value                                    |
|---------------------------------|------------------------------------------|
| Bucket Versioning               | Enabled                                  |
| Default Object Lock             | Enabled at bucket-creation time          |
| Per-object retention mode       | `COMPLIANCE` (not `GOVERNANCE`)          |
| Retention days                  | `WORM_RETENTION_DAYS = 365*7+2 = 2557`   |
| Legal hold                      | Not set by default                       |
| SSE                             | `aws:kms` with per-tenant CMK            |
| Key prefix                      | `tenant/<tenant-id>/run/<run-id>/`       |

Compliance-mode retention means **even the root account cannot shorten
or delete** an object during the 7-year window — this is the property
that makes the bundles auditor-grade evidence under SOC 2 CC7.2 / ISO
A.8.15 / PCI 10.5.1.

Terraform reference (excerpt — see `infra/terraform/s3-evidence/`):

```hcl
resource "aws_s3_bucket" "evidence" {
  bucket              = "sentinelx-evidence-${var.tenant_short}"
  object_lock_enabled = true
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    default_retention {
      mode  = "COMPLIANCE"
      years = 7
    }
  }
}
```

The Postgres `evidence_files` table holds the key + sha256 + hmac for
every uploaded object, so the WORM bucket is auditable from the
database even if the S3 inventory is unavailable.

---

## 6. GRC outbound push (P2-009)

After a successful run the service hands the `BundleSummary` to the
`sx-integrations::grc` outbound queue, which fans out to whichever
providers the tenant has enabled:

| Provider     | Endpoint                                       | Auth                                                         |
|--------------|------------------------------------------------|--------------------------------------------------------------|
| Vanta        | `POST https://api.vanta.com/v1/integrations/sentinelx/evidence` | OAuth2 client credentials, refresh on 401, token in `sx-secrets` |
| Drata        | `POST https://public-api.drata.com/v1/evidence` | API key (X-Drata-Api-Key), encrypted at rest                 |
| ServiceNow   | `POST https://<instance>.service-now.com/api/now/table/sn_compliance_evidence` | Basic auth + table-level ACL                                  |

Push semantics:

- **Idempotent.** Each request carries `X-SentinelX-Run-Id: <uuid>` so
  the provider can deduplicate on retry.
- **Encrypted tokens.** Provider credentials live in `sx-secrets` and
  are wrapped under the tenant's KEK. Rotation rotates only the wrap —
  the underlying token survives until the provider invalidates it.
- **Exponential backoff retry.** 30 s, 2 m, 10 m, 1 h, 6 h, give up.
  After give-up an `IncidentP2` event is raised for the tenant's GRC
  team.
- **Audit row per attempt.** `action = grc.push_attempted` (success or
  failure) so the auditor can reconstruct delivery from the chain alone.

Operator commands:

```bash
# List configured GRC providers for a tenant.
sx-cli compliance grc list --tenant 11111111-1111-1111-1111-111111111111

# Rotate the Vanta OAuth token (this rewraps under the current KEK).
sx-cli compliance grc rotate-credentials \
  --tenant 11111111-1111-1111-1111-111111111111 \
  --provider vanta

# Re-push a stuck run after fixing a 4xx (e.g. tenant ID typo).
sx-cli compliance grc replay --run-id 8c5f...e0
```

---

## 7. Manual bundle build (auditor-on-site flow)

When an auditor is in the room and needs a bundle for a specific
window, the operator uses the `bundle` wrapper:

```bash
sx-cli compliance bundle \
  --tenant-id 11111111-1111-1111-1111-111111111111 \
  --since 2026-01-01T00:00:00Z \
  --until 2026-04-01T00:00:00Z \
  --framework soc2 \
  --framework iso27001 \
  --framework pci_dss \
  --output ./Q1-2026-evidence.zip
```

The wrapper:

1. Reads `evidence_runs` for the window (read-only — the WORM objects
   are never re-uploaded).
2. Streams the referenced WORM objects through the bundle exporter.
3. Signs `manifest.json` with the tenant's HMAC key.
4. Writes a single audit row `action = compliance.bundle_exported`
   carrying the operator's identity, the framework set, and the SHA-256
   of the produced ZIP.

Hand the ZIP to the auditor along with the auditor verification key
(`sx-cli compliance hmac-public --tenant <id> --output auditor-key.bin`).
The auditor runs `sx audit-bundle verify` (§4) to satisfy themselves
that the manifest is intact.

---

## 8. API endpoints (sx-api)

All endpoints require `permissions: compliance:read` (list, download)
or `compliance:write` (collect) and a valid tenant claim.

```http
POST /v1/compliance/evidence/collect
Content-Type: application/json

{
  "control_ids": ["SX-MFA-ENROLLMENT-RATE", "SX-VAULT-SEALED-STATE"],
  "force": false   // true => ignore last_run_at + schedule
}
```

```http
GET /v1/compliance/evidence/bundles?since=2026-01-01T00:00:00Z&framework=soc2
```

```http
GET /v1/compliance/evidence/bundles/{bundle_id}/download
# 302 redirect to a pre-signed S3 GET URL valid for 5 minutes.
# The S3 GetObject does not bypass Object Lock — it is a read.
```

Errors map onto `ApiError`:

| HTTP | `ApiError` variant          | Cause                                                  |
|------|-----------------------------|--------------------------------------------------------|
| 400  | `ValidationFailed`          | Unknown control ID; framework set empty                |
| 403  | `Forbidden`                 | Permission missing or tenant mismatch                  |
| 404  | `NotFound`                  | Bundle id unknown to this tenant                       |
| 409  | `Conflict`                  | `force=false` and schedule has not elapsed             |
| 503  | `DependencyUnavailable`     | S3 / Vault / Postgres unreachable                       |

---

## 9. Audit-row contract

Every operation listed below emits exactly one signed audit row. The
chain is verifiable end-to-end via `sx audit verify --strict`. Auditors
rely on this contract to map any line in the bundle back to its
provenance row.

| Operation                              | `action`                            | Subject                                |
|----------------------------------------|-------------------------------------|----------------------------------------|
| Scheduler dispatches a collector       | `compliance.evidence_run_started`   | `(tenant_id, control_id, run_id)`      |
| Collector returns evidence             | `compliance.evidence_collected`     | `(run_id, control_id, sha256)`         |
| Collector errors                       | `compliance.evidence_collection_failed` | `(run_id, control_id, error_code)` |
| Bundle exporter writes the ZIP         | `compliance.bundle_exported`        | `(bundle_id, operator_id, frameworks)` |
| WORM upload succeeds                   | `compliance.worm_uploaded`          | `(bundle_id, s3_key, retention_days)`  |
| GRC outbound push attempt              | `grc.push_attempted`                | `(provider, bundle_id, outcome)`       |
| GRC credential rotation                | `grc.credentials_rotated`           | `(provider, kek_version)`              |

---

## 10. Operational notes and failure modes

- **Bundle generation is read-only.** Safe to run on a warm replica.
- **HMAC key rotation** rewraps the key in `sx-secrets`; previously
  signed bundles remain verifiable because the wrap is per-version and
  auditors fetch the verifier key for the era they are validating.
- **A failed collector does not stop the run.** Other collectors
  proceed; the manifest records which controls failed so the gap is
  visible.
- **WORM is non-deletable.** Do not run the collector against
  test data with production credentials — the 7-year retention applies
  to every object you upload.
- **GRC outage handling.** Provider 5xx triggers the exp-backoff queue;
  the manifest is still in S3 and the audit row is still chained, so
  evidence is durable regardless of provider health.
- **Cross-tenant isolation tests** in
  `tests/p1_004_tenant_isolation.rs` MUST be green before any cut to
  the compliance crate is merged. The test suite forbids constructing
  a service that can read across tenants.

---

## 11. Cross-references

- [`docs/security/threat-model-stride.md`](../security/threat-model-stride.md)
  — Tampering and Repudiation rows that this collector mitigates.
- [`docs/operations/runbook.md`](./runbook.md) — boot, RLS verification,
  ClickHouse rebuild.
- [`docs/runbooks/disaster-recovery.md`](../runbooks/disaster-recovery.md) —
  Scenario C (audit-chain tamper) and the WORM evidence used to confirm
  recovery.
- [`docs/compliance/pci-dss-v4-mapping.md`](../compliance/pci-dss-v4-mapping.md)
  — every PCI requirement above maps back to a SentinelX capability.
