# ADR 0019 — Evidence bundle WORM lock: S3 Object Lock Compliance mode + 7-year retention + HMAC-SHA256 signed manifests

Status: Accepted
Date: 2026-06-12
Deciders: CISO, Principal Security Engineer, Principal Data Engineer, Compliance Lead
Supersedes: None
Superseded by: None

## Context

P1-004 ships the automated compliance evidence collector. Output is
a **bundle**: a ZIP archive of evidence files (config snapshots,
signed audit excerpts, screenshots, policy artefacts) plus a
manifest. The bundle is the artefact handed to a SOC 2 / ISO 27001
/ PCI DSS auditor.

The auditor needs to trust that:

- the bundle is **unchanged** since it was produced;
- no one — not the customer, not SentinelX, not a cloud
  administrator — could have rewritten any file inside it after
  the fact;
- the retention is at least the compliance framework's minimum
  (7 years for SOC 2; we adopt 7 years as the platform default
  for every framework).

The evidence bundle is the worst-case forensic artefact: if a
customer claims a control was effective at time T, the bundle
proves it.

## Decision

### Object Lock: Compliance mode, 7-year retention

Bundles land in the `sx-evidence-<region>` S3 bucket with:

- **Versioning** enabled (mandatory for Object Lock).
- **Object Lock** enabled bucket-wide.
- **Compliance mode** (not Governance mode). Compliance mode
  refuses overwrite / delete even from the root account; Governance
  mode allows root override with the right IAM policy.
- **Retention period** of 2,557 days (7 years) on every object.
- **Cross-region replication** to a second region (separate AWS
  account boundary) for DR.

Compliance mode is irreversible: once enabled on a bucket, it
cannot be disabled. We make this choice deliberately. The cost is
operational: a misconfigured upload (wrong key, wrong tenant, wrong
file) cannot be deleted for 7 years. We accept the cost because
the alternative — Governance mode with operator override — defeats
the trust property the bundle is trying to establish.

### Bundle structure

A bundle is a ZIP archive:

```
<run_id>/
├── manifest.json              # signed bundle manifest (see below)
├── manifest.sig               # HMAC-SHA256 of manifest.json under bundle-signing key
├── controls/
│   ├── SX-AC-01.json          # one JSON file per evidence control
│   ├── SX-AC-02.json
│   └── ...
├── audit/
│   └── chain-tip.json         # HMAC chain tip at bundle time
└── meta/
    ├── tenant.json            # tenant id, name, region
    ├── operator.json          # operator who triggered the run
    └── trace.json             # trace id chain for the bundle's collection
```

Every file inside the ZIP has a recorded SHA-256 in the manifest.

### `manifest.json` shape

```json
{
  "schema_version": 1,
  "bundle_id": "<uuid>",
  "tenant_id": "<uuid>",
  "run_id": "<uuid>",
  "framework": "SOC2",
  "produced_at": "2026-06-14T09:12:34Z",
  "produced_by": "<operator-principal>",
  "files": [
    {
      "path": "controls/SX-AC-01.json",
      "sha256": "<hex>",
      "byte_len": 4823,
      "collected_at": "2026-06-14T09:11:01Z"
    },
    ...
  ],
  "bundle_sha256": "<hex>",
  "signing_key_id": "<vault-key-id>",
  "audit_chain_tip": "<base64 chain tip>",
  "audit_chain_anchor_run_id": "<uuid>"
}
```

`bundle_sha256` is the SHA-256 of the whole ZIP **excluding**
`manifest.json` and `manifest.sig` (so the manifest can be added
last and still match the digest). The auditor can re-derive
`bundle_sha256` by hashing the ZIP minus those two files.

### Signed manifest (HMAC-SHA256)

The manifest is signed with HMAC-SHA-256 keyed by a **bundle-
signing key** held in the per-tenant Vault. The bundle-signing key
is distinct from the audit-chain HMAC key — compromise of one does
not allow forgery of the other.

`manifest.sig` is the raw HMAC bytes; the auditor verifies via:

```bash
openssl dgst -sha256 -hmac "$(vault read -field=key …)" \
    < manifest.json | xxd -r -p | cmp - manifest.sig
```

The key id (`signing_key_id`) is recorded inside the manifest so a
verifier can identify which key version was used (keys rotate every
90 days; old keys are retained for 7 years for verification).

### Audit-chain pinning

The manifest carries:

- `audit_chain_tip` — the `audit_event` chain tip at bundle time;
- `audit_chain_anchor_run_id` — the most recent `audit_anchor_runs`
  row (RDBMS §4.49) that covers the chain at that tip.

The auditor can:

1. Verify the manifest's HMAC.
2. Walk the chain tip back through the audit log entries in the
   bundle.
3. Verify the chain tip is the same one that the TSA-anchored
   `audit_anchor_runs` row attested to.

A bundle's audit-chain claim is therefore as strong as the RFC
3161 anchor (ADR 0008).

### Storage path + RDBMS mapping

- `bundle_key` lands in
  `s3://sx-evidence-<region>/tenant/<tid>/bundles/<run_id>.zip`
  with the per-object retention.
- The same key is recorded in `compliance_evidence_runs.bundle_key`
  (RDBMS §4.41).
- Each per-control file is also written individually at
  `s3://sx-evidence-<region>/tenant/<tid>/runs/<run_id>/files/<control_id>.json`
  and recorded in `compliance_evidence_files` (RDBMS §4.42). The
  individual files exist so an auditor who wants one specific
  control's evidence doesn't have to download the whole bundle.

### Bundle replay

A bundle, once written, cannot be modified. A re-run of the same
control set produces a **new** bundle with a new `run_id` and a
new key. The old bundle stays in S3 for the full retention period.
This matches the auditor expectation that historical evidence
"as of date X" is preserved verbatim.

## Consequences

- **Tamper-proof by construction.** Object Lock Compliance + HMAC
  manifest signing + audit-chain pinning are three independent
  defences; defeating any one of them is insufficient to forge a
  bundle.
- **No "oops, delete that".** A misconfigured upload is permanent
  for 7 years. We mitigate via pre-write validation (manifest
  shape, file digests, tenant-id match) and via the rule that
  bundle uploads are always system-initiated, not operator-
  initiated.
- **Cross-region replication.** A region-loss disaster does not
  cost an auditor's bundle.
- **Cost.** S3 Standard pricing × 7 years × ~50 KB / bundle ×
  12 bundles / tenant / year. At 10 k tenants this is ~$60 / year
  in storage; tractable.
- **Auditor experience.** Off-the-shelf verification — `unzip`,
  `sha256sum`, `openssl dgst -hmac`. No SentinelX-specific
  tooling needed at the verifier.
- **DR.** Cross-region replication enabled on the bucket; a
  region outage does not lose bundles. The replica is in a
  separate AWS account boundary to defend against a same-account
  compromise.

## Alternatives Considered

- **Object Lock Governance mode (allow root override).** Rejected
  — the override path is exactly what an attacker with root
  access would target.
- **No Object Lock; rely on application-layer immutability.**
  Rejected — a compromised application path can re-write the
  bundle.
- **Sign with RSA / Ed25519 instead of HMAC.** Considered. HMAC
  is symmetric (only the holder of the key can verify), which
  means the auditor needs to be granted the key or the bundle
  must be verifiable through SentinelX. We accept this trade-off
  because the auditor's verification flow is mediated through the
  bundle-verification CLI we ship; a future revision may add
  Ed25519 signing for offline verification.
- **6-year retention instead of 7.** Rejected — 7 years covers
  the longest required window across our supported frameworks
  (SOC 2 Type II, ISO 27001, PCI DSS, HIPAA).
