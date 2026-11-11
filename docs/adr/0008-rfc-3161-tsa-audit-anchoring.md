# ADR 0008 — RFC 3161 TSA audit anchoring: FreeTSA dev / commercial prod, pinned-CA verify, MerkleTreeBuilder, broken-chain SEV path

Status: Accepted
Date: 2026-06-12
Deciders: CISO, Principal Security Engineer, Principal Platform Engineer
Supersedes: None (refines ADR 0005)
Superseded by: None

## Context

ADR 0005 specifies an HMAC-chained `audit_event` with **periodic
external anchoring**. It deliberately leaves the choice of external
anchor to a follow-up ADR; that follow-up is this document.

An external anchor pins the audit chain's tip to a trust root we
do not control, so an attacker who gains DBA on Postgres cannot
silently rewrite history without invalidating an anchor previously
delivered to a third party.

The candidates were:

1. **RFC 3161 Time-Stamping Authority (TSA).** Standardised,
   accepted by every major auditor we've encountered (PwC, KPMG,
   BDO), `genTime` is signed by a CA-issued cert, mature Rust
   parsing libraries (`x509-parser`, `cms`, `rfc3161-rs`).
2. **Public blockchain (Ethereum / Bitcoin).** Strong public
   anchor, no per-anchor cost beyond gas, but per-anchor latency
   (~12 s Ethereum, ~10 min Bitcoin) and the auditor experience is
   poor.
3. **Sigstore Rekor.** Transparency-log style, free, but the trust
   model assumes a Sigstore production deployment which is itself
   a single point of policy.
4. **AWS QLDB / Azure Confidential Ledger.** Vendor-locked, per-
   tenant cost, and the audit story leans on the cloud provider's
   integrity claim.

We need a default that:

- works against an offline / air-gapped customer if needed (an
  on-prem TSA suffices);
- has a free-of-cost dev path so contributors can run the full
  audit pipeline locally;
- emits an artefact (the TSA token) the auditor can verify with
  off-the-shelf tools (`openssl ts -verify`).

## Decision

### Provider choice: FreeTSA in dev, commercial CA-backed TSA in prod

| Environment | TSA provider | Trust root |
|---|---|---|
| `APP_ENV=development` | [FreeTSA.org](https://freetsa.org) | FreeTSA root CA, pinned in `config/tsa/freetsa-ca.pem` |
| `APP_ENV=staging` | DigiCert TSA (or operator override) | DigiCert root CA, pinned per-tenant |
| `APP_ENV=production` | DigiCert TSA, Sectigo TSA, or operator override | Per-tenant pinned root CA in `tenant.tsa_root_ca_pem` |

FreeTSA is **forbidden** outside `development` by
`crates/sx-audit/src/anchor/tsa.rs::reject_freetsa_outside_dev`.

Operator-supplied TSA endpoints are configured per-tenant in
`tenant.tsa_url` + `tenant.tsa_root_ca_pem` so a sovereign customer
can pin their own jurisdictional TSA.

### Pinned-CA verification (no system trust store)

The TSA response includes a SignedData (CMS / PKCS#7) blob carrying
a `TSTInfo` structure. The verifier:

1. Parses the SignedData with `cms::CmsContentInfo`.
2. Extracts the signer cert chain.
3. Verifies every intermediate's signature up to a **root that
   matches the operator-pinned `tsa_root_ca_pem` byte-for-byte**.
   The system trust store is explicitly **not** consulted.
4. Verifies the `TSTInfo.messageImprint` equals the SHA-256 of the
   Merkle root we submitted.
5. Verifies `TSTInfo.genTime` is within `[now - 5min, now + 30s]`
   skew tolerance.
6. Stores the verified row in `audit_anchor_runs` (RDBMS §4.49) with
   the verbatim TSA reply in `payload_bytes`. The verbatim bytes
   never leave the database — the API exposes only
   `payload_size_bytes`.

Pinned-CA-only verification rejects an attacker who managed to
issue a TSA cert from a CA outside the operator's trust set, even
if that CA chains to a public root.

### Merkle tree construction: `MerkleTreeBuilder`

`MerkleTreeBuilder` walks the `audit_event` rows in
`[audit_seq_from, audit_seq_to]` and computes a SHA-256 Merkle
root over the rows' canonical-CBOR serialisation. Reasons:

- The audit chain is already SHA-256-keyed; reusing the same hash
  primitive keeps the verifier code single-curve.
- A Merkle tree (over a plain rolling hash) lets the auditor verify
  **any single row** in the window with O(log n) proof bytes,
  without needing the full window. This is the property that
  matters when forensics asks "prove row 12345 was sealed before
  09:00".

The Merkle root submitted to the TSA is the **root of the tree**;
the per-row Merkle proofs are kept in S3 alongside the TSA token
under `sx-audit-anchor-<region>/tenant/<tid>/proofs/<run_id>.cbor`.

### Broken-chain SEV path

A *broken chain* is detected when:

- `audit_event.prev_hmac` of row N+1 does not match row N's
  `row_hmac` (in-Postgres tamper);
- the Merkle root computed from current rows differs from a
  previously TSA-anchored root over the same window (post-anchor
  tamper);
- a TSA verification fails after a successful submission (cert-
  rotation drift or replay).

Detection runs in two places:

1. **Hot path:** every audit-event INSERT trigger recomputes the
   `row_hmac` and compares against the prior tip. Failure
   atomically aborts the transaction and emits a `SEV-1` alert.
2. **Periodic verifier:** `crates/sx-audit/bin/verify.rs` runs
   hourly out-of-process, walks every anchored window, and asserts
   the Merkle root + chain still verify.

On either trigger:

- The audit-writer role is **revoked from the application user**
  (`REVOKE INSERT ON audit_event FROM sx_app_role`), forcing every
  state-changing request to fail until the chain is reviewed.
- The kill-switch (ADR 0004) is set globally.
- An incident row is auto-opened in `ir_incidents` (RDBMS §4.56)
  using the `chain_break` playbook id (NIST SP 800-61 Rev 2,
  unauthorised access).
- The customer is notified via the contractual incident channel
  within 1 h per SOC 2 CC7.4.

There is no automatic recovery path. A chain break is by definition
a security incident; the runbook
(`docs/runbooks/audit-chain-break.md`) prescribes manual review by
two engineers + CISO sign-off before the audit-writer role is
re-granted.

## Consequences

- **Auditor-friendly.** The TSA token is `openssl ts -verify`-able
  off-platform; we ship the verification command in the auditor
  bundle.
- **Per-tenant TSA choice.** Sovereign customers can pin their own
  TSA; the cost is the operator must mint the per-tenant
  configuration row.
- **Latency.** TSA submission takes ~200–400 ms on the public
  internet. We submit asynchronously every hour, not on the hot
  write path, so the user-facing latency is unaffected.
- **Storage.** A TSA token is ~3–4 KB; over 12 months at 1 anchor
  per hour per tenant this lands at ~36 MB per tenant per year.
  See RDBMS §4.49 size estimate (~210 GB at 10 k tenants).
- **Fail-closed correctness.** A chain break stops every
  state-changing request until manual review. The operational cost
  is steep but it is the only stance that preserves the audit
  log's primary trust property.

## Alternatives Considered

- **Public blockchain.** Rejected — latency, the auditor
  experience, the gas-price tail risk.
- **Sigstore Rekor.** Rejected — transitive trust on a single
  Sigstore production deployment, not what most enterprise
  auditors want.
- **No external anchor (HMAC chain only).** Rejected — does not
  defend against a DBA who has held the box long enough to rewrite
  history before any auditor sees it.
- **Auto-recovery on chain break (e.g. forking the chain from the
  last known-good row).** Rejected — auto-recovery turns a
  detected tamper into a silent recovery, which defeats the point
  of the chain.
