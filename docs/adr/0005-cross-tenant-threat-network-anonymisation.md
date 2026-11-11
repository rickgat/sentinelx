# ADR 0005 — Cross-tenant threat-intelligence network: anonymisation and opt-in consent

Status: Accepted
Date: 2026-05-30

## Context

SentinelX customers see attack patterns long before they reach a public
threat-intel feed. A finding observed by customer A at 09:00 frequently
predicts the same finding at customer B at 11:00. Sharing this signal
across the customer base — without sharing identifying information — is
a force-multiplier for detection and a marquee differentiator for the
product.

It is also a high-stakes legal and security primitive. Customers must
know exactly what leaves their tenant, why, and have a one-click way to
turn it off. Any leak of customer-identifying data through this channel
is a contract-ending incident.

## Decision

### Scope of what is shared

Only the following derived facts are shared across tenants:

- **Indicator**: a CVE id, a malware family name from MITRE ATT&CK, an
  ATT&CK technique id, a normalised IoC type (`ipv4_hash`, `domain_hash`,
  `file_sha256`), or the hash of a JA3/JA4 fingerprint.
- **First-seen / last-seen timestamps**, rounded to the nearest 15
  minutes (UTC).
- **Tenant geography bucket** — ISO 3166-1 alpha-2 country code only.
- **Industry bucket** — coarse NAICS-2 code only.
- **Confidence band** — `low`, `medium`, `high`.

The following are **never** shared, even hashed: tenant name, tenant id,
engagement id, asset id, asset identifier (FQDN, IP, URL), user id, raw
finding text, raw evidence artefacts, customer-uploaded files.

### Anonymisation steps

Every share record is built through the `sx-collab::share::pipeline`,
which is the **only** code path allowed to write to the cross-tenant
table. The pipeline:

1. Selects the eligible fields above (allow-list, not deny-list).
2. Hashes IoCs that are not already standardised tokens (IPs, domains,
   filenames) with HMAC-SHA-256 using a per-platform peppered key. The
   pepper is rotated quarterly and old values discarded so historical
   shares cannot be re-identified by future pepper leaks.
3. Bucketises timestamps to 15-minute boundaries and locations to
   country level.
4. Strips every other field via a strict serde structure that does not
   round-trip unknown keys.
5. Writes the record with the contributing-tenant id set to a
   deterministically derived **share id** (HMAC of the tenant id under
   a per-quarter pepper). Consumers see the share id, never the tenant
   id; the share id rotates each quarter so even longitudinal analysis
   cannot link records back to a tenant.
6. Emits an audit-chain entry on the contributing tenant's own audit
   log so they can see exactly what their tenant contributed.

### Consent model

- Cross-tenant sharing is **opt-in per tenant**. The default for new
  tenants is **off**. There is no implicit consent flow.
- Opt-in is a two-step UI gesture: a tenant admin must toggle the
  feature and acknowledge an explainer page that lists the exact fields
  above. The acknowledgment writes a signed consent record to the
  audit chain with the admin's user id and IP.
- Opt-out is one click and takes effect immediately. Historical shares
  are not retroactively deleted (they are already anonymised), but new
  contributions stop atomically and the tenant is removed from the
  contributing-tenants index.
- Consumption of the shared feed is governed by the same toggle: a
  tenant that does not contribute cannot consume. This is a deliberate
  ethical position, not a technical limitation.

### Transport

- HTTPS (TLS 1.3) only, no plaintext channel, no fallback. The
  cross-tenant fan-out service refuses requests below TLS 1.3 and
  pins to the SentinelX platform CA. Customers can verify the pin
  through a published transparency log.
- Per-tenant API tokens are scoped strictly to the cross-tenant
  endpoint and cannot read or write any other tenant resource.

## Consequences

- **Legal review burden.** Each customer contract needs an explicit
  data-sharing rider before the feature is enabled. Sales and Legal
  are aware; the rider is in `legal/cross-tenant-sharing-rider.md`.
- **Operational complexity.** Quarterly pepper rotation requires a
  coordinated key-management workflow; this is documented in
  `docs/operations/runbook.md#cross-tenant-pepper-rotation`.
- **Anonymisation is not undoable.** If a customer demands deletion of
  their contributions, we delete the contributing-tenant index entry,
  but the share records themselves are anonymous by construction and
  cannot be linked back. This is intended; we document it clearly.
- **No alternative to HTTPS.** Air-gapped customers cannot participate
  in cross-tenant sharing. This is a deliberate trade-off: the feature
  requires verifiable transport.
- **Trust signal.** Customers who sign up gain access to detection
  signals weeks before public feeds. The conversion narrative is
  "you opt in, you get a sneak peek; you opt out, you keep the same
  product minus the sneak peek".
