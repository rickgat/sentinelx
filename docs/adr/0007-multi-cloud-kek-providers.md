# ADR 0007 — Multi-cloud KEK providers: pluggable trait, encryption-context binding, fail-closed fallback

Status: Accepted
Date: 2026-06-12
Deciders: CISO, Principal Platform Engineer, Principal Security Engineer
Supersedes: None
Superseded by: None

## Context

`sx-secrets` owns the per-tenant Data Encryption Key (DEK) lifecycle
(see RDBMS §4.29.1). Every DEK is wrapped by a Key Encryption Key
(KEK) held in an external Key Management Service so the wrapped form
on disk (`tenant_deks.wrapped`) has no plaintext path back without
an unwrap call.

Customers deploy SentinelX into three cloud profiles plus a self-
hosted sovereign profile:

| Profile | Preferred KMS | Notes |
|---|---|---|
| AWS-native | AWS KMS | per-tenant CMK, AAD via `EncryptionContext` |
| GCP-native | GCP Cloud KMS | per-tenant CryptoKey, AAD via `additional_authenticated_data` |
| Azure-native | Azure Key Vault | per-tenant wrapping key, AAD via `unwrapKey` request body |
| Sovereign | HashiCorp Vault (transit) | self-hosted, on-prem only, AAD via `context` |

Dev / local profile uses a `LocalKekProvider` that wraps with a
keyfile on disk — useful for unit tests, forbidden in production.

Requirements:

- A new KEK provider must be addable **without** touching any caller.
- Every wrap / unwrap call must bind a structured **encryption
  context** (`tenant_id` + `key_id` + `purpose`). The context
  prevents a wrapped DEK from being unwrapped under the wrong
  tenant if a copy of `tenant_deks` leaks.
- The system must **fail closed** when the KMS is unreachable —
  there is no "cached plaintext DEK" fallback.

## Decision

### Pluggable `KekProvider` trait

```rust
#[async_trait]
pub trait KekProvider: Send + Sync {
    fn id(&self) -> &str;                 // 'aws-kms', 'gcp-kms', 'azure-kv', 'vault-transit', 'local'

    async fn generate_dek(
        &self,
        ctx: &EncryptionContext,
    ) -> Result<GeneratedDek, KekError>;  // returns plaintext + wrapped

    async fn unwrap(
        &self,
        wrapped: &[u8],
        ctx: &EncryptionContext,
    ) -> Result<PlaintextDek, KekError>;

    async fn schedule_key_deletion(
        &self,
        kek_id: &str,
        retention_days: u32,
    ) -> Result<(), KekError>;
}
```

`EncryptionContext` is a strict-key map serialised the same way for
every provider:

```rust
pub struct EncryptionContext {
    pub tenant_id: Uuid,
    pub kek_id: String,
    pub purpose: &'static str,  // 'sx-secrets/dek'
}
```

`generate_dek` returns a `GeneratedDek { plaintext, wrapped }`. The
caller drops `plaintext` into a `zeroize::Zeroizing<[u8; 32]>` so
the buffer is wiped at scope exit.

Provider impls live in `crates/sx-secrets/src/kek/*.rs`. The trait
is `Send + Sync` and async-friendly; every provider speaks to its
KMS via `reqwest` or the cloud SDK's gRPC client.

### Encryption-context binding

Every provider MUST pass the structured `EncryptionContext` as the
KMS's AAD primitive:

| Provider | KMS AAD primitive |
|---|---|
| AWS KMS | `EncryptionContext: {tenant_id, kek_id, purpose}` |
| GCP Cloud KMS | `additional_authenticated_data` = CBOR-serialised `EncryptionContext` |
| Azure Key Vault | `unwrapKey` request `additional_authenticated_data` |
| Vault transit | `context` = base64(CBOR(`EncryptionContext`)) |
| `LocalKekProvider` | refuses to instantiate when `APP_ENV=production` |

A provider that cannot bind AAD (rare — only the dev `LocalKek`)
is forbidden in production by
`crates/sx-secrets/src/policy.rs::reject_no_aad_in_prod`, which
runs at adapter construction.

A drift between the calling context and the row's persisted
`(tenant_id, key_id)` aborts the operation with
`KekError::ContextMismatch` before the unwrap is even attempted.

### Fail-closed fallback

When the configured KEK provider is unreachable:

1. The adapter retries 3× with jittered exponential backoff (200ms,
   600ms, 1.4s). Total worst case: ~2.2 s.
2. If all retries fail, the adapter returns
   `KekError::ProviderUnavailable` to the caller. The caller path
   (token-issue, finding-write, audit-write) MUST fail the request
   — there is no plaintext-cache or wrapped-cache fallback. The
   error mapping in the API surface returns HTTP 503 with
   `Retry-After: 5`.
3. A circuit breaker (60 s open window after 5 consecutive
   failures) prevents the API from pummelling a flapping KMS.
4. The breaker open / close transitions emit an audit row to
   `audit_event` with action `kms.breaker.opened` /
   `kms.breaker.closed` so the SOC sees the outage on its own
   pipeline.

**A *secondary* provider for high-availability is explicitly not in
scope.** A secondary KEK would mean two trust roots for the same
wrapped DEK, which (a) doubles the attack surface and (b) requires
the operator to keep the two KMSes synchronised on every
rotation — neither of which is a tradeoff we're willing to make.

The "fallback when the provider is down" answer is therefore: fail
the request, page on-call, restore the primary KMS. We document
this in `docs/runbooks/kms-outage.md` with the corresponding RTO /
RPO numbers.

## Consequences

- **Operational complexity.** Every cloud deployment provisions the
  matching KMS profile. We ship Terraform modules in
  `deploy/terraform/kms-*` so the provisioning is one variable
  away.
- **Per-tenant KEK rotation.** Rotation is a provider-level
  operation (`schedule_key_deletion(old_kek_id, retention_days =
  7)`) + an adapter-level re-wrap that touches every tenant's row.
  Documented in `docs/runbooks/kek-rotation.md`.
- **Provider lock-in is per-deployment, not platform-wide.** An
  AWS-native deployment that switches to GCP can do so by
  re-running the adapter through the trait — every wrapped DEK is
  unwrapped under the old provider, re-wrapped under the new one,
  and written back. Documented as a "rare but possible" exercise.
- **Test discipline.** Every provider has a hermetic test that
  exercises the wrap + unwrap round trip against a recorded cassette
  (no live KMS contact in CI). The cassettes are validated against
  the real KMS once per quarter by a manual run.

## Alternatives Considered

- **Use only Vault transit everywhere.** Rejected — adds an
  operational dependency on Vault for every cloud-native customer,
  and tenants in regulated industries often need their KMS
  certified by their own auditor (HSM-backed AWS KMS or Azure Key
  Vault Premium).
- **In-app wrapping with a master key in env var.** Rejected — the
  master key would be a single point of compromise and would not
  survive an env-var leak.
- **Active-active multi-KMS for HA.** Rejected — see "fail closed"
  rationale above.
- **Per-request KEK derivation from a HKDF over a master.**
  Rejected — moves the trust root into our codebase, defeating the
  point of using a managed KMS.
