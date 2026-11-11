# ADR 0012 — WebAuthn counter monotonicity: strict increment + W3C §7.2 step 21 carve-out for synced passkeys

Status: Accepted
Date: 2026-06-12
Deciders: Principal Security Engineer, Principal Platform Engineer
Supersedes: None
Superseded by: None

## Context

P1-002 ships FIDO2 / WebAuthn as the primary 2FA mechanism (plus the
underlying primitive for password-less sign-in in a later cut).
Every authenticator response carries a 32-bit `signCount` that the
W3C spec says SHOULD strictly increase between assertions from the
same credential. A regression (new counter ≤ old counter) is the
canonical signal of a cloned authenticator — an attacker who
extracted the private key from one device and replayed it from a
second.

The W3C spec ([§7.2 Verifying an Authentication Assertion, step
21](https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion))
gives Relying Parties two compliance levels:

> If `authData.signCount` is `0` and `storedSignCount` is `0`, the
> authenticator does not implement the signature counter. In this
> case, the RP MAY... [either continue or fail].

This carve-out is **load-bearing** for synced passkeys (Apple
iCloud Keychain, Google Password Manager, 1Password) which
deliberately keep `signCount = 0` because the credential is
syncronised across devices and a strict-monotonic counter would
trip on every cross-device assertion.

The naive policy is "reject any non-increasing counter". This
would lock out every iCloud / Google synced passkey user — every
single one of them.

## Decision

### Strict counter monotonicity for hardware authenticators

- `webauthn_credentials.counter` (RDBMS §4.38) stores the
  last-seen counter per credential.
- On every successful assertion, the adapter compares
  `new_counter` against `stored_counter`:

| Stored | New | Action |
|---|---|---|
| `0` | `0` | accept (synced-passkey carve-out, see below) |
| `0` | `> 0` | accept, update to `new` (authenticator was previously synced but is now reporting; switch to strict mode) |
| `> 0` | `> stored` | accept, update to `new` |
| `> 0` | `≤ stored` | **reject, revoke credential, alert** |
| `> 0` | `0` | **reject, revoke credential, alert** (transition from strict to synced is a clone signal) |

The "reject" path:

- Returns HTTP 401 with `WWW-Authenticate: WebAuthn,
  error="webauthn_clone_signal"`.
- Sets `webauthn_credentials.revoked_at = NOW()` so the credential
  cannot be re-used until manually re-enrolled.
- Emits an `audit_event` with action `webauthn.clone_signal` +
  `target_id = credential_id`.
- Triggers the high-severity webhook in the tenant's SOC
  integration (`severity = critical`).
- Opens an `ir_incidents` row using the `credential_clone`
  playbook.

### Synced-passkey carve-out (W3C §7.2 step 21)

When **both** `stored_counter` and `new_counter` are `0`, the
adapter treats the credential as a synced passkey and:

- accepts the assertion;
- does **not** update `counter` (it stays at 0);
- records the assertion in the regular login audit log but does
  **not** treat it as a clone signal.

The carve-out is conditioned on the authenticator's `aaguid`
landing in the **synced-passkey allow-list**:

| Provider | AAGUID |
|---|---|
| Apple Passkeys | `f24a8e70-d0d3-4fe4-bd4f-78a2acba65a7` |
| Google Password Manager | `ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4` |
| 1Password | `bada5566-a7aa-401f-bd96-45619a55120d` |
| iCloud Keychain (multi-platform) | `adce0002-35bc-c60a-648b-0b25f1f05503` |

A credential whose `aaguid` is **not** in the allow-list AND
whose `stored_counter = 0` AND `new_counter = 0` is rejected as a
clone signal — the assumption is that a hardware authenticator that
never increments its counter is malfunctioning or malicious.

The allow-list lives in
`crates/sx-iam/src/webauthn/synced_passkey_aaguids.rs` and is
updated as new providers ship synced-passkey support. The list is
versioned (each entry has a `since_version` field) so the audit log
can prove which list was active at decision time.

### Attestation policy

`webauthn_credentials.attestation` records the attestation level
the credential was registered under:

- `none`: default for synced passkeys (Apple, Google often refuse
  to attest).
- `indirect`: anonymised attestation; most U2F-era YubiKeys.
- `direct`: full AAGUID + cert chain. Required for tenants that
  enable `webauthn_tenant_rp.attestation = 'direct'`.
- `enterprise`: cert chain bound to an enterprise PKI. Used by a
  handful of finance-sector tenants.

A tenant configured for `direct` attestation refuses synced-passkey
registration. We document this in the WebAuthn enrolment runbook —
direct attestation and synced passkeys are mutually exclusive by
design (synced passkeys can't prove device provenance).

### Hardware-only mode

Tenants that operate with sensitive data (finance, classified
deployments) can set `webauthn_tenant_rp.attestation = 'direct'` +
`require_hardware_key = TRUE`. With both set:

- The registration ceremony refuses an authenticator whose
  `aaguid` is in the synced-passkey allow-list.
- The assertion ceremony enforces strict counter monotonicity even
  for `signCount = 0` (no carve-out).
- The dashboard surfaces a "hardware-only mode" badge.

## Consequences

- **iCloud / Google / 1Password users work out of the box.**
  Without the carve-out, the launch would lock these users out
  on day 1.
- **Clone detection still works for hardware keys.** YubiKeys,
  Titan Keys, Feitians, and every other hardware authenticator
  ship a non-zero `signCount` that increments per use; the strict
  monotonicity rule catches their clones.
- **Hardware-only mode is opt-in.** Tenants with the strictest
  threat model can deny synced passkeys at the RP level.
- **The allow-list is a maintenance burden.** New synced-passkey
  providers ship occasionally; we update the list per quarter and
  document this in the WebAuthn runbook.
- **A clone signal is a high-severity event.** It opens an IR
  incident, fires the SOC webhook, and revokes the credential.
  The recovery path is "user re-enrols". We accept the friction;
  the alternative is silent acceptance of a cloned authenticator.

## Alternatives Considered

- **Reject any non-strict-monotone counter (including synced
  passkeys).** Rejected — locks out the largest segment of users
  on day 1.
- **Skip counter checks entirely.** Rejected — defeats the
  primary purpose of WebAuthn's clone-detection design.
- **Per-credential allow / deny opt-in by the user.** Rejected
  for v1 — too much UX surface for a primitive most users will
  never see; the AAGUID allow-list is the operator-level lever.
- **Trust the authenticator's `backupEligible` / `backupState`
  flags instead of the AAGUID allow-list.** Considered — would
  be more provider-agnostic, but the flags ship inconsistently
  across browsers in 2026; the AAGUID list is more reliable in
  the current window.
