# ADR 0011 — SCIM 2.0 bearer token separation: distinct from user JWT, per-tenant rotation, audit on every mutation

Status: Accepted
Date: 2026-06-12
Deciders: Principal Security Engineer, Principal Platform Engineer
Supersedes: None
Superseded by: None

## Context

P0-005 ships SCIM 2.0 user-provisioning endpoints. SCIM clients
(Okta, Azure AD, OneLogin) authenticate using a long-lived bearer
token they paste into their provisioning console. The token is a
**capability**: anyone holding it can create / update / delete
users in the tenant.

The naive option is to reuse the existing user JWT — mint a "SCIM
admin" user, issue them a JWT, hand the JWT to the SCIM client. We
reject this for three reasons.

## Decision

### A SCIM token is NOT a user JWT

- **No user identity.** SCIM tokens authenticate the **tenant**,
  not a user. There is no `sub` claim, no `roles` claim, no
  expiration tied to a user session. SCIM operations attribute to
  the synthetic actor `scim:<token_name>` rather than a user id.
- **Distinct table.** `scim_tokens` (RDBMS §4.35) is separate from
  any user / session table. The token's plaintext is returned to
  the operator exactly once at mint; only `SHA-256(token)` is
  stored, never the plaintext.
- **Distinct authentication path.** SCIM endpoints
  (`/scim/v2/Users`, `/scim/v2/Groups`) accept *only* SCIM bearer
  tokens. Presenting a user JWT to the SCIM endpoint returns 401.
  Conversely, presenting a SCIM token to any non-SCIM endpoint
  returns 401. The handlers are wired through
  `axum::middleware::from_fn_with_state` with two non-overlapping
  layers.

### Constant-time comparison

The adapter compares incoming bearer tokens against the persisted
`SHA-256(token)` using `subtle::ConstantTimeEq`. A linear scan of
N tokens is wall-clock proportional to N regardless of the matched
row's position; the wall-clock comparison **per row** is
constant-time, so an attacker cannot binary-search the token via
timing.

### Per-tenant rotation

- A token has no expiration. It is revoked only by an explicit
  `DELETE /v1/scim/tokens/{id}`.
- The dashboard surfaces a "last used at" column from
  `scim_tokens.last_used_at`; tokens with `last_used_at IS NULL`
  after 30 days are flagged for revocation.
- Rotation is the standard two-step: mint the new token, configure
  the SCIM client to use it, revoke the old. The dashboard
  guides the operator through this and refuses to leave a tenant
  with zero active SCIM tokens unless the operator explicitly
  acknowledges they are off-boarding the provisioning integration.
- An emergency `revoke_all` endpoint kills every SCIM token in a
  tenant at once. Used during incident response.

### Audit on every mutation

Every SCIM CREATE / REPLACE / DELETE writes one row to `scim_audit`
(RDBMS §4.36):

- `tenant_id`: from the SCIM token's `tenant_id`;
- `scim_user_id`: SCIM `externalId` of the subject (NULL for
  group mutations);
- `action`: one of `create_user`, `replace_user`, `delete_user`,
  `create_group`;
- `payload`: the JSON the SCIM client sent, *minus* sensitive
  sub-attributes (`password`, `recovery_codes`, MFA secrets). The
  strip is performed by `scim_audit::redact_payload` and is unit-
  tested against the SCIM 2.0 attribute schema.
- `ts`: wall-clock at handler entry.

The audit row is committed in the same transaction as the underlying
user mutation. A failed mutation does not write an audit row; a
successful mutation always does.

The dashboard renders `scim_audit` per-token and per-user so an
analyst can answer "which SCIM token created this user".

### Cross-cutting checks

- **Token name length / charset.** Length 1–128 ASCII printable;
  enforced at the API layer and by the CHECK on `name`.
- **One token rotation per minute.** Rate-limited via Redis token
  bucket (key `sx:<tenant>:rl:scim_mint`).
- **No mass-delete without confirmation.** A SCIM DELETE on a user
  that has any audit-event rows in the last 30 days requires a
  `force=true` query param + the audit row records that the force
  flag was used.

## Consequences

- **No JWT-stealing pivot.** Compromising a user JWT does not
  yield SCIM access; compromising a SCIM token does not yield
  user-session access. The two capability domains are disjoint.
- **Operationally simple.** Operators understand "this is the
  SCIM token I paste into Okta", which is a well-understood
  primitive in the enterprise auth world.
- **Auditable.** Every provisioning mutation has a row in
  `scim_audit` with the originating token's metadata + the JSON
  payload. SOC 2 CC6.1 (logical access) and CC7.4 (incident
  response) both lean on this trail.
- **Rotation requires operator action.** No automatic rotation;
  if the operator never rotates the token, it lives forever. The
  dashboard nudges via the "last used at" surface but cannot
  force rotation on a third-party SCIM client.

## Alternatives Considered

- **Reuse user JWT for SCIM.** Rejected — cross-capability
  spillover, expiration semantics don't fit a provisioning client,
  audit attribution would confuse a user action with an
  integration action.
- **Auto-expire SCIM tokens at 90 days.** Considered, rejected for
  v1 — would silently break provisioning integrations the operator
  forgot to rotate. The dashboard nudge + manual revoke is the
  pragmatic alternative.
- **Mint SCIM tokens as scoped JWTs.** Considered — would let us
  encode the tenant in the token signature. Rejected because the
  bearer-token primitive is what every SCIM client speaks
  natively, and a JWT brings JWT-shaped problems (clock skew,
  rotation of the signing key) for no win.
- **Sign every SCIM request with HMAC instead of bearer.**
  Rejected — not in the SCIM 2.0 specification, would not
  inter-operate with off-the-shelf SCIM clients.
