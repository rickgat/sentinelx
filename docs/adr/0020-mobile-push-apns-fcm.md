# ADR 0020 — Mobile push: ES256 JWT for APNs, OAuth2 service account for FCM, severity ≥ CRITICAL gating

Status: Accepted
Date: 2026-06-12
Deciders: Principal Platform Engineer, Product Lead, Principal Security Engineer
Supersedes: None
Superseded by: None

## Context

The SentinelX mobile companion app receives push notifications for
SOC-relevant events. The app exists so an on-call engineer who is
not at a desk gets a low-latency nudge for a critical alert.

The push pipeline talks to two providers:

- **APNs** (Apple Push Notification service) for iOS / iPadOS /
  macOS.
- **FCM** (Firebase Cloud Messaging) for Android.

The decisions to make:

1. **APNs authentication.** Provider-token (ES256 JWT) vs.
   certificate-based.
2. **FCM authentication.** Legacy server-key (deprecated by Google
   in 2024) vs. OAuth2 service account.
3. **Gating.** Should every event push? Only critical ones? Per-
   tenant configurable?
4. **Payload privacy.** Push providers can read the payload
   in transit; what do we put in it?

## Decision

### APNs: ES256 JWT (provider token)

- We use Apple's "Token-Based Connection to APNs" flow. Each push
  request carries an ES256-signed JWT in the `Authorization`
  header.
- The signing key is a P-256 EC private key held in the per-region
  Vault. Rotation cadence: 180 days.
- The JWT's `iss` claim is the Apple Team ID; `kid` is the key id.
- We refuse to fall back to certificate-based auth — certificates
  expire on schedules we cannot easily integrate into our rotation
  story, and provider tokens are Apple's current-recommended path.

### FCM: OAuth2 service account

- We use Google's recommended HTTP v1 API with OAuth2 access
  tokens minted from a per-region service account.
- The service account's private key (JSON keyfile) is held in
  Vault. Rotation cadence: 90 days, enforced by a CronJob that
  rotates and pushes the new keyfile to the running pods.
- Access tokens are short-lived (1 h). The push worker caches the
  token in memory; on 401 it refreshes once and retries.
- The legacy server-key API is **not** used. It is deprecated by
  Google and authenticates an entire project rather than a service
  account.

### Severity gating: ≥ CRITICAL by default

The push pipeline subscribes to the `audit_event` stream and to
the SOC alert stream. The default policy is:

- Push **only** if `severity == CRITICAL` (i.e. SOC severity 5 or
  OCSF `severity_id = 6`).
- Per-tenant configurable down to `HIGH` (severity 4) or up to
  `CRITICAL` only.
- Per-user opt-out (subscription preferences in-app).

Rationale: an on-call engineer's phone vibrating for a `MEDIUM`
event is alert fatigue. The on-call rota expects the phone to
buzz only when it matters; that's the contract.

A critical-only default also means the per-user notification volume
is small (single-digit per day for a healthy tenant), which keeps
the push provider quotas well under any rate limit.

### Payload privacy

The push payload contains:

- a notification id (UUIDv7);
- a tenant id;
- a coarse `category` ("incident", "alert");
- a localised title and short body;
- no PII, no secrets, no IoC values, no asset identifiers.

The full event content is fetched by the app over an authenticated
HTTPS call to the platform after the user opens the notification.
The push providers (APNs, FCM) see only the coarse envelope; they
cannot reconstruct the underlying event from the payload.

Push payloads are *not* encrypted beyond the TLS transport; we
considered shipping an end-to-end encrypted payload (per-device
key, derived at device registration) but rejected it for the MVP
because:

- the payload contains no PII;
- the in-app fetch flow is the canonical event surface;
- E2E push encryption is a meaningful engineering effort with
  thin marginal benefit at the current threat model.

A future ADR may revisit E2E push encryption for tenants with the
strictest threat model.

### Device registration

Each device registers with the platform via
`POST /v1/mobile/devices`:

```json
{
  "platform": "ios" | "android",
  "device_token": "<APNs or FCM token>",
  "user_id": "<uuid>",
  "tenant_id": "<uuid>",
  "app_version": "1.4.2"
}
```

Tokens are rotated by the OS (iOS rotates ~once per week, Android
similar). A 410 Gone response from the provider on push marks the
device as stale and triggers a re-registration prompt on next app
open.

### Failure handling

- 200 / 200 OK from the provider → success.
- 410 Gone → device token retired (write to `device_status`
  table; remove from active subscription set).
- 429 / 5xx → retry with jittered exponential backoff, up to 3
  attempts; then drop the push and log a counter.
- Persistent 4xx (other than 410) → log to the SOC stream as a
  push-pipeline degraded signal.

Quotas:

- APNs allows ~600 pushes / second per connection. We hold a
  connection pool of 8 per worker; ample headroom.
- FCM HTTP v1 allows 600 RPS per project default. Same headroom.

## Consequences

- **Modern auth on both providers.** No deprecated server keys,
  no certificate-rotation surprises.
- **Critical-only push by default.** Alert fatigue is minimised;
  per-tenant override exists for teams that want a wider net.
- **Push providers see only an envelope.** PII is not in the
  payload.
- **Per-region keys.** APNs and FCM credentials are held in the
  per-region Vault; a single-region compromise does not yield
  cross-region push capability.
- **Cost.** APNs and FCM are free for our volume; the engineering
  cost is the token-rotation CronJobs + the in-app deep-link
  registration flow.

## Alternatives Considered

- **Certificate-based APNs.** Rejected — rotation is operationally
  worse than provider tokens.
- **FCM legacy server keys.** Rejected — deprecated by Google;
  authenticates the whole project, not a service account.
- **Push every event.** Rejected — alert fatigue, push provider
  quotas, no on-call ergonomics.
- **SMS / Voice fallback.** Considered for tier-1 customers;
  out of scope for this ADR and tracked separately (would land
  via Twilio with its own threat model and key-rotation story).
- **End-to-end encrypted push payloads.** Considered, deferred —
  the payload contains no PII so the marginal benefit is small;
  revisit for the strictest-tier customers.
- **WebPush for the browser console.** Tracked separately; the
  decisions in this ADR are mobile-only.
