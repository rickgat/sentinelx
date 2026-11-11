# SentinelX — STRIDE Threat Model

> **Status:** living document. **Owner:** Security Architecture WG.
> **Review cadence:** quarterly + on every new trust boundary.
> **Last reviewed:** 2026-06-13 — added §11 P-task → STRIDE coverage and
> §12 residual-risk summary.

This document walks the SentinelX platform through a STRIDE threat model.
For every category (Spoofing, Tampering, Repudiation, Information disclosure,
Denial of service, Elevation of privilege) we enumerate:

1. The trust boundary and assets at risk.
2. Concrete threat scenarios.
3. **Mitigations already implemented** (with a pointer into the codebase).
4. **Residual risk** that survives the current mitigations.
5. **Planned hardening** to close the gap.

## Table of contents

1. [Scope and architectural assumptions](#1-scope-and-architectural-assumptions)
2. [Trust boundaries](#2-trust-boundaries)
3. [Spoofing](#3-spoofing)
4. [Tampering](#4-tampering)
5. [Repudiation](#5-repudiation)
6. [Information disclosure](#6-information-disclosure)
7. [Denial of service](#7-denial-of-service)
8. [Elevation of privilege](#8-elevation-of-privilege)
9. [Cross-cutting controls](#9-cross-cutting-controls)
10. [Open issues and follow-up tickets](#10-open-issues-and-follow-up-tickets)

---

## 0. How to read this document

This is a STRIDE walkthrough — not a generic security checklist. STRIDE
is structured as a per-asset, per-trust-boundary enumeration. For each
of the six categories (Spoofing, Tampering, Repudiation, Information
disclosure, Denial of service, Elevation of privilege) you will find:

1. A short scope statement naming the boundary and the asset class.
2. A numbered table whose rows are individual threat scenarios.
3. The current state of mitigations, with **a code pointer for each
   claim** so the model stays auditable.
4. A residual-risk column that names what survives the mitigation.
5. A planned-hardening column that names the next step.

Empty cells are honest: an empty "Planned" column means we have
deliberately accepted the residual risk for this revision. An empty
"Mitigation" column means we have not yet shipped anything and the
risk is open.

This document is **not** a runbook. Operational responses to specific
fired detectors live in `docs/runbooks/`. This document is also **not**
the supply-chain threat model, which is owned by
[`supply-chain.md`](./supply-chain.md).

---

## 1. Scope and architectural assumptions

SentinelX is a Rust-first, single-tenant-per-row, multi-tenant security
operations platform. The deployment shape under analysis here is the
**Phase 1 monolith** (`services/sx-monolith`) plus its sibling worker
(`services/sx-agent`) and CLI (`services/sx-cli`), driven by an Axum
HTTP gateway (`crates/sx-api`) and a Next.js operator dashboard
(`web/dashboard`).

Out of scope for this revision:

- Phase 2 microservice extraction (separate document).
- Customer-installed on-prem **agent** binaries (covered by the
  `sx-agent` threat model in `docs/security/agent-threat-model.md`).
- Sigstore / supply-chain trust (see [`supply-chain.md`](./supply-chain.md)).

### 1.1 Assets

| Asset | Sensitivity | Location |
|---|---|---|
| Bearer JWTs, refresh tokens | High | Browser local storage, sx-api memory |
| Tenant findings, scan output | High | Postgres `findings`, S3 raw artefacts |
| Audit chain | Critical | Postgres `audit_entries`, HMAC-anchored |
| Engagement scope (in-scope CIDRs) | High | Postgres `engagement_scopes` |
| Scanner credentials, OAuth secrets | Critical | Vault (`sx-secrets`) |
| Tenant-scoped knowledge graph | High | Neo4j, tenant-namespaced |
| Threat-intel feed material | Medium | Redis cache, sx-intel-feeds |
| Operator activity logs | Medium | OTLP exporter -> Tempo / Loki |

### 1.2 Personas

- **Operator** — interactive user of the dashboard.
- **Service account** — non-interactive API client (scoped JWT).
- **Internal worker** — monolith calling itself across module boundaries.
- **Scanner** — sx-agent or in-tree scanner module (sx-discovery, sx-bas).
- **Compromised insider** — privileged but malicious operator (in scope
  for elevation-of-privilege analysis only).
- **External attacker** — unauthenticated, network-adjacent or remote.

---

## 2. Trust boundaries

```
+-------------------+         +-----------------+         +----------------+
|                   |  HTTPS  |                 |  TCP/TLS|                |
|   Browser         +-------->+   sx-api (axum) +-------->+  Postgres      |
|   (dashboard)     |  JWT    |                 |  PG     |  (per-tenant   |
|                   |         |                 |  TLS    |   row-scope)   |
+--------+----------+         +---+----+--------+         +----------------+
         |                        |    |
         |    OIDC redirect       |    |   Redis TLS
         v                        |    +-----------------+
+-------------------+             |                      |
|                   |             |              +-------v--------+
|  External IdP     |<------------+              |                |
|  (Okta / Azure)   |  OIDC                      |  Redis (sx-    |
|                   |                            |   ratelimit,   |
+-------------------+                            |   sx-cache)    |
                                                 +----------------+
                              sx-monolith
                              (composes sx-api + all sx-* crates)
                                          |
                          +---------------+----------------+
                          |               |                |
                          v               v                v
                  +---------------+ +-----------+  +---------------+
                  |  Vault        | |  Scanner  |  |  OTLP / Loki  |
                  |  (sx-secrets) | |  fleet    |  |  Tempo        |
                  +---------------+ +-----------+  +---------------+
```

Each arrow above crosses a trust boundary that this document analyses
under every STRIDE category that applies:

- **B1**: Browser ⇄ Dashboard (Next.js)
- **B2**: Dashboard ⇄ sx-api (Axum)
- **B3**: sx-api ⇄ Postgres
- **B4**: sx-api ⇄ Redis
- **B5**: sx-api ⇄ External IdP (OIDC)
- **B6**: Monolith ⇄ Scanner fleet (sx-agent / in-tree)
- **B7**: Monolith ⇄ Vault
- **B8**: Monolith ⇄ Observability backplane (OTLP, Loki, Tempo)

### 2.1 Trust assumptions per boundary

| Boundary | What we trust | What we do not trust |
|---|---|---|
| B1 | The browser will honour CSP, HSTS, `SameSite` cookie attrs | The endpoint network (assume hostile Wi-Fi) |
| B2 | TLS termination at the edge proxy | Anything downstream of the proxy that lacks mTLS |
| B3 | Postgres process integrity, AppRole identity | Anything in the same VPC that can speak Postgres wire protocol |
| B4 | Redis process integrity, ACL password rotation | Any peer that gets a stale Redis password |
| B5 | The pinned issuer URL + JWKS | The TLS chain alone — we also pin the issuer |
| B6 | The enrolled agent's mTLS cert lineage | The host OS of the agent (assume not airgapped) |
| B7 | Vault root-of-trust signed by an offline CA | Vault's own AppRole binding without IP scope |
| B8 | OTLP collector identity | The lossy nature of UDP-shaped exporters (we use OTLP/HTTP) |

### 2.2 Data flow walkthroughs

Two flows are worth tracing explicitly because every STRIDE row below
references them.

**Flow A — Operator login and first request:**

```
Browser  -- TLS 1.3 -->  Edge proxy  -- HTTP/2 + mTLS -->  sx-api
                                                            |
                          (1) auth_middleware extracts bearer
                          (2) validates via sx-iam::ValidateTokenPort
                          (3) inserts AuthenticatedUser in extensions
                          (4) anti_abuse_middleware (future round)
                          (5) controller dispatches to use case
                                                            |
                                                            v
                          (6) sx-storage executes parametrised SQL
                          (7) sx-audit records the action via
                              RecordAuditEventUseCase
                          (8) view::envelope wraps the response
```

**Flow B — Agent reports a finding:**

```
Agent  -- mTLS + JWT -->  sx-api  -- internal call -->  sx-discovery
                                                            |
                          (1) ValidateTokenPort confirms agent identity
                          (2) Scope check against engagement_scopes
                          (3) sx-storage upserts the finding row
                          (4) sx-audit records FindingCreated
                          (5) sx-risk enriches the row asynchronously
```

Every threat row in §3–§8 names which flow it sits on, so the reader
can correlate the mitigation back to the code that runs at that step.

---

## 3. Spoofing

> An attacker convinces the system they are someone else.

### 3.1 Browser-to-dashboard (B1)

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| S-1.1 | Phishing site impersonates the dashboard | Strict CSP, HSTS preload, branded login URLs | Users still vulnerable to homoglyph domains | Add `expected-domain` browser extension; FIDO2 promotion path |
| S-1.2 | Session-cookie forgery | Cookies are `Secure`, `HttpOnly`, `SameSite=Lax`; CSRF token on state-mutating routes | XSS would still leak the bearer | Migrate session marker into Trusted Types-only origin |
| S-1.3 | OAuth callback spoof (open redirect) | Allow-listed callback URIs; PKCE; state nonce | Compromised IdP could forge a callback | Move to DPoP-bound tokens |

### 3.2 Dashboard-to-sx-api (B2)

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| S-2.1 | Stolen access token replayed by a third party | Short-lived (15 min) tokens; refresh requires session id; `jti` recorded | Until anti-abuse middleware lands, replay within validity window not detected | **`crates/sx-api/src/middleware/anti_abuse.rs` — Replay detector flags duplicate `jti` within 5-minute window** |
| S-2.2 | Anonymous request to authenticated route | `auth_middleware` rejects missing/malformed bearer with 401 (`middleware/auth.rs`) | Allow-list bypass list is static; new public routes need manual review | Generate the bypass list from route attributes |
| S-2.3 | Forged `X-Forwarded-For` to spoof source IP | Reverse proxy at edge (Envoy) strips downstream forwards | Mis-deployed local-only instance honours client header | Document strict deployment checklist; add startup self-check |

### 3.3 sx-api-to-Postgres (B3)

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| S-3.1 | Rogue process connects to Postgres directly | mTLS required by `pg_hba`; CA pinned in `sx-storage` connection builder | Stolen client cert is unbound | Issue short-lived certs via SPIFFE/SPIRE |
| S-3.2 | Row-level spoof (write under another tenant) | Every query parametrised on `tenant_id` from `AccessClaims`; sqlx prepared statements | Application bug that drops the predicate is a single-LOC vulnerability | Postgres RLS policy mirroring app-level filter; integration tests assert RLS |

### 3.4 sx-api-to-Redis (B4)

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| S-4.1 | Anonymous network peer connects to Redis | TLS-only; ACL with rotating password from Vault | Long-lived password if Vault outage prevents rotation | Move to client-cert auth |

### 3.5 sx-api-to-IdP (B5)

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| S-5.1 | Bogus IdP serving signed JWTs | OIDC discovery doc cached + verified against pinned issuer; JWKS rotation tracked | First-touch trust-on-first-use during config rotation | Static JWKS bundle reviewed in-tree |
| S-5.2 | Token substitution (audience confusion) | `aud` and `iss` strict-checked in `sx-iam/jwt_validator` | None at protocol level | Annual audit |

### 3.6 Monolith-to-Scanner (B6)

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| S-6.1 | Rogue agent claims a valid tenant | Mutual mTLS bootstrap; agent enrolment token used once and exchanged for cert | Compromised enrolment token is single-use auth | Hardware attestation (TPM) path |

### 3.7 Monolith-to-Vault (B7)

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| S-7.1 | Process not in the AppRole reads secrets | AppRole + IP-binding; per-secret policy | Single AppRole shared by all monolith pods | Per-pod identity via Kubernetes auth method |

---

## 4. Tampering

> An attacker modifies data in transit or at rest.

### 4.1 Audit chain (critical asset)

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| T-1 | Operator edits a row in `audit_entries` to hide an action | Per-tenant SHA-256 hash chain + HMAC anchor (`sx-audit::chain`); chain verifier endpoint | DBA with raw SQL access can rewrite the chain + recompute hashes if the HMAC key is compromised | HSM-backed HMAC key; external witness (push every Nth digest to a transparency log) |
| T-2 | Replay of a previous entry under a new `seq` | `seq` monotonic per tenant; `prev_hash` chained | None at protocol level | — |
| T-3 | Hash-chain truncation by deleting the tail | Chain verifier reads from genesis to current; missing tail breaks verification | Detection is reactive | Scheduled background verifier (`docs/runbooks/audit-verify.md`) |

### 4.2 Engagement scope mutations

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| T-4 | Attacker widens scope to scan an out-of-bounds CIDR | `ScopeMutated` is an `AuditAction` recorded via `RecordAuditEventUseCase`; mutations require `engagement:write` permission | Audit detects after-the-fact, not before | Pre-flight policy gate that requires 2-of-N approver consent for production scopes |

### 4.3 In-flight tampering

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| T-5 | MITM mutates JSON on the wire | mTLS B2/B3/B4/B7; Browser-side TLS 1.3 + HSTS for B1 | Browser-side TLS-terminating proxy at the user’s endpoint can re-sign | Subresource integrity for dashboard assets; signed responses for high-value endpoints (future work) |

### 4.4 Configuration tampering

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| T-6 | Attacker pushes a config that disables auth | All config is loaded via `sx-config` schema with deny-by-default booleans; `auth.enabled = false` requires explicit override flag at process start | Operator with PR-merge rights can still ship a bad config | GitOps + 2-of-N review for `config/prod.*.toml` |

---

## 5. Repudiation

> A user denies having performed an action.

### 5.1 Operator action repudiation (B1 → B2)

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| R-1 | Operator denies triggering a destructive action (e.g. `kill_switch_triggered`) | Every state-mutating endpoint records an `AuditEntry` with the `Actor` derived from `AuthenticatedUser`; chain anchored via HMAC | Action attribution depends on whoever held the bearer token at the time | Sign critical actions with a per-session WebAuthn assertion captured at action time |

### 5.2 Service-to-service repudiation (B2 → B3, etc.)

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| R-2 | Internal worker denies issuing a destructive SQL statement | All writes go through the storage layer which emits a `tracing::event!(target: "audit", ...)` event; OTLP exporter ships it to Loki | If Loki is down, in-flight events are dropped | Bounded local spill buffer in `sx-telemetry` |
| R-3 | Anti-abuse flag is fired but the operator denies the underlying behaviour | The new `anti_abuse` middleware emits structured audit-shaped events at `target = "abuse"` carrying request-id, redacted IP, UA snapshot, action, severity | Without an explicit user binding, attribution is IP-only for unauthenticated traffic | Pair `anti_abuse` events with the `RequestId` and (when present) `AuthenticatedUser.sub` for full attribution |

### 5.3 Repudiation by silence (the system "didn’t notice")

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| R-4 | Failed auth attempts are not recorded | `LoginFailed` is an explicit `AuditAction` variant; the login flow records it on every wrong-credential attempt | Rate-limited storms can race past the audit sink | Backpressure: drop the request before the password check if the sink is unhealthy |

---

## 6. Information disclosure

> Confidential data is exposed to an unauthorised reader.

### 6.1 Header leakage (B1 ↔ B2)

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| I-1 | `Authorization` header logged into Loki | `middleware/sensitive_headers.rs` marks `Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`, `X-API-Key` sensitive at the tower-http layer | Custom middleware that logs headers manually can still leak | Lint rule that flags `req.headers()` access outside the sensitive-headers allow-list |
| I-2 | Error response body leaks an internal stack trace | `ApiError -> IntoResponse` mapping is total and emits only stable codes + safe messages (`crate::error`) | A handler `Display`-formats a domain error directly | Property test: round-trip every `ApiError` variant and assert no `std::error::Error::source()` chain leaks |

### 6.2 IP / UA leakage in audit (introduced by this round)

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| I-3 | Anti-abuse audit events leak full source IP into Loki | `anti_abuse::redact_ip` reduces IPv4 to `/24` and IPv6 to `/48` before the event is emitted | Operators with raw Loki access can still correlate `/24` with NAT pools | Promote `/24` -> `/28` for high-cardinality traffic; bake the redaction policy into a shared `sx-telemetry` helper |
| I-4 | `User-Agent` leak (fingerprinting) | `anti_abuse::truncate_ua` caps the UA at 120 chars and ellipsises the tail | UA strings are still high-cardinality | Add a UA -> canonical-family mapping (chromium/firefox/curl/…) and emit the family instead of the raw string |

### 6.3 Cross-tenant disclosure (B3)

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| I-5 | Tenant A reads Tenant B’s findings | Every storage query is parametrised on `tenant_id`; integration tests assert cross-tenant denial | App-layer-only enforcement is one bug away from breach | Postgres RLS as a defence-in-depth layer (already in plan; see T-6) |
| I-6 | Cross-tenant cache poisoning | Redis keys are namespaced with `tenant:{id}:` prefix; cache reads validate the prefix | If a developer forgets the prefix, a single key collides across tenants | Typed cache key wrapper (`TenantCacheKey<T>`) that cannot be constructed without a `tenant_id` |

### 6.4 Secrets in environment / process tree (B7)

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| I-7 | Secrets in env vars are visible to ptrace / `/proc` | All secrets fetched at runtime from Vault into the `secrecy::Secret<T>` type which zeroises on drop; never logged via `Display` | Operator with shell access on the pod can ptrace | gVisor / sysbox isolation in production |

### 6.5 Telemetry leakage (B8)

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| I-8 | OTLP span attribute leaks a JWT | `sx-telemetry::redaction` strips known sensitive keys before export | Custom span builders can still attach raw values | Compile-time-enforced span attribute allowlist |

---

## 7. Denial of service

> An attacker degrades or halts the service for legitimate users.

### 7.1 Volumetric (B1 / B2)

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| D-1 | Unauthenticated request flood against `/v1/auth/login` | Per-IP token-bucket rate limiter (`middleware/rate_limit.rs`) configured via `RateLimitConfig` | Distributed attackers from many `/24`s bypass per-IP keying | The new `anti_abuse` rate-anomaly detector raises a high-signal flag when one IP exceeds 3× the rolling median, complementing the hard limiter |
| D-2 | Slowloris / connection holding | Axum / hyper `connection-timeout`, `http2-keep-alive-interval`, `request_body_timeout` tunables | Long-running operator exports may legitimately hold connections | Separate "interactive" and "export" listeners with distinct quotas |

### 7.2 Logical (B2 → app)

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| D-3 | Pathological scan input causes scanner to spin | Scanner timeouts at the supervisor; kill-switch (`KillSwitchTriggered`) halts all running scans | Recovery still requires operator action | Auto-trip the kill switch when global error rate > 5% / 1m (see SLO doc) |

### 7.3 Resource exhaustion (B3 / B4)

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| D-4 | Connection pool exhaustion via slow queries | Postgres pool sized per service; per-query `statement_timeout` | A single tenant can still saturate the pool with legitimate but heavy queries | Per-tenant connection budget in the pool wrapper |
| D-5 | Redis OOM via runaway cache keys | Hard memory limit + LFU eviction; `MAXMEMORY-POLICY` allkeys-lfu | Eviction can drop high-value entries | Per-namespace memory quotas |

### 7.4 Audit pipeline DoS (B8)

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| D-6 | Flood of audit events from a single tenant | `RecordAuditEventUseCase` is single-writer per tenant via internal lock; sink bounded queue | Mass enrolment of malicious tenants could exhaust the global queue | Per-tenant queue with weighted fairness |

---

## 8. Elevation of privilege

> An attacker gains more privilege than they should have.

### 8.1 Vertical escalation (B2)

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| E-1 | Operator with `findings:read` self-promotes to `engagements:write` | Permissions are claim-encoded in the JWT; the gateway validates per-route; permission changes go through `PermissionChanged` audit action | Insider with `permissions:write` is a fully trusted admin role | Quorum requirement for role grants above `editor` |
| E-2 | Token swap (use service-account token from operator session) | Token type is encoded in `AccessClaims.token_type` and validated per-route; bypass list is exact-match | Route author forgets to declare an allowed token type | Default-deny route attribute system |

### 8.2 Horizontal escalation across tenants (B3)

Already analysed under **I-5**. Application-level mitigation is the
sole barrier today; Postgres RLS is the planned defence-in-depth.

### 8.3 Container / host escalation

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| E-3 | Process breaks out of the container | `unshare`, `seccomp` default profile, `--read-only` root FS, non-root UID | Kernel CVE | Quarterly base-image rebase; consider gVisor for scanner workloads |
| E-4 | Compromised dependency runs at startup | All Rust crates pinned with lockfile + `cargo-deny`; image signed | `build.rs` runs unsandboxed | Adopt `cargo-vet` to track third-party trust |

### 8.4 In-app abuse (the focus of this round)

| # | Threat | Mitigation | Residual | Planned |
|---|---|---|---|---|
| E-5 | Attacker harvests JWTs from a compromised SDK and replays them at scale | The new `AntiAbuseLayer.Detector` flags `jti` re-use within 5 minutes (`Replay`) and emits an audit event with severity `high`; pairs naturally with the rate-anomaly and agent-rotation detectors | Detector is observation-only in this round — no automatic mitigation | Wire the detector to the request-id scope so downstream rate-limiter can short-circuit known-bad sessions |
| E-6 | Credential-stuffing botnet rotates UA per request | `AgentRotation` detector flags any IP that produces more than 5 distinct UAs in 10 minutes | UA rotation across many IPs (residential proxies) bypasses the per-IP grouping | Pair UA rotation with TLS-fingerprint diversity once the gateway exposes it |

---

### 8.5 Worked attack walkthrough — replay of a stolen developer JWT

To illustrate how the rows above compose, consider the most realistic
elevation path on the platform today: a developer laptop is
compromised, the attacker grabs the bearer token from session storage,
and replays it from a different network.

1. **What we get for free.** The stolen token's `aud` and `iss` match
   the production issuer, so it passes `auth_middleware` (S-2.2 is not
   triggered). The token has its full TTL (default 15 minutes) ahead
   of it.
2. **What the existing rate limiter does.** The per-key bucket keys
   on `(tenant_id, route)` for authenticated traffic, so attacker
   traffic shares the legitimate operator's bucket. The legitimate
   operator notices "weird" 429s but the attacker is essentially
   invisible (D-1 residual risk).
3. **Where the new detector helps.** The replay detector (E-5) keys on
   the JWT `jti`. The attacker's first call from a new IP reuses the
   `jti` the legitimate operator has already presented — `Replay` fires,
   severity `high`, audit event is emitted. Even though the request
   itself is allowed, the SOC receives a high-signal alert with the
   redacted attacker IP (/24), the truncated attacker UA, and the
   `jti` to revoke.
4. **What still survives.** If the attacker's first action is to
   request a refresh, they will receive a fresh `jti` and the next
   request will not trip `Replay`. This is intentional — refresh-token
   theft is a separate threat (S-1.3) that DPoP-binding is meant to
   address.

### 8.6 Worked attack walkthrough — credential stuffing through residential proxies

A second realistic scenario is credential stuffing through a
residential proxy network that rotates source IPs aggressively.

1. **What we get for free.** Per-IP rate limiting is useless when the
   adversary rotates IPs every request.
2. **Where rate anomaly helps.** Most residential proxies still
   exhibit moderate per-IP burstiness within the rate window (60s).
   The `RateAnomaly` flag fires for any IP that exceeds 3× the rolling
   median across all observed IPs — this captures aggressive proxies
   that haven't yet been allocated more endpoints.
3. **Where UA rotation helps.** Many stuffing tools rotate UAs more
   aggressively than IPs, particularly when the proxy pool is small.
   The `AgentRotation` flag captures any IP that shows >5 distinct UAs
   in a 10-minute window — a very high-precision signal.
4. **What still survives.** A skilled attacker who rotates *both* UA
   and IP per request (e.g. each request through a different residential
   exit) bypasses all three current detectors. The Phase 2 plan to
   join TLS-fingerprint diversity (E-6) is meant to close this.

---

## 9. Cross-cutting controls

### 9.1 Anti-abuse middleware (this round)

The middleware lives at `crates/sx-api/src/middleware/anti_abuse.rs`.
It is **observation only** in this round: it emits audit-shaped tracing
events but does not refuse any request. The audit pipeline consumes
events at `target = "abuse"` and routes them into the standard audit
chain via `sx-audit::RecordAuditEventUseCase`.

Three detectors live behind one configuration surface
(`AntiAbuseConfig`):

| Detector | Default threshold | Audit `action` | Severity |
|---|---|---|---|
| Replay | same `jti` within 5 min | `replay` | `high` |
| Rate anomaly | > 3× rolling median over 60 s, min 4 samples | `rate_anomaly` | `medium` |
| Agent rotation | > 5 distinct UAs per IP over 10 min | `agent_rotation` | `medium` |

Every flag emits a single audit event with the following fields:

```text
target      = "abuse"
audit       = true
action      = <replay | rate_anomaly | agent_rotation>
severity    = <low | medium | high>
ip_prefix   = "<IPv4-/24>" or "<IPv6-/48>"
user_agent  = <truncated UA, <=120 chars>
jti         = <jti or "">
request_id  = <request id or "">
```

IP redaction is enforced inside the middleware so even a misconfigured
log shipper cannot expose the full address.

### 9.2 Audit chain

The audit chain (`crates/sx-audit/src/chain.rs`) is the platform-level
defence against repudiation, tamper, and forensic loss. Every domain
crate that touches mutating state must funnel through
`RecordAuditEventUseCase`. The action enum is `#[non_exhaustive]` so
new variants can be added without breaking existing chain replay.

### 9.3 Sensitive-header redaction

`crates/sx-api/src/middleware/sensitive_headers.rs` marks the following
headers sensitive on both directions: `Authorization`, `Cookie`,
`Set-Cookie`, `Proxy-Authorization`, `X-API-Key`. Marking is enforced
at the tower-http layer, before the trace span is opened.

### 9.4 Error envelope

`ApiError -> IntoResponse` (`crates/sx-api/src/error.rs`) maps every
internal error to a stable code + safe message. Internal error text
is never returned to clients. A request id is always included so an
operator can correlate the public envelope with private logs.

### 9.5 Configuration safety

All config loads through `sx-config`, which:

- Refuses to start if a deny-by-default boolean is missing.
- Enforces typed schemas (no stringly-typed env access — `clippy.toml`
  bans direct `std::env::var`).
- Logs the source of every value (file vs env vs default) at boot.

### 9.6 Layered defence summary

The picture below shows where each defence layer is enforced relative
to the request lifecycle. Reading left-to-right is reading the path of
a single request from the moment it lands at the edge:

```
[ edge proxy ]
   |  TLS termination, IP reputation
   v
[ sensitive_headers middleware ]
   |  flag Authorization/Cookie/etc. before any logger touches them
   v
[ request_id middleware ]
   |  attach correlation id, echo onto response
   v
[ trace middleware ]
   |  open tracing span; only safe attributes attached
   v
[ cors middleware ]
   |  reject pre-flights from non-allowed origins (never "*")
   v
[ rate_limit middleware ]
   |  hard 429 cut-off per (tenant, route) or per IP
   v
[ auth middleware ]
   |  reject 401 if bearer is missing/invalid; insert AuthenticatedUser
   v
[ anti_abuse middleware ]   (exposed but not yet wired this round)
   |  observation-only audit emission on replay / rate anomaly / UA rot
   v
[ controller -> use case ]
   |  parameterised storage calls (tenant_id always pinned)
   v
[ audit chain ]
   |  every mutation funnels through RecordAuditEventUseCase
   v
[ view envelope ]
   |  shape response, never leak internal error text
```

Each layer is **independently** valuable: removing any one of them
still leaves a defensible posture. This is the property STRIDE calls
"defence in depth" and is why the planned hardening column above
focuses on adding new layers rather than reinforcing existing ones.

### 9.7 Forbidden constructs

Workspace-wide: `#![forbid(unsafe_code)]` in every crate under
analysis; CI gate runs `cargo clippy --all-targets -- -D warnings` and
`cargo-deny`. The HTTP gateway additionally bans `.unwrap()`,
`.expect()`, and `panic!()` in non-test code via the workspace lint
profile.

---

## 10. Open issues and follow-up tickets

| Ref | Title | Owner | ETA |
|---|---|---|---|
| SEC-001 | Postgres RLS as defence-in-depth for tenant scope (I-5) | Storage WG | next quarter |
| SEC-002 | DPoP-bound tokens (S-1.3) | IAM WG | Phase 2 |
| SEC-003 | SPIFFE/SPIRE-issued client certs (S-3.1) | Platform | next quarter |
| SEC-004 | External witness for the audit chain (T-1) | Audit WG | Phase 2 |
| SEC-005 | Wire `anti_abuse` middleware into the router with feature flag (E-5) | API WG | next round |
| SEC-006 | TLS-fingerprint join into the agent-rotation detector (E-6) | API WG | Phase 2 |
| SEC-007 | UA canonicalisation map (I-4) | API WG | next round |
| SEC-008 | Per-tenant audit queue with fair scheduling (D-6) | Audit WG | next quarter |
| SEC-009 | Quorum approval for `permissions:write` (E-1) | IAM WG | Phase 2 |
| SEC-010 | Compile-time-enforced span attribute allowlist (I-8) | Telemetry WG | next quarter |

---

## 11. P-task → STRIDE coverage

This section is the *forward* index from the
`docs/SECURITY_GAP_REMEDIATION_TASKS.md` register into the STRIDE
categories above. Each row names a delivered capability and the
specific category it strengthens.

### 11.1 Spoofing

| P-task        | Capability                                                      | STRIDE row(s) reinforced                                          |
|---------------|------------------------------------------------------------------|-------------------------------------------------------------------|
| P0-004 SAML SSO          | Cryptographic assertion validation; pinned IdP issuer       | S-5.1, S-5.2                                                       |
| P0-005 SCIM provisioning | Server-validated user lifecycle; rejects unknown attributes  | S-2.2 (route-author defaults), S-7.1 (principal attribution)        |
| P1-002 WebAuthn          | Phishing-resistant authentication; replay-counter check     | S-1.1 (phishing), S-1.2 (cookie forgery), S-2.1 (token replay)     |
| P1-003 Risk-based auth   | Behavioural step-up; impossible-travel and new-device gates | S-1.1, S-2.1                                                       |
| P2-008 Device trust      | mTLS device cert; refuses non-attested endpoints            | S-2.1, S-2.3                                                       |

### 11.2 Tampering

| P-task        | Capability                                                      | STRIDE row(s) reinforced                                          |
|---------------|------------------------------------------------------------------|-------------------------------------------------------------------|
| P1-015 Hash-chained audit + RFC 3161 TSA anchoring | Chain digest externally anchored every N entries; `BROKEN_CHAIN` CRITICAL | T-1, T-2, T-3 |
| P3-009 Audit replay       | Replays the chain offline against a fresh DB dump            | T-3 (truncation detection)                                         |
| P1-004 Evidence collector | WORM S3 Object Lock COMPLIANCE — even root cannot mutate     | T-3 for evidence bundles, T-6 for configuration freeze             |
| P2-014 K8s admission analyzer | 16 admission rules reject non-conforming workloads        | T-6 (configuration tampering)                                      |

### 11.3 Repudiation

| P-task        | Capability                                                      | STRIDE row(s) reinforced                                          |
|---------------|------------------------------------------------------------------|-------------------------------------------------------------------|
| P1-015 Hash-chained audit log + TSA anchoring | Every action chained + externally anchored               | R-1, R-2, R-3, R-4 (full coverage)                                  |
| P1-002 WebAuthn assertion + P1-003 RBA decision capture | Per-action WebAuthn signature; RBA decision in audit row | R-1 (operator action repudiation)                                  |
| P2-016 Falco runtime events (OCSF) | Process-tree + container identity attached to events            | R-2 (service-to-service repudiation)                               |

### 11.4 Information disclosure

| P-task        | Capability                                                      | STRIDE row(s) reinforced                                          |
|---------------|------------------------------------------------------------------|-------------------------------------------------------------------|
| P2-006 DLP content inspection | 12+ detectors; PAN/PII/secrets blocked inline; plaintext never persisted | I-1, I-3, I-7, I-8 (broad — egress + telemetry + audit)         |
| P1-005 AWS KMS KEK | Per-tenant CMK; auditable rotation                                  | I-7 (secrets-in-env), I-5 (cross-tenant)                            |
| P1-006 GCP Cloud KMS KEK | Same trait, GCP backend                                       | I-7, I-5                                                           |
| P1-007 Azure Key Vault KEK | Same trait, Azure backend                                    | I-7, I-5                                                           |
| Per-tenant Postgres RLS (FORCE)  | RLS as defence-in-depth for tenant scope                 | I-5, I-6                                                           |

### 11.5 Denial of service

| P-task        | Capability                                                      | STRIDE row(s) reinforced                                          |
|---------------|------------------------------------------------------------------|-------------------------------------------------------------------|
| Rate-limiter middleware                          | Per-IP + per-(tenant, route) token-bucket                 | D-1                                                               |
| Kill switch (Redis pub/sub)                       | Halts all running scans within 1 s                        | D-3                                                               |
| Anti-abuse middleware (`anti_abuse.rs`)           | Replay + rate-anomaly + UA-rotation detectors             | D-1                                                               |
| P2-012 (inverse): chaos hardening                 | Engineered fault injection; verifies graceful degradation  | D-1, D-2, D-4, D-5 (all volumetric + resource)                    |
| Audit pipeline backpressure                       | Bounded per-tenant queue                                   | D-6                                                               |

### 11.6 Elevation of privilege

| P-task        | Capability                                                      | STRIDE row(s) reinforced                                          |
|---------------|------------------------------------------------------------------|-------------------------------------------------------------------|
| P2-014 K8s admission analyzer (16 rules)          | Rejects privileged containers, hostPath mounts, missing seccomp, cluster-admin bindings | E-3 (container escape) |
| P2-008 Device trust posture middleware            | Privileged scopes additionally require attested device      | E-1 (vertical escalation)                                          |
| Two-person approvals (engagement + chain + reset) | High-impact actions require independent approver            | E-1, T-6                                                          |
| P2-016 Falco rule 6 (privileged escalation in container) | Detection on cap-gain inside a container             | E-3                                                               |
| Per-tenant Postgres RLS (FORCE)                   | Stops horizontal escalation across tenants                  | I-5 / E-2                                                          |

---

## 12. Residual risk register (post-coverage)

Even with the P-task coverage above, the following residual risks
remain at the time of this review. Each is logged as a backlog ticket
(§13) and revisited at the next quarterly walk.

| #  | Category | Residual                                                                                                   | Mitigation in flight                                   |
|----|----------|------------------------------------------------------------------------------------------------------------|--------------------------------------------------------|
| RR-1 | Spoofing | Homoglyph login domain attacks bypass WebAuthn UX gates                                                    | "expected-domain" browser-extension push (Q3)          |
| RR-2 | Tampering | DBA with raw SQL access could rewrite the chain + recompute HMAC + skip TSA submission for a single epoch | External-witness transparency log (SEC-004)             |
| RR-3 | Repudiation | Bearer tokens still attribute by `sub` only; DPoP-binding deferred                                       | DPoP migration (SEC-002)                                |
| RR-4 | Information disclosure | Operator with shell on the pod can ptrace the process                                                  | gVisor / sysbox for production (SEC-research-2026)      |
| RR-5 | Denial of service | Distributed residential-proxy attacks bypass per-IP rate limit; rate-anomaly detector helps but not fully | TLS-fingerprint join (SEC-006)                          |
| RR-6 | Elevation of privilege | `permissions:write` is single-actor today                                                            | Quorum on role-grant above `editor` (SEC-009)           |
| RR-7 | Information disclosure | WORM evidence bundles older than 7 days are non-deletable; a DPR-erasure for a subject whose ID appeared in an old bundle has only the redaction tombstone available | See DPIA §10.1 and §8.3.1                              |

---

## Appendix A — Mapping STRIDE to code

The intent of this section is to make the model auditable: every "yes"
in the mitigation column above points at concrete code today, not
aspirational design.

| STRIDE row | File |
|---|---|
| S-2.1 (replay) | `crates/sx-api/src/middleware/anti_abuse.rs` |
| S-2.2 (no auth) | `crates/sx-api/src/middleware/auth.rs` |
| T-1, T-2, T-3 (audit chain) | `crates/sx-audit/src/chain.rs`, `crates/sx-audit/src/model/entry.rs` |
| R-1 (operator action) | `crates/sx-audit/src/controller/record_event.rs` |
| R-3 (abuse flag) | `crates/sx-api/src/middleware/anti_abuse.rs` (`emit_audit`) |
| I-1 (sensitive headers) | `crates/sx-api/src/middleware/sensitive_headers.rs` |
| I-2 (error envelope) | `crates/sx-api/src/error.rs`, `crates/sx-api/src/view/envelope.rs` |
| I-3 (IP redaction) | `crates/sx-api/src/middleware/anti_abuse.rs::redact_ip` |
| I-4 (UA truncation) | `crates/sx-api/src/middleware/anti_abuse.rs::truncate_ua` |
| D-1 (rate limit) | `crates/sx-api/src/middleware/rate_limit.rs` |
| D-1 (rate anomaly) | `crates/sx-api/src/middleware/anti_abuse.rs::Detector::observe_rate` |
| E-1 (permissions) | `crates/sx-iam/src/model/claims.rs`, `crates/sx-api/src/extractor/permission.rs` |
| E-5 (replay flag) | `crates/sx-api/src/middleware/anti_abuse.rs` |
| E-6 (UA rotation flag) | `crates/sx-api/src/middleware/anti_abuse.rs::Detector::observe_agent` |

## Appendix B — Re-applying the model

This document should be re-walked:

1. Whenever a new trust boundary is introduced (e.g. a new external
   integration, a split-out microservice, a new client SDK).
2. Whenever a `#[non_exhaustive]` enum at a trust boundary gains a new
   variant (e.g. a new `AuditAction`, a new `ApiError`).
3. Whenever a CVE in a transitive dependency widens an existing threat.
4. Quarterly, even in the absence of the above triggers.

Each re-walk SHOULD produce a diff against this document, reviewed by
at least two members of the Security Architecture WG and merged via
the standard PR flow.
