# SentinelX Bug Bounty Program + Bridge (P3-010)

> **Last reviewed:** 2026-06-13
> **Maintainer:** Security Engineering Lead (`security@sentinelx.example`)
> **Next review:** 2026-09-13 (quarterly)
> **Status:** Public, accepting submissions
> **Program version:** 3.0.0

This document has two halves:

- **Part A — Researcher-facing policy.** Scope, rewards, safe harbour,
  disclosure timeline. This is the half published at
  `https://sentinelx.example/security/bug-bounty`.
- **Part B — Operator playbook for the bug-bounty bridge (P3-010).**
  Technical architecture of the platform bridge that pulls reports from
  HackerOne + Bugcrowd, deduplicates against existing findings using
  TF-IDF cosine similarity, and pushes severity ≥ HIGH outbound to the
  remediation queue. Internal-only.

---

# Part A — Researcher-facing policy

## A.1 Mission

SentinelX is a defensive-security platform. Vulnerabilities in our own
product directly weaken the security posture of every customer that
depends on us. We operate a paid, public bug bounty program so that
external researchers have a clear, legal, and well-compensated path to
report findings — and so that we hear about issues before adversaries
do.

This program complements (it does **not** replace):

- Internal security review and threat modelling
  ([`threat-model-stride.md`](./threat-model-stride.md)).
- The quarterly internal red-team rotation
  ([`internal-red-team.md`](./internal-red-team.md)).
- Automated supply-chain controls ([`supply-chain.md`](./supply-chain.md)).
- Runtime detection (P2-016 Falco) — see
  [`../operations/runtime-security.md`](../operations/runtime-security.md).

## A.2 Scope

### A.2.1 In scope (assets)

| Asset                              | Type           | Notes                                       |
|------------------------------------|----------------|----------------------------------------------|
| `https://app.sentinelx.example`    | Web dashboard  | Production tenant UI                         |
| `https://api.sentinelx.example`    | REST/JSON API  | Customer-facing API gateway                  |
| `https://auth.sentinelx.example`   | OIDC IdP       | Authentication and token issuance            |
| `https://docs.sentinelx.example`   | Documentation  | Static; XSS reports only                     |
| `https://status.sentinelx.example` | Status page    | Static; subdomain takeover reports only      |
| `ghcr.io/sentinelx/*`              | Container imgs | All published images                         |
| `sentinelx-cli` (latest release)   | Binary         | Cross-platform CLI                           |
| `github.com/sentinelx/*`           | Source repos   | Code-level issues, supply-chain weaknesses   |
| Kubernetes Helm chart `sentinelx`  | Deployment art.| Default values, RBAC, NetworkPolicy          |

Out of scope: pre-release `*.dev.sentinelx.example` (belongs to the
internal red team's playground), third-party SaaS we depend on,
denial-of-service, social engineering, physical attacks, self-XSS
without a delivery path, missing headers without demonstrated impact,
TLS configurations rated below "C" on SSL Labs.

### A.2.2 Test accounts

Researchers must use the dedicated bug-bounty tenant:

- Sign up at `https://app.sentinelx.example/signup?ref=bounty` using an
  email of the form `your-handle+bounty@example.com`.
- The tenant is rate-limited and clearly tagged `bounty-research` in our
  logs (so internal detection won't open an unwarranted IR ticket).
- Do **not** test against tenants you do not own.

## A.3 Reward table

Rewards are paid in USD via bank transfer, PayPal, or — at the
researcher's written request — donated to one of three pre-approved
digital-rights charities.

| Severity   | CVSS v3.1 base | Examples                                                                                          | Reward (USD) |
|------------|----------------|---------------------------------------------------------------------------------------------------|--------------|
| Critical   | 9.0 – 10.0     | Unauthenticated RCE; cross-tenant data read at scale; signature bypass on update channel          | **$15,000**  |
| High       | 7.0 – 8.9      | Authenticated RCE; full account takeover via reset flow; broken tenant isolation on a single tenant| **$5,000**   |
| Medium     | 4.0 – 6.9      | Stored XSS in dashboard; IDOR exposing project metadata; SSRF without secrets impact              | **$1,500**   |
| Low        | 0.1 – 3.9      | Reflected XSS in low-traffic page; CSRF on non-critical setting; verbose error leaking stack trace| **$400**     |
| Informational | 0.0         | Best-practice notes accepted with thanks; not paid                                                | **$0**       |

Modifiers: +25 % exceptional report, +50 % chained submission,
+$1,000 first-of-kind, −50 % late report.

## A.4 Submission

### A.4.1 Channels

Primary submission channels (both feed the same intake queue via the
P3-010 bridge — see Part B):

- **HackerOne:** `https://hackerone.com/sentinelx-bb`
- **Bugcrowd:** `https://bugcrowd.com/sentinelx-bb`

PGP-encrypted email to `security@sentinelx.example` is accepted only if
both platforms are unreachable. Fingerprint:
`7F4A 2C19 9D8E 0B6F 3E11  4A85 9C2D 0F77 1B6A 5E3C`.

Do **not** use public GitHub issues, X/Twitter, or our support chat.

### A.4.2 Required content

A submission is triaged only once it contains:

1. **Title** — one sentence describing the impact.
2. **Affected asset(s)** — URL(s), version, commit hash, image digest.
3. **Vulnerability class** — pick from the in-scope list above.
4. **Severity self-assessment** — CVSS v3.1 vector string + base score.
5. **Reproduction steps** — numbered, copy-pasteable.
6. **Proof of concept** — within the limits in A.4.3.
7. **Impact statement.**
8. **Suggested remediation.**
9. **Researcher identity** — handle, email, payout preference.

### A.4.3 PoC limits

- Use the bounty tenant (A.2.2) or assets you own.
- Stop at minimum necessary: read one record / print `id` / enumerate 5 IDs.
- Do not modify, delete, or persist data on other tenants.
- Do not pivot to internal networks beyond a single DNS resolution proof.
- Include exact UTC timestamps of every interaction.

## A.5 Triage SLA

| Phase                     | Target               | Owner                       |
|---------------------------|----------------------|-----------------------------|
| Initial human response    | 24 h                 | On-call triage analyst      |
| Triage / dedup check      | 72 h                 | Triage analyst              |
| Severity decision         | 72 h                 | Security Engineering Lead   |
| Fix engineering           | Sev-based; see A.5.1 | Owning product team         |
| Re-test by researcher     | 7 d after fix        | Original reporter           |
| Payout                    | 30 d from accept     | Finance + Security Lead     |
| Public disclosure         | See A.7              | Security Lead + Researcher  |

### A.5.1 Remediation SLA by severity

- Critical: hotfix within 7 d, rollout within 14 d.
- High: fix within 30 d.
- Medium: fix within 60 d.
- Low: fix within 90 d or next minor release.

## A.6 Safe harbour

SentinelX commits, for any researcher acting in good faith under this
policy:

1. **No legal action** under CFAA / Computer Misuse Act / § 202c StGB /
   UU ITE for activity that targets only in-scope assets, stays within
   PoC limits, reports through documented channels, and respects the
   disclosure timeline.
2. **DMCA / anti-circumvention waiver** for security research on our
   products.
3. **Account preservation** of bounty-tenant accounts.
4. **Coordinated third-party disclosure** where a finding incidentally
   touches a vendor we depend on.

Good-faith research means: avoid privacy violations, destruction of
data, and interruption of services; only interact with accounts you own
or have explicit permission to access; give us reasonable time to
resolve the issue before disclosing.

## A.7 Coordinated disclosure timeline

Measured from the date we **acknowledge** acceptance:

| Day | Event                                                              |
|-----|--------------------------------------------------------------------|
| 0   | Acceptance acknowledged. Researcher informed of CVSS + reward tier.|
| 1–N | SentinelX engineers fix and roll out per A.5.1.                    |
| N   | Patch generally available.                                         |
| N+7 | SentinelX publishes advisory (CVE + GHSA) crediting the researcher.|
| N+30| Researcher may publish a write-up; we review for sensitive details.|
| 90  | **Hard cap.** Researcher may disclose regardless. We will not retaliate.|

---

# Part B — Operator playbook for the bug-bounty bridge (P3-010)

The bridge lives in `crates/sx-integrations/src/bb/`. It is an outbound
**and** inbound channel between SentinelX and HackerOne + Bugcrowd. Per
tenant per platform, the bridge:

- **Inbound** (P3-010 primary): polls the platform API every 5 min for
  new reports, verifies HMAC-signed webhook calls in constant time,
  deduplicates against existing tenant findings via TF-IDF cosine, and
  promotes new reports into the SentinelX finding store.
- **Outbound:** pushes SentinelX-discovered findings of severity ≥
  HIGH back into the bounty platform as an internal report (so the
  triage timeline aligns and the program can track them).

## B.1 Architecture

```
+---------------------+      +---------------------+      +-------------+
| HackerOne API +     |<---->|  sx-integrations    |<---->|  Bugcrowd   |
| HackerOne webhook   |      |  ::bb               |      |  API +      |
+---------------------+      |                     |      |  webhook    |
                             |  - HMAC verify      |      +-------------+
                             |  - TF-IDF dedup     |
                             |  - Severity gate    |
                             |  - Per-tenant creds |
                             +---------+-----------+
                                       |
                  +--------------------+--------------------+
                  v                                         v
+----------------------------+                +----------------------------+
| findings table (per tenant)|                | audit chain (P1-015 anchor)|
+----------------------------+                +----------------------------+
```

## B.2 Per-tenant per-platform credential storage

Credentials are wrapped under the **tenant KEK** via `sx-secrets`
(P1-005/6/7) and never logged. Schema (`bb.bridge_credentials`):

| Column                | Description                                                       |
|-----------------------|-------------------------------------------------------------------|
| `tenant_id`           | UUID, FK to `tenants`                                             |
| `platform`            | `hackerone | bugcrowd`                                            |
| `api_token_wrapped`   | KEK-wrapped Vault path                                            |
| `webhook_secret_wrapped` | KEK-wrapped HMAC key for inbound verification                  |
| `program_handle`      | Platform-specific program slug                                    |
| `created_at`, `updated_at`, `last_rotated_at` | timestamps                                |

Operator commands:

```bash
# Enable HackerOne bridge for a tenant.
sx-cli bb enable \
  --tenant 11111111-1111-1111-1111-111111111111 \
  --platform hackerone \
  --program-handle sentinelx-bb \
  --api-token-stdin

# Set the webhook secret used by HackerOne to sign outbound calls.
sx-cli bb set-webhook-secret \
  --tenant 11111111-1111-1111-1111-111111111111 \
  --platform hackerone \
  --read-secret

# Show all enabled platforms for a tenant.
sx-cli bb list --tenant 11111111-1111-1111-1111-111111111111

# Disable a platform (existing reports remain; new ones stop flowing).
sx-cli bb disable \
  --tenant 11111111-1111-1111-1111-111111111111 \
  --platform bugcrowd
```

Token rotation is the same operation as enable — the prior token is
zeroised on overwrite. Rotation emits an audit row
`action = bb.credentials_rotated` carrying the KEK version used.

## B.3 Inbound HMAC signature verification

Every webhook is verified **before** the body is parsed:

1. Read `X-SentinelX-Tenant` header (set by our edge proxy after
   resolving the program handle to a tenant).
2. Read the platform's native signature header (HackerOne:
   `X-H1-Signature`; Bugcrowd: `X-Bugcrowd-Signature`).
3. Look up the tenant's webhook secret from `sx-secrets`.
4. Compute the platform-native HMAC (HackerOne: HMAC-SHA256 of raw
   body; Bugcrowd: HMAC-SHA256 of `timestamp || raw_body`).
5. **Constant-time** compare via `subtle::ConstantTimeEq`. A
   mismatch returns HTTP 401 and emits
   `action = bb.webhook_rejected_bad_sig` severity high.
6. For Bugcrowd, additionally reject timestamps outside `[now-5min, now+5min]`.

Metrics:

- `sx_bb_webhook_received_total{platform, outcome}` —
  `outcome ∈ {ok, bad_sig, bad_ts, unknown_tenant}`.
- A bad-sig rate > 5 / min over 10 min pages the security on-call
  (potential brute-force or rotated-secret skew).

## B.4 TF-IDF dedup against existing findings

When a new report passes signature verification, the bridge computes a
TF-IDF vector over its `title + description + steps_to_reproduce`
fields and compares it against every open finding in the tenant.

Implementation summary (`crates/sx-integrations/src/bb/dedup.rs`):

- **Vocabulary**: rolling per-tenant, persisted as `bb.tfidf_vocab`.
  Re-computed weekly via `sx-cli bb dedup rebuild-vocab`.
- **Normalisation**: lowercase, strip punctuation, strip stop-words
  (English + the SentinelX domain stop-words `sentinelx`, `engagement`,
  `tenant`, etc. — see `bb/dedup_stopwords.txt`).
- **Cosine similarity** between the new report's vector and every open
  finding's stored vector.
- **Threshold**: `cosine ≥ 0.85` is treated as a duplicate. The new
  report is linked to the existing finding (`bb.report_links`) and
  closed on the platform with a templated "duplicate of #N" reply.
- **Threshold floor**: `cosine < 0.65` is always a new finding.
- **Grey zone**: `0.65 ≤ cosine < 0.85` is queued for human triage
  (default route: `#sec-bb-triage`).

The 0.85 threshold was calibrated on a corpus of 1200 historical
SentinelX reports; precision at 0.85 is 0.97 with recall 0.92. Tune
with care — `sx-cli bb dedup tune --threshold 0.83` runs the
calibration against the corpus first and refuses to apply if precision
drops below 0.95.

## B.5 Severity floor for outbound push

SentinelX-discovered findings push outbound to the configured bounty
program **only when severity ≥ HIGH**. Rationale:

- Internal MEDIUM/LOW findings are handled in the standard
  vulnerability backlog and do not justify a program report.
- HIGH and CRITICAL are tracked publicly on the program so the
  research community sees the engagement is active and so external
  researchers do not duplicate the work in flight.

Outbound push is idempotent on `finding_id` — re-runs are safe.

## B.6 Operator playbook

### B.6.1 Enable the bridge for a new customer tenant

```bash
TENANT=11111111-1111-1111-1111-111111111111

# 1. Enable HackerOne.
sx-cli bb enable --tenant $TENANT --platform hackerone \
  --program-handle sentinelx-bb --api-token-stdin

# 2. Set the HackerOne webhook secret (same value entered in H1 portal).
sx-cli bb set-webhook-secret --tenant $TENANT --platform hackerone \
  --read-secret

# 3. (Optional) Same for Bugcrowd.
sx-cli bb enable --tenant $TENANT --platform bugcrowd \
  --program-handle sentinelx-bb --api-token-stdin
sx-cli bb set-webhook-secret --tenant $TENANT --platform bugcrowd \
  --read-secret

# 4. Smoke-test: send a synthetic webhook and confirm it lands.
sx-cli bb test-webhook --tenant $TENANT --platform hackerone

# 5. Confirm the inbound metric incremented.
sx-cli metrics show sx_bb_webhook_received_total
```

### B.6.2 Manage reports

```bash
# List inbound reports awaiting triage (cosine in grey zone).
sx-cli bb reports list --tenant $TENANT --status pending-triage

# Inspect dedup details for one report.
sx-cli bb reports show --report-id rep_01J... --include-dedup

# Force the report into a finding (override grey-zone hold).
sx-cli bb reports promote --report-id rep_01J... \
  --severity HIGH \
  --reason "novel chained SSRF — distinct from #FND-2026-0481"

# Force a duplicate link (e.g. cosine = 0.83 but it really is a dup).
sx-cli bb reports link-duplicate \
  --report-id rep_01J... --to-finding FND-2026-0481

# Close a report as informational (no platform reward).
sx-cli bb reports close --report-id rep_01J... --reason informational
```

Every command above emits a signed audit row:

| Command                 | `action`                       |
|-------------------------|--------------------------------|
| `bb enable`             | `bb.bridge_enabled`            |
| `bb set-webhook-secret` | `bb.webhook_secret_rotated`    |
| `bb reports promote`    | `bb.report_promoted`           |
| `bb reports link-duplicate` | `bb.report_linked_duplicate`|
| `bb reports close`      | `bb.report_closed`             |

### B.6.3 When the dedup vocabulary drifts

Symptoms: cosine starts gravitating to 0.0 for novel reports, or
historical duplicates start landing as grey-zone holds. Cause: the
vocabulary has not been refreshed after a wave of new feature areas.

Procedure:

```bash
# 1. Inspect freshness.
sx-cli bb dedup vocab-info --tenant $TENANT

# 2. Rebuild from the last 90 days of findings.
sx-cli bb dedup rebuild-vocab --tenant $TENANT --since 90d

# 3. Re-score every open report against the new vocab.
sx-cli bb dedup rescore --tenant $TENANT --status pending-triage
```

The rebuild is idempotent; existing dedup links are preserved unless
the new cosine drops below 0.65, in which case the link is broken and
the report returns to pending-triage with a notification.

### B.6.4 When HackerOne / Bugcrowd is down

- The poller backs off exponentially (5 min → 1 h → 6 h) and emits
  `bb.poller_backoff` metrics; on six consecutive failures it pages the
  security on-call.
- Webhook calls that arrive during platform-side instability are still
  processed normally — they are independent of the poller.
- The outbound push queue is durable (`bb.outbound_queue` Postgres
  table). Items remain until the platform accepts them.

## B.7 Metrics + alerts

| Metric                                              | Threshold       | Action                                  |
|-----------------------------------------------------|------------------|----------------------------------------|
| `sx_bb_webhook_received_total{outcome="bad_sig"}`   | >5/min × 10 min  | Page security on-call                  |
| `sx_bb_outbound_failures_total`                     | >0 over 30 min   | Slack `#sec-bb-triage`                 |
| `sx_bb_pending_triage_count`                        | >25 sustained 24 h | Slack `#sec-bb-triage`                 |
| `sx_bb_dedup_cosine_p50`                            | <0.10 for 24 h   | Vocab refresh likely needed            |
| `sx_bb_poller_consecutive_failures`                 | ≥6               | Page                                   |

## B.8 Related documents

- [`../operations/runbook.md`](../operations/runbook.md) — credential
  rotation, KEK rotation per provider.
- [`internal-red-team.md`](./internal-red-team.md) — internal red-team
  rotation that produces a parallel finding stream.
- [`threat-model-stride.md`](./threat-model-stride.md) — STRIDE rows
  the public bounty program is most likely to surface.
- [`../compliance/engagement-roe-template.md`](../compliance/engagement-roe-template.md) —
  rules of engagement for *contracted* security testing (distinct from
  the public bounty).
