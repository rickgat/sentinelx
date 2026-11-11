# SentinelX Service Level Objectives

Maintainer: Site Reliability Engineering (`#sentinelx-platform`)
Last reviewed: 2026-06-14
Reflects HEAD: `14a04a1`

This document defines what "the platform is healthy" means in
numbers. It is the contract between engineering and the rest of the
company: when we are within budget we ship; when we are out of budget
we stop and fix.

Cross-refs: [FSD.md](FSD.md) for the per-endpoint functional surface,
[ARCHITECTURE.md](ARCHITECTURE.md) for runtime topology,
[onboarding.md](onboarding.md) §6.2 for the OpenAPI 1.1 spec, and
the runbooks under `runbooks/` for incident response.

Owning team: SRE / Platform Engineering.
Review cadence: quarterly, and after every breach.

---

## 1. Conventions

### 1.1 Vocabulary

| Term | Meaning |
|---|---|
| SLI | Service Level Indicator. A measured quantity (a number computed from telemetry). |
| SLO | Service Level Objective. A target value for an SLI. |
| SLA | Service Level Agreement. A contract with a customer. **Not the same as an SLO.** SLAs derive from SLOs. |
| Error budget | The complement of the SLO. If the SLO is 99.9%, the budget is 0.1% (= 43.2 minutes per 30 days). |
| Burn rate | How fast we are consuming the budget. 1× is the steady rate; 14.4× consumes the monthly budget in 2 days. |
| Synthetic | A scripted client that simulates a real user request against a production-like endpoint at a fixed interval. |

### 1.2 Measurement window

All SLOs are measured over a **rolling 30-day window** unless
otherwise specified. The window slides every minute.

### 1.3 Telemetry source

SLIs are computed from Prometheus metrics emitted by `sx-telemetry`.
The exporter labels every request with `route`, `method`, and
`tenant_id` so SLOs can be sliced. Background-job SLIs are computed
from per-job histograms (`sx_job_duration_seconds_bucket`) and freshness
gauges (`sx_feed_last_pull_age_seconds`, `sx_anchor_last_success_age_seconds`).

Dashboard SLIs come from the Next.js RUM tracker plus a synthetic
crawler that opens every sidebar page once a minute.

### 1.4 Per-tenant vs. global

Availability and latency SLOs are evaluated **per tenant** and
**globally**. A breach in any single tenant counts as a breach;
multiple tenant breaches do not multiply. The error budget is a
**global** quantity but is debited proportionally when a single
tenant breaches.

---

## 2. Availability SLOs

### 2.1 Critical surfaces — 99.9%

| Surface | Target | Allowance / 30 days |
|---|---|---|
| `POST /v1/auth/login` | 99.9% | 43.2 min downtime |
| `POST /v1/auth/refresh` | 99.9% | 43.2 min downtime |
| `POST /v1/auth/logout` | 99.9% | 43.2 min downtime |
| `POST /v1/auth/saml/acs` (P0-004) | 99.9% | 43.2 min downtime |
| `POST /v1/safety/kill-switch` | 99.9% | 43.2 min downtime |
| `GET  /v1/safety/kill-switch` | 99.9% | 43.2 min downtime |
| `GET  /openapi.json` | 99.9% | 43.2 min downtime |
| `GET  /v1/audit/anchors` (P1-015) | 99.9% | 43.2 min downtime |

These are the controls customers must be able to trust in an emergency.
The kill switch is the platform's load-bearing safety contract; if
customers cannot reach it, our guarantee is broken. Audit anchoring
is the trust contract for evidence — see §4.

**SLI definition** (availability):

- Success: HTTP 2xx OR HTTP 4xx (client error; not our fault).
- Failure: HTTP 5xx, or no response within the timeout.
- Window: 30 days rolling, per route.

### 2.2 Standard surfaces — 99.5%

| Surface group | Target | Allowance / 30 days |
|---|---|---|
| `/v1/engagements/*` | 99.5% | 3.6 h downtime |
| `/v1/findings/*` | 99.5% | 3.6 h downtime |
| `/v1/assets/*` | 99.5% | 3.6 h downtime |
| `/v1/bas/*` (non-safety) | 99.5% | 3.6 h downtime |
| `/v1/reports/*` | 99.5% | 3.6 h downtime |
| `/v1/compliance/*` | 99.5% | 3.6 h downtime |
| `/v1/admin/*` | 99.5% | 3.6 h downtime |
| `/v1/cloud/*` | 99.5% | 3.6 h downtime |
| `/v1/intel/*` | 99.5% | 3.6 h downtime |
| `/v1/soc/*` | 99.5% | 3.6 h downtime |
| `/v1/ueba/*` | 99.5% | 3.6 h downtime |
| `/v1/device-trust/*` | 99.5% | 3.6 h downtime |
| `/v1/rba/*` | 99.5% | 3.6 h downtime |
| `/v1/hunt/*` | 99.5% | 3.6 h downtime |
| `/v1/ir/*` | 99.5% | 3.6 h downtime |
| `/v1/dlp/*` | 99.5% | 3.6 h downtime |
| `/v1/grc/*` | 99.5% | 3.6 h downtime |
| `/v1/soar/*` | 99.5% | 3.6 h downtime |
| `/v1/plugins/*` | 99.5% | 3.6 h downtime |
| `/v1/integrations/bugbounty/*` | 99.5% | 3.6 h downtime |
| `/v1/notifications/*` | 99.5% | 3.6 h downtime |
| `/v1/autonomy/*` | 99.5% | 3.6 h downtime |
| `/v1/runtime/falco/*` | 99.5% | 3.6 h downtime |
| `/v1/copilot/*` | 99.5% | 3.6 h downtime |
| `/v1/remediation/*` | 99.5% | 3.6 h downtime |

### 2.3 Best-effort surfaces

Some routes intentionally have no SLO:

- `/v1/chaos/config` (operator-only chaos toggle; P2-012).
- Background batch dispatch routes.
- Webhook receivers from third parties (latency depends on caller).

These routes still emit metrics; they just do not page.

---

## 3. Latency SLOs

### 3.1 Read endpoints — p99 < 250 ms

| Method | Routes | Target |
|---|---|---|
| GET | `/v1/engagements/*` | p99 < 250 ms |
| GET | `/v1/findings/*` | p99 < 250 ms |
| GET | `/v1/assets/*` | p99 < 250 ms |
| GET | `/v1/safety/kill-switch` | p99 < 250 ms |
| GET | `/v1/admin/*` | p99 < 250 ms |
| GET | `/v1/audit/*` (search / replay / diff / anchors) | p99 < 500 ms |
| GET | `/v1/soc/alerts` | p99 < 250 ms |

**SLI definition** (latency):

- Measured from the start of axum's handler to the start of the
  response body write.
- Excludes time spent on network egress.
- Window: 30 days rolling, per route.
- Metric: `histogram_quantile(0.99, sum by (le, route)(rate(sx_http_request_duration_seconds_bucket{method="GET"}[5m])))`.

### 3.2 Write endpoints — p99 < 800 ms

| Method | Routes | Target |
|---|---|---|
| POST/PUT/PATCH/DELETE | All `/v1/*` writes EXCEPT report generation, DAST, BAS dispatch, vuln-import | p99 < 800 ms |
| POST | `/v1/safety/kill-switch` (trip) | p99 < 250 ms |
| POST | `/v1/auth/login` | p99 < 400 ms |

The kill-switch trip is held to the read target despite being a write —
the operational use case demands it.

### 3.3 Special cases

| Endpoint | Target |
|---|---|
| `POST /v1/reports/render` (synchronous form) | p99 < 30 s |
| `POST /v1/reports/diff` (P2-003) | p99 < 5 s |
| `POST /v1/bas/run` | p99 < 1 s |
| `POST /v1/bas/chains/{id}/run` (P2-015) | p99 < 2 s |
| `POST /v1/discovery/dast/scan` (P2-013) | p99 < N min for N requests, where N is the request count in the OpenAPI schema (default 5 ms / request, capped at 60 min) |
| `POST /v1/vuln/import` (P0-002, 50 MB cap) | p99 < 90 s |
| `POST /v1/hunt/query` (P3-006) | p99 < 30 s |
| `POST /v1/compliance/evidence/collect` (P1-004) | p99 < 60 s |
| `POST /v1/soar/workflows/{id}/run` (P3-005) | p99 < workflow-declared timeout; default workflow timeout 5 min |
| `POST /v1/cloud/drift/scan` (P2-004) | p99 < 5 min |
| `GET  /v1/cloud/blast-radius` (P1-010) | p99 < 5 s |

The BAS submission target includes the safety pipeline evaluation
(kill-switch check + mode gate + window gate + approval gate;
~8 ms typical) plus dispatch into Redis Streams.

### 3.4 Threat-intel freshness — feed-pull SLOs

These are not endpoint SLOs; they are background-job freshness SLOs.

| Feed | Target | Measurement |
|---|---|---|
| CISA TAXII pull cycle (P0-001) | ≤ 1 h | `sx_feed_last_pull_age_seconds{feed="cisa_taxii"}` |
| NVD CVE sync (P0-006) | ≤ 1 h | `sx_feed_last_pull_age_seconds{feed="nvd"}` |
| CISA KEV sync | ≤ 24 h | `sx_feed_last_pull_age_seconds{feed="kev"}` |
| EPSS sync (P1-013) | ≤ 24 h | `sx_feed_last_pull_age_seconds{feed="epss"}` |
| Vendor advisory feeds (GitHub, MISP, OTX) | ≤ 6 h | `sx_feed_last_pull_age_seconds{feed=~"github\|misp\|otx"}` |

Breach: any 5-minute interval where the gauge exceeds the target.
Budget: standard 99.5% on the gauge-under-target SLI.

### 3.5 Knowledge-graph latency (Neo4j, P1-001)

| Query | Target |
|---|---|
| `GET /v1/graph/attack-paths` top-N (≤ 10 paths, depth ≤ 7) | p95 < 200 ms on a 1M-node graph |
| GraphSAGE risk-update batch | completes within 15 min cycle |
| Path explanation render | p99 < 500 ms |

Measurement: `histogram_quantile(0.95, sum by (le)(rate(sx_graph_query_duration_seconds_bucket[5m])))`.

### 3.6 Identity surfaces

| Endpoint | Target |
|---|---|
| `POST /v1/auth/saml/acs` (P0-004) | p99 < 200 ms |
| `POST /v1/admin/scim/users` write (P0-005) | p99 < 500 ms |
| `GET  /v1/admin/scim/users` paginated | p99 < 250 ms |
| `POST /v1/auth/mfa/webauthn/register/start` (P1-002) | p99 < 300 ms |
| `POST /v1/auth/mfa/webauthn/register/finish` | p99 < 300 ms |
| `POST /v1/auth/mfa/webauthn/login/start` | p99 < 300 ms |
| `POST /v1/auth/mfa/webauthn/login/finish` | p99 < 300 ms |
| RBA evaluate (in-process middleware) | p99 < 10 ms |
| KMS wrap (per provider; P1-005/6/7) | p99 < 50 ms |
| KMS unwrap (per provider) | p99 < 50 ms |

The RBA evaluator is hot-path on every authenticated request; the
budget is tight by design.

KMS wrap / unwrap is measured per provider label
(`provider="aws"|"gcp"|"azure"|"vault"`). A breach on any provider
debits the budget; the failover policy is documented in
[ADR 0005 audit-log HMAC chain anchoring](adr/0005-audit-log-hmac-chain-anchoring.md)
and the per-tenant KEK rotation runbook.

### 3.7 Audit anchoring (P1-015)

| SLI | Target |
|---|---|
| TSA anchor success rate per period | ≥ 99.9% per rolling 30-day window |
| Time-to-anchor after batch close | p99 < 5 min |
| Audit chain verification (`/v1/audit/anchors/verify/{run_id}`) | p99 < 10 s for a 30-day window |

A single missed anchor period debits the budget by the full period
length (5 min ⇒ 5 min). Any verification mismatch is treated as an
audit-durability breach — see §4.

### 3.8 Audit replay (P3-009)

| Endpoint | Target |
|---|---|
| `GET /v1/audit/replay` (≤ 10k events) | p99 < 2 s |
| `GET /v1/audit/diff` (≤ 10k events / side) | p99 < 3 s |

### 3.9 SOAR + DAST + automation latency

| Endpoint | Target |
|---|---|
| `POST /v1/soar/workflows/{id}/run` (P3-005) | success rate 99.5%; runtime p99 ≤ workflow-declared timeout |
| `GET  /v1/soar/runs/{id}` | p99 < 250 ms |
| `POST /v1/discovery/dast/scan` (P2-013) | scan completes within (N requests × 5 ms) + 30 s baseline, capped at 60 min; budget alerts if completion exceeds target |
| `POST /v1/plugins/install` (P3-007) | p99 < 3 s (excluding cold-pull of manifest, which has its own gauge) |

### 3.10 Dashboard — sidebar p50 ≤ 3 ms

Measured in production-build mode (`npm start` / `next start`) from
synthetic crawler:

| SLI | Target |
|---|---|
| Sidebar render p50 | ≤ 3 ms |
| Sidebar render p99 | ≤ 50 ms |
| Cmd+K search open p99 | ≤ 100 ms |
| First contentful paint (dashboard root) p99 | ≤ 1.5 s |
| Time to interactive (engagement detail) p99 | ≤ 2.5 s |

Dev-mode latency (`npm run dev`) is explicitly out of scope (see
[onboarding.md §7.3](onboarding.md)).

---

## 4. Audit log durability — 99.999%

The audit log is the single most load-bearing artifact on the
platform (see [ADR 0005](./adr/0005-audit-log-hmac-chain-anchoring.md)).
Our durability target is **99.999%**: effectively zero loss.

### 4.1 SLI definition

- **Loss**: any committed write to `audit.entry` that is not present
  in the next chain-verification pass OR is not represented in an
  S3 anchor within 1 hour.
- **Failure to anchor**: any 5-minute interval in which an anchor
  manifest was due and not written; the RFC 3161 TSA must return
  a valid timestamp token within 5 min of batch close.
- **Failure to verify**: any verification mismatch in
  `sx-cli audit verify` OR the `/v1/audit/anchors/verify/{run_id}`
  endpoint.

The SLI is computed daily:

```text
durability = 1 - (lost_entries / committed_entries)
                   + 0 if all anchors landed
                   + 0 if all verifications passed
```

Any non-zero loss or anchor failure or verification failure debits the
budget by 100% for the day.

### 4.2 Why 99.999%

At 99.999% over 30 days, the budget is approximately 26 seconds of
outage. We are not committing to zero loss in the absolute sense
(physics objects); we are committing that any loss event is treated as
a P0 incident and addressed within 26 seconds of detection across the
rolling window.

In practice we expect zero events. The number exists so the policy
[Section 6](#6-error-budget-policy) is unambiguous: any audit loss
event freezes ship.

---

## 5. Error budget calculation

For an SLO `T` (e.g. 0.999), the budget in a 30-day window is:

```
budget_seconds = 30 * 24 * 3600 * (1 - T)
              = 2,592,000 * (1 - T)
```

| SLO target | Budget over 30 days |
|---|---|
| 99.9% | 2,592 seconds = 43.2 min |
| 99.95% | 1,296 seconds = 21.6 min |
| 99.5% | 12,960 seconds = 3.6 h |
| 99.0% | 25,920 seconds = 7.2 h |
| 99.999% | 25.9 seconds |

### 5.1 Budget consumption

A failed second debits the budget by 1 second. We classify failure as:

- For availability: any second in which the route had at least one
  HTTP 5xx **and** the success rate for that second was below the
  target.
- For latency: any second in which the p99 for that route exceeded
  the target.
- For freshness (intel + anchor): any minute in which the freshness
  gauge exceeded the target.
- For audit durability: see [§4](#4-audit-log-durability--99999).

### 5.2 Burn rate alerts

We alert on **multi-window, multi-burn-rate** thresholds (Google SRE
book style):

| Alert | Burn rate | Window | Page level |
|---|---|---|---|
| Fast burn (1 hr) | 14.4× | 1 hr | P1 |
| Fast burn (5 min) | 36× | 5 min | P0 |
| Slow burn (6 hr) | 6× | 6 hr | P2 |
| Slow burn (3 days) | 1× | 3 days | warning |

A 14.4× burn rate for 1 hour consumes a full month's budget — we page
P1. A 36× burn rate for 5 minutes is a smoking-gun outage — we page P0.

---

## 6. Error budget policy

### 6.1 In-budget (> 25% remaining)

- Ship at normal velocity.
- Run canary experiments as planned.
- Take new architecture risks if the team can justify them.

### 6.2 Budget burn elevated (10–25% remaining)

- Continue shipping but mandate canary for any change touching the
  affected surface.
- Pause large architecture changes on the affected surface.
- Engineering manager updated daily.

### 6.3 Budget burn high (5–10% remaining)

- All non-emergency deploys to the affected service require **two
  approvers** (one of whom must be the SLO owner).
- Postpone planned feature work that touches the affected surface.
- Dedicated incident-debt sprint considered.

### 6.4 Budget exhausted (< 5% remaining)

- **Ship freeze on the affected surface** until budget recovers.
- The only deploys permitted are reliability fixes for the affected
  surface or critical security patches.
- Incident commander appointed even outside an active incident.
- Daily standup with engineering, SRE, and product until recovered.

### 6.5 Ship freeze for audit durability

Audit log durability is special. **Any breach** (a single loss event,
a single failed anchor, a single failed verification) is an immediate
ship freeze on **any change touching `sx-audit`, `sx-storage`, or the
audit-anchor infrastructure** until:

1. The root cause is identified and fixed.
2. A post-mortem is published.
3. The next 7 days of anchor manifests verify cleanly.

This is documented separately because audit durability is the
platform's trust contract and we will not negotiate it against ship
velocity.

### 6.6 Ship freeze for kill-switch availability

The kill switch shares the same hard-stop rule. A breach of
`POST /v1/safety/kill-switch` 99.9% availability OR a confirmed
failure of a real-world trip freezes ship on `sx-bas` and the
composition root until the trip is reproduced in a chaos drill.

---

## 7. SLOs per critical user journey

In addition to per-route SLOs, we track end-to-end **critical user
journey** (CUJ) SLOs. These are what customers experience.

### 7.1 CUJ: Sign in

| Step | Target |
|---|---|
| Time from click to redirect | p99 < 1.5 s |
| Success rate | 99.9% (over auth surface) |

The CUJ aggregates `/v1/auth/login` + redirect handling. Failures of
the IdP itself are excluded — we cannot control Okta or Azure AD
uptime. SAML CUJs additionally aggregate the IdP-initiated
`/v1/auth/saml/acs` round-trip; the IdP segment is excluded from
the SLO but reported in the CUJ dashboard.

### 7.2 CUJ: Open the engagement dashboard

| Step | Target |
|---|---|
| Time to first paint of engagement summary | p99 < 1.0 s |
| Time to interactive | p99 < 2.5 s |
| Success rate | 99.5% |

Measured from the dashboard's RUM tracker.

### 7.3 CUJ: Submit a BAS technique

| Step | Target |
|---|---|
| Submit → safety pipeline → dispatch | p99 < 1 s |
| Submit → first telemetry event in stream | p99 < 5 s |
| Success rate (submit endpoint) | 99.5% |

### 7.4 CUJ: Trip the kill switch

| Step | Target |
|---|---|
| API call to global cluster effect | p99 < 1 s |
| Success rate | 99.99% |

The kill switch tolerates no degradation. A failed trip is a P0
incident under [the IR playbook](./runbooks/incident-response.md).

### 7.5 CUJ: Generate a compliance report

| Step | Target |
|---|---|
| Submit → downloadable artifact (SOC 2 evidence pack) | p99 < 60 s |
| Success rate | 99.0% (cold-data dependent) |

Lower availability target reflects that report generation depends on
downstream services (S3 evidence pulls, TSA anchor cross-checks).

### 7.6 CUJ: Audit log verification

| Step | Target |
|---|---|
| `sx-cli audit verify --tenant <id>` | p99 < 10 s for a 30-day window |
| `GET /v1/audit/anchors/verify/{run_id}` | p99 < 5 s |
| Success rate | 99.999% (any failure is a P0 finding) |

### 7.7 CUJ: Vuln import → finding visible (P0-002)

| Step | Target |
|---|---|
| Upload Nessus / Qualys / Burp / Nuclei / OpenVAS / ZAP → finding visible in `/v1/findings` | p99 < 90 s for a 50 MB import |
| Success rate | 99.0% |

### 7.8 CUJ: Cloud blast radius (P1-010)

| Step | Target |
|---|---|
| Submit seed ARN → blast-radius graph rendered in dashboard | p99 < 6 s |
| Success rate | 99.5% |

### 7.9 CUJ: SOAR workflow run (P3-005)

| Step | Target |
|---|---|
| Submit → first step started | p99 < 1 s |
| Workflow completed within declared timeout | success rate 99.5% |

### 7.10 CUJ: API DAST scan (P2-013)

| Step | Target |
|---|---|
| Scan submission → completion | p99 < (N × 5 ms + 30 s), capped at 60 min for a 1k-request scan |
| Success rate | 99.0% |

---

## 8. Synthetic monitor coverage

Every endpoint with an SLO above has a corresponding synthetic monitor.
The monitor fleet runs from three geographic locations (Singapore,
Tokyo, Frankfurt) at the cadence below.

| Endpoint group | Cadence | Locations |
|---|---|---|
| `/healthz`, `/readyz`, `/metrics` | 30 s | all |
| `/openapi.json` | 5 min | all |
| `/v1/auth/login` | 1 min | all |
| `/v1/auth/refresh` | 1 min | all |
| `/v1/auth/saml/acs` (synthetic IdP) | 5 min | all |
| `/v1/auth/mfa/webauthn/*` | 5 min | all |
| `/v1/admin/scim/*` | 5 min | one |
| `/v1/safety/kill-switch` GET + dry-trip | 30 s | all |
| `/v1/engagements/*` read sample | 1 min | all |
| `/v1/findings/*` read sample | 1 min | all |
| `/v1/bas/run` dry-run | 5 min | one |
| `/v1/intel/check` indicator | 5 min | all |
| `/v1/audit/search` recent window | 5 min | all |
| `/v1/audit/anchors` head + verify | 5 min | all |
| `/v1/graph/attack-paths` top-N | 5 min | one |
| `/v1/cloud/blast-radius` seed query | 5 min | one |
| `/v1/reports/render` (no-op template) | 30 min | one |
| `/v1/reports/diff` (no-op pair) | 30 min | one |
| `/v1/compliance/evidence/collect` (no-op) | 30 min | one |
| `/v1/hunt/query` (canary query) | 5 min | one |
| `/v1/soar/workflows/{id}/run` (canary workflow) | 5 min | one |
| `/v1/discovery/dast/scan` (1-request canary) | 30 min | one |
| `/v1/vuln/import` (1 KB canary) | 30 min | one |
| `/v1/ueba/anomalies` read | 5 min | all |
| `/v1/device-trust/policy` read | 5 min | all |
| `/v1/rba/decisions` read | 5 min | all |
| `/v1/runtime/falco/alerts` read | 5 min | all |
| `/v1/dlp/scan` (canary payload) | 5 min | one |
| `/v1/grc/configs` read | 5 min | one |
| `/v1/ir/playbooks` read | 5 min | all |
| `/v1/plugins` read | 5 min | one |
| `/v1/notifications/devices` read | 5 min | one |
| `/v1/integrations/bugbounty/configs` read | 5 min | one |
| Dashboard sidebar render | 1 min | all |
| Dashboard `/dashboard` first paint | 1 min | all |
| Feed-freshness gauges | 1 min | (in-cluster) |
| KMS wrap / unwrap (per provider) | 5 min | one |

The synthetic suite is owned by SRE and re-validated quarterly.

---

## 9. SLO ownership

| SLO | Owner |
|---|---|
| `/v1/auth/*` availability | Platform Eng |
| `/v1/auth/saml/*` availability + latency (P0-004) | Identity squad |
| `/v1/admin/scim/*` (P0-005) | Identity squad |
| `/v1/auth/mfa/webauthn/*` (P1-002) | Identity squad |
| RBA evaluator (P1-003) | Identity squad |
| KMS wrap / unwrap (P1-005/6/7) | Platform Eng |
| `/v1/safety/*` availability + latency | SecEng |
| Audit log durability + TSA anchoring (P1-015) | SecEng + SRE |
| Audit replay + diff (P3-009) | SecEng |
| Standard route availability | SRE |
| Feed freshness (TAXII, NVD, KEV, EPSS) | Intel squad |
| Neo4j graph latency (P1-001) | Detection squad |
| Cloud blast-radius latency (P1-010) | Cloud squad |
| UEBA / device-trust / RBA latency | Detection squad |
| SOAR workflow run | Automation squad |
| API DAST scan completion | Offensive squad |
| Dashboard sidebar p50 | Frontend platform |
| End-to-end CUJ | SRE + Product |
| Burn rate alert routing | SRE |

The owner is responsible for:

- Reviewing the SLO target quarterly.
- Responding to burn-rate alerts.
- Filing the ship freeze when budget exhausts.
- Publishing the post-mortem when an SLO is breached.

---

## 10. Reporting

- **Weekly SLO digest** in `#sentinelx-platform` summarising budget
  remaining for each critical SLO and freshness gauge.
- **Monthly SLO review** with engineering leadership covering the
  full surface inventory in §3.
- **Quarterly SLO recalibration** — we may raise or lower a target
  based on the previous quarter's data.

A target is only lowered if (a) it has been chronically unmet **and**
(b) the lowered target is still acceptable to product. A lowered
target requires CTO sign-off.

---

## 11. What is *not* an SLO

To keep this doc honest, here is what we have explicitly chosen not to
make an SLO:

- **Dashboard frame rate in dev-mode**. Measured in RUM; never pages.
- **Third-party integration uptime** (Okta, Azure AD, Slack, Jira,
  GitHub, bug-bounty platforms). We report it but do not own it.
- **Customer-side network**. The agent connection is best-effort
  with retries; we do not commit to its uptime.
- **Cold-start latency**. The first request after a pod restart is
  excluded from the latency window.
- **Chaos-mode runs** (P2-012). When `SX_CHAOS_ENABLED=1`, SLOs are
  paused — chaos is a deliberate stress test, not a production state.

---

## 12. Change log

| Date | Change | Approved by |
|---|---|---|
| 2026-05-30 | Initial publication. | CTO |
| 2026-06-14 | Major expansion: per-module SLO inventory matching the 8-module sidebar; freshness SLOs for TAXII / NVD / KEV / EPSS (P0-001 / P0-006 / P1-013); SAML ACS + SCIM + WebAuthn + RBA + KMS latency targets (P0-004 / P0-005 / P1-002 / P1-003 / P1-005/6/7); Neo4j top-N + blast-radius latency (P1-001 / P1-010); TSA anchoring success and audit replay latency (P1-015 / P3-009); SOAR + DAST + vuln-import scan-completion targets (P3-005 / P2-013 / P0-002); dashboard sub-3 ms sidebar p50; synthetic monitor matrix; CUJ entries for vuln import, blast radius, SOAR, DAST; ship-freeze rule for kill-switch availability. | CTO |
