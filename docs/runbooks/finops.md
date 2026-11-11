# FinOps Runbook

> **Last reviewed:** 2026-06-13
> **Maintainer:** FinOps Lead (`finops@sentinelx.example`) / Backup: Platform Eng Manager
> **Next review:** 2026-09-13 (quarterly)
> **Document owner:** Platform Engineering & Finance (joint)
> **Classification:** Internal

---

## 1. Purpose

This runbook defines how SentinelX operates a disciplined **FinOps** practice:
who owns cost, how budgets are set and enforced, how alerts trigger action,
and the monthly review cadence that keeps cloud spend aligned with revenue.

It is owned jointly by **Platform Engineering** (who provision the spend) and
**Finance** (who account for it). Disagreements are resolved by the FinOps
Council (CTO, CFO, VP Eng) per §6.

---

## 2. Cost Categories

SentinelX cloud spend is decomposed into five primary categories. Every
resource must be tagged with `cost-category` matching one of these values; the
nightly tagging-compliance job (`finops-tag-audit`) reports drift.

### 2.1 Compute

- **What:** EC2, EKS nodes, Fargate, Lambda, batch workers.
- **Tag value:** `compute`.
- **Subtags:** `workload` (api | bas-worker | ml | etl | edge), `tier`
  (production | staging | dev | ephemeral).
- **Drivers:** Request volume, BAS scan concurrency, ML retraining cadence.
- **Optimization levers:** Right-sizing, spot, reserved instances, scaling
  policies, idle-shutdown.

### 2.2 Network

- **What:** Inter-AZ, cross-region, internet egress, NAT, load balancers,
  PrivateLink, VPN.
- **Tag value:** `network`.
- **Drivers:** Customer egress, cross-region replication, BAS outbound
  scans, DR replication.
- **Optimization levers:** VPC endpoints (replace NAT), CRR throttling,
  CloudFront for static, peering vs. transit gateway.

### 2.3 Storage

- **What:** S3, EBS, EFS, FSx, Glacier, snapshot fees.
- **Tag value:** `storage`.
- **Subtags:** `data-class` (raw | processed | audit | backup),
  `retention-policy`.
- **Drivers:** Audit log retention, WAL-G backups, customer artifact
  storage, ML model store.
- **Optimization levers:** S3 lifecycle to IA/Glacier, intelligent-tiering,
  snapshot age caps, dedup.

### 2.4 Secret Store

- **What:** Vault Enterprise licensing, KMS, Secrets Manager, HSM (CloudHSM).
- **Tag value:** `secret-store`.
- **Drivers:** API requests/sec, key count, HSM instance hours.
- **Optimization levers:** Cache KMS data keys, batch Vault renewals,
  consolidate KMS CMKs where blast-radius allows.

### 2.5 Observability

- **What:** Datadog, ingestion + retention, logging (CloudWatch, OpenSearch),
  tracing (Tempo), metrics, on-call tooling (PagerDuty, Statuspage).
- **Tag value:** `observability`.
- **Drivers:** Log volume, custom metric cardinality, trace sampling rate.
- **Optimization levers:** Sampling, cardinality budgets, log tier
  (hot/cold), retention.

### 2.6 Category share (steady state, May 2026)

| Category | % of monthly cloud spend | Trend MoM |
| --- | --- | --- |
| Compute | 46% | ↓ 2% |
| Network | 14% | ↑ 1% |
| Storage | 18% | flat |
| Secret store | 5% | flat |
| Observability | 17% | ↑ 3% |

Observability creep is currently the biggest watch-out — see §4.

### 2.7 SentinelX-specific cost model components

The categories above are the cost-accounting buckets. The drivers below
are the SentinelX-specific data structures that move cost between
those buckets. Operators sizing a new deployment should walk the list
in order.

#### 2.7.1 ClickHouse — OCSF event store (`events_ocsf`)

ClickHouse holds OCSF-normalised events (Falco P2-016, audit chain,
OCSF P0-003 pipeline) and is the dominant per-tenant log-volume cost.

**Sizing model:**

```
events_per_tenant_per_day = (
    audit_events                 # baseline ~20k/day per active tenant
  + ocsf_runtime_events          # P2-016 Falco: 200k/day typical, 10M/day for noisy K8s
  + ocsf_admission_events        # P2-014: 5k/day per cluster
  + ueba_baseline_emits          # P2-005: 1k/day per actor; tenant has ~50 actors
)

raw_bytes_per_day  = events_per_tenant_per_day * 1_500   # avg OCSF row size
compressed_bytes   = raw_bytes_per_day * 0.10           # ZSTD on (tenant_id, time)
hot_tier_days      = 30
warm_tier_days     = 90
cold_tier_days     = 365 * 7   # audit chain class only

cluster_cost_USD_per_month
  = (hot_tier_days  * compressed_bytes * S3_standard_per_gb_month)
  + (warm_tier_days * compressed_bytes * S3_ia_per_gb_month)
  + (cold_tier_days * compressed_bytes * S3_glacier_per_gb_month)
  + clickhouse_compute_per_replica * 3   # 3-replica HA minimum
```

Concrete reference (`tier=enterprise`, ~10M events/day): a 3-node
m6id.4xlarge cluster + S3 lifecycle as above costs **~USD 9.4k/month**
including storage. The `clickhouse_compute_per_replica` line is the
dominant lever for read-heavy hunting workloads (P3-006).

**Drivers to watch:**

- Falco rule changes that increase `notice`-priority emission can 10×
  the row count overnight. Always shadow-test rule changes against the
  cardinality budget (`scripts/finops/clickhouse-cardinality-check.sh`).
- Hunt queries (P3-006 KQL/SPL) that don't pin `tenant_id` trigger a
  full-scan — cap with `MAX_EXECUTION_TIME = 60` on the query role.

#### 2.7.2 Neo4j — optional knowledge graph

`sx-graph` (assets + relationships + blast-radius — P1-010, P2-014,
P2-016 enrichments) runs on Neo4j. It is **optional**: the default
deployment skips it and routes blast-radius queries through ClickHouse
materialised views.

**When to enable Neo4j:**

- Tenant has > 10k cloud assets (P1-010 BFS becomes prohibitively
  expensive in SQL).
- Detection engineering wants graph-style hunts (e.g. "find me every
  pod within 2 hops of a publicly-exposed internet endpoint that has
  service-account mounted").
- Customer requests rich graph view in the dashboard.

**Cost model:**

```
neo4j_compute = 3 × r6id.2xlarge          # 3-node Causal Cluster
              = ~USD 3.1k / month
neo4j_storage = nodes × 200 B + relationships × 100 B
              # 1 M nodes + 5 M relationships ≈ 700 MB; trivial vs compute
neo4j_license = USD 0 (Community Edition acceptable for current scale)
                # Enterprise Edition required if Causal Cluster + RBAC needed
```

A typical large tenant (`100k assets, 1M relationships`) lands around
**USD 3.4k/month** all-in.

**Off-switch:** `SENTINELX__GRAPH__BACKEND=clickhouse_views` falls
back; queries that exceed 2 hops degrade gracefully to `Unsupported`
errors (the dashboard handles this).

#### 2.7.3 Multi-cloud KMS per-request pricing

The three KEK providers (P1-005 AWS KMS, P1-006 GCP Cloud KMS, P1-007
Azure Key Vault) have distinct pricing curves. The DEK cache (default
TTL 5 min) is the single biggest lever.

| Provider     | Per-request (USD)              | KEK at rest (USD/month) | Notes                                        |
|--------------|---------------------------------|--------------------------|----------------------------------------------|
| AWS KMS      | 0.03 / 10k                      | 1.00 per CMK            | First 20k requests / month free per CMK      |
| GCP Cloud KMS| 0.03 / 10k (symmetric)          | 0.06 per key version    | Cross-region replicas cost +50 %             |
| Azure Key Vault | 0.03 / 10k                   | 1.00 per HSM-backed key | Software-protected keys: 0.03 / 10k same     |

**Sizing model** (DEK cache hit-ratio > 95 % typical):

```
kms_calls_per_month =
    distinct_dek_versions_unwrapped
  + dek_rotations_per_month
  + dek_cache_cold_starts             # pod roll, etc.

# At hit-ratio 95 %, kms_calls ~= (writes + cold_starts) / 0.05
```

A typical busy tenant (500 K writes/day, 10 cold starts/day) lands
around **USD 9 / month / tenant** across all three providers — KMS is
genuinely cheap if the cache is healthy. **Anti-pattern**: a process
that loops on `unwrap_dek` per row burns the budget; tune
`SENTINELX__SECRETS__DEK_CACHE_TTL` upward, never downward.

#### 2.7.4 S3 Object Lock vs standard storage — 7-yr retention premium

The P1-004 evidence bundles are stored under **S3 Object Lock
COMPLIANCE mode with 7-year retention**. The premium over standard
storage is two-fold:

1. **Cannot use lifecycle to Glacier Deep Archive** for objects under
   active retention — they would otherwise become indistinguishable
   from deleted objects. We use **Glacier Instant Retrieval** instead.
2. **Cannot delete** for 7 years even on tenant churn — the bucket
   retains data after the tenant leaves, billed to SentinelX (then
   billed back via the off-boarding clause in the MSA).

**Cost model:**

```
bundle_bytes_per_tenant_per_year
  = num_collectors × runs_per_year × avg_bundle_kb
  # 5 collectors × 52 weekly runs × 8 KB ~= 2 MB / tenant / year (trivial!)

standard_storage_USD_per_tenant_per_year
  = bundle_bytes * (S3_standard or Glacier_IR price)
```

A pure bundle workload is trivially cheap (sub-cent per tenant per
year). The **real cost premium** comes from the operational requirement
to also store **forensic snapshots** (Postgres + Redis state at each
incident) in the same WORM bucket. Each snapshot is 50–500 MB; one
incident a quarter at S3 Standard + 7-year COMPLIANCE retention is
about **USD 90 / tenant / year** at full retention. Glacier IR brings
this down to **USD 11 / tenant / year** at the cost of a 5-minute
retrieval delay — acceptable for evidence access, not for hot DR.

**Lever:** the per-tenant `evidence.snapshot_retention_class` setting
chooses between `standard` (legal/financial customers) and
`glacier-instant-retrieval` (everyone else). Default is
`glacier-instant-retrieval`.

---

## 3. Budget Alerts

### 3.1 Thresholds

Budgets are set **monthly per category** and enforced by AWS Budgets plus
SentinelX's internal `finops-controller`. Thresholds:

| Threshold | Trigger | Action | Who is paged |
| --- | --- | --- | --- |
| **Warn — 70%** | MTD spend ≥ 70% of monthly budget at any point | Slack `#finops-alerts`, ticket auto-created | FinOps Lead, category owner |
| **Page — 90%** | MTD spend ≥ 90% of monthly budget | PagerDuty `finops-budget-page`, mandatory standup within 4h | FinOps Lead + Platform Eng Manager |
| **Kill — 110%** | MTD spend ≥ 110% of monthly budget OR forecast ≥ 110% by EOM | Auto-throttle ephemeral workloads; freeze non-production capacity expansions | FinOps Council (CTO + CFO + VP Eng) |

### 3.2 Action ladder

| Threshold | Allowed | Forbidden | Approvals to override |
| --- | --- | --- | --- |
| 0–70% | Normal ops | – | – |
| 70–90% | New ephemeral workloads allowed if tagged + cost-sized | Untagged spend > $100/day | Category owner |
| 90–110% | Only revenue-critical new spend | New experimentation env | Platform Eng Manager + FinOps Lead |
| 110%+ | Only customer-impacting work | All new resources requiring approval | FinOps Council (must convene within 24h) |

### 3.3 Kill-switch behavior

When the 110% threshold trips, the `finops-controller` automatically:

1. Scales `tier=ephemeral` nodegroups to zero (dev sandboxes, scratch
   notebooks).
2. Pauses non-prod CI/CD jobs (workflows tagged `ci-throwaway`).
3. Drops BAS worker concurrency to 50% of normal.
4. Freezes Terraform applies that create new resources tagged
   `cost-category=compute|network|storage` unless flagged `finops-override`.

Override is a signed change request (CTO + CFO countersign) recorded in
[`../operations/finops-overrides.md`](../operations/finops-overrides.md).

### 3.4 Per-service budgets (current)

| Service | Monthly budget (USD) | Owner |
| --- | --- | --- |
| Production compute | 92,000 | Platform Eng |
| BAS workers | 38,000 | Detection Eng |
| ML training | 24,000 | ML Eng |
| Observability | 31,000 | SRE |
| Storage (audit) | 11,500 | Compliance |
| Storage (other) | 9,800 | Platform Eng |
| Secret store | 6,200 | SecEng |
| Network egress | 22,400 | Platform Eng |
| Dev / staging | 14,000 | Eng Productivity |
| **Total** | **249,900** | – |

Budgets are reset on the 1st of each month, prorated for new services.

---

## 4. Cost Optimization Checklist

Run through this list during every **monthly review** (§5) and after any
threshold breach.

### 4.1 Right-sizing

- [ ] `finops-cli rightsizing --workload api` — review p95 CPU/mem over
      14 days.
- [ ] Any workload < 30% utilization for 7 consecutive days flagged for
      downsize.
- [ ] Any workload > 80% sustained CPU flagged for upsize *before* it
      degrades SLO.
- [ ] Database instance class matches connection count + working set,
      verified via `pg_stat_statements` + buffer-cache hit ratio ≥ 95%.

### 4.2 Reserved instances / Savings Plans

- [ ] Steady-state compute covered by Savings Plans at ≥ 70% of baseline.
- [ ] RIs renewed 30 days before expiry — automated reminder via Asana
      project `finops-reserved-renewals`.
- [ ] Coverage gaps recomputed monthly via `finops-cli ri-recommendations`.
- [ ] Quarterly evaluation of 1y vs. 3y commitments — 3y only for
      revenue-tied baseline (≥ 12 months of usage history).
- [ ] No SPs for `tier=ephemeral`.

### 4.3 Spot for BAS workers

- [ ] BAS worker fleet at ≥ 70% spot mix.
- [ ] Spot interruption handler verified to drain in ≤ 90s without job loss
      (interrupted job re-enqueues onto SQS DLQ).
- [ ] At least 4 instance families in the spot pool to keep capacity score
      ≥ 7/10.
- [ ] On-demand floor of 20% to absorb spot interruptions during peak.
- [ ] Per-region spot mix reported weekly.

Current BAS spot mix: **74%** (target 70%).

### 4.4 S3 lifecycle

- [ ] All buckets have a lifecycle policy. (`finops-cli s3 untagged`
      returns empty.)
- [ ] Standard → Standard-IA at 30 days for `data-class=processed`.
- [ ] → Glacier Instant at 90 days for `data-class=audit` (cannot use
      deeper tiers — must satisfy 7y compliance retrieval SLA).
- [ ] → Deep Archive at 180 days for `data-class=backup`.
- [ ] Incomplete-multipart-upload cleanup at 7 days.
- [ ] Noncurrent version expiration at 30 days, except `audit` (versioning
      + Object Lock retained).

### 4.5 Network

- [ ] All AWS service traffic routed via VPC endpoints (no NAT egress for
      `s3 | dynamodb | kms | sts | logs`).
- [ ] CloudFront in front of all static + API where caching helps.
- [ ] Inter-AZ chatter reviewed: any service > 1 TB/day cross-AZ flagged.
- [ ] Cross-region traffic limited to: DR replication, CRR, Vault perf
      replica, audit anchors. Anything else requires FinOps approval.

### 4.6 Observability

- [ ] Custom metric cardinality budget per service ≤ 50k unique series.
- [ ] Trace sampling rate ≥ 1%, ≤ 10% (tail-based sampling for errors at
      100%).
- [ ] Log tier policy: `hot=14d`, `warm=30d`, `cold=365d` for audit,
      `cold=90d` otherwise.
- [ ] No `DEBUG` logs in production (verified by lint rule in CI).
- [ ] Datadog dashboards with no views in 90 days auto-archived.

### 4.7 Secret store

- [ ] KMS data keys cached in-process for ≥ 5 minutes for high-rate paths.
- [ ] Unused KMS CMKs scheduled for deletion (30-day window).
- [ ] Vault token TTLs aligned with workload lifetime (no 30-day tokens for
      short-lived jobs).

### 4.8 Tagging hygiene

- [ ] `finops-tag-audit --strict` returns zero untagged resources.
- [ ] All resources have: `cost-category`, `team`, `service`, `tier`,
      `environment`.
- [ ] Untagged resources older than 7 days auto-quarantined into the
      `untagged-quarantine` OU.

---

## 5. Monthly Review

### 5.1 When

First Tuesday of each month, 10:00–11:30 SGT. Attendance:

- FinOps Lead (chair)
- CFO delegate
- Platform Eng Manager
- One engineer per category owner (compute, network, storage,
  secret-store, observability)
- VP Eng (quarterly only)

### 5.2 Template

```markdown
# FinOps Monthly Review — YYYY-MM

## 1. Headline numbers
- Total spend: USD ___
- Budget: USD ___
- Variance: ___ %
- Unit economics: cost per protected asset (CPPA): USD ___ (target ≤ X)
- Cost per detection-action: USD ___ (target ≤ Y)

## 2. By category (vs. budget)
| Category | Budget | Actual | Variance | Owner | Notes |
| --- | --- | --- | --- | --- | --- |
| Compute | | | | | |
| Network | | | | | |
| Storage | | | | | |
| Secret store | | | | | |
| Observability | | | | | |
| **Total** | | | | | |

## 3. Top 10 cost drivers (any category)
| Rank | Resource / service | Spend | % MoM | Owner | Action |
| --- | --- | --- | --- | --- | --- |
| 1 | | | | | |

## 4. Anomalies (variance > 15% vs. forecast)
- ...

## 5. Optimization checklist
[Paste status of §4 items: green/yellow/red]

## 6. Wins this month
- ...

## 7. New commitments (RIs/SPs purchased or rolled)
| Date | Type | Term | Hourly commit | Coverage | Approver |
| --- | --- | --- | --- | --- | --- |
| | | | | | |

## 8. Action items
| # | Owner | Due | Description | Tracking |
| --- | --- | --- | --- | --- |

## 9. Risks for next month
- ...

## 10. Sign-off
- FinOps Lead: __________
- Platform Eng Manager: __________
- CFO delegate: __________
```

### 5.3 Retrospective format (quarterly)

The quarterly retro (run as part of April / July / October / January reviews)
adds:

```markdown
## Q{n} Retrospective

### What we set out to do
- Cost target: ____
- Optimization target: ____

### What we achieved
- ...

### What we didn't achieve
- ...

### Why (root cause, not symptoms)
- ...

### What we'll change next quarter
- Process change:
- Tooling change:
- People change:

### Long-term trajectory (12-month view)
[Chart: monthly spend, attached]
- Forecast EOY: USD ___
- vs. plan: ___ %
```

---

## 6. Escalation to CFO

Most FinOps decisions are made at the working level. The **CFO is engaged
directly** when:

1. **Monthly variance ≥ +10%** with no plausible re-baseline within
   the month.
2. **Annualized run-rate change ≥ +5%** vs. the approved plan.
3. **Single capacity decision ≥ USD 50,000/month** (e.g., new region,
   new GPU fleet, large RI purchase).
4. **Reserved Instance / Savings Plan commitments ≥ USD 250,000 TCV**
   (any single contract).
5. **Kill threshold (110%) tripped in any category for two consecutive
   months.**
6. **Auditor / regulator question that ties spend to compliance posture**
   (e.g., "can you prove audit retention is funded for 7 years?").
7. **Vendor consolidation or new vendor onboarding ≥ USD 100,000/yr**.
8. **Any chargeback model change** that affects how customer pricing is
   computed.

### Escalation channel

| Step | Action | Owner | SLA |
| --- | --- | --- | --- |
| 1 | FinOps Lead summarizes trigger in `finops-escalation` template | FinOps Lead | Same day |
| 2 | CFO delegate triages within 1 business day | CFO office | 1 BD |
| 3 | CFO meeting scheduled within 5 BD or async decision | CFO | 5 BD |
| 4 | Decision recorded in `../operations/finops-decisions.md` | FinOps Lead | Same day |

### Escalation template

```markdown
# FinOps Escalation — {short title}

- **Date:** YYYY-MM-DD
- **Trigger:** [variance | run-rate | capacity | RI/SP | kill repeat | other]
- **Requested decision:** [approve | reject | defer | other]
- **Decision deadline:** YYYY-MM-DD (and why)

## Context
{2-3 paragraphs}

## Options
1. ...
2. ...
3. ...

## Recommendation
{...}

## Financial impact
- Monthly: USD ___
- Annualized: USD ___
- One-time: USD ___

## Risk if rejected
- ...

## Risk if approved
- ...

## Approvers required
- [ ] CFO
- [ ] CTO
- [ ] VP Eng
```

---

## 7. Tooling

| Tool | Purpose | Owner |
| --- | --- | --- |
| AWS Cost Explorer / CUR | Source of truth, daily refresh | Finance |
| `finops-cli` (internal) | Right-sizing, RI recs, tagging audit | Platform Eng |
| `finops-controller` (internal) | Kill switch + tier throttles | Platform Eng |
| Datadog Cloud Cost | Real-time anomaly + per-team drill-down | SRE |
| Asana `finops-reserved-renewals` | RI/SP renewal tracking | Finance |
| Looker dashboard `finops/unit-economics` | CPPA, CPDA, gross margin | Finance + FinOps Lead |

---

## 8. Roles & Responsibilities

| Role | Responsibility |
| --- | --- |
| FinOps Lead | Chairs monthly review, owns runbook, single point of contact for category owners |
| Category owner | Knows their category's drivers cold, executes optimization items |
| Platform Eng Manager | Approves Terraform overrides during 90%+ states |
| CFO delegate | Reviews monthly numbers, surfaces to CFO on triggers |
| CFO | Final approval on §6 escalations |
| Engineers | Tag resources correctly; respond to ticket auto-created at 70% |

---

## 9. Cross-References

- [Disaster Recovery Runbook](./disaster-recovery.md) — DR exercises must
  have a cost line item (drill spend tagged `cost-category=compute`,
  `tier=ephemeral`, `drill=true`).
- [Incident Response Runbook](./incident-response.md) — major incidents
  often have cost tails (overprovisioning, retries) — review in next monthly.
- [Operations: FinOps decisions log](../operations/finops-decisions.md).
- [Operations: FinOps overrides log](../operations/finops-overrides.md).
- [SLOs](../slos.md) — cost-vs-reliability tradeoffs documented here.

---

## 10. Change History

| Date | Author | Change |
| --- | --- | --- |
| 2026-05-30 | FinOps Lead | Initial publication. Budgets per §3.4. |
| 2026-06-13 | FinOps Lead | Added §2.7 SentinelX-specific cost model: ClickHouse OCSF event store sizing, optional Neo4j tier, multi-cloud KMS (P1-005/6/7) per-request pricing, S3 Object Lock COMPLIANCE-mode 7-year retention premium (P1-004). |
