# ADR 0013 — OCSF 1.x as the canonical event shape; source-to-OCSF mapping table

Status: Accepted
Date: 2026-06-12
Deciders: Principal Data Engineer, Principal Security Engineer, SOC Lead
Supersedes: None
Superseded by: None

## Context

P0-003 ships log ingestion across heterogeneous sources:

- AWS CloudTrail
- syslog (RFC 5424)
- GCP Cloud Audit Logs
- Azure Activity Logs
- JSON webhooks (custom)
- Kubernetes audit logs
- generic CEF / LEEF (later)

Each source has its own schema. The SOC correlator, the UEBA
engine, the IR playbook engine, and the threat-hunting query
language all need to read events as a **single canonical shape** —
otherwise every consumer ends up with N source-specific code paths
that drift independently.

We evaluated three canonical shapes:

1. **OCSF 1.x** (Open Cybersecurity Schema Framework, AWS / Splunk
   / IBM / CrowdStrike co-sponsored). Well-defined classes
   (Authentication, Process Activity, Network Activity, …),
   typed columns, JSON schema published, growing vendor mapping
   set.
2. **ECS** (Elastic Common Schema). Older, larger, defined as
   "what Elasticsearch indexes well". Strong on tooling but
   slightly fuzzier on semantic boundaries.
3. **CIM** (Splunk Common Information Model). Older still,
   tightly coupled to Splunk's data model.

OCSF 1.0 went GA in 2023 and 1.x has stabilised; AWS Security Lake
publishes in OCSF, CrowdStrike Falcon exports in OCSF, and
multiple SIEM vendors have native readers.

## Decision

### Canonical shape: OCSF 1.x

- Every event in `events_normalized` (RDBMS §16.2) carries the
  OCSF taxonomy quartet:

  - `class_uid` (e.g. `3002` Authentication)
  - `category_uid`
  - `activity_id`
  - `type_uid`

  …plus the OCSF severity (`severity_id` + `severity` string).

- Promoted columns mirror the OCSF top-level shape: `time`,
  `src_ip`, `dst_ip`, `actor_user_name`, `actor_session_id`,
  `target_resource`, `target_type`, plus cloud denormalisations.

- Fields the columns don't promote land in the `ocsf` String
  column as canonical JSON. Consumers can `JSONExtract*` for
  the fields they care about without polluting the column set.

### Source-to-OCSF mapping table

The mapping lives in `crates/sx-log-ingest/src/normalize/`. One
module per source; each module exports a single
`Normalizer<Input>` impl that emits `events_normalized` rows.

| Source | OCSF class | OCSF class_uid | Mapping notes |
|---|---|---|---|
| AWS CloudTrail Management | Authentication / API Activity | 3002 / 6003 | `eventName` → `activity_id`; `userIdentity.arn` → `actor_user_name`; `sourceIPAddress` → `src_ip`; `requestParameters` flattened into `ocsf` |
| AWS CloudTrail Data | Application Activity | 6005 | `resources[].ARN` → `target_resource`; `eventTime` → `time` |
| syslog RFC 5424 | Generic / Process Activity | 1000 / 1007 | `PROCID` → `actor_session_id`; `APP-NAME` → `source_host`; structured-data flattened into `ocsf` |
| GCP Cloud Audit | Authentication / API Activity | 3002 / 6003 | `protoPayload.authenticationInfo.principalEmail` → `actor_user_name`; `protoPayload.methodName` → `activity_id` |
| Azure Activity | Authentication / API Activity | 3002 / 6003 | `caller` → `actor_user_name`; `resourceId` → `target_resource`; `correlationId` → `actor_session_id` |
| Kubernetes audit | Application Activity | 6005 | `user.username` → `actor_user_name`; `verb` → `activity_id`; `objectRef` → `target_resource` |
| Generic JSON webhook | configured per integration | — | the integration's manifest declares the mapping; default is Application Activity (6005) |

The mapping table is unit-tested with **two fixtures per source**:
a positive case (well-formed event) and a malformed case
(missing-field tolerance). Every mapping module owns its
fixtures; CI fails if the fixtures don't round-trip through the
normaliser.

### Failure modes

A source-specific normaliser may fail when:

- The event JSON is malformed (parse error).
- A required OCSF field cannot be derived from the source event
  (e.g. CloudTrail with no `eventTime`).

On failure:

- The raw event is still kept in `events_raw` (RDBMS §16.1) for
  the 7-day replay window.
- A counter is incremented in `intel_feed_status`-like telemetry
  (per-source) and surfaced on the dashboard.
- The event is dropped from `events_normalized` — we explicitly
  refuse to forward a partially-mapped event to the SOC
  correlator, because a missing field is worse than a missing
  event (correlation rules silently miss).

### OCSF version pinning

We pin to OCSF schema version `1.1` (or `1.x` as it ships). Major-
version bumps are gated by an ADR amendment; minor / patch bumps
are mechanical and land via the schema-update job.

### Roundtrip with `events_raw`

Every normalised event references its `events_raw.event_id`
through the shared `event_id`. An operator can always re-derive
the source-shape blob from the raw row + replay the normaliser
against the latest version, which is the basis for the "replay on
normaliser bugfix" runbook.

## Consequences

- **Single consumer surface.** SOC, UEBA, IR, and threat-hunt
  query language all read OCSF; cross-source correlation works
  out of the box.
- **Vendor mapping reuse.** OCSF's community ships reference
  mappings for the major cloud sources; we don't have to invent
  them.
- **Mapping drift is the maintenance burden.** When a source
  changes its schema (CloudTrail occasionally does), we update
  the mapping + the fixtures. The 7-day raw replay window means
  the fix can backfill recent rows.
- **Search ergonomics in the dashboard.** The dashboard renders
  OCSF columns by name; a user querying "auth events for user
  X" hits a promoted column instead of a JSON path.
- **OCSF version churn.** OCSF is still evolving; we pin a
  minor version and accept that schema additions are a quarterly
  task.

## Alternatives Considered

- **ECS.** Considered seriously. Rejected because OCSF's class
  taxonomy is more precise for security-event semantics and the
  vendor momentum in our peer set leans toward OCSF.
- **No canonical shape — per-consumer per-source mappers.**
  Rejected — code-path explosion, drift between consumers, no
  cross-source correlation story.
- **Custom shape derived from our domain.** Rejected — we'd be
  re-inventing OCSF without the community mapping set.
- **CIM.** Rejected — tight Splunk coupling, smaller community
  momentum outside the Splunk ecosystem.
