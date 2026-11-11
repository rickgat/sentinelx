# SentinelX Operations Runbook

> **Last reviewed:** 2026-06-13
> **Maintainer:** SRE on-call rotation (`#sx-oncall`)
> **Next review:** 2026-09-13 (quarterly)
> **Document owner:** SRE Lead
> **Classification:** Internal — Restricted

Quick reference for deploying and debugging SentinelX in production.
Optimised for an on-call engineer who has 5 minutes to act. Everything in
this document must work today against the HEAD image; drift is a P1
documentation bug.

For runtime-security alerting (Falco, OCSF normaliser) see
[`runtime-security.md`](./runtime-security.md). For ArgoCD-level operations
see [`gitops.md`](./gitops.md). For evidence collection see
[`compliance-evidence.md`](./compliance-evidence.md).

---

## 1. Boot and readiness contract

The monolith exposes two distinct liveness/readiness endpoints. The
distinction matters:

| Endpoint     | Purpose                                                                              | Failure semantics                  |
|--------------|--------------------------------------------------------------------------------------|-----------------------------------|
| `/healthz`   | Liveness — the process is alive and the HTTP server accepts connections             | Restart pod                       |
| `/readyz`    | Readiness — every required dependency (Postgres, Redis, Vault, KMS) returned within `READYZ_BUDGET_MS` | Take pod out of Service rotation |

```bash
kubectl -n sentinelx port-forward svc/sentinelx 8080:8080 &
curl -fsS http://127.0.0.1:8080/healthz   # plain "ok"
curl -fsS http://127.0.0.1:8080/readyz    # JSON: dependencies + budgets
```

`readyz` payload (truncated):

```json
{
  "ready": true,
  "checks": {
    "postgres":   { "ok": true, "latency_ms": 4   },
    "redis":      { "ok": true, "latency_ms": 1   },
    "vault":      { "ok": true, "latency_ms": 28  },
    "kek_aws":    { "ok": true, "latency_ms": 31, "version": "v3" },
    "kek_gcp":    { "ok": true, "latency_ms": 47, "version": "v1" },
    "kek_azure":  { "ok": true, "latency_ms": 39, "version": "v2" },
    "tsa":        { "ok": true, "latency_ms": 122 },
    "clickhouse": { "ok": true, "latency_ms": 9   }
  }
}
```

A `false` on any check returns HTTP 503 within 250 ms; the pod is
removed from the Service endpoints by kubelet within one probe interval.

---

## 2. First-time deploy checklist

Before the first `helm upgrade --install`:

- [ ] Image is built, signed, and SBOM-attested (see
      [`docs/security/supply-chain.md`](../security/supply-chain.md)).
- [ ] Namespace exists (or pass `--create-namespace`).
- [ ] Postgres reachable; DB user has `CREATE` on the target schema;
      `sslmode=require` in the URL.
- [ ] Redis reachable, password protected.
- [ ] Vault reachable, KMS-auto-unsealed, IRSA bound.
- [ ] At least one KMS KEK provider configured (AWS P1-005, GCP P1-006,
      or Azure P1-007).
- [ ] Secrets prepared (see [Secret matrix](#secret-matrix)).
- [ ] NetworkPolicy egress CIDRs in `values.yaml` cover managed DB / Redis
      / OTel / KMS endpoints.
- [ ] cert-manager Issuer ready if `ingress.tls` is set.
- [ ] Prometheus Operator installed if `metrics.serviceMonitor.enabled`.

### Deploy

```bash
helm upgrade --install sentinelx deploy/helm/sentinelx \
  --namespace sentinelx --create-namespace \
  -f my-values.yaml

kubectl -n sentinelx rollout status deploy/sentinelx --timeout=5m
kubectl -n sentinelx get pods,svc,netpol,job
```

### Smoke test

```bash
kubectl -n sentinelx port-forward svc/sentinelx 8080:8080 &
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz | jq
```

### Secret matrix

| Secret key                    | Env var                                       | Purpose                                                     |
|-------------------------------|-----------------------------------------------|-------------------------------------------------------------|
| `database-url`                | `SENTINELX__DATABASE__URL`                    | Postgres connection string                                  |
| `redis-url`                   | `SENTINELX__REDIS__URL`                       | Redis connection string                                     |
| `jwt-signing-key`             | `SENTINELX__JWT__SIGNING_KEY`                 | HS256 signing key (>= 32 bytes)                             |
| `attempt-pepper`              | `SENTINELX__IAM__ATTEMPT_EMAIL_PEPPER`        | HMAC pepper for login attempts                              |
| `bootstrap-admin-phc`         | `SENTINELX__IAM__BOOTSTRAP_ADMIN_PHC`         | Argon2id PHC for initial admin                              |
| `audit-hmac-key`              | `SENTINELX__AUDIT__HMAC_KEY`                  | Audit chain HMAC anchor                                     |
| `falco-webhook-key`           | `SENTINELX__RUNTIME__FALCO_WEBHOOK_KEY`       | HMAC-SHA256 ingestion key for Falco webhook (P2-016)        |
| `grc-vanta-token` (per tenant)| `SENTINELX__GRC__VANTA__TOKEN__<tenant>`      | Vanta OAuth refresh token (encrypted via per-tenant KEK)    |
| `grc-drata-token` (per tenant)| `SENTINELX__GRC__DRATA__TOKEN__<tenant>`      | Drata API key (encrypted)                                   |
| `tsa-url`                     | `SENTINELX__AUDIT__TSA_URL`                   | RFC 3161 TSA endpoint (P1-015)                              |
| `tsa-ca-bundle`               | `SENTINELX__AUDIT__TSA_CA_BUNDLE_PATH`        | TSA chain validation bundle                                 |

---

## 3. Rotate the JWT signing key

The JWT carries `kid`. Keep the old key in the verifier set for
`access_ttl` to avoid mass logouts.

```bash
NEW_KEY=$(openssl rand -base64 32)
NEW_KID="kid-$(date -u +%Y-%m)"

# Patch Secret to add the new key (old remains until ttl).
kubectl -n sentinelx patch secret sentinelx-secrets \
  --type='json' \
  -p="[{\"op\":\"replace\",\"path\":\"/data/jwt-signing-key\",\"value\":\"$(printf '%s' "$NEW_KEY" | base64)\"}]"

# Update kid in values and roll.
helm upgrade sentinelx deploy/helm/sentinelx \
  -n sentinelx -f my-values.yaml \
  --set config.jwt.key_id=$NEW_KID

kubectl -n sentinelx rollout status deploy/sentinelx
```

Verification:

```bash
kubectl -n sentinelx logs deploy/sentinelx \
  | jq -r 'select(.message=="jwt key loaded") | .key_id'
```

---

## 4. Trip the kill switch from CLI

The kill switch halts all active engagements via Redis pub/sub on
`sentinelx.killswitch`. Two paths:

### A. Public API (admin JWT required) — preferred

```bash
TOKEN=$(./sx-cli auth login --email admin@example.com --read-password)
curl -fsS -X POST https://sentinelx.example.invalid/v1/safety/kill-switch \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{
        "scope": "global",
        "reason": "oncall manual trip",
        "tripped_by": "<your-handle>"
      }'
```

Scopes supported: `global | tenant | engagement | family` (see
[`docs/runbooks/incident-response.md`](../runbooks/incident-response.md)).

### B. Inside a pod (admin endpoint, no public exposure)

```bash
POD=$(kubectl -n sentinelx get pod -l app.kubernetes.io/name=sentinelx -o name | head -1)
kubectl -n sentinelx exec -it $POD -- \
  curl -fsS -X POST http://127.0.0.1:8080/admin/killswitch \
       -H 'content-type: application/json' \
       -d '{"reason":"oncall manual trip","operator":"<your-handle>"}'
```

Verify propagation:

```bash
kubectl -n sentinelx exec -it $POD -- \
  redis-cli -u "$SENTINELX__REDIS__URL" PUBSUB NUMSUB sentinelx.killswitch
# numsub == replica count means every watchdog is subscribed.
```

`sx_killswitch_triggered_total` increments by 1 within one second of
trip. Reset requires the two-person rule — see
`docs/runbooks/incident-response.md#5-eradication-and-recovery`.

---

## 5. Tune the RBA threshold (P1-003)

Risk-based authentication is configured per-tenant via the
`risk_policies` table. The `step_up` threshold is the score above which
WebAuthn re-prompt is forced.

```bash
# Inspect current thresholds for a tenant.
sx-cli rba policy show --tenant 11111111-1111-1111-1111-111111111111

# Raise the step-up threshold (less friction) — emits an audit row.
sx-cli rba policy set \
  --tenant 11111111-1111-1111-1111-111111111111 \
  --step-up-threshold 0.72 \
  --reason "Q2 friction-tuning per 2026-Q2 retro"
```

Direct SQL fallback (audit row will still emit via the trigger):

```sql
UPDATE risk_policies
   SET step_up_threshold = 0.72,
       updated_at        = now()
 WHERE tenant_id = '11111111-1111-1111-1111-111111111111'
RETURNING *;
```

Hot-reload is automatic — the policy cache TTL is 30 s.

---

## 6. Rotate the Falco webhook key (P2-016)

The Falco webhook authenticates every inbound event with HMAC-SHA256
over `(timestamp || body)` keyed off the **tenant-scoped** webhook key.

```bash
# 1. Mint a new key (32 bytes, base64).
NEW_KEY=$(openssl rand -base64 32)

# 2. Push it into sx-secrets (per-tenant), keeping the previous key as
#    a verifier-side fallback for 60 minutes.
sx-cli runtime falco rotate-webhook-key \
  --tenant 11111111-1111-1111-1111-111111111111 \
  --new-key "$NEW_KEY" \
  --grace-period 60m

# 3. Update Falcosidekick config to send the new key.
kubectl -n falco patch secret falcosidekick-secrets \
  --type='json' \
  -p="[{\"op\":\"replace\",\"path\":\"/data/sentinelx-key\",\"value\":\"$(printf '%s' "$NEW_KEY" | base64)\"}]"

# 4. Roll Falcosidekick (the daemonset Falco itself does not need a roll).
kubectl -n falco rollout restart deploy/falcosidekick

# 5. After 60 minutes verify only the new key remains.
sx-cli runtime falco list-webhook-keys --tenant 11111111-1111-1111-1111-111111111111
```

A drop in `sx_runtime_falco_events_received_total{auth="ok"}` to zero
indicates a key mismatch — roll back to the previous key within the
grace window.

---

## 7. Rotate a GRC provider token (P2-009)

```bash
# Vanta — initiate OAuth refresh.
sx-cli compliance grc rotate-credentials \
  --tenant 11111111-1111-1111-1111-111111111111 \
  --provider vanta

# Drata — paste a new API key.
sx-cli compliance grc set-credentials \
  --tenant 11111111-1111-1111-1111-111111111111 \
  --provider drata \
  --read-token

# ServiceNow — paste basic-auth creds.
sx-cli compliance grc set-credentials \
  --tenant 11111111-1111-1111-1111-111111111111 \
  --provider servicenow \
  --user svc.sentinelx \
  --read-password
```

Each command emits an audit row `action=grc.credentials_rotated`
carrying the KEK version used to wrap the new value (see
[`compliance-evidence.md`](./compliance-evidence.md#10-operational-notes-and-failure-modes)).

---

## 8. Rotate the KEK per provider

The DEK envelope is unwrapped at boot; rotating a KEK rewraps every
DEK but does **not** re-encrypt the data. Procedure is provider-specific.

### 8.1 AWS KMS (P1-005)

```bash
# 1. Create the new KEK version (or rotate the existing key alias).
aws kms create-key --description "sentinelx-tenant-<tid>" \
  --key-usage ENCRYPT_DECRYPT --key-spec SYMMETRIC_DEFAULT

# 2. Tell SentinelX about the new key.
sx-cli secrets kek rotate \
  --tenant <tid> \
  --provider aws \
  --new-key-id arn:aws:kms:ap-southeast-1:...:key/<new-id>

# 3. SentinelX rewraps every active DEK under the new key.
# 4. Schedule deletion of the previous key after 30 days.
aws kms schedule-key-deletion --key-id <previous-key-arn> --pending-window-in-days 30
```

### 8.2 GCP Cloud KMS (P1-006)

```bash
# 1. Create the new key version inside the existing crypto-key.
gcloud kms keys versions create --location global \
  --keyring sentinelx --key tenant-<tid>

# 2. Rotate the version that SentinelX uses.
sx-cli secrets kek rotate \
  --tenant <tid> \
  --provider gcp \
  --new-key-version projects/.../cryptoKeys/tenant-<tid>/cryptoKeyVersions/2

# 3. Disable the old version 30 days later (no destroy until then).
gcloud kms keys versions disable 1 --location global \
  --keyring sentinelx --key tenant-<tid>
```

### 8.3 Azure Key Vault (P1-007)

```bash
# 1. Bump the key version inside the same vault.
az keyvault key rotate --vault-name sentinelx-prod --name tenant-<tid>

# 2. Inform SentinelX (it discovers the new version via the SDK but the
#    explicit call writes an audit row).
sx-cli secrets kek rotate \
  --tenant <tid> \
  --provider azure \
  --discover

# 3. Disable the old version after 30 days.
az keyvault key set-attributes \
  --vault-name sentinelx-prod \
  --name tenant-<tid> \
  --version <old-version> \
  --enabled false
```

All three providers share the same trait (`sx-secrets::kek::KekProvider`)
and emit an audit row `action=secrets.kek_rotated` carrying the provider
discriminant, the tenant id, the old + new version identifiers, and the
operator id.

---

## 9. TSA fallback procedure (P1-015)

The audit chain anchors a digest of every N entries (`AUDIT_TSA_BATCH_SIZE`,
default 1024) to the configured RFC 3161 TSA. The fallback chain is:

1. Primary: `tsa.digicert.com`.
2. Secondary: `freetsa.org` (free, lower SLO).
3. Tertiary: **self-anchored** — write the digest to a separate
   `audit_tsa_local_anchors` table and queue it for re-submission to the
   primary TSA when it returns.

When two consecutive submissions fail, `sx_audit_tsa_failures_total`
breaches the alert threshold and `category=BROKEN_CHAIN` is emitted as a
CRITICAL incident. Procedure:

```bash
# 1. Confirm which TSAs are currently configured.
sx-cli audit tsa list

# 2. Add the secondary as primary if the primary is down >30 minutes.
sx-cli audit tsa promote --url https://freetsa.org/tsr

# 3. Verify the next anchor lands.
watch -n 5 'sx-cli audit tsa last-anchor'

# 4. After primary recovers, re-submit any locally-anchored batches.
sx-cli audit tsa replay-local --until $(date -u +%FT%TZ)
```

Restoring the primary as primary is the same `promote` command with the
original URL.

---

## 10. Rebuild a ClickHouse projection

ClickHouse projections back the OCSF-normalised event store. Rebuild is
sometimes necessary after a `version2` of an event type lands.

```bash
# 1. Identify the projection.
clickhouse-client --query "
  SELECT database, table, name, type, parts_count
  FROM system.projections
  WHERE table = 'events_ocsf'
"

# 2. Drop and re-create with the new ORDER BY.
clickhouse-client --query "
  ALTER TABLE events_ocsf DROP PROJECTION events_by_actor;
"

clickhouse-client --query "
  ALTER TABLE events_ocsf ADD PROJECTION events_by_actor (
    SELECT *
    ORDER BY (tenant_id, actor.user.uid, time)
  );
"

# 3. Materialise it on existing parts.
clickhouse-client --query "
  ALTER TABLE events_ocsf MATERIALIZE PROJECTION events_by_actor;
"

# 4. Watch progress.
clickhouse-client --query "
  SELECT command, is_done, progress, elapsed
  FROM system.mutations
  WHERE table = 'events_ocsf' AND not is_done
"
```

The rebuild runs in the background; queries against the table continue
to work, but `events_by_actor`-accelerated queries fall back to a full
scan until materialisation completes.

---

## 11. Verify Postgres FORCE-RLS is on

Every tenant-scoped table must have row-level security enabled **and**
forced (so even the table owner cannot bypass it). The verification
query:

```sql
SELECT n.nspname            AS schema,
       c.relname            AS table,
       c.relrowsecurity     AS rls_enabled,
       c.relforcerowsecurity AS rls_forced
FROM   pg_class c
JOIN   pg_namespace n ON n.oid = c.relnamespace
WHERE  c.relkind = 'r'
  AND  n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND  EXISTS (
         SELECT 1 FROM pg_attribute a
         WHERE a.attrelid = c.oid AND a.attname = 'tenant_id'
       )
ORDER BY n.nspname, c.relname;
```

Expectation: every row shows `rls_enabled = t` AND `rls_forced = t`.
Any `f` in either column is a **P0 finding** — open a hotfix branch
adding `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` and
`ALTER TABLE ... FORCE ROW LEVEL SECURITY`. The same check runs in CI
(`ci/migrations`) so the gap is normally caught pre-merge.

`tenant_id` setter at request entry:

```sql
SET LOCAL sentinelx.tenant_id = '11111111-1111-1111-1111-111111111111';
SET LOCAL ROLE sentinelx_app;
```

Both `SET LOCAL`s are emitted by `sx-storage::conn::pin_tenant()` once
per checkout from the pool.

---

## 12. Read structured logs

SentinelX emits one JSON object per line.

```bash
# Live tail across all pods.
kubectl -n sentinelx logs -f -l app.kubernetes.io/name=sentinelx --tail=100 \
  | jq -rc 'select(.level=="ERROR" or .level=="WARN")'

# Only auth events for a specific user (hashed_attempt_id):
kubectl -n sentinelx logs -l app.kubernetes.io/name=sentinelx --since=1h \
  | jq -c 'select(.target=="iam::login" and .attempt_id=="<hash>")'

# Slowest 20 requests in last hour:
kubectl -n sentinelx logs -l app.kubernetes.io/name=sentinelx --since=1h \
  | jq -c 'select(.message=="request completed")' \
  | jq -s 'sort_by(.duration_ms)|reverse|.[0:20]|.[]|{ts,route,status,duration_ms}'
```

Trace correlation: every log line carries `trace_id` and `span_id`.

---

## 13. Common failure modes & recovery

### 13.1 DB unreachable

**Symptoms**: `/readyz` 503, logs `database connect: timeout` or
`statement_timeout`, alert `SXDatabaseDown`.

```bash
kubectl -n sentinelx exec deploy/sentinelx -- \
  sh -c 'pg_isready -d "$SENTINELX__DATABASE__URL"'
```

- If `pg_isready` fails: check managed-DB console; verify NetworkPolicy.
- If `pg_isready` succeeds but queries time out: investigate slow
  queries via `pg_stat_activity` and bump `statement_timeout_ms`
  temporarily.

### 13.2 OTLP collector down

**Symptoms**: logs `otlp export failed`; no traces. App keeps serving.

```bash
kubectl -n observability get pod -l app.kubernetes.io/name=opentelemetry-collector
kubectl -n observability logs -l app.kubernetes.io/name=opentelemetry-collector --tail=200
```

Recovery: restart the collector. If down >15 min and you need traces,
set `SENTINELX__TELEMETRY__OTLP_ENDPOINT=""` to disable export until
recovery.

### 13.3 Secrets missing / invalid

**Symptoms**: pod in `CrashLoopBackOff`; init log `config error: SENTINELX__JWT__SIGNING_KEY missing`.

```bash
kubectl -n sentinelx get secret sentinelx-secrets -o yaml | yq '.data | keys'
kubectl -n sentinelx describe pod -l app.kubernetes.io/name=sentinelx \
  | sed -n '/Events:/,$p'
```

Recovery: re-apply the secret, delete the failing pod.

### 13.4 Kill switch stuck on

```bash
kubectl -n sentinelx exec deploy/sentinelx -- \
  redis-cli -u "$SENTINELX__REDIS__URL" DEL sentinelx:killswitch:active
kubectl -n sentinelx exec deploy/sentinelx -- \
  redis-cli -u "$SENTINELX__REDIS__URL" PUBLISH sentinelx.killswitch reset
```

Followed by the formal two-person reset via the API.

### 13.5 Migration Job failed

```bash
kubectl -n sentinelx get job -l app.kubernetes.io/component=migrate
kubectl -n sentinelx logs job/sentinelx-migrate
```

Fix the failing migration, build a new image, delete the failed Job,
re-run `helm upgrade`.

### 13.6 KEK provider unreachable

If `readyz` reports `kek_aws.ok = false` (or `kek_gcp`, `kek_azure`):

```bash
# Verify the SDK can talk to the provider from the pod.
kubectl -n sentinelx exec deploy/sentinelx -- \
  sh -c 'aws kms describe-key --key-id alias/sentinelx-tenant-<tid>'

# Or for GCP:
kubectl -n sentinelx exec deploy/sentinelx -- \
  sh -c 'gcloud kms keys versions list --location global --keyring sentinelx --key tenant-<tid>'
```

If the provider is genuinely down >5 min, fail over to the secondary
provider configured in `kek.fallback_provider` — see
`docs/operations/runbook.md#8-rotate-the-kek-per-provider` for the
rewrap flow.

---

## 14. On-call escalation path

| Tier   | Role                       | Channel                  | SLA     |
|--------|----------------------------|--------------------------|---------|
| L1     | SentinelX on-call primary  | `#sx-oncall`             | 15 min  |
| L2     | SentinelX platform lead    | PagerDuty escalation     | 30 min  |
| L3     | Engineering manager        | PagerDuty escalation     | 60 min  |
| Sec    | Security on-call           | `#sec-oncall`            | Any kill-switch trip or data-exfil suspicion |
| CCO    | Chief Compliance Officer   | PagerDuty                | Any audit-chain CRITICAL or P0 breach        |

Update the table with real contact info during go-live.
