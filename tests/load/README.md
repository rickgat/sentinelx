# Load-test harness

> **Status:** Runnable artifacts. Production endpoints exist and respond to
> the seed creds documented in `config/sentinelx.dev.example.yaml`. These
> scripts target a staging deployment of the same `sx-monolith` binary
> exercised by the in-process integration tests under
> `services/sx-monolith/tests/`.
>
> **TOP5-#4 (production-deployment validation):** See
> `docs/SPRINT_HARDENING_HANDOFF.md`. This harness is the runnable half of
> the deliverable; the cloud-infra half remains externally blocked until
> the PO provisions staging.

---

## 1. What this harness measures

Five k6 scenarios, one per critical user journey:

| Script | Journey | Key assertions |
| --- | --- | --- |
| `k6/auth_flow.js` | login → list engagements → list findings → finding detail → logout | per-endpoint p95 < 500 ms, error rate < 1% |
| `k6/scan_flow.js` | login → `POST /v1/scans/http-headers` → poll → fetch SARIF | scan p95 < 30 s, SARIF p95 < 1 s |
| `k6/finding_emission_burst.js` | 1 000 rate-limit rejects in 60 s (P2-008 emission path) | ~4–5 findings (15-min aggregation), insert p95 < 100 ms |
| `k6/saml_acs.js` | replay synthetic XSW fixtures against `/v1/auth/saml/acs` | every known XSW shape rejected within budget |

All scripts reuse the production seed credentials from the dev YAML
(`admin@sentinelx.dev` / `sentinelx-admin-pw`, tenant
`01010101-0101-0101-0101-010101010101`). Staging must seed those rows
identically for the harness to authenticate.

The targets and ports come from environment variables — defaults match
the workspace bootstrap. See §3 for the override matrix.

---

## 2. Prerequisites

- [`k6`](https://k6.io) ≥ 0.49 on the load-driver host. Brew:
  `brew install k6`. The scripts use only the standard `k6/http`,
  `k6/encoding`, `k6/metrics` modules — no extensions required.
- Network reachability from the driver to the staging monolith on the
  `SX_BASE_URL` (default `http://127.0.0.1:8080`).
- Staging seeded with `admin@sentinelx.dev`. (The
  `sx-monolith` binary does this idempotently at boot via
  `config/sentinelx.dev.example.yaml`; CI gates already prove the seed
  is deterministic.)
- For `scan_flow.js`: a reachable test target with a deterministic
  header response. Defaults to `https://httpbin.org/response-headers`
  — override with `SX_SCAN_TARGET` if your egress is firewalled.
- For `saml_acs.js`: no extra setup — the synthetic XSW bodies are
  inlined under `fixtures/saml/`. Note: the live ACS path requires an
  `IdpRecord` for the test tenant (see the deviation note in
  `services/sx-monolith/tests/saml_attack_emits_finding.rs`); when that
  row is missing the script falls back to asserting the *boundary*
  rejection (route + form decode + adapter rejection), which is what
  the FOUND-001 wire-shape test asserts today.

---

## 3. Environment-variable matrix

Every script reads the same base set. Per-script extras are noted under
each script's header.

| Var | Default | Meaning |
| --- | --- | --- |
| `SX_BASE_URL` | `http://127.0.0.1:8080` | scheme://host:port of the staging monolith |
| `SX_ADMIN_EMAIL` | `admin@sentinelx.dev` | seed admin email (per dev YAML §59) |
| `SX_ADMIN_PASSWORD` | `sentinelx-admin-pw` | seed password (per dev YAML §10) |
| `SX_TENANT_ID` | `01010101-0101-0101-0101-010101010101` | seed tenant id |
| `SX_SCAN_TARGET` | `https://httpbin.org/response-headers?HSTS=missing` | URL the http-headers scanner probes |
| `K6_VUS` | per-script default | concurrent virtual users |
| `K6_DURATION` | per-script default | total run duration |

The seed creds match the strings asserted in
`services/sx-monolith/tests/login_with_readme_creds.rs` lines 164–165
and the example config at `config/sentinelx.dev.example.yaml` lines 10
and 48–59. If the seed contract changes, those tests fail before this
harness misbehaves.

---

## 4. Running

```bash
# 1. Smoke a single VU against local staging (catches config drift fast).
k6 run --vus 1 --duration 10s tests/load/k6/auth_flow.js

# 2. Real load run (defaults to 20 VUs / 5 min).
k6 run tests/load/k6/auth_flow.js

# 3. All five scenarios sequentially (~25 min). For CI use `k6 cloud` or
# a parallel runner — k6 itself does not orchestrate multi-script runs.
for s in auth_flow scan_flow finding_emission_burst saml_acs; do
    k6 run "tests/load/k6/${s}.js" || exit 1
done

# 4. Output to JSON for post-run analysis (and Grafana ingestion).
k6 run --out json=results.json tests/load/k6/auth_flow.js
```

### Smoke-test mode

Every script honours `K6_VUS=1 K6_DURATION=10s` for a fast pre-flight.
Use this to verify the staging cluster is reachable and the seed creds
land before kicking off a real load run.

---

## 5. Interpreting results

### 5.1 Pass / fail

k6's exit code is **non-zero** if any threshold defined in the script
fails. The thresholds are codified per script — see the `thresholds:`
block at the top of each file. Treat a zero exit as the SLO gate
passing for that single run.

### 5.2 The four numbers that matter

For every run, record:

1. **Error rate** — `http_req_failed{...}` rate. Target < 1% for
   read paths, < 5% for the scan path (scans are external-target
   dependent).
2. **p95 latency per endpoint** — the per-`name` `http_req_duration`
   p95. Must satisfy the per-endpoint threshold; the budgets mirror
   `docs/slos-production.md` and reconcile against `docs/slos.md`.
3. **Throughput** — `http_reqs` rate. Compared against the
   topology-class capacity claim in
   `docs/runbooks/multi-region-deployment.md` §2.
4. **Custom metrics** — each script defines a `Trend` or `Counter`
   for the scenario-specific SLI (e.g. `scan_completion_time` in
   `scan_flow.js`).

### 5.3 When a threshold fails

1. Re-run with `--vus 1 --duration 30s` to rule out load-side
   exhaustion (driver CPU, ulimit, DNS).
2. Pull the monolith's Prometheus scrape during the failed window —
   `sx_http_request_duration_seconds_bucket{route=...}` is the
   authoritative server-side measurement. The k6 numbers include the
   driver-side network leg.
3. Cross-check with the SLO doc (`docs/slos.md`) — the targets here
   are tighter than the contractual SLOs so a k6 miss is an early
   warning, not yet a contract breach.

---

## 6. Cross-references

- **SLO contract:** `docs/slos.md` (workspace-wide), `docs/slos-production.md`
  (production-deploy gate subset).
- **Telemetry checklist:** `docs/runbooks/telemetry-readiness.md`.
- **Multi-region drill:** `docs/runbooks/multi-region-deployment.md` +
  `docs/runbooks/failover-drill-template.md`.
- **Endpoint inventory:** `crates/sx-api/src/router.rs` is the only
  source of truth for what routes exist. Re-read it if a 404 shows up
  unexpectedly.
- **In-process equivalents:**
  - Auth: `services/sx-monolith/tests/login_with_readme_creds.rs`
  - SARIF: `crates/sx-api/tests/scan_sarif_endpoint.rs`
  - Rate-limit finding: `crates/sx-api/tests/rate_limit_emits_finding.rs`
  - SAML XSW: `services/sx-monolith/tests/saml_attack_emits_finding.rs`

These cover the wire contract in-process; the k6 scripts add load + the
real network leg + cross-endpoint composition.

---

## 7. Local smoke (docker-compose harness)

> **Added 2026-06-25 (TOP5-#4 LOCAL-VALIDATED).** For PO-side validation
> before paying for cloud staging.

The workspace ships a self-contained docker-compose stack at
`deploy/local-multiregion/` that boots `pg_primary` + `pg_standby`
(streaming replication), a single ClickHouse, two `sx-monolith`
instances behind an nginx LB, and a `smoke_runner` container with k6
0.51 pre-installed.

```bash
# 1. Bring up the stack.
cp deploy/local-multiregion/.env.example deploy/local-multiregion/.env
docker compose -f deploy/local-multiregion/docker-compose.yml up -d --build

# 2. Smoke the auth flow from inside the docker network.
docker compose -f deploy/local-multiregion/docker-compose.yml \
    exec smoke_runner k6 run /tests/load/k6/auth_flow.js

# 3. Bigger run (override env on the exec line).
docker compose -f deploy/local-multiregion/docker-compose.yml \
    exec -e K6_VUS=20 -e K6_DURATION=5m \
    smoke_runner k6 run /tests/load/k6/auth_flow.js

# 4. Tear down (drop -v to keep volumes for relaunch speed).
docker compose -f deploy/local-multiregion/docker-compose.yml down -v
```

The harness pre-sets `SX_BASE_URL=http://nginx_lb:8090` and the seed
admin creds inside the `smoke_runner` env (see
`deploy/local-multiregion/docker-compose.yml`). The `tests/load/`
directory is bind-mounted at `/tests/load/` inside the runner so the
workspace scripts run as-is.

**`scan_flow.js` against an airgapped env:** the smoke_runner env
sets `SX_SCAN_TARGET=http://nginx_lb:8090/healthz` to satisfy the
"reachable test target with deterministic header response" prereq
(§2) without requiring egress to `httpbin.org`.

**What it does NOT cover:** real cross-region latency, cloud-LB
failover, ClickHouse multi-shard, network partitions, cloud KMS/IAM.
See `docs/runbooks/multi-region-deployment.md` §12.3 for the full
gap list.

---

## 8. Deviations / scope notes

- `finding_emission_burst.js` exercises the rate-limit emission path via
  the log-ingest surface (`crates/sx-log-ingest::rate_limit`,
  `RATE_LIMITED_COUNTER = "log_ingest.rate_limited_total"`). The
  observable end is the FOUND-001 insertion gate; the script measures
  it via `GET /v1/findings` polling because there is no production
  endpoint that returns insert-latency directly. p95-insert is therefore
  an **upper bound** derived from list-after-insert observation, not a
  per-insert histogram.
- `saml_acs.js` posts the synthetic XSW body and asserts the
  non-200 rejection at the route boundary. The finding-emission
  half (asserting metadata + idempotency) lives in the in-process
  bin-spawn test cited above; a k6 script cannot reach the
  `IdpRecord`-seed surface without a feature-sized admin endpoint
  that does not exist today (same scope constraint documented in
  `saml_attack_emits_finding.rs` lines 24–46).
- All thresholds are tighter than the SLO doc. If a staging run
  needs to relax them temporarily (e.g. before a perf-tuning sprint),
  do it via `--threshold-override` rather than editing the script —
  the script is the documented contract.
