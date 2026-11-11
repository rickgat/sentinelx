# SentinelX local multi-region smoke harness

> **Status:** LOCAL-VALIDATED — TOP5-#4 follow-up to
> `bbb7f70` (TOP5-#4 PARTIAL).
> **Scope:** lets the PO drive the TOP5-#4 validation artifacts
> (k6 scripts, migration parity, runbooks) on a laptop before paying for
> a cloud staging cluster.

---

## 1. What this is

A `docker-compose` stack that boots a SentinelX deployment that looks
*topologically* like a multi-region production install:

```
                         smoke_runner (k6)
                                │
                                ▼
                          [ nginx_lb :8090 ]
                            │        │
                            ▼        ▼
                  [ monolith_primary ]   [ monolith_standby ]
                            │        │
                            └───┬────┘
                                ▼
              [ pg_primary ] ──── streaming repl ────▶ [ pg_standby ]
                                ▲
                                │
                          [ clickhouse ]   (analytics path, dormant in smoke)
```

It is enough infrastructure to:

- Run `tests/load/k6/auth_flow.js` against a real HTTP load balancer.
- Validate that two `sx-monolith` instances behind nginx round-robin
  serve the same auth-flow journey.
- Run `tests/migration/parity_check.sh` against a Postgres 16 in the
  same Docker engine.
- Dry-run the `docs/runbooks/multi-region-deployment.md` §6 promotion
  playbook (`pg_basebackup` → `standby.signal` → `pg_promote()`) on a
  real streaming-replication pair.

## 2. What this is NOT

- **Not real multi-region.** Single host, single Docker network, no
  cross-region latency, no anycast, no GeoDNS.
- **Not a cloud-LB failover validator.** nginx round-robin only; no
  active health probing in the OSS build.
- **Not a ClickHouse multi-shard topology.** Single CH node is enough
  for the smoke; multi-shard CH requires Keeper / Zookeeper plus
  per-shard config that is out of scope for a laptop harness.
- **Not a network-partition validator.** Docker bridge networking
  doesn't model partitions; use `tc netem` or `pumba` separately if
  you need that.
- **Not a Postgres-backed monolith smoke.** The monolith config in
  `monolith_config/sentinelx.local.yaml` keeps `database.enabled =
  false` so the smoke focuses on the wire / LB path. The Postgres
  cluster is still booted so the **migration parity** and the
  **streaming-replication topology** are validated independently. To
  flip the monolith onto the live primary, set `database.enabled =
  true` and `database.url` in the config and rebuild.

## 3. Files in this directory

| File | Purpose |
| --- | --- |
| `docker-compose.yml` | the stack |
| `.env.example` | dev creds (copy to `.env`) |
| `pg_primary/init.sql` | replication role + slot |
| `pg_primary/pg_hba_extra.sh` | appends `host replication` line on first boot |
| `pg_standby/standby-entrypoint.sh` | `pg_basebackup` → standby.signal → exec |
| `nginx_lb/nginx.conf` | round-robin upstream + `/lb-health` |
| `monolith.dockerfile` | rust:bookworm build → debian-slim runtime |
| `monolith_config/sentinelx.local.yaml` | container-friendly dev config |
| `scripts/parity_local.sh` | wrapper around `tests/migration/parity_check.sh` |

## 4. Prereqs

- Docker Engine ≥ 24 (Compose v2 plugin)
- ~6 GB free RAM (Rust release build is the heavyweight; once cached
  the stack runs in ~2 GB)
- Free local ports: `8090` (LB), `55432`/`55433` (pg primary/standby),
  `58123`/`59000` (clickhouse).

## 5. Bring up

```bash
# 1. From the repo root.
cd deploy/local-multiregion

# 2. Copy the dev env defaults (safe — well-known constants).
cp .env.example .env

# 3. Build images + boot. First build runs `cargo build --release -p
#    sx-monolith` inside the builder image; expect 10–25 min on first
#    run, ~1 min on subsequent runs (cargo cache layer).
docker compose up -d --build

# 4. Wait for health.
docker compose ps
# All six services should report (healthy). nginx_lb depends on both
# monoliths being healthy, so once it's up you're ready to smoke.
```

## 6. Run the smoke (k6)

The compose file mounts `tests/load/` into the `smoke_runner` container
at `/tests/load/`, so the workspace scripts are available as-is.

```bash
# Single-VU smoke (10 s) — what the smoke_runner env is preset for.
docker compose exec smoke_runner k6 run /tests/load/k6/auth_flow.js

# Full load run (20 VUs / 5 min) by overriding env on the exec line.
docker compose exec \
    -e K6_VUS=20 -e K6_DURATION=5m \
    smoke_runner k6 run /tests/load/k6/auth_flow.js

# Run the other scripts the same way:
docker compose exec smoke_runner k6 run /tests/load/k6/scan_flow.js
docker compose exec smoke_runner k6 run /tests/load/k6/finding_emission_burst.js
docker compose exec smoke_runner k6 run /tests/load/k6/saml_acs.js
```

The smoke_runner image is `grafana/k6:0.51.0`, which is the version the
workspace targets in `tests/load/README.md` §2.

## 7. Run the migration parity gate locally

```bash
# From the repo root.
./deploy/local-multiregion/scripts/parity_local.sh
```

The wrapper:

1. Checks `docker info` is reachable.
2. Defers to `tests/migration/parity_check.sh`, which boots its **own**
   ephemeral Postgres container on port 55434 (so it doesn't collide
   with `pg_primary` on 55432).
3. Reports pass / fail and the schema dump path on success.

Expected exit code: **0**. Forward-only migrations report
`PARITY CHECK PASSED (forward-only mode)` per the script's own
documented contract.

## 8. Failover dry-run against pg_primary / pg_standby

Once the stack is up, the failover-playbook in
`docs/runbooks/multi-region-deployment.md` §6.2 (promote standby → new
primary) can be exercised:

```bash
# Confirm replication is live.
docker compose exec pg_primary psql -U sentinelx -d sentinelx -c \
    "SELECT slot_name, active, restart_lsn FROM pg_replication_slots;"
# Expect: sx_standby_slot | t | <lsn>

# Promote the standby (the actual playbook step).
docker compose exec pg_standby psql -U sentinelx -c "SELECT pg_promote(true, 60);"

# Verify it's now a primary.
docker compose exec pg_standby psql -U sentinelx -d sentinelx -c \
    "SELECT pg_is_in_recovery();"
# Expect: f
```

This dry-run is the cheap rehearsal that the runbook §6 expects every
on-call to do at least once a quarter — see also
`docs/runbooks/failover-drill-template.md`.

## 9. Tear down

```bash
# Stop containers; keep volumes (faster relaunch).
docker compose down

# Clean slate: also drop volumes (pg_primary_data, pg_standby_data).
docker compose down -v
```

## 10. CI

This harness is **not wired into CI**. CI runs the k6 scripts against a
separately-provisioned staging cluster post-cluster-up (the cloud-infra
half of TOP5-#4 still belongs to the PO). This stack exists so a PO
can validate the artifacts locally before paying for that cloud
staging.

## 11. Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `monolith_primary` build fails on `apt-get update` | Corporate proxy / mirror outage | Set `--build-arg HTTP_PROXY=` and rebuild |
| `pg_standby` exits with "no pg_hba.conf entry for replication" | `pg_hba_extra.sh` did not run (PGDATA pre-existed) | `docker compose down -v` then `up` again |
| `nginx_lb` healthcheck times out | One of the monoliths is `unhealthy` | `docker compose logs monolith_primary` — usually a YAML parse error |
| `smoke_runner exec` reports "executable file not found" for k6 | Image not pulled / version drift | `docker compose pull smoke_runner` |
| k6 `login: status is 200` check fails | Seed creds drift | Confirm `bootstrap.admin_password_phc` in `monolith_config/sentinelx.local.yaml` still verifies `sentinelx-admin-pw` |

## 12. Cross-references

- Validation artifacts: `tests/load/README.md`, `tests/migration/`
- Runbook this harness lets you dry-run: `docs/runbooks/multi-region-deployment.md` §12
- Failover drill: `docs/runbooks/failover-drill-template.md`
- SLO contract: `docs/slos.md`, `docs/slos-production.md`
- TOP5-#4 backlog row: `docs/SPRINT_HARDENING_HANDOFF.md`
