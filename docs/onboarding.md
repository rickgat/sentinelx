# SentinelX Onboarding Guide

Maintainer: Platform Engineering (`#sentinelx-platform`)
Last reviewed: 2026-06-25
Reflects HEAD: `6a182a8` (46/47 of P0–P3 remediation tasks delivered;
TOP5-#1 PHASE-1A → PHASE-2B + TOP5-#3 Phase 2 all eight emitters +
TOP5-#5 MVP + FU1/FU2/FU3 + SSRF guard + QC suite landed
2026-06-24 → 2026-06-25 wave)

Welcome. This document is the single source of truth for ramping up on
SentinelX. If anything here is wrong, fix it in the same PR as your
finding — onboarding docs are tested by the next new hire and rot fast
otherwise.

Cross-refs: [FSD.md](FSD.md) for the functional surface,
[ARCHITECTURE.md](ARCHITECTURE.md) for runtime topology,
[slos.md](slos.md) for the SLO catalog,
[SECURITY_GAP_REMEDIATION_TASKS.md](SECURITY_GAP_REMEDIATION_TASKS.md)
for the in-flight programme.

---

## 1. Why SentinelX exists (the one-page executive summary)

SentinelX is a continuous security validation platform. We do four
things, in order, on a tight loop:

1. **Discover** what an organisation actually owns — domains, hosts,
   buckets, repositories, cloud accounts — without trusting a
   hand-typed asset inventory.
2. **Correlate** every finding with live threat intelligence (NVD,
   EPSS, CISA KEV, TAXII feeds, vendor advisories, GitHub advisories)
   and compute a single composite risk score per asset and per finding.
3. **Validate** that findings are exploitable in this specific
   environment by traversing a Neo4j attack graph, then optionally
   running guarded breach-and-attack simulations (BAS) against the
   customer's own infrastructure.
4. **Report and remediate** with auditor-ready PDF / SARIF / STIX / CSV
   output and a remediation copilot that proposes vendor-blessed fixes
   under strict human-in-the-loop guardrails.

We exist because the existing market splits the workflow across at
least four tools (ASM, VM, BAS, GRC) and customers pay for the
integration glue in human-hours. SentinelX collapses the loop into one
platform with a shared knowledge graph and a single
tamper-evident audit trail.

**Non-goals**: SentinelX is not an EDR, not a SIEM, not a SOAR (we
embed a SOAR engine for workflow automation but we are not the system
of record for host telemetry or alert routing).

### Who uses it

- **Security engineers** drive engagements, review findings, run BAS.
- **GRC / compliance leads** pull control mappings and evidence packs.
- **Engineering managers** look at remediation copilot suggestions.
- **Auditors** receive read-only reports and the cryptographic audit
  log proof bundle (RFC 3161 TSA + S3 Object Lock COMPLIANCE).
- **Operators (us)** keep the lights on and the kill switch oiled.

### The promise

> Every mutating action SentinelX takes is logged into a tamper-evident
> audit chain; every simulated attack is gated by mode / window /
> approval / kill-switch; every external dependency is reached through
> a port so the platform is testable without the internet.

---

## 2. Prerequisites

| Tool | Required version | Why |
|---|---|---|
| Rust toolchain | 1.88 stable | Pinned in `rust-toolchain.toml`; auto-installed by rustup. |
| Cargo | bundled with Rust 1.88 | Build and test runner. |
| Node.js | 22 LTS | `web/dashboard` is Next.js 15 / React 19. |
| npm | bundled with Node 22 | Dashboard package manager (workspace uses npm, not pnpm). |
| `argon2` CLI | latest | Generate Argon2id PHC strings for bootstrap admin. `brew install argon2` on macOS; `apt install argon2` on Debian/Ubuntu. |
| Docker Engine | ≥ 24.0 | Optional. Required only when running Postgres / Redis locally instead of the in-memory adapters. |
| Postgres | 16 | Optional. Default config (`bootstrap.enabled = false`, `database.enabled = false`) runs entirely in memory. |
| Redis | 7 | Optional. Same — required only for the Redis-backed kill switch and lockout tracker. |
| Neo4j | 5.x | Optional. Required for `sx-graph` Neo4j adapter; otherwise the in-memory adapter is used. |
| `sqlx-cli` | 0.8.x | DB migrations. `cargo install sqlx-cli --no-default-features --features rustls,postgres`. |
| `cargo-deny` | 0.16.x | License + advisory checks. `cargo install cargo-deny`. |
| `cargo-nextest` | latest | Faster test runner. `cargo install cargo-nextest`. |
| `shellcheck` | ≥ 0.9.0 | Lint `scripts/`. CI gates on it. |
| `libxmlsec1` (system pkg) | 1.2.x | **Optional.** Required only when building `sx-xmlsec` with the `xmlsec1` feature (TOP5-#1 libxmlsec1 SAML signature verifier). Default workspace build leaves the feature OFF so this package is not required for `cargo check --workspace`. macOS: `brew install libxmlsec1`; Debian/Ubuntu: `apt install libxmlsec1-dev libxmlsec1-openssl libxml2-dev pkg-config`. See [ADR-0022](./adr/0022-saml-xmldsig-libxmlsec1-replacement.md) and `runbooks/supply-chain.md` §8. |

Verify:

```sh
rustc --version           # rustc 1.88.0 (...)
node --version            # v22.x
npm --version
argon2 -h | head -1       # Argon2 PHC string generator
cargo --version
sqlx --version
cargo deny --version
cargo nextest --version
docker compose version    # only if running Docker stack
```

---

## 3. Repo layout

```
security-check/
├── Cargo.toml                  # workspace root
├── Cargo.lock
├── rust-toolchain.toml         # pins Rust 1.88
├── rustfmt.toml
├── clippy.toml
├── deny.toml                   # cargo-deny config
├── docker-compose.yml          # optional: postgres, redis, jaeger, otel
├── README.md
├── api/openapi.yaml            # generated mirror of /openapi.json
├── config/
│   └── sentinelx.example.yaml  # config template; copy to sentinelx.yaml
├── crates/                     # 40 sx-* crates; hexagonal — no direct deps
├── services/
│   ├── sx-monolith/            # the production binary (composition root)
│   ├── sx-cli/                 # operator CLI
│   └── sx-agent/               # remote probe agent
├── web/
│   └── dashboard/              # Next.js 15 / React 19 dashboard
├── scripts/
│   ├── local-dev.sh            # boot full stack
│   └── local-dev-pg.sh         # Postgres-only fast iteration
├── deploy/                     # Helm charts, kustomize overlays
├── docs/                       # this directory
└── target/                     # cargo output (gitignored)
```

### The 40 sx-* crates in one sentence each

| Crate | Purpose |
|---|---|
| `sx-core` | Shared kernel: errors, `TenantId`, `RequestId`, time, IDs. |
| `sx-config` | Typed `serde`-backed config loader from YAML + `SENTINELX__*` env overrides. |
| `sx-telemetry` | OTel tracing + Prometheus metrics exporter. |
| `sx-storage` | Postgres + Redis pools, in-memory test repos, FORCE-RLS migrations. |
| `sx-audit` | Hash-chained append-only audit log; RFC 3161 TSA anchoring (P1-015); replay (P3-009). |
| `sx-iam` | Tenants, users, JWT, OIDC, password reset, SAML (P0-004), WebAuthn (P1-002). |
| `sx-scim` | SCIM 2.0 user / group sync + scoped tokens (P0-005). |
| `sx-engagement` | Engagement lifecycle state machine. |
| `sx-discovery` | Asset discovery + agent-less probing + DAST scans (P2-013). |
| `sx-vuln-ingest` | Multi-scanner import: Nessus, Qualys, Burp, Nuclei, OpenVAS, OWASP ZAP (P0-002). |
| `sx-risk` | Composite risk scoring + per-tenant tuning (P1-014). |
| `sx-graph` | Attack graph via Neo4j adapter (P1-001) + in-memory test adapter. |
| `sx-bas` | Breach-and-attack simulation; safety pipeline; kill switch; BAS chains (P2-015). |
| `sx-remediation` | Vendor advisories + Claude copilot + HITL approvals (P1-012); remediation outcomes (P1-011). |
| `sx-compliance` | Framework catalogue + control mapping + evidence collector (P1-004). |
| `sx-report` | Reports + templates + diff (P2-001/2/3) producing PDF / SARIF / STIX / CSV. |
| `sx-ml` | Triage classifier + UEBA baseline / anomaly detection (P2-005). |
| `sx-collab` | Comments, mentions, watchers, OOB collaborator receivers. |
| `sx-autonomy` | Auto-remediation PR proposals + cross-tenant threat network. |
| `sx-cloud` | AWS / GCP / Azure inventory + drift baselines (P2-004) + blast radius (P1-010). |
| `sx-intel-feeds` | NVD / KEV / EPSS / TAXII pull adapters (P0-001 / P0-006 / P1-013). |
| `sx-intel-ioc` | Bloom-backed IOC lookup + STIX 2.1 parser. |
| `sx-api` | Axum HTTP gateway + OpenAPI 1.1 spec generator + per-route trait `port.rs`. |
| `sx-device-trust` | Device posture policy + session evaluation (P2-008). |
| `sx-rba` | Risk-based authentication + impossible-travel detector (P1-003 / P2-007). |
| `sx-runtime` | Falco runtime webhook receiver (P2-016). |
| `sx-policy` | K8s admission controller + OPA bundle loader (P2-014). |
| `sx-hunt` | KQL + SPL parser and query engine (P3-006). |
| `sx-ir-playbooks` | IR incident state machine + step gating (P3-004). |
| `sx-dlp` | DLP pattern engine + scan results (P2-006). |
| `sx-integrations` | GRC connectors (P2-009) + bug-bounty platforms (P3-010). |
| `sx-soar` | Workflow engine: DAG steps, triggers, run history (P3-005). |
| `sx-plugins` | Manifest-installed plugins with scoped tokens (P3-007). |
| `sx-webhooks` | Outbound webhooks + chat-ops (P3-002) + mobile push (P3-008). |
| `sx-chaos` | Chaos injection middleware behind `SX_CHAOS_ENABLED` (P2-012). |
| `sx-secrets` | KEK provider trait + AWS / GCP / Azure / Vault implementations (P1-005/6/7). |
| `sx-mtls` | mTLS server + client adapter (optional at boot). |
| `sx-soc` | SOC alert correlator + OCSF event sink (P0-003). |
| `sx-twin` | Digital twin snapshot + scenario engine. |
| `sx-log-ingest` | OCSF NDJSON log ingest (P0-003). |

### The crate dependency rule

Crates **never depend on each other directly**. If `sx-risk` needs a
finding, it defines a `FindingsPort` trait and asks the composition
root to inject an implementation. The composition root
(`services/sx-monolith/src/adapters/mod.rs`) is the only place where
adapters are wired into traits. This is hexagonal architecture and it
is enforced by `cargo-deny` config in `deny.toml`. If you find
yourself adding `sx-iam` as a `[dependencies]` entry to another crate,
stop and read [ADR 0001](./adr/0001-rust-modular-monolith.md).

### `services/sx-monolith` composes everything

```text
services/sx-monolith/src/main.rs
    builds: PgPool, RedisPool, ClaudeClient, Neo4jClient, KEK provider, ...
    constructs: Box<dyn IamPort>, Box<dyn EngagementPort>, ...
    mounts: sx_api::router::build_router(state) into axum Router
    starts: axum server + telemetry + audit chain rotator + TSA anchor job
```

The same binary boots into hermetic-test mode (in-memory adapters,
no Postgres / Redis / Neo4j), local-dev mode (Postgres on Docker), or
production mode (real cloud, real Claude API, real KMS).

---

## 4. First build

```sh
git clone <repo>
cd security-check
cargo build --release
```

Target build times:

| Build kind | Target |
|---|---|
| Cold (no `target/` cache) | ≤ 15 min |
| Warm incremental (single crate change) | ≤ 45 s |

If your cold build exceeds 15 minutes, check `~/.cargo/config.toml`
for parallel codegen settings and run `cargo build --release
--timings` to find the slow crate.

---

## 5. Bootstrap admin flow

The monolith ships in a **safe-by-default** configuration:

- `bootstrap.enabled = false` — no admin is seeded on first boot.
- `database.enabled = false` — repositories are in-memory.
- `redis.enabled = false` — kill switch uses in-memory broadcast.

There are two paths to a working dev instance — pick one:

### Quick path (matches README quick-start)

If you only want a local instance that backs the credentials documented
in `README.md` (`admin@sentinelx.dev` / `sentinelx-admin-pw` / tenant
`01010101-0101-0101-0101-010101010101`):

```sh
cp config/sentinelx.dev.example.yaml config/sentinelx.dev.yaml
SENTINELX_CONFIG=./config/sentinelx.dev.yaml \
  cargo run --release -p sx-monolith
```

The example file is checked into the repository (gitignore carves a
one-line exception) and contains a verified Argon2id PHC for the
documented password plus a well-known HS256 signing key + pepper.
**Never reuse those values outside local dev.** A 10-line wrapper —
`scripts/dev-bootstrap.sh` — does the copy + sets `SENTINELX_CONFIG`
for you.

### Quick path — local multi-region (docker-compose)

For exercising failover / read-replica behaviour or running the k6
load harness against a near-prod topology without a cloud account,
boot the local multi-region smoke stack instead:

```sh
cp deploy/local-multiregion/.env.example deploy/local-multiregion/.env
docker compose -f deploy/local-multiregion/docker-compose.yml up -d --build
# smoke run inside the prewired k6 container
docker compose -f deploy/local-multiregion/docker-compose.yml \
  exec smoke_runner k6 run /tests/load/k6/auth_flow.js
# parity check (Pg primary vs standby logical row count diff)
./deploy/local-multiregion/scripts/parity_local.sh
```

The stack ships 7 services: Postgres primary + streaming standby, a
single ClickHouse, two `sx-monolith` instances, nginx LB doing
round-robin to both monoliths with a `/lb-health` probe, and a k6
0.51 smoke_runner mounted against `tests/load/`. Both monoliths read
the dev YAML at `deploy/local-multiregion/monolith_config/sentinelx.local.yaml`.
This is the same harness the PO uses to validate the TOP5-#4 cloud
runbook steps before provisioning real infrastructure — see
[`runbooks/multi-region-deployment.md`](./runbooks/multi-region-deployment.md)
§12.

### Custom path (per-deployment PHC, your own admin email / tenant)

The remainder of this section walks the long-form flow used for
staging, production, and any deployment that must not ship a
well-known credential:

1. Generate an Argon2id PHC hash for your admin password (§5.1).
2. Set the `SENTINELX__BOOTSTRAP__*` env vars (or edit
   `config/sentinelx.yaml`).
3. Boot the monolith.

### 5.1 Argon2id PHC generation

We use Argon2id with parameters `m=14` (16 MiB), `t=2`, `p=1`,
matching the workspace policy in `sx-iam`. The `argon2` CLI writes the
PHC string to stdout when run in encode mode (`-e`).

```sh
# Replace `correct horse battery staple` with your dev password.
echo -n 'correct horse battery staple' | \
  argon2 "$(head -c 16 /dev/urandom | base64)" -id -t 2 -m 14 -p 1 -e
# example output:
# $argon2id$v=19$m=16384,t=2,p=1$<salt>$<hash>
```

Paste the entire `$argon2id$...$<hash>` string into
`SENTINELX__BOOTSTRAP__ADMIN_PASSWORD_PHC`.

> **Do not** put the plaintext password into any env var or config
> file. The PHC string is the only artifact the monolith reads.

### 5.2 Required env vars

| Env var | Required | Purpose |
|---|---|---|
| `SENTINELX_CONFIG` | yes | Path to the YAML config (e.g. `./config/sentinelx.yaml`). |
| `SENTINELX__ENVIRONMENT` | yes | `dev` / `staging` / `prod`. Gates loopback bypasses. |
| `SENTINELX__BOOTSTRAP__ENABLED` | yes (dev) | Set to `true` to seed the admin on first boot. |
| `SENTINELX__BOOTSTRAP__ADMIN_TENANT_SLUG` | yes | e.g. `acme`. |
| `SENTINELX__BOOTSTRAP__ADMIN_TENANT_NAME` | yes | Human-friendly name. |
| `SENTINELX__BOOTSTRAP__ADMIN_EMAIL` | yes | Sign-in email; use a **proper email** like `admin@acme.dev`, not the bare `admin@local` (zod rejects bare TLD-less emails — see §7). |
| `SENTINELX__BOOTSTRAP__ADMIN_PASSWORD_PHC` | yes | Argon2id PHC string from §5.1. |
| `SENTINELX__BOOTSTRAP__SEED_DEMO_DATA` | optional | `true` to seed demo tenant + 3 engagements + 5 assets + 8 findings (only honored when DB is disabled). |
| `SENTINELX__JWT__SIGNING_KEY` | yes | base64 HS256 key ≥ 32 bytes. |
| `SENTINELX__DATABASE__URL` | optional | Postgres URL when `database.enabled = true`. |
| `SENTINELX__DATABASE__ENABLED` | optional | `true` to use Postgres instead of in-memory. |
| `SENTINELX__REDIS__URL` | optional | Redis URL when `redis.enabled = true`. |
| `SENTINELX__REDIS__ENABLED` | optional | `true` to enable Redis-backed kill switch. |
| `SENTINELX__AI_COPILOT__API_KEY` | optional | Anthropic API key for the copilot. |
| `SENTINELX__SECRETS__KEK__AWS__*` | optional | AWS KMS provider config (P1-005). |
| `SENTINELX__SECRETS__KEK__GCP__*` | optional | GCP Cloud KMS provider config (P1-006). |
| `SENTINELX__SECRETS__KEK__AZURE__*` | optional | Azure Key Vault provider config (P1-007). |
| `SENTINELX__SECRETS__KEK__VAULT__*` | optional | HashiCorp Vault Transit provider config. |
| `SENTINELX__CLOUD__AWS__*`, `__GCP__*`, `__AZURE__*` | optional | Cloud connector credentials. |
| `SENTINELX__GITHUB__*` | optional | Autonomy PR-bot credentials. |
| `SENTINELX__INTEL_FEEDS__*` | optional | NVD / EPSS / KEV / TAXII feed API keys. |
| `SENTINELX__OIDC__*` | optional | OIDC IdP configuration. |
| `SENTINELX__MTLS__ENABLED` | optional | Boot with mTLS. |
| `SX_HTTP_PORT` | optional | Override API bind port (default 8080). |
| `SX_METRICS_PORT` | optional | Override Prometheus scrape port (default 9090). |
| `SX_CHAOS_ENABLED` | optional | `1` to enable `sx-chaos` middleware (P2-012). |
| `POSTGRES_HOST_PORT` | optional | Docker host-port override. |
| `REDIS_HOST_PORT` | optional | Docker host-port override. |
| `AWS_REGION`, `AZURE_*`, `SENTINELX_KMS_TEST_KEY_ID`, `SENTINELX_TEST_BUCKET`, `TEST_DATABASE_URL` | optional | Integration tests only. |

The convention is `SENTINELX__<section>__<field>`, each `__` becomes
one YAML nesting level. Values overlay the YAML file at startup.

### 5.3 Putting it together

```sh
export SENTINELX_CONFIG=./config/sentinelx.yaml
export SENTINELX__ENVIRONMENT=dev
export SENTINELX__JWT__SIGNING_KEY="$(head -c 32 /dev/urandom | base64)"
export SENTINELX__BOOTSTRAP__ENABLED=true
export SENTINELX__BOOTSTRAP__ADMIN_TENANT_SLUG=acme
export SENTINELX__BOOTSTRAP__ADMIN_TENANT_NAME='Acme Corp'
export SENTINELX__BOOTSTRAP__ADMIN_EMAIL='admin@acme.dev'
export SENTINELX__BOOTSTRAP__ADMIN_PASSWORD_PHC='$argon2id$v=19$m=16384,t=2,p=1$<salt>$<hash>'
export SENTINELX__BOOTSTRAP__SEED_DEMO_DATA=true

cargo run --release -p sx-monolith
```

---

## 6. First boot

Once `cargo run` is happy you should see, in order:

1. `sx-config` loaded YAML + env overrides.
2. `sx-telemetry` exporter ready on `:9090/metrics`.
3. `sx-storage` opened in-memory repositories (or migrated Postgres).
4. `sx-audit` rotated the chain segment; TSA anchor job scheduled.
5. `sx-iam` seeded admin user `<admin_email>` for tenant `<slug>`.
6. `sx-api` axum router built (145 paths, 171 operations).
7. Server bound to `127.0.0.1:8080`.

### 6.1 Health check

```sh
curl -sS http://127.0.0.1:8080/healthz | jq
# { "data": { "status": "ok" }, "meta": { "request_id": "...", "ts": "..." } }

curl -sS http://127.0.0.1:8080/readyz | jq
```

### 6.2 OpenAPI discovery

The OpenAPI 1.1 spec is public:

```sh
curl -sS http://127.0.0.1:8080/openapi.json | jq '.paths | keys | length'
# 145
curl -sS http://127.0.0.1:8080/openapi.json | jq '.tags | map(.name)'
# ["operations","engagement","discovery","offensive","detection","identity","governance","developer"]
```

### 6.3 Login

```sh
ACCESS=$(curl -sS -X POST http://127.0.0.1:8080/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"admin@acme.dev","password":"correct horse battery staple"}' \
  | jq -r '.data.access_token')

curl -sS http://127.0.0.1:8080/v1/engagements \
  -H "authorization: Bearer ${ACCESS}" | jq '.data | length'
```

You should see at least 1 if `SEED_DEMO_DATA=true`; otherwise 0
(empty tenant).

---

## 7. Dashboard development

The dashboard lives in `web/dashboard/`. Production-build mode is the
only mode that hits the sub-3 ms p50 menu latency target.

### 7.1 First install

```sh
cd web/dashboard
npm install
```

### 7.2 Production build + serve (recommended)

```sh
npm run build
npm start
# Next.js bound to http://127.0.0.1:3000
```

Why production mode? Next.js dev-mode does on-demand compilation for
every route, which inflates p50 latency by an order of magnitude. The
sidebar p50 ≤ 3 ms target in [slos.md](slos.md) only applies to
`npm start`.

### 7.3 Hot-reload dev mode

If you are iterating on UI code you can run `npm run dev` instead.
Accept that menu latency will be 50–200 ms in this mode; that is a
known property of Next.js dev-server, not a regression.

### 7.4 `/login` flow

1. Open `http://127.0.0.1:3000/login`.
2. Enter the email + password from §5.3.
3. The form posts to the dashboard's `/api/auth/login` proxy, which
   forwards to the monolith's `/v1/auth/login`.
4. On success you are redirected to `/dashboard`.
5. The session cookie is HttpOnly + SameSite=Lax; the JWT lives in
   memory only.

If login fails with a 401, check:

- The monolith logs for `auth.login.failed` audit rows.
- That your dev environment did **not** trigger the RBA "loopback
  block" — see §7 gotchas below.

---

## 8. Common dev gotchas

The four gotchas below catch every new hire at least once.

### 8.1 RBA blocks loopback by default

The risk-based-auth crate (`sx-rba`, P1-003) flags logins from
`127.0.0.1` as high-risk because loopback has no geolocation.
In dev, override by setting an `X-Forwarded-For` header to a public IP
(we use `8.8.8.8` in test scripts):

```sh
curl -sS -X POST http://127.0.0.1:8080/v1/auth/login \
  -H 'content-type: application/json' \
  -H 'x-forwarded-for: 8.8.8.8' \
  -d '{"email":"admin@acme.dev","password":"..."}'
```

The dashboard proxy injects this header automatically when
`SENTINELX__ENVIRONMENT=dev`.

### 8.2 zod email validator rejects bare TLD-less emails

The login form uses zod's email validator on the client. zod rejects
`admin@local` and `admin@sentinelx` because they have no TLD. Use a
`.dev` / `.test` / `.localhost` suffix in dev — for example
`admin@acme.dev` — to pass client-side validation. The monolith
accepts both, but the form will not POST without a TLD.

### 8.3 Velocity-window cool-down

Repeated failed logins from the same IP within the velocity window
(default 15 minutes) start to debit `sx-rba`'s velocity score. Five
failures inside the window will lock the account for 15 minutes.
If you have been thrashing your password during dev:

```sh
# Either wait 15 minutes, or restart the monolith — in-memory adapter
# state is reset, and Postgres-backed lockout rows can be cleared with:
psql $DATABASE_URL -c "DELETE FROM iam_login_lockouts WHERE email_hash = '<sha256_of_email>';"
```

### 8.4 Dev cache nuke

If the dashboard behaves strangely after pulling new code — usually
because Next.js cached a stale RSC payload or a Turbopack module map
— blow away the local caches:

```sh
cd web/dashboard
rm -rf .next .turbo node_modules/.cache
npm run build
npm start
```

This recovers in 90% of "but it works on main" cases.

---

## 9. Testing

### 9.1 Rust tests

```sh
cargo test --workspace
# Or, faster + better isolated:
cargo nextest run --workspace --all-features
```

Per-crate:

```sh
cargo nextest run -p sx-engagement
cargo nextest run -p sx-bas --test safety_pipeline
```

Integration tests against Postgres (set `TEST_DATABASE_URL`):

```sh
scripts/local-dev-pg.sh
export TEST_DATABASE_URL="postgres://sentinelx:sentinelx_dev@127.0.0.1:5432/sentinelx"
sqlx migrate run --source crates/sx-storage/migrations
cargo nextest run -p sx-storage --test '*'
```

### 9.2 Clippy (strict workspace lints)

```sh
cargo clippy --workspace --all-targets -- -D warnings
```

CI fails on any warning. The workspace lints are declared in
`Cargo.toml` `[workspace.lints.*]` and `clippy.toml`.

> **Note (MSRV cascade).** The 2026-06-23 LOW-001-FU2 cascade bumped
> rustc 1.88 → 1.92. New clippy lints (`cloned_ref_to_slice_refs`,
> `doc_markdown`, `duplicated_attributes`, `filter_next`,
> `significant_drop_tightening`) became errors against pre-existing
> code; LOW-009-FU1 (`5166f00`) cleared them. **When you next bump
> MSRV, bundle a clippy-sweep task in the same wave** — the lint
> surface always widens on a stable rustc bump.

### 9.2.1 Format (workspace baseline enforced)

```sh
cargo fmt --all -- --check     # CI gate
cargo fmt --all                # local fix
```

As of the 2026-06-24 sweep (M3-FU1, commit `b85048b`) workspace fmt is
clean against stable rustfmt. The previously-tolerated
`match_arm_blocks = true` setting in `rustfmt.toml` is unstable and
silently skipped by stable rustfmt; the sweep cleared 401 files of
accumulated drift (+6014/-5199) and going forward **agent dispatches
must NOT run `cargo fmt --workspace` mid-flight** — it produces
hundreds of cross-file edits that contaminate the salvage-and-finish
pattern. Hand-edit affected lines instead, or restrict fmt to the
files you actually touched.

### 9.3 Dashboard tests

```sh
cd web/dashboard
npm test                      # vitest (unit + component)
npx playwright test           # e2e (requires monolith running on :8080)
```

The Playwright suite covers sign-in, engagement create, BAS approve,
and audit-replay flows end-to-end against a real monolith.

### 9.4 Quick reference

| Want | Command |
|---|---|
| One Rust test by name | `cargo nextest run -p sx-iam tenant_create_persists` |
| Verbose logs from one test | `RUST_LOG=debug cargo nextest run -p sx-iam --nocapture` |
| Style check | `cargo fmt --all -- --check` |
| Auto-fix style | `cargo fmt --all` |
| License + advisory audit | `cargo deny check` |
| Snapshot review | `cargo insta review` |
| Fuzz a target (24 h) | `cargo +nightly fuzz run audit_decode -- -max_total_time=86400` |
| Dashboard one test | `npx playwright test e2e/login.spec.ts` |

If a Rust test reaches the network, it MUST be marked `#[ignore]`
with the reason `requires_network`. Default `cargo test` runs offline.

### 9.5 Integration tests that bin-spawn the monolith

Several new tests (added in the SX-REVIEW-002 + FOUND-001 + TOP5-#3
P2 waves) spawn the production `sx-monolith` binary against the dev
example config and assert wire-level behaviour:

| Test | Crate | What it asserts |
|---|---|---|
| `login_with_readme_creds.rs` | `sx-monolith` | README quick-start credentials POST 200 on `/v1/auth/login` (C2). |
| `login_with_analyst_creds.rs` | `sx-monolith` | Seeded analyst can log in (L1-FU1). |
| `finding_insert.rs` | `sx-monolith` | `FindingRepositoryPort::insert(view)` idempotency on `(tenant_id, id)` (FOUND-001). |
| `audit_chain_break_emits_finding.rs` | `sx-monolith` | Audit-chain break observer fires a FOUND-001 finding (P2-007). |
| `rba_block_emits_finding.rs` | `sx-monolith` | RBA Block decision above threshold emits a finding (P2-005). |
| `saml_attack_emits_finding.rs` | `sx-monolith` | SAML XSW POST to `/v1/auth/saml/acs` is rejected + observer wire-shape (P2-004-FU1). |
| `scan_detail_endpoint.rs` | `sx-api` | `GET /v1/scans/{id}` JSON detail + `.sarif` envelope (QC-SCAN fix). |
| `scan_sarif_endpoint.rs` | `sx-api` | SARIF v2.1.0 envelope reaches the wire (TOP5-#3-P2-SARIF-API). |
| `scan_enrichment_reaches_wire.rs` | `sx-api` | Phase 1 enrichment payload (CVSS / CWE / MITRE) on `/v1/scans/http-headers` (C1). |

These tests use `assert_cmd` to start the binary on an ephemeral port
and `reqwest` to drive HTTP; they need no Postgres / Redis / Neo4j.
They run on every `cargo nextest run --workspace`.

### 9.6 QC suite (integration shell + Playwright)

The QC suite under `tests/integration/qc_*` and `web/dashboard/e2e/qc-edge-cases.spec.ts`
exercises the live `/v1/scans/*` and `/v1/auth/*` endpoints against
the running monolith. Reports land at
`tests/integration/qc_rerun_report_2026-06-25.md`. Run:

```sh
# bring up the monolith on :8080 first
./tests/integration/qc_scan_simulation.sh             # 12 cases
./tests/integration/qc_scan_simulation_extra.sh       # 12 extra cases (DNS rebind, IPv6, AWS/GCP/Alibaba metadata)
cd web/dashboard && npx playwright test e2e/qc-edge-cases.spec.ts
```

---

## 9.7 Disk hygiene + Claude Code worktree pattern

Workspace `target/` directories grow fast — a `cargo build --release`
is ~6 GB and grows another 1–2 GB per `cargo test --workspace` pass.
The standard Claude Code agent dispatch pattern uses **isolated git
worktrees** under `.claude/worktrees/agent-<hash>/` so each agent
builds independently from `main`; this multiplies the disk cost.

Conventions:

- **One worktree per task.** Branch + worktree pattern is documented
  in [`SPRINT_HARDENING_HANDOFF.md`](./SPRINT_HARDENING_HANDOFF.md) §2.1.
  Naming: `feat/<task-id>-<slug>` for features, `docs/<wave>-<slug>`
  for documentation refreshes, `wip/<crate>/<task>` for salvage.
- **`cargo clean` per worktree when disk gets tight.** Run inside the
  worktree (`cd .claude/worktrees/agent-<hash> && cargo clean`) — do
  not `cargo clean` from the main repo or the cached compile of every
  other in-flight worktree disappears too.
- **Drop finished worktrees promptly.** After merging into `main` from
  the orchestrator session: `git worktree remove --force <path>` +
  `git worktree prune`.
- **Use the `rtk` proxy.** Agents should call `rtk` for git / cargo /
  npm operations to claw back the 60-90% token cost on dev plumbing.
  See `~/.claude/RTK.md`.

---

## 10. Commit + PR convention

We use Conventional Commits. Scopes are crate names (without the
`sx-` prefix) or `dashboard`, `infra`, `docs`, plus a sub-area for
docs.

```text
feat(iam): add refresh token rotation
fix(bas): clamp window override to engagement bounds
chore(deps): bump axum to 0.7.12
docs(adr): add 0005 audit log HMAC chain
docs(functional): expand FSD per-page entries
```

### 10.1 PR template highlights

```text
## Summary
- 1-3 bullets.

## Verification
- [ ] cargo nextest run --workspace --all-features green
- [ ] cargo clippy --workspace --all-targets -- -D warnings clean
- [ ] cargo deny check clean
- [ ] Dashboard npm test green (if web/ touched)
- [ ] OpenAPI updated (if HTTP surface changed)

## Blast radius
- Auth / Audit / BAS / Billing: yes / no.
- If yes: which ADR governs this and what review is required?

## Rollout plan
- Feature-flagged? Migration? Backfill?
```

### 10.2 Merge style

Squash merge is the only allowed style on `main`. The squashed
commit message follows Conventional Commits.

### 10.3 ADR for architectural decisions

Any architectural decision — new crate, new port, new external
dependency, change to the safety pipeline — requires an ADR in
`docs/adr/` with the next sequential number. The ADR template is
in `docs/adr/README.md`. ADRs are short: context, decision,
consequences.

### 10.4 Review expectations

- Two reviewers for changes to `sx-iam`, `sx-audit`, `sx-bas`, or
  the composition root. One must be a senior engineer.
- One reviewer for everything else.
- Reviewers run the code for changes in the safety pipeline.
- First response within one business day; final approval within
  two business days.

---

## 11. Where to find things (code map)

| Dashboard module | Backing crate(s) | Port trait |
|---|---|---|
| Operations / SOC | `sx-soc` | `SocPort` |
| Operations / Approvals | `sx-bas`, `sx-remediation` | `ApprovalsPort`, `CopilotApprovalsPort` |
| Operations / Safety | `sx-bas` | `SafetyPort` |
| Engagement / Engagements | `sx-engagement` | `EngagementPort` |
| Engagement / Findings | `sx-storage`, `sx-ml` | `FindingsPort`, `MlTriagePort` |
| Engagement / Remediation | `sx-remediation` | `RemediationOutcomePort` |
| Engagement / Reports | `sx-report` | `ReportPort` |
| Engagement / Copilot | `sx-remediation` | `CopilotPort` |
| Discovery / Scans + Vuln Import | `sx-discovery`, `sx-vuln-ingest` | `ScanPort`, `VulnIngestPort` |
| Discovery / Cloud | `sx-cloud` | `CloudInventoryPort`, `CloudDriftPort` |
| Discovery / Logs | `sx-log-ingest` | `LogIngestPort` |
| Discovery / Intel | `sx-intel-ioc`, `sx-intel-feeds` | `IntelIocPort`, `IntelFeedsPort` |
| Offensive / BAS + Chains | `sx-bas` | `BasPort`, `BasChainPort` |
| Offensive / Graph | `sx-graph` | `GraphPort` |
| Offensive / Blast Radius | `sx-cloud` | `BlastRadiusPort` |
| Offensive / Twin | `sx-twin` | `TwinPort` |
| Offensive / Redteam + DAST | `sx-bas`, `sx-discovery` | `RedteamPort`, `DastPort` |
| Detection / UEBA | `sx-ml` | `UebaPort` |
| Detection / Device Trust | `sx-device-trust` | `DeviceTrustPort` |
| Detection / RBA + Impossible Travel | `sx-rba` | `RbaPort` |
| Detection / Falco | `sx-runtime` | `RuntimePort` |
| Detection / K8s Admission | `sx-policy` | `PolicyPort` |
| Detection / Hunt | `sx-hunt` | `HuntPort` |
| Identity / Auth + SAML + WebAuthn | `sx-iam` | `IamPort`, `SamlPort`, `WebauthnPort` |
| Identity / SCIM | `sx-scim` | `ScimPort` |
| Identity / Secrets (KMS) | `sx-secrets` | `KekProviderPort` |
| Governance / Compliance + Evidence | `sx-compliance` | `CompliancePort` |
| Governance / Audit (replay + anchor) | `sx-audit` | `AuditPort`, `AuditAnchorPort` |
| Governance / GRC | `sx-integrations` | `GrcConnectorPort` |
| Governance / IR Playbooks | `sx-ir-playbooks` | `IrPlaybooksPort` |
| Governance / DLP | `sx-dlp` | `DlpPort` |
| Developer / API Docs + Playground | `sx-api` (controller::openapi) | — |
| Developer / SOAR | `sx-soar` | `SoarPort` |
| Developer / Plugins | `sx-plugins` | `PluginsPort` |
| Developer / Chat-ops + Mobile Push | `sx-webhooks` | `WebhookPort`, `NotificationsPort` |
| Developer / Bug Bounty | `sx-integrations` | `BugBountyPort` |
| Developer / Chaos | `sx-chaos` | `ChaosPort` |
| Developer / Risk Tuning | `sx-risk` | `RiskTuningPort` |
| Developer / Autonomy | `sx-autonomy` | `AutonomyPort` |

All port traits live in `crates/sx-api/src/port.rs`; adapters are
wired in `services/sx-monolith/src/adapters/`.

---

## 12. Where to go next

- Read [`./FSD.md`](./FSD.md) for the per-page + per-endpoint spec.
- Read [`./ARCHITECTURE.md`](./ARCHITECTURE.md) for the dependency
  graph and runtime data flow.
- Read [`./slos.md`](./slos.md) so you know when we are within
  budget and when we are not.
- Skim the [ADR index](./adr/) — each ADR is ~5 minutes and explains
  a load-bearing decision.
- Bookmark the [incident response playbook](./runbooks/incident-response.md);
  you will be on-call within your first six weeks.
- Track the open programme of work in
  [SECURITY_GAP_REMEDIATION_TASKS.md](SECURITY_GAP_REMEDIATION_TASKS.md).
- Join `#sentinelx-platform` (engineering), `#sentinelx-secops`
  (operations), `#sentinelx-onboarding` (your first 90 days).

Welcome to the team. Break things in dev, fix things in main, and ask
questions early.
