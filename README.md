# SentinelX

SentinelX is a security assessment and operations platform delivered as a
single Rust modular monolith with a Next.js dashboard. It brings
vulnerability management, external attack-surface discovery, combined
penetration testing, breach and attack simulation, AI system auditing,
cloud posture, threat intelligence, detection and response, and
compliance evidence under one control plane, one data model, and one
audit trail.

It is built on a simple premise learned the hard way: findings that are
not correlated, not scoped, and not provable to an auditor are noise.
Every offensive action in SentinelX is bound to an authorized engagement,
every material decision lands in a tamper-evident audit chain, and every
control claim is backed by evidence the platform can produce on demand.

---

## Authorized use

SentinelX contains active offensive capability: network, TLS, web and
API scanning, credentialed scanner ingest, attack simulation, and
prompt-injection probing of language-model endpoints. Run it only
against systems you own or are explicitly authorized in writing to
test. The platform enforces this technically (see
[Offensive safety controls](#offensive-safety-controls)), but technical
gates do not replace a signed Rules of Engagement. A template is
provided in
[`docs/compliance/engagement-roe-template.md`](docs/compliance/engagement-roe-template.md).

---

## Contents

- [What SentinelX is, and what it is not](#what-sentinelx-is-and-what-it-is-not)
- [Engineering doctrine](#engineering-doctrine)
- [Capabilities](#capabilities)
- [Architecture](#architecture)
- [Repository layout](#repository-layout)
- [Getting started](#getting-started)
- [Configuration](#configuration)
- [HTTP API](#http-api)
- [Dashboard](#dashboard)
- [Operator CLI](#operator-cli)
- [Security model](#security-model)
- [Compliance coverage](#compliance-coverage)
- [Observability](#observability)
- [Deployment](#deployment)
- [Testing and quality gates](#testing-and-quality-gates)
- [Maturity and known limitations](#maturity-and-known-limitations)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Reporting a vulnerability](#reporting-a-vulnerability)
- [License](#license)

---

## What SentinelX is, and what it is not

SentinelX is:

- A **system of record for security exposure**: assets, findings,
  engagements, risk scores, and the evidence behind them, isolated per
  tenant.
- An **orchestrator of authorized offensive testing**: one engagement can
  chain reconnaissance, scanning, software composition and secret
  analysis, credentialed scanner import, attack simulation, and
  attack-graph analysis, with cross-scanner correlation and
  de-duplication.
- An **evidence engine**: SOC 2, ISO/IEC 27001, PCI DSS, HIPAA and
  AI-governance controls are mapped to findings and collected as
  verifiable artifacts.

SentinelX is not:

- A replacement for human judgement on exploitability. Automated
  severity is a starting point for triage, not a verdict.
- An EDR or a full SIEM. It ingests and correlates telemetry (OCSF logs,
  Falco runtime alerts, SOC events) but it does not sit in the kernel
  path of your endpoints.
- A certification. Mapping a control is not the same as passing an
  audit; attestation remains the job of your assessor or QSA.

---

## Engineering doctrine

These are not aspirations. They are enforced by the build.

- **Hexagonal boundaries.** Domain crates do not know about HTTP,
  Postgres, or Tokio. Every cross-domain dependency is a Rust trait
  (port). Concrete adapters live only in
  `services/sx-monolith/src/adapters/`, assembled in one composition
  root. The monolith can be split into services without rewriting
  domain logic.
- **Fail closed.** Authorization checks, scope checks, kill switches, ML
  scorers without a model, and external anchors without configuration
  all deny or report `unavailable`. Nothing reports a fabricated pass.
- **No `unsafe`.** The workspace sets `unsafe_code = "forbid"`. The single,
  documented exception is `sx-xmlsec`, the FFI boundary to `libxmlsec1`
  for XML signature verification, which opts out of the workspace lint
  table and confines `unsafe` to its `ffi` module.
- **No panics in production paths.** Clippy runs with `pedantic`,
  `nursery` and `cargo` groups, and denies `unwrap_used`, `expect_used`
  and `panic` outside tests. CI builds with `-D warnings`.
- **No hardcoded operational values.** Limits, thresholds, intervals and
  endpoints come from configuration (ADR-0002).
- **Tenant isolation in depth.** The tenant is taken from the verified
  token, enforced at every handler, and backed by Postgres row-level
  security on tenant-scoped tables.

---

## Capabilities

| Domain | What ships | Principal crates |
|---|---|---|
| Identity and access | Argon2id passwords, JWT access tokens with rotating refresh tokens, OIDC token exchange and RP-initiated, front- and back-channel logout, SAML 2.0 SSO and single logout, SCIM 2.0 provisioning, TOTP MFA with single-use recovery codes, WebAuthn/FIDO2 with AAGUID policy and metadata-service refresh, OAuth client credentials, `resource:action` RBAC with wildcards | `sx-iam`, `sx-scim`, `sx-xmlsec` |
| Adaptive authentication | Risk-based authentication scoring IP geolocation, ASN, device, time of day and velocity to allow, step up, or block; device-trust posture evaluation; optional gradient-boosted-tree scorer behind the `ml-rba` feature | `sx-rba`, `sx-device-trust`, `sx-ml` |
| Engagements | Draft, Active, Paused, Completed and Aborted lifecycle; scope and denylist validation; Rules of Engagement time windows; intensity ceilings; global and per-tenant kill switch; two-person approval for destructive actions | `sx-engagement` |
| Discovery and scanning | Passive and active asset discovery, TLS and HTTP security-header scanning, web and API DAST, software composition analysis, secret and infrastructure-as-code scanning, Prowler import, continuous SCA/SBOM monitoring | `sx-discovery`, `sx-collab` |
| Combined penetration testing | One engagement chaining reconnaissance, network/TLS/web/API scanning, SCA/secret/IaC, credentialed ingest, attack simulation and attack-graph chaining; every phase gated by the engagement authorization check; findings carry CVSS v3.1, CWE and MITRE ATT&CK identifiers | `sx-pentest` |
| Vulnerability ingest | Nessus (`.nessus`) and OpenVAS XML parsing with de-duplication and check-id mapping | `sx-vuln-ingest` |
| Risk | Composite CVSS, EPSS and KEV scoring with SSVC decisions, per-tenant configuration, GraphSAGE-style risk propagation across the asset graph | `sx-risk`, `sx-ml`, `sx-graph` |
| Breach and attack simulation | MITRE-tagged techniques, safe-by-default operating modes, attack chains, continuous validation, red-team chain composer | `sx-bas`, `sx-autonomy` |
| AI security audit | AI asset inventory and CycloneDX-ML AI-BOM; 17-probe prompt-injection, jailbreak, system-prompt-leak, data-exfiltration and excessive-agency corpus mapped to OWASP LLM Top 10 and MITRE ATLAS; probing of the platform copilot and of engagement-authorized external LLM endpoints; pickle and safetensors model-file scanning; NIST AI RMF, ISO/IEC 42001 and EU AI Act controls; audit of every copilot decision | `sx-ai-audit` |
| Attack graph and digital twin | Asset, finding, CVE and technique graph with attack-path queries (in-memory or Neo4j); deterministic tick-based attack-propagation twin | `sx-graph`, `sx-twin` |
| Cloud posture | AWS (S3, EC2, IAM via the AWS SDK), Google Cloud Asset Inventory and Azure Resource Graph connectors; configuration drift baselines; blast-radius analysis | `sx-cloud` |
| Threat intelligence | STIX 2.1 / TAXII 2.1 feed client, sharded bloom-filter IOC store, anonymised cross-tenant threat network | `sx-intel-feeds`, `sx-intel-ioc`, `sx-autonomy` |
| Detection and response | OCSF 1.x log ingestion, KQL/SPL-style hunt language compiled to ClickHouse, SOC rule engine and correlator, UEBA baselines with freeze mode, Falco runtime alerts and Kubernetes admission decisions, DLP content inspection, SOAR workflows, NIST SP 800-61 incident-response playbooks | `sx-log-ingest`, `sx-hunt`, `sx-soc`, `sx-ueba`, `sx-runtime`, `sx-dlp`, `sx-soar`, `sx-ir-playbooks` |
| Remediation | Vendor advisory lookup, guarded AI remediation copilot with approval tokens, auto-remediation pull-request proposals, remediation outcome and regression tracking | `sx-remediation`, `sx-autonomy` |
| Reporting | Executive and technical PDF, SARIF, STIX and CSV exporters; per-tenant branding; scheduled distribution; report diffing | `sx-report` |
| Audit | Per-tenant HMAC hash chain, S3 Object Lock anchoring, RFC 3161 time-stamp anchoring with fallback and circuit breaking, time-travel queries | `sx-audit` |
| Compliance | Control catalogs, finding-to-control mapping, SOC 2 and ISO 27001 evidence collectors, WORM evidence bundles | `sx-compliance` |
| Integrations | Splunk HEC and Syslog/CEF forwarding, Jira and PagerDuty sinks, GRC and bug-bounty connectors, signature-verified GitHub, Slack and Jira webhooks | `sx-integrations`, `sx-webhooks` |
| Extensibility | WASM-sandboxed plugins (wasmtime) with capability-scoped host functions and signed outbound dispatch; deterministic JSON policy DSL with bounded execution | `sx-plugins`, `sx-policy` |
| Resilience engineering | Opt-in fault injection for latency, error rate and dependency failure, restricted to non-production (ADR-0018) | `sx-chaos` |
| Detection accuracy | Benchmark harness that scores findings against a labelled ground truth (precision, recall, F1, exact false-positive and false-negative lists) | `sx-bench` |

---

## Architecture

```
            Operators, customers, CI, SIEM, IdP
                          |
                          | HTTPS (optional mTLS)
                          v
   +---------------------------------------------------+
   |  Next.js 15 dashboard (App Router, Auth.js v5)    |
   |  server-side route handlers proxy to the API      |
   +---------------------------------------------------+
                          |
                          v
   +---------------------------------------------------+
   |  sx-monolith  (single Rust binary)                |
   |                                                   |
   |  sx-api (axum)                                    |
   |    middleware: request-id, trace, CORS,           |
   |    sensitive-header redaction, auth, device       |
   |    posture, policy, anti-abuse, rate limit        |
   |                       |                           |
   |                       v                           |
   |  AppState: Arc<dyn Port> for every domain         |
   |                       |                           |
   |                       v                           |
   |  Domain crates (no I/O, no HTTP, no SQL)          |
   |                       |                           |
   |                       v                           |
   |  Adapters (composition root)                      |
   |    Postgres, Redis, S3, Vault, ClickHouse,        |
   |    Neo4j, cloud SDKs, TSA, or in-memory           |
   |                                                   |
   |  Background jobs (see Observability)              |
   +---------------------------------------------------+
        |           |          |            |
        v           v          v            v
    Postgres      Redis     S3-compatible   Vault
    (RLS, 67    (sessions,  (Object Lock    (KV v2,
    migrations)  lockout,    audit anchors,  DEKs)
                 kill switch) evidence)
```

**Composition root.** `services/sx-monolith` builds every adapter in one
place and injects it into `AppState`. Wiring changes happen there and
nowhere else.

**Persistence.** With `database.enabled: false` the monolith runs
entirely on in-memory adapters. This is the quick-start path and the
default for tests. With Postgres enabled, schema is managed by
`sqlx` migrations in `crates/sx-storage/migrations/`. Not every port has
a durable adapter yet; see
[Maturity and known limitations](#maturity-and-known-limitations).

**Optional backends.** Neo4j for the attack graph (ADR-0006), ClickHouse
for log events and IOC cold storage (ADR-0014), HashiCorp Vault for
secrets, and AWS, GCP or Azure KMS for key encryption keys (ADR-0007).

Design rationale is recorded as Architecture Decision Records in
[`docs/adr/`](docs/adr/), and the architecture narrative is in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## Repository layout

```
.
|-- Cargo.toml              workspace manifest and lint policy
|-- rust-toolchain.toml     pinned toolchain (1.92.0)
|-- clippy.toml, deny.toml, rustfmt.toml
|-- crates/                 45 library crates
|-- services/
|   |-- sx-monolith         HTTP server, composition root, background jobs
|   |-- sx-cli              operator CLI (binary name: sx)
|   `-- sx-agent            in-cluster scan agent (DaemonSet, reports over mTLS)
|-- web/dashboard/          Next.js 15 dashboard
|-- api/                    OpenAPI mirror and Postman collection
|-- config/                 example configuration files
|-- deploy/                 Helm, Terraform, Argo CD, Argo Rollouts, Linkerd,
|                           Falco, OPA Gatekeeper, Vault, Grafana, Sigstore,
|                           Dockerfiles, local multi-region harness
|-- tests/                  integration, load and migration suites
|-- scripts/                local-dev orchestration, smoke tests, image verification
|-- sbom/                   SBOM reproduction notes (artifacts generated in CI)
`-- docs/                   ADRs, runbooks, operations, security, compliance
```

Crates by concern:

| Concern | Crates |
|---|---|
| Foundation | `sx-core`, `sx-config`, `sx-telemetry`, `sx-storage`, `sx-api` |
| Identity | `sx-iam`, `sx-scim`, `sx-xmlsec`, `sx-rba`, `sx-device-trust`, `sx-mtls`, `sx-secrets` |
| Offensive | `sx-engagement`, `sx-discovery`, `sx-pentest`, `sx-vuln-ingest`, `sx-bas`, `sx-collab`, `sx-ai-audit` |
| Exposure analysis | `sx-risk`, `sx-graph`, `sx-twin`, `sx-ml`, `sx-cloud`, `sx-bench` |
| Detection and response | `sx-log-ingest`, `sx-hunt`, `sx-soc`, `sx-ueba`, `sx-runtime`, `sx-dlp`, `sx-soar`, `sx-ir-playbooks`, `sx-intel-feeds`, `sx-intel-ioc` |
| Governance and output | `sx-audit`, `sx-compliance`, `sx-report`, `sx-policy` |
| Automation and integration | `sx-autonomy`, `sx-remediation`, `sx-integrations`, `sx-webhooks`, `sx-plugins`, `sx-chaos` |

---

## Getting started

### Prerequisites

- Rust 1.92.0. `rust-toolchain.toml` pins it; `rustup` installs it on
  first build.
- Node.js 22 and npm, for the dashboard.
- Docker, for the Postgres, Redis and tracing stack.
- `libxmlsec1` and `pkg-config`, only when building with the `xmlsec1`
  feature (enabled by `--all-features`).

### In-memory mode

The shortest path to a running system. No database, no Redis, demo data
seeded.

```sh
# 1. Seed the local dev config (the target path is gitignored)
cp config/sentinelx.dev.example.yaml config/sentinelx.dev.yaml

# 2. Start the API on 127.0.0.1:8080
SENTINELX_CONFIG=./config/sentinelx.dev.yaml cargo run --release -p sx-monolith

# 3. In a second shell, start the dashboard on :3000
cd web/dashboard
cp .env.example .env.local    # see the note below
npm ci
npm run dev
```

For the dashboard, set `AUTH_SECRET` to a random value of at least 32
characters, `NEXT_PUBLIC_ALLOW_CREDENTIALS_LOGIN=true`, and
`NEXT_PUBLIC_DEFAULT_TENANT_ID=01010101-0101-0101-0101-010101010101`
(the seeded dev tenant) in `.env.local`.

Sign in at `http://localhost:3000/login` with `admin@sentinelx.dev` and
`sentinelx-admin-pw`. That credential exists only in the dev example
config; the PHC in that file must never leave a workstation.
`scripts/dev-bootstrap.sh` performs step 1 and prints the export line.

### Postgres and Redis

```sh
bash scripts/local-dev-pg.sh
```

The script starts Postgres and Redis in Docker, applies migrations,
generates a fresh bootstrap admin PHC with `sx hash-password`, and runs
the monolith against the database. `scripts/local-dev.sh` brings up the
full stack including Jaeger and the OpenTelemetry collector. Read each
script header for overrides.

### Build

```sh
cargo build --release -p sx-monolith      # target/release/sx-monolith
cargo build --release -p sx-cli           # target/release/sx
cd web/dashboard && npm ci && npm run build && npm run start
```

---

## Configuration

Configuration is layered: built-in defaults, then a YAML file selected by
`SENTINELX_CONFIG`, then environment variables prefixed `SENTINELX__`
with `__` as the nesting separator.

Top-level sections: `server`, `database`, `redis`, `bootstrap`, `jwt`,
`oidc`, `mtls`, `iam`, `rba`, `anti_abuse`, `engagement`, `discovery`,
`collab`, `cloud`, `risk`, `graph`, `intel_feeds`, `secrets`,
`ai_copilot`, `github`, `integrations`, `telemetry`.

Minimal environment override set for local work:

```sh
export SENTINELX__SERVER__BIND_ADDR="127.0.0.1:8080"
export SENTINELX__DATABASE__ENABLED="false"
export SENTINELX__REDIS__ENABLED="false"
export SENTINELX__JWT__SIGNING_KEY="<base64 of at least 32 random bytes>"
export SENTINELX__IAM__ATTEMPT_EMAIL_PEPPER="<at least 16 random bytes>"
export SENTINELX__BOOTSTRAP__ENABLED="true"
export SENTINELX__BOOTSTRAP__SEED_DEMO_DATA="true"
```

Generate real secrets with `sx rotate-keys`, never by hand. JWT signing
supports HS256, HS384 and HS512 with a shared secret, and RS256 with a
PEM key pair; prefer asymmetric keys whenever tokens are verified by
more than one service.

Reference files: `config/sentinelx.example.yaml` (production template,
every key documented), `config/sentinelx.dev.example.yaml` (local), and
`web/dashboard/.env.example` (dashboard, including OIDC settings).

---

## HTTP API

The authoritative contract is `GET /openapi.json`, rendered in the
dashboard at `/dashboard/api-docs` and exercisable at
`/dashboard/api-playground`. A static mirror lives in
`api/openapi.yaml`. The router (`crates/sx-api/src/router.rs`) registers
188 routes. Every authenticated route enforces its documented
`resource:action` permission inside the handler; this was audited
across all handlers under SEC-AUTHZ-001 and is guarded in CI by the
`handler-auth-audit` job.

| Area | Prefixes |
|---|---|
| Health and discovery (public) | `/healthz`, `/readyz`, `/metrics`, `/openapi.json`, `/.well-known/jwks.json`, `/.well-known/openid-configuration` |
| Authentication (public) | `/v1/auth/login`, `refresh`, `logout`, `signup`, `verify-email`, `forgot-password`, `reset-password`, `/v1/auth/oidc/*`, `/v1/auth/saml/*`, `/v1/auth/mfa/webauthn/*`, `/v1/oauth/token` |
| Identity administration | `/v1/mfa/*`, `/v1/iam/webauthn/*`, `/v1/admin/users`, `/v1/admin/roles`, `/v1/admin/tenants`, `/v1/admin/saml/idp`, `/v1/admin/scim/*`, `/v1/admin/oidc/*`, `/scim/v2/Users`, `/scim/v2/Groups` |
| Adaptive access | `/v1/rba/*`, `/v1/device-trust/*` |
| Engagements and safety | `/v1/engagements/*` (create, activate, pause, resume, abort, complete, clone), `/v1/safety/kill-switch` |
| Assets and findings | `/v1/assets/*` (including bulk import), `/v1/findings/*` (status, bulk update, remediation link, export) |
| Offensive operations | `/v1/discovery/*`, `/v1/scans/*`, `/v1/pentest/runs`, `/v1/vuln/import`, `/v1/bas/*`, `/v1/redteam/chain`, `/v1/collab/tokens` |
| AI security | `/v1/ai-audit/run`, `run-external`, `assets`, `aibom`, `controls`; `/v1/copilot/chat`, `/v1/copilot/approvals` |
| Exposure analysis | `/v1/risk/*`, `/v1/graph/attack-paths`, `/v1/twin/*`, `/v1/ml/predict/*`, `/v1/cloud/*` (inventory, drift, blast radius) |
| Detection and response | `/v1/logs`, `/v1/hunt/query`, `/v1/soc/*`, `/v1/ueba/*`, `/v1/runtime/*`, `/v1/dlp/*`, `/v1/soar/*`, `/v1/ir/*`, `/v1/intel/*` |
| Governance and reporting | `/v1/audit/*` (search, export, replay, diff, anchors), `/v1/compliance/*`, `/v1/reports/*`, `/v1/grc/*` |
| Automation and integration | `/v1/autonomy/*`, `/v1/remediation/*`, `/v1/integrations/*`, `/v1/plugins/*`, `/v1/notifications/devices`, `/v1/chaos/config` |
| Platform administration | `/v1/tenants/me`, `/v1/admin/secrets/*`, `/v1/admin/webhooks/keys/rotate`, `/v1/admin/dlp/thresholds`, `/v1/admin/log-ingest/*`, `/v1/admin/runtime/*`, `/v1/admin/ueba/*` |

---

## Dashboard

Next.js 15 (App Router), React 19, Auth.js v5, TypeScript, Tailwind CSS
v4, TanStack Table and Query, Recharts, and `swagger-ui-dist`. API calls are
proxied through server-side route handlers under `src/app/api/`.

The dashboard has 60 pages. The principal ones:

| Area | Routes |
|---|---|
| Overview and analytics | `/dashboard`, `/dashboard/analytics`, `/dashboard/reporting` |
| Engagements and safety | `/dashboard/engagements`, `/dashboard/approvals`, `/dashboard/safety` |
| Exposure | `/dashboard/findings`, `/dashboard/scans`, `/dashboard/vuln-import`, `/dashboard/graph`, `/dashboard/blast-radius`, `/dashboard/cloud`, `/dashboard/twin` |
| Offensive | `/dashboard/pentest`, `/dashboard/bas`, `/dashboard/bas/techniques`, `/dashboard/redteam`, `/dashboard/ai-audit` |
| Detection and response | `/dashboard/soc`, `/dashboard/logs`, `/dashboard/ueba`, `/dashboard/rba`, `/dashboard/device-trust` |
| Remediation | `/dashboard/remediation`, `/dashboard/copilot`, `/dashboard/copilot-approvals` |
| Governance | `/dashboard/compliance`, `/dashboard/compliance/evidence`, `/dashboard/reports`, `/dashboard/branding` |
| Identity and administration | `/dashboard/iam`, `/dashboard/mfa`, `/dashboard/scim`, `/dashboard/tenants`, `/dashboard/admin/secrets`, `/dashboard/settings`, `/dashboard/profile` |
| Reference | `/dashboard/help/*`, `/dashboard/handbook`, `/dashboard/api-docs`, `/dashboard/api-playground` |

Public routes are `/login`, `/signup`, `/verify-email`,
`/forgot-password` and `/reset-password`.

---

## Operator CLI

The operator CLI builds from `services/sx-cli` as the binary `sx`. Every
command accepts `--json` for machine-readable output and `-v` for debug
logging.

```sh
# Secrets and bootstrap
sx rotate-keys --kind jwt-signing --out-env-file ./jwt.env     # also: iam-pepper, audit-hmac
sx tenant-bootstrap --slug acme --name "ACME Corp" \
  --admin-email secops@acme.example --out-env-file ./acme.env
printf '%s' "$ADMIN_PW" | sx hash-password                     # Argon2id PHC on stdout

# Audit chain
sx audit dump   --tenant <tenant_id> --to ./audit.ndjson
sx audit verify --tenant <tenant_id> --from ./audit.ndjson
sx audit-tail   --since 24h --from ./audit.ndjson --output table
sx audit simulate-break ...                                    # tamper drill against a TEST tenant

# Compliance and evidence
sx compliance list   --framework pcidss                        # iso27001, soc2, pcidss, hipaa, nist80053, cisaws
sx compliance map    --category <finding_category> --finding-id <id>
sx compliance report --framework pci-dss --out ./pci-dss.pdf
sx evidence soc2 collect --out ./evidence/soc2                 # also: iso27001, list-controls
sx evidence ship --framework soc2 --from ./evidence/soc2 --bucket <bucket> [--real]

# Key management and UEBA
sx secrets rotate-dek --tenant <tenant_id>                     # also: rotate, rotation-status
sx ueba freeze|unfreeze|snapshot ...
```

Pass passwords on stdin. `--password` exists, but it exposes the secret
in the process table. Files written by `rotate-keys` and
`tenant-bootstrap` are created with mode `0600`.

---

## Security model

| Control | Implementation |
|---|---|
| Transport | TLS via rustls; optional mutual TLS with hot-reloaded certificates (`sx-mtls`) |
| Credentials | Argon2id PHC; per-deployment pepper for login-attempt anonymisation; anti-abuse lockout |
| Sessions | Short-lived JWT access tokens, rotating refresh tokens with revocation, OIDC and SAML single logout |
| Strong authentication | TOTP (RFC 6238) with recovery codes; WebAuthn with signature-counter monotonicity (ADR-0012) and AAGUID allow/deny policy |
| Adaptive access | Risk-based authentication and device posture at login and on sensitive routes |
| Authorization | `resource:action` permissions with wildcards, enforced in every handler (SEC-AUTHZ-001); policy middleware for cross-cutting rules |
| Tenant isolation | Tenant bound from the verified token; Postgres row-level security on tenant-scoped tables; `SECURITY DEFINER` resolvers for cross-table lookups |
| SAML | Hand-rolled XMLDSig verifier hardened against XSW, XXE, entity expansion and transform abuse, with a fuzz corpus; staged replacement by `libxmlsec1` (ADR-0010, ADR-0022) |
| Outbound requests | SSRF guard on server-initiated fetches (ADR-0024) |
| Secrets | Vault KV v2 with TTL cache; per-tenant data encryption keys with rotation; KEKs in cloud KMS; redacted `Debug` on secret types |
| Webhooks | HMAC-SHA256 inbound verification with constant-time comparison; signed outbound dispatch with key rotation |
| Audit | Per-tenant HMAC chain, S3 Object Lock anchors, RFC 3161 time stamps (ADR-0005, ADR-0008) |
| AI and LLM | Copilot input sanitisation against OWASP LLM01 (role markers, fences, zero-width characters); human approval for copilot actions; copilot decisions recorded in the audit chain as hashes, not raw text (ADR-0004) |
| Code safety | `unsafe` forbidden outside `sx-xmlsec`; strict Clippy; `-D warnings` |
| Supply chain | `cargo-audit`, `cargo-deny`, OSV-Scanner, CycloneDX/SPDX SBOMs with Grype, Sigstore-signed release images verified in CI |

The STRIDE threat model is in
[`docs/security/threat-model-stride.md`](docs/security/threat-model-stride.md).

### Offensive safety controls

Active testing is where a security platform can itself cause an
incident. SentinelX treats that risk as a first-class requirement.

- **Scope is checked before every action**, not once per engagement.
  Each pentest phase, scan and probe is validated in this order:
  kill switch, engagement Active, Rules of Engagement window, denylist,
  intensity ceiling, target scope. Any failure denies the action.
- **Intensity tiers** cap what an engagement may do, in ascending order:
  `theoretical` (no network I/O), `passive_validation` (DNS, WHOIS,
  certificate transparency), `safe_interactive` (low-rate, non-mutating
  probes), `active_exploit`, and `red_team` (chained exploitation and
  lateral movement). Anything at `active_exploit` or above requires dual
  approval.
- **Two-person approval** applies to high-impact actions: engagements at
  exploit intensity, attack simulation runs, and engagement abort.
- **Kill switch** at global and tenant level halts active scanning,
  simulation and LLM probing. Passive inventory continues so that the
  record remains complete.
- **External LLM targets** must be registered in configuration, with
  credentials referenced by environment variable name and never stored
  inline, and the target host must sit inside an active, in-window,
  approved engagement scope.

---

## Compliance coverage

Catalog depth differs by framework. The figures below are the control
counts the platform serves today, as reported by
`sx compliance list --framework <id>`.

| Framework | Controls in catalog | Notes |
|---|---|---|
| PCI DSS v4.0.1 | 250 | All 12 requirements with defined sub-requirements; PDF mapping report via `sx compliance report` |
| HIPAA Security Rule | 65 | Administrative, physical and technical safeguards |
| SOC 2 (TSC) | 8 | Representative criteria; automated evidence collectors |
| ISO/IEC 27001:2022 | 8 | Representative Annex A controls; automated evidence collectors |
| NIST SP 800-53 | 8 | Representative subset |
| CIS AWS Foundations | 6 | Representative subset |
| NIST AI RMF, ISO/IEC 42001, EU AI Act | via `sx-ai-audit` | AI-governance controls evaluated against the AI inventory |

Evidence collectors for SOC 2 and ISO 27001 read operational artifacts,
including the ADRs, runbooks and security documents under `docs/`,
hash them, and package them into WORM evidence bundles (ADR-0019).
Evidence that cannot be produced is reported as `unavailable`, never as
satisfied. Privacy obligations under GDPR and Indonesia's UU PDP are
addressed in [`docs/compliance/gdpr-pdp-dpia.md`](docs/compliance/gdpr-pdp-dpia.md).

---

## Observability

| Signal | Implementation |
|---|---|
| Metrics | Prometheus exposition at `/metrics`, for example `sx_http_requests_total`, `sx_http_request_duration_seconds`, `sx_findings_total`, `sx_engagements_active`, `sx_bas_runs_total`, `sx_killswitch_triggered_total`, `sx_soc_alerts_fired_total` |
| Traces | OpenTelemetry OTLP export; Jaeger in the local stack |
| Logs | `tracing` with JSON or text output; request IDs propagated end to end; sensitive headers redacted |
| Audit | Searchable, exportable as NDJSON, replayable and diffable through `/v1/audit/*` |
| Health | `/healthz` (liveness), `/readyz` (readiness) |
| Dashboards | Grafana definitions under `deploy/grafana/` |

Background jobs run inside the monolith: GraphSAGE risk propagation,
prediction-drift detection, continuous attack simulation, TAXII feed
polling (when feeds are configured), scheduled report distribution,
continuous SCA/SBOM monitoring, outbound webhook signing-key rotation,
and OOB collaborator purge.

Service-level objectives are defined in [`docs/slos.md`](docs/slos.md).

---

## Deployment

| Target | Location | Notes |
|---|---|---|
| Docker Compose | `docker-compose.yml` | Monolith, Postgres, Redis, Jaeger and OpenTelemetry collector on one host; suitable for evaluation and small estates |
| Kubernetes | `deploy/helm/sentinelx/` | Monolith only, with a migration job, NetworkPolicy, PodDisruptionBudget, ServiceMonitor and admission webhook; expects externally managed Postgres and Redis. Start from `values.example.yaml` |
| AWS infrastructure | `deploy/terraform/dev/` | EKS, RDS, ElastiCache, KMS, IAM, networking and observability |
| GitOps and progressive delivery | `deploy/argocd/`, `deploy/argocd-rollouts/`, `deploy/rollouts/` | Analysis-gated canary rollouts |
| Mesh, runtime and admission | `deploy/linkerd/`, `deploy/falco/`, `deploy/opa/` | mTLS mesh, runtime detection rules, Gatekeeper constraints |
| Secrets and signing | `deploy/vault/`, `deploy/sigstore/` | Vault policies, cosign verification |
| Multi-region rehearsal | `deploy/local-multiregion/` | Local harness for the failover runbook |

```sh
helm upgrade --install sentinelx ./deploy/helm/sentinelx \
  --namespace sentinelx --create-namespace \
  --values ./my-values.yaml
```

Verify release images before you deploy them: `scripts/verify-image.sh`
checks the cosign signature and SBOM attestation.

Operational procedures are in
[`docs/operations/runbook.md`](docs/operations/runbook.md),
[`docs/operations/gitops.md`](docs/operations/gitops.md) and
[`docs/runbooks/`](docs/runbooks/).

---

## Testing and quality gates

| Layer | Command |
|---|---|
| Unit, property and integration | `cargo test --workspace --all-features` |
| Lint | `make lint` (Clippy, identical to CI) |
| Format | `cargo fmt --check` |
| Advisories and licences | `make audit`, `cargo deny check` |
| SBOM | `make sbom`, `make sbom-verify` |
| HTTP smoke against Postgres and Redis | `scripts/integration-smoke.sh` |
| Dashboard type check and end-to-end | `npm run typecheck`, `npm run e2e` (Playwright) |
| SAML fuzzing | `cargo fuzz` targets under `crates/sx-iam/fuzz/` |
| Load | `tests/load/` |

GitHub Actions workflows:

| Workflow | Jobs |
|---|---|
| `ci` | format, clippy, test, deny |
| `audit` | cargo-audit, RSA-decrypt surface check, handler authorization audit, SBOM with Grype |
| `dependency-scan` | cargo-audit, cargo-deny, OSV-Scanner |
| `integration` | smoke test against Postgres and Redis |
| `playwright` | dashboard end-to-end |
| `fuzz-saml` | SAML fuzzing and corpus sanity |
| `release`, `verify-release` | image build, signing and signature verification |

---

## Maturity and known limitations

A security product that overstates its own state is a liability. These
are the current, known gaps.

- **Durable persistence is partial.** Many ports are durable on Postgres
  or Redis, including token revocation, MFA and WebAuthn. Others still
  run on in-memory adapters even when the database is enabled, and their
  state is lost on restart. Audit `services/sx-monolith/src/adapters/`
  before relying on a module in production.
- **External audit anchoring is not scheduled.** S3 Object Lock and
  RFC 3161 anchoring are implemented and exposed through
  `/v1/audit/anchors`, but the periodic anchoring scheduler is not yet
  wired into the monolith.
- **DEK rotation is disabled by default.** The rotation routes respond
  with a deterministic `422` until a deployment supplies KMS, the
  re-encryption registry and a durable progress store.
- **Several compliance catalogs are representative subsets** (SOC 2,
  ISO 27001, NIST 800-53, CIS AWS). Do not present them to an auditor as
  complete control sets.
- **The ML-based login scorer ships without a model.** The `ml-rba`
  feature fails closed until you supply a trained model artifact.
- **The SAML XMLDSig verifier is hand-rolled.** It is fuzzed and
  hardened, and its replacement by `libxmlsec1` is in progress
  (ADR-0022).
- **No external penetration test has been performed yet.** One is
  required before any production deployment that handles third-party
  data.

---

## Documentation

The repository versions only the documentation the platform consumes at
runtime or that operators need in order to run it safely:

| Path | Contents |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Layers, components and deployment topology |
| [`docs/adr/`](docs/adr/) | Architecture Decision Records |
| [`docs/security/`](docs/security/) | STRIDE threat model, supply-chain policy, SAML fuzzing, bug bounty, internal red team |
| [`docs/runbooks/`](docs/runbooks/) | Incident response, breach notification, audit-chain compromise, disaster recovery, failover, multi-region, supply chain, telemetry readiness |
| [`docs/operations/`](docs/operations/) | Operations runbook, GitOps, runtime security, compliance evidence |
| [`docs/compliance/`](docs/compliance/) | PCI DSS mapping, GDPR and UU PDP DPIA, Rules of Engagement template |
| [`docs/onboarding.md`](docs/onboarding.md) | Engineer onboarding |
| [`docs/slos.md`](docs/slos.md) | Service-level objectives |
| [`api/openapi.yaml`](api/openapi.yaml), [`api/postman.collection.json`](api/postman.collection.json) | API contract mirror and collection |

Product and requirements documents (business, product, functional and
technical requirements, database design, system flows) are maintained
outside version control.

---

## Contributing

1. Branch from `main` using a `feat/`, `fix/`, `chore/` or `docs/`
   prefix.
2. Keep commits focused. Format only the files you touched
   (`cargo fmt -- <files>`); workspace-wide reformatting buries real
   changes in noise.
3. Any change to a domain port needs unit tests and at least one
   integration test through the user-facing entry point, whether that is
   an HTTP route, a CLI command or a background job.
4. Run `make lint` and the tests of the crates you changed before you
   open a pull request.
5. In the pull request, state the scope, any breaking change, and the
   security impact. Changes to authentication, authorization, tenant
   isolation, cryptography, audit or offensive safety controls require
   review by a security owner.
6. If a change alters an architectural decision, add or amend an ADR in
   the same pull request.
7. Submitting a contribution means accepting the contribution terms in
   [`LICENSING.md`](LICENSING.md#contributions).

---

## Reporting a vulnerability

Do not open a public issue for a security defect. Follow the disclosure
process in [`docs/security/bug-bounty.md`](docs/security/bug-bounty.md),
which covers scope, safe-harbour terms and encrypted reporting.

---

## License

SentinelX is source-available under the
[PolyForm Noncommercial License 1.0.0](LICENSE). Personal, research,
educational and other noncommercial use, including modification and
redistribution for those purposes, is permitted. Commercial use,
including use by or for a business, paid services, hosting, or
modification and redistribution for a commercial purpose, requires a
separate written license from the copyright holder. See
[`LICENSING.md`](LICENSING.md) for what is and is not covered and how to
request a commercial license.

Copyright (c) 2026 rickgat.
