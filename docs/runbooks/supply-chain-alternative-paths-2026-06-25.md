# LOW-001-FU5 / FU6 — Alternative-path analysis (2026-06-25 re-probe)

> Companion to [`supply-chain.md`](./supply-chain.md) §6.4 (LOW-001-FU5 row)
> and §7 (LOW-001-FU6 probe). The §7 probe of 2026-06-23 concluded "every
> FU6 advisory co-blocked on FU5"; the 2026-06-24 re-probe confirmed nothing
> moved on crates.io. This document asks the next question: **is the
> co-blocked path still the cheapest path, or has the dependency landscape
> shifted enough that a sideways move (fork swap, patch override, parent
> bump, hand-rolled replacement) is now cheaper than waiting?**
>
> Output is a costed decision matrix for the PO. **No code change is
> proposed here** — implementation tickets must be filed separately.

## 1. Decision matrix (TL;DR)

Effort is in **dev-days end-to-end** (probe → branch → bump → fix → tests
→ audit-clean → review). Risk class:

- **R1 — pure compile-time / no runtime delta** (proc-macro swap, ignore-rule edit).
- **R2 — narrow runtime delta** (single subsystem, bounded blast radius).
- **R3 — broad runtime delta** (multi-crate, touches request/response path).
- **R4 — strategic** (vendoring / fork ownership; ongoing maintenance debt).

| # | Crate (advisory) | 2026-06-25 re-probe outcome | Best alternative | Effort (days) | Risk |
|---|---|---|---|---|---|
| 1 | `backoff@0.4.0` (RUSTSEC-2025-0012) — via `neo4rs@0.8.0` | No upstream movement; abandoned since 2022 | **Wait for `neo4rs@0.9.x` GA** (Option A1 below). Pre-release `0.9.0-rc.10` already drops `backoff`. Pinning the rc is a viable contingency at +0.5 days extra audit-toml work but PO declined 2026-06-23/-24. | 0 (wait) / **3-4** (rc pin) / 8-12 (rewrite on `bolt-client`) | R2 (rc pin) / R3 (rewrite) |
| 2 | `paste@1.0.15` (RUSTSEC-2024-0436) — via `neo4rs@0.8.0` only | David Tolnay deprecation note still visible on `dtolnay/paste`. **Maintained successor `pastey@0.2.3`** exists (MIT/Apache-2.0, MSRV 1.54, drop-in). Workspace inventory: **`neo4rs` is now the ONLY parent** (wasmtime path closed by FU2 on 2026-06-23). | **Suppress with sharpened rationale** (Option B3 below). Drop-in swap is blocked because **we don't consume `paste` directly** — `neo4rs@0.8.0` does. A `[patch.crates-io]` override against `paste` would not work (different crate name), and forking `neo4rs` to swap `paste → pastey` upstream costs ≥ 4 dev-days plus ongoing fork debt for a compile-time-only macro. | 0.25 (audit-toml comment refresh) / 4-5 (neo4rs fork swap) | R1 / R4 |
| 3 | `rustls-pemfile@2.2.0` (RUSTSEC-2025-0134) — via 6 parents | **4 of 6 parents already shipped releases that drop it** (`axum-server 0.8`, `tonic 0.14`, `kube 4.0`, `redis 1.2.4`). 2 still pull it: `neo4rs@0.8.0` (direct) and `rustls-native-certs@0.7.3` (via neo4rs). Re-probe surfaces **`rustls-native-certs@0.8.4`** as a clean bump. | **Partial parent-bump cascade (Option C1)** — bump axum-server / tonic / kube-client / redis / rustls-native-certs. **Does NOT close the advisory** (neo4rs holdout) so the ignore stays, but it shrinks the attack surface from 6 paths → 1 and pre-stages the FU5 unblock. Pure `[patch.crates-io]` override (Option C2) is rejected: rustls-pemfile 3.x is API-breaking against tonic/kube call sites. | **5-7** (cascade, no audit-toml change) / 0 (wait) | R3 (cascade) |
| 4 | `instant@0.1.13` (RUSTSEC-2024-0384) — via `backoff` via `neo4rs` | No upstream movement. `instant` itself recommends `web-time` as successor but the consumer is `backoff` (unmaintained), not us. | **Co-resolve with item 1** — same path. No independent action available. | 0 (wait) | R1 |
| 5 | `proc-macro-error2@2.0.1` (RUSTSEC-2026-0173) — via `validator_derive@0.20.0` | No newer `validator_derive` release on crates.io (0.20.0 still current). Pure compile-time consumer (proc-macro crate); no runtime code emitted. | **Wait** (Option D1). Fork swap to `manyhow` / `syn::Error` (Option D2) requires patching `Keats/validator` upstream OR vendoring; cost > waiting. | 0 (wait) / 6-8 (vendor validator_derive) | R1 / R4 |

**Recommended PO posture:** items 1, 4, 5 — **continue to wait** (status quo).
Items 2 and 3 — **two clear-cost actionable swaps surface**:

- **Item 2** — refresh the `paste` audit.toml comment block (the existing
  comment incorrectly cites `metrics-exporter-prometheus 0.15 macros` as
  the consumer; the true and only consumer is now `neo4rs@0.8.0`). 0.25
  dev-days, R1, eliminates a stale rationale audit trap.
- **Item 3** — execute the partial parent-bump cascade (axum-server,
  tonic, kube-client, redis, rustls-native-certs). 5-7 dev-days, R3.
  Does NOT retire the audit-toml ignore (neo4rs holdout) but cuts the
  attack-surface fan-in from 6 → 1 and pre-stages the eventual FU5
  unblock so that the day neo4rs 0.9 GA lands, FU6 closes in one bump
  instead of six.

Both of these qualify for downgrade from 🔒 BLOCKED to 🟡
AWAITING-PO-DECISION in the tracker. **All other unmaintained crates
remain co-blocked on neo4rs 0.9 GA.**

---

## 2. Per-crate detailed analysis

### 2.1 `neo4rs` 0.8 → 0.9 (`backoff` parent — LOW-001-FU5)

#### 2.1.1 Re-probe (2026-06-25)

```
$ cargo info neo4rs
version: 0.8.0 (latest 0.9.0-rc.10)
```

Same line as 2026-06-24. No `0.9.0` stable release. Last published rc
(`0.9.0-rc.10`) is the upstream replacement path that drops `backoff`
(per `cargo info` of rc.10: `backoff` no longer in the dependency tree,
internal retry loop reimplemented on `tokio` primitives).

#### 2.1.2 Workspace exposure

`cargo tree -i neo4rs` → consumed by `sx-graph` only.

`grep -rn "neo4rs::"` across `sx-graph` returns **21 call sites** across
4 files:

```
crates/sx-graph/src/neo4j.rs                  (9 imports / uses)
crates/sx-graph/src/error.rs                  (1 import)
crates/sx-graph/src/service/neo4j_pool.rs     (5 imports / uses)
crates/sx-graph/src/service/neo4j_graph.rs    (6 imports / uses)
```

The API surface actually consumed: `Graph`, `Query`, `ConfigBuilder`,
`Error`, `BoltType` (+ `BoltMap`, `BoltList`, `BoltString`), `Path`,
`Node`, `query()`. All of these still exist in `0.9.0-rc.10` per
`docs.rs`; the rc release notes list one breaking change (`Row::get`
signature tightened to require a `BoltType` deserializer) and one
non-breaking ergonomic shift (`Graph::run` returns `RunResult` instead
of `()`).

#### 2.1.3 Alternative paths

| Option | Description | Pros | Cons | Days | Risk |
|---|---|---|---|---|---|
| **A1 — Wait for `neo4rs@0.9.0` GA** (status quo) | Re-probe weekly via cron + 2026-09-23 review point. | Zero engineering cost. Critical-path graph driver stays on a stable upstream. | Backoff / instant / paste / rustls-pemfile ignores remain. | 0 | R1 |
| **A2 — Pin `0.9.0-rc.10`** | Move workspace `neo4rs = "0.8"` → `neo4rs = "=0.9.0-rc.10"`. Migrate the 21 call sites. Re-run audit. | Closes `backoff`, `instant`, removes one of the 6 `rustls-pemfile` parents AND `rustls-native-certs@0.7.3`. Net: 2 advisory closures + 2 attack-surface reductions. | Pinning a pre-release on the critical-path graph driver is the exact thing the PO declined 2026-06-23 and reaffirmed 2026-06-24. If maintainers cut breaking changes between rc.10 and GA we eat the migration twice. | 3-4 | R2 |
| **A3 — Migrate to `bolt-client@0.11.0`** | Pure-Rust Bolt protocol implementation from `0xSiO/bolt-rs`. | Eliminates `neo4rs` dependency entirely. Active maintenance (latest 2024). Smaller dep surface. | API is markedly lower-level (raw Bolt messages vs. `Graph::execute` / `Row::get`). All 21 call sites rewrite. `bolt-client` does not ship connection pooling — we'd own the pool. Last release 0.11.0 has no Neo4j 5.x compatibility statement. | 8-12 | R3 |
| **A4 — DIY Bolt over `tokio-tungstenite`** | Hand-roll the Bolt 5.0 handshake + message framing. | Zero third-party graph-driver dependency. | High maintenance debt. Bolt protocol versioning is non-trivial. Re-implements `bolt-proto@0.12.0` poorly. | 25-40 | R4 |

#### 2.1.4 Recommendation

**A1 (wait).** Re-probe weekly. The cost/benefit on A2 (pin rc.10) is
acceptable contingency-wise — 3-4 days work for 2 advisory closures —
but the PO has rejected this twice and the rc churn risk is real. A3
and A4 are not credible at this point: `bolt-client` has not seen
Neo4j 5.x validation, and a DIY Bolt impl is a strategic mistake for a
secondary feature path.

---

### 2.2 `paste@1.0.15` (LOW-001-FU6)

#### 2.2.1 Re-probe (2026-06-25)

```
$ cargo info paste
version: 1.0.15
repository: https://github.com/dtolnay/paste
```

David Tolnay's deprecation notice on `dtolnay/paste` remains. No new
release since `1.0.15`. RUSTSEC-2024-0436 is an **unmaintained**
advisory (informational warning), not a CVE. No exploit, no patch.

#### 2.2.2 Workspace exposure

```
$ cargo tree -i paste
paste v1.0.15 (proc-macro)
└── neo4rs v0.8.0
    └── sx-graph v0.1.0
```

**Single parent: `neo4rs@0.8.0`.** Compile-time only (`proc-macro`
crate) — no runtime code emitted from `paste` into our binaries.

> ⚠️ **Documentation accuracy finding:** `.cargo/audit.toml` line 110
> states `paste` is "used by metrics-exporter-prometheus 0.15 macros."
> This is **factually incorrect** as of 2026-06-25 — `cargo tree -i paste`
> shows only `neo4rs` as the consumer. The wasmtime parent existed pre-FU2
> and was closed 2026-06-23 by the wasmtime 24→36 cascade. The
> metrics-exporter-prometheus citation was either pre-FU2 or never
> accurate. Recommend `audit.toml` comment refresh as part of any
> implementation ticket downstream of this analysis.

#### 2.2.3 Alternative paths

| Option | Description | Pros | Cons | Days | Risk |
|---|---|---|---|---|---|
| **B1 — Wait for `neo4rs@0.9.0` GA** | Co-resolve with item 1. Per `cargo info neo4rs@0.9.0-rc.10` the `paste` dependency persists in the rc; closure on B1 is not actually guaranteed by `neo4rs` 0.9 alone — would need a further upstream pastey swap. | Zero engineering cost. | Co-blocked indefinitely; even neo4rs 0.9 may not close it. | 0 | R1 |
| **B2 — `[patch.crates-io] paste = { package = "pastey", version = "0.2.3" }`** | Crate-name remap: force any Cargo resolution of `paste` to use `pastey` under the same name. | Closes the advisory without touching neo4rs. **Pastey is explicitly the "successor of paste"** (per crate description) and presents the same macro surface. License: MIT OR Apache-2.0 (compatible). MSRV 1.54 (well below our 1.92). | Cargo `[patch.crates-io]` with `package =` rename has known compat issues — the macro hygiene depends on the crate-name resolution at proc-macro expansion time. If pastey re-exports differ in even one macro (`paste!`, `paste_expr!`, `expr!`), neo4rs's macro usage breaks at COMPILE time, surfaced only when the build runs. Requires CI validation gate. | 1.5-2.5 | R2 (compile-time only, but a compile failure would block the workspace) |
| **B3 — Suppress with sharpened rationale (RECOMMENDED)** | Update `audit.toml` ignore for RUSTSEC-2024-0436 to: (a) correct the parent inventory, (b) explicitly note `paste` is compile-time only with no exploit path, (c) reference the pastey contingency. | Eliminates the stale rationale audit trap. Documents the residual risk-class precisely (process-policy, not exploitable). 15 minutes of writing. | Advisory ignore persists in the audit gate count. PO-visible at the 2026-12-15 review. | 0.25 | R1 |
| **B4 — Fork `neo4rs` and swap `paste → pastey` upstream** | Maintain a SentinelX vendored fork at `crates/vendor/neo4rs/`. | Closes the advisory cleanly. | Ongoing maintenance debt; we'd own all neo4rs CVE response. We'd duplicate the FU5 0.9 migration when it lands. | 4-5 (initial) + ~2 days every neo4rs release thereafter | R4 |

#### 2.2.4 Recommendation

**B3 (suppress with sharpened rationale).** This is the only option with
genuinely positive ROI right now: the existing audit-toml comment is
factually wrong (cites a non-existent metrics-exporter-prometheus
consumer), which means a 2026-12-15 reviewer would have no accurate
context. Fixing the comment is 15 minutes of work, costs no audit-gate
churn, and eliminates a documented-rationale trap. **B2 is the
contingency** if the PO wants closure-before-FU5 — the pastey swap is
technically credible but the compile-time fragility is real and a
4-hour CI run is needed to validate. **Do not pursue B4** under any
circumstances; vendoring neo4rs for a compile-time macro hygiene risk
is strategically wrong.

---

### 2.3 `rustls-pemfile@2.2.0` (LOW-001-FU6)

#### 2.3.1 Re-probe (2026-06-25)

```
$ cargo info rustls-pemfile
version: 2.2.0
```

Still the same version. RUSTSEC-2025-0134 is the **unmaintained**
advisory against `rustls-pemfile@2.x` line. No CVE; the underlying
library is intentionally minimal and remains feature-complete for PEM
parsing — the maintainer flag is process-only ("we don't plan to ship
2.3+; users should migrate to `rustls-pki-types`").

#### 2.3.2 Workspace exposure (6 parent paths)

```
rustls-pemfile v2.2.0
├── axum-server v0.7.3       → CAN BUMP to 0.8.0 (rustls-pki-types adopted)
├── kube-client v0.96.0      → CAN BUMP to 4.0.0 (rustls-pki-types adopted)
├── neo4rs v0.8.0            → HOLDOUT (co-blocked on FU5)
├── redis v0.27.6            → CAN BUMP to 1.2.4 (newly available — was pre-1.0 at FU2 time)
├── rustls-native-certs v0.7.3 (via neo4rs) → CAN BUMP to 0.8.4
└── tonic v0.12.3            → CAN BUMP to 0.14.6 (rustls-pki-types adopted)
```

5 of 6 parents are bump-able. **Only `neo4rs@0.8.0` is the holdout**
(also responsible for the `rustls-native-certs@0.7.3` instance, which
would close automatically on FU5).

#### 2.3.3 Alternative paths

| Option | Description | Pros | Cons | Days | Risk |
|---|---|---|---|---|---|
| **C1 — Partial parent-bump cascade (RECOMMENDED)** | Workspace bumps: `axum-server 0.7→0.8`, `tonic 0.12→0.14`, `kube-client 0.96→4.0`, `redis 0.27→1.2.4`, `rustls-native-certs 0.7→0.8.4`. | Attack-surface fan-in: 6 paths → 1 path. Pre-stages the FU5 unblock: the day `neo4rs 0.9` GAs, FU6 closes in 1 bump instead of 6. Tonic 0.14 fixes a separate axum-internal http2 issue and is on the modernization roadmap anyway. | Does NOT close the audit-toml ignore (neo4rs holdout). 5-7 dev-days because tonic 0.12→0.14 has breaking API changes (`Channel::builder`, `Server::builder` signatures), kube 0.96→4.0 is a major (CRD API), redis 0.27→1.x renamed several connection types. | 5-7 | R3 |
| **C2 — `[patch.crates-io] rustls-pemfile = "3.0.0"`** | Force resolution to `rustls-pemfile@3.x`. | Single-line workspace edit. | rustls-pemfile 3.x removed the legacy `read_*` free functions; tonic 0.12 / kube-client 0.96 / redis 0.27 call these directly — would break the workspace build. | 0.5 (probe) + likely abandoned | R3 |
| **C3 — Wait** | Status quo. Continue to ignore RUSTSEC-2025-0134. | Zero engineering cost. | 5 unnecessary parent paths still pull an unmaintained crate; widens attack surface for any future RUSTSEC discovery against rustls-pemfile. | 0 | R1 |

#### 2.3.4 Recommendation

**C1 (cascade) IS actionable today, even though it does not close the
audit-toml ignore.** The 5-7 dev-day cost buys: (i) attack-surface
narrowing from 6 → 1 parent path; (ii) FU5 unblock pre-staging — the
moment neo4rs 0.9 GAs, the rustls-pemfile ignore retires in 1 bump
instead of 6; (iii) tonic and kube modernization that is on the roadmap
regardless. **C2 is rejected** because rustls-pemfile 3.x is API-breaking
against the very parents we'd be trying to patch. **C3 is the cheapest
short-term but leaves five paths of latent risk.**

Recommend filing this as a standalone follow-up ticket
(`LOW-001-FU7 — rustls-pemfile parent cascade`) separate from FU6
itself, so FU6 stays scoped to "wait on neo4rs."

---

### 2.4 `instant@0.1.13` (LOW-001-FU6)

#### 2.4.1 Re-probe (2026-06-25)

```
$ cargo info instant
version: 0.1.13
description: Unmaintained, consider using web-time instead
```

The crate self-deprecates and points at `web-time`. No new releases.

#### 2.4.2 Workspace exposure

```
$ cargo tree -i instant
instant v0.1.13
└── backoff v0.4.0
    └── neo4rs v0.8.0
        └── sx-graph v0.1.0
```

Single chain: `instant ← backoff ← neo4rs`. Identical to item 1 (FU5).

#### 2.4.3 Alternative paths

| Option | Description | Pros | Cons | Days | Risk |
|---|---|---|---|---|---|
| **D1 — Co-resolve with FU5 (RECOMMENDED)** | Closing item 1 closes this. | Zero independent action. | Inherits FU5 timeline. | 0 | R1 |
| **D2 — `[patch.crates-io] instant = { package = "web-time", ... }`** | Crate-name remap. | One-line patch. | `web-time` exposes a SUPERSET of `instant`'s API but the constructor names differ (`web_time::Instant::now` vs `instant::Instant::now` — same signature but the macro hygiene inside `backoff` may break). Requires a CI validation gate. Also: `instant` is compile-time-conditional in backoff (wasm targets only), so we'd only hit it under cross-compilation. | 1-2 | R2 |
| **D3 — Fork `backoff` and swap `instant → web-time` upstream** | Vendored fork at `crates/vendor/backoff/`. | Clean closure. | Ongoing maintenance for an abandoned crate; we'd own the fork forever. | 3-4 (initial) | R4 |

#### 2.4.4 Recommendation

**D1 (co-resolve with FU5).** `instant` is compile-time-conditional in
`backoff` and the workspace does not currently cross-compile to wasm
targets, so the runtime exposure is **zero**. D2 is technically feasible
but unjustified given zero exposure. D3 vendors an unmaintained crate
permanently — strategically wrong.

---

### 2.5 `proc-macro-error2@2.0.1` (LOW-001-FU6)

#### 2.5.1 Re-probe (2026-06-25)

```
$ cargo info proc-macro-error2
version: 2.0.1
repository: https://github.com/GnomedDev/proc-macro-error-2
```

Same line as 2026-06-23. No new release. The `GnomedDev/proc-macro-error-2`
fork itself is the community successor to the original
`dtolnay/proc-macro-error` (which was abandoned with the `proc-macro2`
2.x changes). RUSTSEC-2026-0173 marks 2.0.1 as unmaintained because
GnomedDev has not committed since 2024.

#### 2.5.2 Workspace exposure

```
$ cargo tree -i proc-macro-error2
proc-macro-error2 v2.0.1
└── validator_derive v0.20.0 (proc-macro)
    └── validator v0.20.0
        ├── (used by 10+ sx-* crates via sx-config / sx-api)
```

Single parent: `validator_derive@0.20.0`. **`proc-macro-error2` is itself
a proc-macro crate** — compile-time only, emits no runtime code into our
binaries.

#### 2.5.3 Alternative paths

| Option | Description | Pros | Cons | Days | Risk |
|---|---|---|---|---|---|
| **E1 — Wait for `validator > 0.20`** | Track `Keats/validator` releases; the next minor is expected to migrate proc-macro-error2 → manyhow or hand-rolled `syn::Error` (per upstream tracking issue). | Zero engineering cost. | No timeline from upstream. | 0 | R1 |
| **E2 — Migrate workspace to a different validation crate** | Candidates: `garde@0.22`, hand-rolled trait. | Drops `validator` entirely. | 10+ sx-* crates consume `#[derive(Validate)]`. Full migration estimated at 6-10 dev-days. | 6-10 | R3 |
| **E3 — Vendor `validator_derive` with proc-macro-error2 → manyhow swap** | Workspace fork at `crates/vendor/validator_derive/`. | Clean closure. | Compile-time-only fix for a compile-time-only crate. Doesn't justify the maintenance debt. | 4-5 | R4 |

#### 2.5.4 Recommendation

**E1 (wait).** `proc-macro-error2` is compile-time only with zero runtime
exposure. RUSTSEC-2026-0173 is unmaintained-class (process-policy), not
a CVE. E2 / E3 cost more than the residual risk justifies.

---

## 3. Surfaced cross-cutting findings

1. **`audit.toml` comment drift.** Three of the five FU6 ignore-rule
   comments reference stale parents:
   - `paste@1.0.15` (line 110): "used by metrics-exporter-prometheus
     0.15 macros" — actually `neo4rs@0.8.0` only.
   - `instant@0.1.13` (line 101): "pulled transitively by figment /
     fastrand-style timer crates for non-wasm targets" — actually
     `backoff@0.4.0` (via neo4rs) only.
   - `rustls-pemfile@2.2.0` (line 130): "still pulled by tonic / redis
     / neo4rs / kube-client / axum-server" — accurate but lists 5 of 6;
     also pulled by `rustls-native-certs@0.7.3` (separate path even
     though both ultimately route via neo4rs). Inaccuracy is minor.

   Recommend an `audit.toml`-comment-only refresh ticket independent of
   any implementation work.

2. **`redis 1.x` shipped.** The 2026-06-23 §7.2 probe listed `redis 1.x`
   as a parent-latest target. As of 2026-06-25 `redis@1.2.4` is on
   crates.io. This is **new since the last probe** and is what unlocks
   Option C1 (the partial parent-bump cascade for rustls-pemfile).

3. **`rustls-native-certs@0.8.4` shipped.** Similar — not present in
   the 2026-06-23 probe but is the cleanest path for the second
   `rustls-pemfile` consumer that travels via neo4rs's TLS chain.

4. **`pastey 0.2.3` is a credible drop-in.** License-compatible
   (MIT/Apache-2.0), MSRV 1.54 (well below our 1.92), explicit
   "successor of paste" framing. **Not actionable** for us today
   (the consumer is upstream `neo4rs`, not our code) but it is a viable
   contingency under Option B2 if PO accepts the compile-time fragility.

5. **`bolt-client` exists but is not credible as a `neo4rs` replacement
   for SentinelX in this window.** Last release 0.11.0, no Neo4j 5.x
   compatibility statement, no connection pooling. Recording the
   probe outcome here so future re-probes do not have to repeat it.

---

## 4. Cross-references

- [`supply-chain.md`](./supply-chain.md) §6.4 — the LOW-001-FU5 and
  LOW-001-FU6 row entries link forward to this document.
- [`supply-chain.md`](./supply-chain.md) §7 — the 2026-06-23 LOW-001-FU6
  upstream probe (this is the next-revision re-probe).
- [`../SPRINT_HARDENING_HANDOFF.md`](../SPRINT_HARDENING_HANDOFF.md) —
  the LOW-001-FU5 / LOW-001-FU6 tracker rows are updated to link here.
- `.cargo/audit.toml` — the 5 ignore rules covered by this analysis:
  RUSTSEC-2025-0012, RUSTSEC-2024-0384, RUSTSEC-2024-0436,
  RUSTSEC-2026-0173, RUSTSEC-2025-0134.
