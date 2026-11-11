# ADR 0021 — Promote plugin sandbox to WebAssembly (wasmtime) for the marketplace launch

Status: Accepted
Date: 2026-06-14
Deciders: Principal Platform Engineer, Principal Security Engineer, Product Lead
Supersedes: None
Superseded by: None
Related: ADR 0017 (plugin sandbox capability model)

## Context

P3-007 (ADR 0017) shipped the plugin SDK with an **in-process Rust
trait** loader. Third-party plugins implemented `Plugin` directly in
the host's address space; the only thing standing between a malicious
plugin and the platform's secrets was a capability check at the Rust
API boundary.

That model is **fundamentally inadequate for a marketplace launch.**
The threats we lose under it:

1. **Memory disclosure.** A plugin holds raw pointers in the host's
   address space. A bug (or worse) can read any other plugin's data,
   any tenant's findings, any in-memory DEK.
2. **Process panic.** A panic in plugin code unwinds the host worker
   — the platform takes the whole tenant offline.
3. **CPU starvation.** No timeout / fuel mechanism — a plugin can
   spin a tight loop and block the worker indefinitely.
4. **Syscall surface.** A plugin can call `std::fs`, `std::net`, or
   any `unsafe { libc::… }` with no audit hook.
5. **Resource exhaustion.** A plugin can `Vec::with_capacity(1 << 30)`
   and OOM-kill the pod.

The capability-check-at-API-boundary model is necessary but **not
sufficient**. The plugin shares address space with the host, so any
check it doesn't go through can be bypassed by jumping past it.

For the marketplace launch (CRIT-001) we need a real sandbox.

## Decision

Promote the plugin runtime to a **WebAssembly sandbox** backed by
[`wasmtime`]. The new module is `sx_plugins::wasm_host`. It exposes a
fixed capability-scoped host-function surface (`sentinelx::findings_read`,
`sentinelx::findings_annotate`, `sentinelx::http_fetch`); each fn
*first* verifies the plugin's load-time scope and *then* enforces the
tenant binding.

### Wasmtime version pin

- Target: `wasmtime 24.x` (the most recent stable line at the time
  the CRIT-001 spec was written).
- Shipped: `wasmtime 26.0.1` — the build host had only this minor
  cached locally. The API surface we use (`Engine`, `Module`,
  `Store<T>`, `Linker<T>`, `Config::consume_fuel`, fuel metering on
  `Store`, `ResourceLimiter`, `Module::validate`,
  `Module::from_binary`, `Module::imports`) is **stable across the
  24 → 25 → 26 line** — the upgrade path is a Cargo.toml bump with
  no source-level changes. The ADR records the precise version so
  a future delta is easy to read.
- Feature set: `default-features = false, features = ["cranelift",
  "runtime"]`. We deliberately **disable** wasm threads, async, WASI,
  the component model, debug-builtins, profiling, and the cache —
  every one of those is either irrelevant to our shape or expands
  the attack surface for no win.

### Runtime mode gate

- `LoadMode::Production` ↔ `APP_ENV=production` (or any case
  variant). The host **rejects** any manifest tagged as legacy
  (`required_scopes` contains `"legacy:cdylib"`).
- `LoadMode::Development` accepts both WASM and legacy plugins so the
  P3-007 in-process trait keeps working for the dev loop.

### Crate features

- `wasm-host` — default **ON**. Pulls in wasmtime, compiles the
  WASM host module, re-exports the public types.
- `legacy-cdylib` — default **OFF**. Compile-time switch for the
  legacy in-process trait. Tests that exercise the old path
  continue to work when the workspace is built with this feature
  on.

### Capability tokens enforced at host-function boundary

Every host function takes `Caller<'_, PluginStoreData>` as the first
argument and proceeds in this order:

1. Read the tenant id from `caller.data().caps.tenant_id`. The
   tenant id is **never** sourced from a wasm-supplied argument.
2. Check `caller.data().caps.has_scope(<stable scope string>)`. If
   the manifest did not declare the scope, **trap with
   `HostFnError::ScopeDenied`** before any backend call.
3. For `http_fetch`: rate-limit (sliding 60 s window per plugin),
   then check the URL's host against
   `caller.data().caps.fetch_policy.allow_list`.
4. Audit-log to the `audit` tracing target via
   `tracing::info!(target = "audit", action = "plugins.wasm.host_fn.*", …)`.

### Per-plugin resource limits

| Limit | Default | Configurable via |
| --- | --- | --- |
| Linear memory | 64 MiB | `plugins.memory_limit_mb` |
| CPU fuel per invoke | 30 × 10⁹ units (~30 s) | `plugins.cpu_fuel_per_invoke` |
| HTTP egress | 100 calls / minute / plugin | `plugins.http_calls_per_minute` |

Memory is capped by a [`wasmtime::ResourceLimiter`] hooked through
`Store::limiter`. CPU is capped by `Config::consume_fuel(true)` plus
`Store::set_fuel(N)` on each invocation. HTTP egress is rate-limited
with a `VecDeque<Instant>` sliding window inside `PluginStoreData`.

### Cross-tenant isolation

Two structural facts make cross-tenant data inaccessible:

1. **Tenant binding is load-time.** `WasmPluginHost::load_manifest`
   captures the tenant id into a `Capabilities` bundle that lives in
   the per-store `PluginStoreData`. Host functions read it from
   `caller.data()` — the wasm guest cannot supply a different one.
2. **Linear memory is per-instance.** Each `invoke_export` builds a
   fresh `Store<PluginStoreData>`; wasmtime allocates a private
   linear memory region per store. There is no shared mutable state
   between two instances of the same module loaded for different
   tenants.

The integration test `cross_tenant_isolation_findings_read_uses_load_time_tenant`
loads the same WAT module under tenant A and tenant B; both observe
their own tenant's findings; the `Capabilities.tenant_id` field is
asserted to differ. The `cross_tenant_isolation_linear_memory_is_independent`
test runs the same module twice and verifies the per-invocation store
data is structurally separated.

### Plugin loading flow (host-side)

```
manifest validated by sx-api/plugins controller
        │
        ▼
WasmPluginHost::compile_module(bytes)
  ├─ Module::validate (wasmtime spec validator)
  ├─ Module::from_binary (cranelift codegen)
  └─ check imports: only `sentinelx::*` accepted;
     `wasi_snapshot_preview1`, `wasi`, `env` rejected
        │
        ▼
WasmPluginHost::load_manifest(tenant, manifest, bytes, …)
  ├─ if production AND manifest is legacy → reject
  └─ project capabilities from manifest required_scopes
        │
        ▼
LoadedPlugin { Module, Capabilities }
```

## Consequences

### Positive

- **Memory isolation.** A plugin cannot read the host's address
  space. Period.
- **Crash isolation.** A wasm trap stays inside the wasmtime store;
  the host worker stays up.
- **Fuel metering.** Infinite loops trap on fuel exhaustion. The
  worker stays responsive.
- **Capability tokens become hard guarantees.** The plugin cannot
  bypass them by jumping past the check — every host fn is a
  syscall-equivalent in wasm terms.
- **Audit trail.** Every host-fn call writes a `tracing::info!` to
  the `audit` target.

### Negative

- **Dependency.** `wasmtime` adds ~5 MiB to the compiled artefact
  (cranelift codegen included). The legacy-cdylib build path is
  preserved so internal tooling that does not need the sandbox can
  drop the dep.
- **Cold-start.** First instantiation of a previously-unseen
  module is ~50 ms (wasmtime codegen + linker setup) vs.
  ~1 ms for the in-process trait. Subsequent instantiations of the
  same module reuse the compiled `Module`.
- **SDK surface change.** Plugin authors port their code from a
  Rust trait to wasm. We ship a small Rust-targeting-wasm32 SDK
  that wraps the `sentinelx::*` host imports.

### Neutral

- Plugins lose access to the standard library that the in-process
  trait gave them for free. They can still allocate, iterate, parse
  JSON — anything that doesn't require I/O outside the host-fn
  surface.

## Alternatives considered

### `nsjail` / `bubblewrap` — Linux-only OS-level sandboxing

- ✅ Strong isolation (real Linux namespaces).
- ✅ Reuses the kernel's existing trust boundary.
- ❌ **Linux-only.** Our dev loop runs on macOS for half the team;
  production runs on Linux but CI matrix needs both.
- ❌ Process-per-plugin → 50 ms+ cold-start, plus IPC overhead
  on every host-fn call.
- ❌ Capability-check semantics need bespoke wiring on top of the
  sandbox (the kernel does not enforce our capability vocabulary).

Verdict: rejected for the macOS dev-loop blocker and the IPC
overhead.

### V8 isolates (`rusty_v8`)

- ✅ Battle-tested isolation model.
- ✅ Fast cold-start.
- ❌ Heavy dependency (~80 MiB of V8 binary, plus a non-trivial
  build story on Linux musl).
- ❌ JavaScript-targeted SDK → plugin authors write JS, not Rust,
  Go, or any other language that targets wasm32.
- ❌ Pin to a specific V8 minor; V8 ships a fast cadence and we'd
  inherit their release treadmill.

Verdict: rejected on binary size + ecosystem fit.

### Forked process per plugin

- ✅ Simplest mental model; OS guarantees isolation.
- ❌ ~50 ms per fork + IPC cost on every host-fn call.
- ❌ No fuel/memory metering without bolting on cgroups (Linux-only).
- ❌ Plugin process can issue arbitrary syscalls — sandbox still
  needed → see `nsjail`.

Verdict: rejected — same fundamental issues as `nsjail` plus more
overhead.

### Wasmer instead of wasmtime

- ✅ Comparable feature set, similar API.
- ❌ Wasmer's license trajectory has been bumpier; bytecodealliance's
  wasmtime is the de facto Rust-native default.
- ❌ Smaller embed/governance footprint at the time of writing.

Verdict: wasmtime is the lower-risk choice.

## Operational notes

- The host emits `tracing::info!(target = "audit", action =
  "plugins.wasm.load", …)` on every load, and one of
  `plugins.wasm.host_fn.{deny,findings_read,findings_annotate,http_fetch}`
  on every host-fn invocation. The audit tap-sink threads these
  onto the platform's audit chain.
- The `plugins.memory_limit_mb` / `plugins.cpu_fuel_per_invoke` /
  `plugins.http_calls_per_minute` figment keys override the defaults
  per environment.
- A future ADR will cover the wasm32-targeting **plugin SDK**
  crate (`sx-plugins-sdk-wasm`), which wraps the host-import surface
  in a Rust ergonomic API.
