//! WASM-sandboxed plugin host (CRIT-001).
//!
//! This module promotes the plugin sandbox from the in-process Rust-trait
//! model shipped in P3-007 to a real [`wasmtime`]-backed sandbox. The
//! in-process path is still available behind the opt-in `legacy-cdylib`
//! crate feature for the dev-loop tests but the host actively *rejects*
//! any manifest tagged as legacy in production
//! (`APP_ENV=production`).
//!
//! # Threat model
//!
//! Plugins are third-party code. We trust them only to the extent of
//! their manifest-declared capability scopes. Concretely:
//!
//! - The plugin's linear memory is independent from the host's address
//!   space and from every other plugin instance (wasmtime spawns a
//!   fresh `Store<T>` per [`WasmPluginInstance`]).
//! - The plugin can only call host functions explicitly registered on
//!   the [`wasmtime::Linker`]. Every host function first verifies that
//!   the plugin's load-time [`Capabilities`] cover the required scope;
//!   missing scope ⇒ trap with [`HostFnError::ScopeDenied`].
//! - CPU is bounded by wasmtime fuel-metering
//!   ([`PluginLimits::cpu_fuel_per_invoke`]); exhaustion traps before
//!   the plugin can monopolise the worker thread.
//! - Memory is capped by a [`wasmtime::ResourceLimiter`]
//!   ([`PluginLimits::memory_limit_bytes`]). Growing past the cap fails
//!   the `memory.grow` instruction with `-1` so the plugin learns
//!   without trapping the embedder.
//! - Outbound HTTP is rate-limited per plugin
//!   ([`PluginLimits::http_calls_per_minute`]) and additionally
//!   allow-listed per tenant ([`HostFetchPolicy::allow_list`]).
//! - The tenant id is bound at load time. Host functions implicitly
//!   carry the load-time tenant — the plugin **cannot widen scope** by
//!   passing a different tenant id from inside wasm (the host fn
//!   reads `self.tenant_id`, not a wasm-supplied argument).
//!
//! # Engineering bar
//!
//! - No `unsafe` in this module (workspace `unsafe_code = "forbid"`).
//!   wasmtime internally uses `unsafe`; that is their guarantee.
//! - Every host function audit-logs to the `audit` target via
//!   [`tracing::info!`] so the platform's tap-sink threads the call
//!   onto the audit chain.

// Note: the module-level `#[cfg(feature = "wasm-host")]` lives in
// `lib.rs` where the module is declared; repeating it here would trip
// the `duplicated_attributes` lint.
#![allow(clippy::significant_drop_tightening)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use wasmtime::{Caller, Config, Engine, Linker, Module, ResourceLimiter, Store, Trap};

use crate::manifest::PluginManifest;
use crate::sdk::{HostFetchPolicy, PluginFindingView, Scope};

// ---------------------------------------------------------------------------
// Public configuration types
// ---------------------------------------------------------------------------

/// Per-plugin resource limits.
///
/// Defaults match the CRIT-001 acceptance criteria:
///
/// - 64 MiB linear memory.
/// - 30 s of fuel per invocation (the exact fuel→time mapping depends on
///   wasmtime's per-op consumption; we treat 30 s as 30 billion fuel
///   units which is the wasmtime example baseline).
/// - 100 outbound HTTP calls per minute per plugin.
///
/// Production overrides come from the
/// `plugins.memory_limit_mb` / `plugins.cpu_fuel_per_invoke` /
/// `plugins.http_calls_per_minute` figment keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PluginLimits {
    /// Maximum linear memory in bytes. Default 64 MiB.
    pub memory_limit_bytes: usize,
    /// Fuel granted per invocation. Default 30 billion units (~30 s).
    pub cpu_fuel_per_invoke: u64,
    /// Maximum outbound HTTP calls per rolling 60 s window per plugin.
    pub http_calls_per_minute: u32,
}

impl PluginLimits {
    /// Default linear memory cap (64 MiB).
    pub const DEFAULT_MEMORY_BYTES: usize = 64 * 1024 * 1024;
    /// Default fuel per invoke (~30 s of CPU at wasmtime's baseline cost).
    pub const DEFAULT_FUEL: u64 = 30_000_000_000;
    /// Default outbound-HTTP rate (100 calls/min/plugin).
    pub const DEFAULT_HTTP_PER_MIN: u32 = 100;
}

impl Default for PluginLimits {
    fn default() -> Self {
        Self {
            memory_limit_bytes: Self::DEFAULT_MEMORY_BYTES,
            cpu_fuel_per_invoke: Self::DEFAULT_FUEL,
            http_calls_per_minute: Self::DEFAULT_HTTP_PER_MIN,
        }
    }
}

/// Wire form of the `APP_ENV` environment hint used by the loader to
/// refuse the legacy in-process path in production.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadMode {
    /// Development / test — legacy plugin manifests are accepted when
    /// the `legacy-cdylib` feature is also compiled in.
    Development,
    /// Production — legacy plugin manifests are *rejected*. Only WASM
    /// bytecode is acceptable.
    Production,
}

impl LoadMode {
    /// Resolve `APP_ENV` → [`LoadMode`]. Anything but the literal
    /// `"production"` (case-insensitive) is treated as development.
    #[must_use]
    pub const fn from_env(value: Option<&str>) -> Self {
        match value {
            Some(v) if v.eq_ignore_ascii_case("production") => Self::Production,
            _ => Self::Development,
        }
    }
}

/// Capability bundle granted to a plugin at load time.
///
/// `tenant_id` is the immutable tenant binding — every host function
/// reads it from `self`, not from arguments supplied by the wasm guest.
#[derive(Debug, Clone)]
pub struct Capabilities {
    /// Tenant the plugin is bound to. Plugins **cannot** widen this.
    pub tenant_id: String,
    /// Scopes the plugin's manifest declared (e.g. `findings:read`).
    pub scopes: HashSet<String>,
    /// Outbound-fetch policy (allow-list of hosts).
    pub fetch_policy: HostFetchPolicy,
    /// Resource limits.
    pub limits: PluginLimits,
}

impl Capabilities {
    /// Build a capability bundle from a manifest and a tenant id.
    #[must_use]
    pub fn from_manifest(
        tenant_id: impl Into<String>,
        manifest: &PluginManifest,
        fetch_policy: HostFetchPolicy,
        limits: PluginLimits,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            scopes: manifest.required_scopes.iter().cloned().collect(),
            fetch_policy,
            limits,
        }
    }

    /// True iff the manifest declared `scope`.
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(scope)
    }
}

// ---------------------------------------------------------------------------
// Host-function error reporting
// ---------------------------------------------------------------------------

/// Reasons a host function will refuse a wasm caller's request.
///
/// These end up as wasm `Trap`s — the plugin sees a fatal error and the
/// host gets a typed reason for the audit log.
#[derive(Debug, Clone, thiserror::Error)]
pub enum HostFnError {
    /// The plugin invoked a host fn whose scope was not declared in the
    /// manifest.
    #[error("scope denied: {0}")]
    ScopeDenied(String),
    /// The plugin tried to fetch a URL whose host is not allow-listed
    /// for this tenant.
    #[error("url not allow-listed: {0}")]
    UrlNotAllowed(String),
    /// Per-plugin rate limit (e.g. `http:fetch`) exceeded.
    #[error("rate limited: {scope} ({calls}/{window:?})")]
    RateLimited {
        /// Scope that hit the limit (e.g. `http:fetch`).
        scope: String,
        /// How many calls were made in the window.
        calls: u32,
        /// Window duration (60 s in defaults).
        window: Duration,
    },
    /// A wasm pointer/length argument was out of bounds for the linear
    /// memory.
    #[error("bad guest pointer: {0}")]
    BadGuestPtr(String),
    /// A downstream dependency (the in-process backing store) reported
    /// an error.
    #[error("dependency: {0}")]
    Dependency(String),
}

// ---------------------------------------------------------------------------
// In-host backing services used by the host functions
// ---------------------------------------------------------------------------

/// Backing store for `host_findings_read` / `host_findings_annotate`.
///
/// The production wiring stitches this into the platform's findings
/// pipeline; tests use the in-memory [`InMemoryFindingsStore`] below.
pub trait FindingsBackend: Send + Sync + std::fmt::Debug {
    /// List findings for `tenant_id` (capped by `limit`).
    ///
    /// # Errors
    ///
    /// Returns [`HostFnError::Dependency`] when the underlying store
    /// cannot be queried.
    fn list_findings(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Vec<PluginFindingView>, HostFnError>;

    /// Append an annotation to a finding.
    ///
    /// # Errors
    ///
    /// Returns [`HostFnError::Dependency`] when the underlying store
    /// cannot be written to.
    fn annotate(&self, tenant_id: &str, finding_id: &str, note: &str) -> Result<(), HostFnError>;
}

/// Backing store for `host_http_fetch`.
pub trait HttpBackend: Send + Sync + std::fmt::Debug {
    /// Synchronously fetch `url` and return the response bytes.
    ///
    /// # Errors
    ///
    /// Returns [`HostFnError::Dependency`] on transport failure.
    fn fetch(&self, url: &str) -> Result<Vec<u8>, HostFnError>;
}

/// In-memory implementation of [`FindingsBackend`] used by tests + by
/// the dev-loop monolith.
#[derive(Debug, Default)]
pub struct InMemoryFindingsStore {
    inner: Mutex<InMemoryFindingsInner>,
}

#[derive(Debug, Default)]
struct InMemoryFindingsInner {
    /// `tenant_id -> Vec<PluginFindingView>`.
    findings: HashMap<String, Vec<PluginFindingView>>,
    /// `(tenant_id, finding_id) -> Vec<note>`.
    annotations: HashMap<(String, String), Vec<String>>,
}

impl InMemoryFindingsStore {
    /// Build an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed the store with a tenant's findings (test helper).
    pub fn seed(&self, tenant_id: &str, findings: Vec<PluginFindingView>) {
        if let Ok(mut g) = self.inner.lock() {
            g.findings.insert(tenant_id.to_owned(), findings);
        }
    }

    /// Read the annotations recorded for `(tenant_id, finding_id)` —
    /// used by tests to verify writes landed in the right tenant slot.
    #[must_use]
    pub fn annotations_for(&self, tenant_id: &str, finding_id: &str) -> Vec<String> {
        self.inner
            .lock()
            .ok()
            .and_then(|g| {
                g.annotations
                    .get(&(tenant_id.to_owned(), finding_id.to_owned()))
                    .cloned()
            })
            .unwrap_or_default()
    }
}

impl FindingsBackend for InMemoryFindingsStore {
    fn list_findings(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Vec<PluginFindingView>, HostFnError> {
        let g = self
            .inner
            .lock()
            .map_err(|_| HostFnError::Dependency("findings mutex poisoned".into()))?;
        Ok(g.findings
            .get(tenant_id)
            .map(|v| v.iter().take(limit).cloned().collect())
            .unwrap_or_default())
    }

    fn annotate(&self, tenant_id: &str, finding_id: &str, note: &str) -> Result<(), HostFnError> {
        {
            let mut g = self
                .inner
                .lock()
                .map_err(|_| HostFnError::Dependency("findings mutex poisoned".into()))?;
            g.annotations
                .entry((tenant_id.to_owned(), finding_id.to_owned()))
                .or_default()
                .push(note.to_owned());
        }
        Ok(())
    }
}

/// Static `HttpBackend` that records the URLs it was called with —
/// good enough for the test surface and for the dev-loop no-op plugin.
#[derive(Debug, Default)]
pub struct InMemoryHttpBackend {
    calls: Mutex<Vec<String>>,
    response: Vec<u8>,
}

impl InMemoryHttpBackend {
    /// Build a backend that returns `response` for every fetch.
    #[must_use]
    pub const fn with_response(response: Vec<u8>) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            response,
        }
    }

    /// Snapshot the list of URLs the backend has been asked to fetch.
    #[must_use]
    pub fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .ok()
            .map(|g| (*g).clone())
            .unwrap_or_default()
    }
}

impl HttpBackend for InMemoryHttpBackend {
    fn fetch(&self, url: &str) -> Result<Vec<u8>, HostFnError> {
        {
            let mut g = self
                .calls
                .lock()
                .map_err(|_| HostFnError::Dependency("http mutex poisoned".into()))?;
            g.push(url.to_owned());
        }
        Ok(self.response.clone())
    }
}

// ---------------------------------------------------------------------------
// Per-store data carried through wasmtime
// ---------------------------------------------------------------------------

/// State threaded through a [`wasmtime::Store`] for a single plugin
/// instance. Host functions look up capabilities + backends through
/// `caller.data()` so the plugin cannot supply them.
#[derive(Debug)]
pub struct PluginStoreData {
    /// Load-time capabilities (tenant id, scopes, limits, allow-list).
    pub caps: Capabilities,
    /// Findings backend.
    pub findings: Arc<dyn FindingsBackend>,
    /// HTTP backend.
    pub http: Arc<dyn HttpBackend>,
    /// Sliding-window timestamps for `http:fetch` calls.
    http_calls: VecDeque<Instant>,
    /// Resource limiter used by wasmtime's `Store::limiter`.
    limiter: PluginResourceLimiter,
}

impl PluginStoreData {
    /// Build a fresh store data bundle from caps + backends.
    pub fn new(
        caps: Capabilities,
        findings: Arc<dyn FindingsBackend>,
        http: Arc<dyn HttpBackend>,
    ) -> Self {
        let limiter = PluginResourceLimiter {
            memory_limit_bytes: caps.limits.memory_limit_bytes,
            denied_memory_grows: 0,
        };
        Self {
            caps,
            findings,
            http,
            http_calls: VecDeque::new(),
            limiter,
        }
    }

    /// Sliding-window rate check for `http:fetch`. Returns
    /// [`HostFnError::RateLimited`] when the plugin exceeded the budget.
    fn check_http_rate(&mut self) -> Result<(), HostFnError> {
        let now = Instant::now();
        let window = Duration::from_secs(60);
        while let Some(front) = self.http_calls.front() {
            if now.duration_since(*front) > window {
                self.http_calls.pop_front();
            } else {
                break;
            }
        }
        let limit = self.caps.limits.http_calls_per_minute;
        let len_u32 = u32::try_from(self.http_calls.len()).unwrap_or(u32::MAX);
        if len_u32 >= limit {
            return Err(HostFnError::RateLimited {
                scope: Scope::HTTP_FETCH.to_owned(),
                calls: len_u32,
                window,
            });
        }
        self.http_calls.push_back(now);
        Ok(())
    }

    /// Snapshot how many times `memory_growing` returned `Ok(false)` for
    /// this instance — used by the malicious-allocate test.
    #[must_use]
    pub const fn denied_memory_grows(&self) -> u32 {
        self.limiter.denied_memory_grows
    }
}

/// Stash-style [`ResourceLimiter`] that caps linear-memory growth.
///
/// `memory_growing` is called by wasmtime on every `memory.grow`. We
/// reject any growth that would push us past the configured cap.
#[derive(Debug)]
struct PluginResourceLimiter {
    memory_limit_bytes: usize,
    denied_memory_grows: u32,
}

impl ResourceLimiter for PluginResourceLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        if desired > self.memory_limit_bytes {
            self.denied_memory_grows = self.denied_memory_grows.saturating_add(1);
            tracing::warn!(
                target: "sx_plugins.wasm",
                desired,
                cap = self.memory_limit_bytes,
                "memory_growing rejected"
            );
            return Ok(false);
        }
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        // Cap tables at 16 K elements — matches wasmtime's default and
        // is plenty for our plugin shape (we do not expose function
        // tables to plugins beyond the import set).
        // LOW-001-FU1 (2026-06-16): wasmtime 24.0.7 changed the
        // ResourceLimiter::table_growing arg type from usize -> u32.
        // LOW-001-FU2 (2026-06-23): wasmtime 36.0.11 reverted that back
        // to usize. The semantics are unchanged.
        Ok(desired <= 16_384)
    }
}

// ---------------------------------------------------------------------------
// WasmPluginHost — the public entry point
// ---------------------------------------------------------------------------

/// Imports namespace exposed to wasm plugins.
///
/// Every host function lives under this module name on the
/// [`wasmtime::Linker`]. Plugins import as
/// `(import "sentinelx" "findings_read" (func ...))`.
pub const HOST_NAMESPACE: &str = "sentinelx";

/// Disallowed import namespaces. Any wasm module that imports anything
/// outside [`HOST_NAMESPACE`] is rejected at load time — that includes
/// the typical exfiltration vectors `wasi_snapshot_preview1`, `env`
/// (which is a magnet for raw syscalls), and friends.
const DISALLOWED_IMPORT_MODULES: &[&str] = &["wasi_snapshot_preview1", "wasi", "env"];

/// Loader-side errors when registering a plugin.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The supplied bytes did not validate as a well-formed wasm module.
    #[error("wasm module validation failed: {0}")]
    Validation(String),
    /// The module imports something other than [`HOST_NAMESPACE`].
    #[error("disallowed import: ({module}, {name})")]
    DisallowedImport {
        /// The wasm import module name.
        module: String,
        /// The wasm import field name.
        name: String,
    },
    /// Production refused to load a legacy in-process plugin.
    #[error("legacy plugin manifests are rejected in production")]
    LegacyInProduction,
    /// The wasmtime engine could not be built or the linker could not
    /// be configured.
    #[error("engine init: {0}")]
    EngineInit(String),
    /// The wasmtime engine accepted the module bytes but module
    /// compilation failed.
    #[error("module compile: {0}")]
    ModuleCompile(String),
}

/// Errors surfaced when a previously-loaded plugin is invoked.
#[derive(Debug, thiserror::Error)]
pub enum InvokeError {
    /// The plugin trapped during execution.
    #[error("plugin trapped: {0}")]
    Trap(String),
    /// The plugin exhausted its fuel allowance.
    #[error("fuel exhausted")]
    FuelExhausted,
    /// Instantiation failed (missing export, type mismatch).
    #[error("instantiate: {0}")]
    Instantiate(String),
    /// Internal error (mutex poisoned, etc.).
    #[error("internal: {0}")]
    Internal(String),
}

/// Sandboxed plugin host backed by [`wasmtime`].
///
/// One [`WasmPluginHost`] per process; it owns a single
/// [`wasmtime::Engine`] (engines are cheap to share across stores) and
/// a linker pre-populated with the host-function surface.
///
/// Each `load_*` call compiles a [`Module`] which can then be
/// instantiated *per tenant* through [`WasmPluginHost::instantiate`] —
/// the per-instance [`Store`] carries the tenant binding so cross-
/// tenant isolation is structural, not a runtime check.
pub struct WasmPluginHost {
    engine: Engine,
    /// The findings backend shared by every plugin in this process. The
    /// `tenant_id` filter is applied inside each host fn.
    findings: Arc<dyn FindingsBackend>,
    /// The HTTP backend shared by every plugin.
    http: Arc<dyn HttpBackend>,
    /// Runtime mode — gates the legacy in-process fallback.
    mode: LoadMode,
}

impl std::fmt::Debug for WasmPluginHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmPluginHost")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl WasmPluginHost {
    /// Build a host with the supplied backends and runtime mode.
    ///
    /// # Errors
    ///
    /// Returns [`LoadError::EngineInit`] when wasmtime refuses the
    /// configured engine (e.g. cranelift unavailable on this build).
    pub fn new(
        findings: Arc<dyn FindingsBackend>,
        http: Arc<dyn HttpBackend>,
        mode: LoadMode,
    ) -> Result<Self, LoadError> {
        let mut cfg = Config::new();
        cfg.consume_fuel(true);
        // NOTE: `wasm_threads(false)` is gated on the wasmtime
        // `threads` feature, which we do not enable. With the feature
        // off threads are unavailable by construction, so the
        // explicit disable is redundant.
        let engine = Engine::new(&cfg).map_err(|e| LoadError::EngineInit(e.to_string()))?;
        Ok(Self {
            engine,
            findings,
            http,
            mode,
        })
    }

    /// Borrow the underlying wasmtime engine — useful for tests that
    /// want to compile fixtures with the same engine the host runs.
    #[must_use]
    pub const fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Read the configured load mode.
    #[must_use]
    pub const fn mode(&self) -> LoadMode {
        self.mode
    }

    /// Validate + compile a WASM module from bytes.
    ///
    /// This is the first stage of [`load_manifest`] — split out so
    /// callers (and tests) can validate untrusted bytes before storing
    /// them.
    ///
    /// # Errors
    ///
    /// * [`LoadError::Validation`] if wasmtime's validator rejected the
    ///   bytes.
    /// * [`LoadError::DisallowedImport`] if the module imports anything
    ///   outside [`HOST_NAMESPACE`].
    /// * [`LoadError::ModuleCompile`] if codegen failed.
    pub fn compile_module(&self, bytes: &[u8]) -> Result<Module, LoadError> {
        // Stage 1: validator (spec compliance).
        Module::validate(&self.engine, bytes).map_err(|e| LoadError::Validation(e.to_string()))?;
        // Stage 2: codegen.
        let module = Module::from_binary(&self.engine, bytes)
            .map_err(|e| LoadError::ModuleCompile(e.to_string()))?;
        // Stage 3: structural check on imports — only `HOST_NAMESPACE`
        // imports are permitted. Everything else (WASI, `env`, …) is
        // rejected so plugins cannot reach raw syscalls.
        for imp in module.imports() {
            let m = imp.module();
            if DISALLOWED_IMPORT_MODULES
                .iter()
                .any(|d| d.eq_ignore_ascii_case(m))
                || m != HOST_NAMESPACE
            {
                return Err(LoadError::DisallowedImport {
                    module: m.to_owned(),
                    name: imp.name().to_owned(),
                });
            }
        }
        Ok(module)
    }

    /// Load a manifest + WASM bytes for a specific tenant.
    ///
    /// Returns a compiled [`Module`] paired with the load-time
    /// [`Capabilities`]; the caller stashes both for later use via
    /// [`instantiate`].
    ///
    /// # Errors
    ///
    /// * [`LoadError::LegacyInProduction`] if the manifest is tagged
    ///   `legacy-cdylib` while `mode == Production`.
    /// * Anything [`compile_module`] returns.
    pub fn load_manifest(
        &self,
        tenant_id: &str,
        manifest: &PluginManifest,
        bytecode: &[u8],
        fetch_policy: HostFetchPolicy,
        limits: PluginLimits,
    ) -> Result<LoadedPlugin, LoadError> {
        // Legacy-mode check — production refuses non-WASM manifests.
        if is_legacy_manifest(manifest) && self.mode == LoadMode::Production {
            return Err(LoadError::LegacyInProduction);
        }
        let module = self.compile_module(bytecode)?;
        let caps = Capabilities::from_manifest(tenant_id, manifest, fetch_policy, limits);
        tracing::info!(
            target: "audit",
            action = "plugins.wasm.load",
            tenant_id = %tenant_id,
            plugin_name = %manifest.name,
            scopes = ?caps.scopes,
            "wasm plugin loaded"
        );
        Ok(LoadedPlugin { module, caps })
    }

    /// Build a fresh [`Store`] + [`Linker`] for `loaded` and call the
    /// guest's exported `_start` function.
    ///
    /// # Errors
    ///
    /// * [`InvokeError::Instantiate`] when wasmtime cannot link or
    ///   instantiate the module.
    /// * [`InvokeError::FuelExhausted`] when the plugin runs out of
    ///   fuel.
    /// * [`InvokeError::Trap`] for every other trap.
    pub fn invoke_start(&self, loaded: &LoadedPlugin) -> Result<InvokeReport, InvokeError> {
        self.invoke_export(loaded, "_start")
    }

    /// Build a fresh [`Store`] + [`Linker`] for `loaded` and call the
    /// guest's exported function `export_name`.
    ///
    /// # Errors
    ///
    /// See [`invoke_start`].
    pub fn invoke_export(
        &self,
        loaded: &LoadedPlugin,
        export_name: &str,
    ) -> Result<InvokeReport, InvokeError> {
        let store_data = PluginStoreData::new(
            loaded.caps.clone(),
            Arc::clone(&self.findings),
            Arc::clone(&self.http),
        );
        let fuel = loaded.caps.limits.cpu_fuel_per_invoke;
        let mut store: Store<PluginStoreData> = Store::new(&self.engine, store_data);
        store
            .set_fuel(fuel)
            .map_err(|e| InvokeError::Internal(format!("set_fuel: {e}")))?;
        store.limiter(|d| &mut d.limiter);

        let mut linker: Linker<PluginStoreData> = Linker::new(&self.engine);
        register_host_fns(&mut linker)
            .map_err(|e| InvokeError::Instantiate(format!("linker: {e}")))?;

        let instance = linker
            .instantiate(&mut store, &loaded.module)
            .map_err(|e| InvokeError::Instantiate(e.to_string()))?;

        // No `_start` export → instantiation alone is the test
        // signal (e.g. malicious-allocate plugin uses a `start`
        // section that runs at instantiation time).
        let outcome = instance
            .get_typed_func::<(), ()>(&mut store, export_name)
            .map_or_else(|_| Ok(()), |start| start.call(&mut store, ()));

        let denied_grows = store.data().denied_memory_grows();
        let http_calls_used = u32::try_from(store.data().http_calls.len()).unwrap_or(u32::MAX);

        let trap = outcome.err().as_ref().map(classify_trap);
        Ok(InvokeReport {
            trap,
            denied_memory_grows: denied_grows,
            http_calls_used,
        })
    }
}

/// A compiled module paired with the load-time capability bundle.
#[derive(Debug)]
pub struct LoadedPlugin {
    /// The compiled wasm module.
    pub module: Module,
    /// Load-time capabilities (tenant binding, scopes, limits).
    pub caps: Capabilities,
}

/// Outcome of [`WasmPluginHost::invoke_export`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvokeReport {
    /// `Some(kind)` if the plugin trapped; `None` for a clean exit.
    pub trap: Option<TrapKind>,
    /// How many `memory.grow` requests the resource limiter denied.
    pub denied_memory_grows: u32,
    /// How many `host_http_fetch` calls landed in this invocation.
    pub http_calls_used: u32,
}

/// Coarse trap classification surfaced to the host audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrapKind {
    /// The plugin exhausted its fuel.
    FuelExhausted,
    /// The plugin called a host fn whose scope was not granted.
    ScopeDenied(String),
    /// The plugin tried to fetch a URL not on the tenant's allow-list.
    UrlNotAllowed(String),
    /// The plugin tripped the per-plugin HTTP rate limit.
    RateLimited(String),
    /// The plugin attempted to grow memory past the cap.
    MemoryCapped,
    /// Any other trap — message preserved verbatim.
    Other(String),
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// True iff the manifest is tagged as a legacy in-process plugin.
///
/// Convention: any required scope containing the literal
/// `"legacy:cdylib"` flags the manifest as legacy. The marketplace UI
/// surfaces this in the install dialog with a "development only" badge.
fn is_legacy_manifest(manifest: &PluginManifest) -> bool {
    manifest
        .required_scopes
        .iter()
        .any(|s| s.eq_ignore_ascii_case("legacy:cdylib"))
}

/// Classify a wasmtime error into a [`TrapKind`] for audit output.
fn classify_trap(err: &anyhow::Error) -> TrapKind {
    // Fuel-exhaust traps carry a wasmtime::Trap::OutOfFuel.
    if let Some(t) = err.downcast_ref::<Trap>() {
        if *t == Trap::OutOfFuel {
            return TrapKind::FuelExhausted;
        }
    }
    if let Some(host_err) = err.downcast_ref::<HostFnError>() {
        return match host_err {
            HostFnError::ScopeDenied(s) => TrapKind::ScopeDenied(s.clone()),
            HostFnError::UrlNotAllowed(u) => TrapKind::UrlNotAllowed(u.clone()),
            HostFnError::RateLimited { scope, .. } => TrapKind::RateLimited(scope.clone()),
            HostFnError::BadGuestPtr(m) | HostFnError::Dependency(m) => TrapKind::Other(m.clone()),
        };
    }
    TrapKind::Other(err.to_string())
}

/// Register every host fn under [`HOST_NAMESPACE`] on the supplied
/// linker. The fn bodies trampoline through `Caller<'_, PluginStoreData>`
/// so the per-tenant binding stays tied to the store.
fn register_host_fns(linker: &mut Linker<PluginStoreData>) -> anyhow::Result<()> {
    linker.func_wrap(HOST_NAMESPACE, "findings_read", host_findings_read)?;
    linker.func_wrap(HOST_NAMESPACE, "findings_annotate", host_findings_annotate)?;
    linker.func_wrap(HOST_NAMESPACE, "http_fetch", host_http_fetch)?;
    Ok(())
}

/// `findings_read(limit: i32) -> i32` — returns the number of findings
/// the host surfaced.
///
/// We deliberately do not copy the JSON into wasm memory in this MVP
/// (that requires a memory exporter on the guest side); the count
/// alone is enough for the capability + tenant-binding tests. The
/// production host extends this to a guest-allocated buffer once the
/// SDK ships.
fn host_findings_read(
    mut caller: Caller<'_, PluginStoreData>,
    limit: i32,
) -> Result<i32, wasmtime::Error> {
    let data = caller.data_mut();
    if !data.caps.has_scope(Scope::FINDINGS_READ) {
        tracing::warn!(
            target: "audit",
            action = "plugins.wasm.host_fn.deny",
            tenant_id = %data.caps.tenant_id,
            scope = Scope::FINDINGS_READ,
            "findings_read denied (no scope)"
        );
        return Err(wasmtime::Error::from(HostFnError::ScopeDenied(
            Scope::FINDINGS_READ.into(),
        )));
    }
    let limit_usize = usize::try_from(limit.max(0)).unwrap_or(0);
    let tenant = data.caps.tenant_id.clone();
    let backend = Arc::clone(&data.findings);
    let findings = backend
        .list_findings(&tenant, limit_usize)
        .map_err(wasmtime::Error::from)?;
    tracing::info!(
        target: "audit",
        action = "plugins.wasm.host_fn.findings_read",
        tenant_id = %tenant,
        returned = findings.len(),
        "host_findings_read"
    );
    Ok(i32::try_from(findings.len()).unwrap_or(i32::MAX))
}

/// `findings_annotate(finding_id_ptr, finding_id_len, note_ptr, note_len) -> i32`
/// — guest passes pointers into its own linear memory; the host reads
/// the bytes through `Caller::get_export("memory")`. Returns 0 on
/// success.
fn host_findings_annotate(
    mut caller: Caller<'_, PluginStoreData>,
    id_ptr: i32,
    id_len: i32,
    note_ptr: i32,
    note_len: i32,
) -> Result<i32, wasmtime::Error> {
    let id = read_guest_string(&mut caller, id_ptr, id_len)?;
    let note = read_guest_string(&mut caller, note_ptr, note_len)?;
    let data = caller.data_mut();
    if !data.caps.has_scope(Scope::FINDINGS_ANNOTATE) {
        tracing::warn!(
            target: "audit",
            action = "plugins.wasm.host_fn.deny",
            tenant_id = %data.caps.tenant_id,
            scope = Scope::FINDINGS_ANNOTATE,
            "findings_annotate denied (no scope)"
        );
        return Err(wasmtime::Error::from(HostFnError::ScopeDenied(
            Scope::FINDINGS_ANNOTATE.into(),
        )));
    }
    let tenant = data.caps.tenant_id.clone();
    let backend = Arc::clone(&data.findings);
    backend
        .annotate(&tenant, &id, &note)
        .map_err(wasmtime::Error::from)?;
    tracing::info!(
        target: "audit",
        action = "plugins.wasm.host_fn.findings_annotate",
        tenant_id = %tenant,
        finding_id = %id,
        "host_findings_annotate"
    );
    Ok(0)
}

/// `http_fetch(url_ptr, url_len) -> i32` — returns response length on
/// success. Traps for scope denial, allow-list miss, or rate-limit
/// exhaustion.
#[allow(clippy::cognitive_complexity)] // host call: arg unmarshal + capability check + allow-list match + fetch + return
fn host_http_fetch(
    mut caller: Caller<'_, PluginStoreData>,
    url_ptr: i32,
    url_len: i32,
) -> Result<i32, wasmtime::Error> {
    let url = read_guest_string(&mut caller, url_ptr, url_len)?;
    let data = caller.data_mut();
    if !data.caps.has_scope(Scope::HTTP_FETCH) {
        tracing::warn!(
            target: "audit",
            action = "plugins.wasm.host_fn.deny",
            tenant_id = %data.caps.tenant_id,
            scope = Scope::HTTP_FETCH,
            "http_fetch denied (no scope)"
        );
        return Err(wasmtime::Error::from(HostFnError::ScopeDenied(
            Scope::HTTP_FETCH.into(),
        )));
    }
    data.check_http_rate().map_err(wasmtime::Error::from)?;
    let parsed = url::Url::parse(&url)
        .map_err(|e| wasmtime::Error::from(HostFnError::BadGuestPtr(format!("url parse: {e}"))))?;
    let host_str = parsed.host_str().unwrap_or("").to_owned();
    if !data.caps.fetch_policy.is_allowed(&host_str) {
        tracing::warn!(
            target: "audit",
            action = "plugins.wasm.host_fn.deny",
            tenant_id = %data.caps.tenant_id,
            host = %host_str,
            "http_fetch denied (host not on allow-list)"
        );
        return Err(wasmtime::Error::from(HostFnError::UrlNotAllowed(host_str)));
    }
    let backend = Arc::clone(&data.http);
    let resp = backend.fetch(&url).map_err(wasmtime::Error::from)?;
    tracing::info!(
        target: "audit",
        action = "plugins.wasm.host_fn.http_fetch",
        tenant_id = %data.caps.tenant_id,
        host = %host_str,
        bytes = resp.len(),
        "host_http_fetch"
    );
    Ok(i32::try_from(resp.len()).unwrap_or(i32::MAX))
}

/// Copy a `(ptr, len)` span out of the wasm linear memory into a
/// host-side `String`. Bounds-checked: out-of-range spans trap with
/// [`HostFnError::BadGuestPtr`].
fn read_guest_string(
    caller: &mut Caller<'_, PluginStoreData>,
    ptr: i32,
    len: i32,
) -> Result<String, wasmtime::Error> {
    let memory = caller
        .get_export("memory")
        .and_then(wasmtime::Extern::into_memory)
        .ok_or_else(|| {
            wasmtime::Error::from(HostFnError::BadGuestPtr("guest exports no `memory`".into()))
        })?;
    let ptr_usize = usize::try_from(ptr)
        .map_err(|_| wasmtime::Error::from(HostFnError::BadGuestPtr("ptr < 0".into())))?;
    let len_usize = usize::try_from(len)
        .map_err(|_| wasmtime::Error::from(HostFnError::BadGuestPtr("len < 0".into())))?;
    let end = ptr_usize.checked_add(len_usize).ok_or_else(|| {
        wasmtime::Error::from(HostFnError::BadGuestPtr("ptr+len overflow".into()))
    })?;
    let data = memory.data(&caller);
    let bytes = data
        .get(ptr_usize..end)
        .ok_or_else(|| wasmtime::Error::from(HostFnError::BadGuestPtr("oob span".into())))?;
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

// ---------------------------------------------------------------------------
// Serde projection used by the manifest validator
// ---------------------------------------------------------------------------

/// Persisted form of [`PluginLimits`] (RFC-style `snake_case` JSON).
///
/// Lives next to [`PluginLimits`] so the figment-loaded operator
/// override merges cleanly.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginLimitsConfig {
    /// Memory cap in megabytes. Defaults to 64.
    #[serde(default = "PluginLimitsConfig::default_mb")]
    pub memory_limit_mb: usize,
    /// Fuel granted per invoke. Defaults to 30 billion.
    #[serde(default = "PluginLimitsConfig::default_fuel")]
    pub cpu_fuel_per_invoke: u64,
    /// HTTP rate ceiling per minute per plugin. Defaults to 100.
    #[serde(default = "PluginLimitsConfig::default_http")]
    pub http_calls_per_minute: u32,
}

impl PluginLimitsConfig {
    const fn default_mb() -> usize {
        64
    }
    const fn default_fuel() -> u64 {
        PluginLimits::DEFAULT_FUEL
    }
    const fn default_http() -> u32 {
        PluginLimits::DEFAULT_HTTP_PER_MIN
    }
}

impl Default for PluginLimitsConfig {
    fn default() -> Self {
        Self {
            memory_limit_mb: Self::default_mb(),
            cpu_fuel_per_invoke: Self::default_fuel(),
            http_calls_per_minute: Self::default_http(),
        }
    }
}

impl From<PluginLimitsConfig> for PluginLimits {
    fn from(c: PluginLimitsConfig) -> Self {
        Self {
            memory_limit_bytes: c.memory_limit_mb.saturating_mul(1024 * 1024),
            cpu_fuel_per_invoke: c.cpu_fuel_per_invoke,
            http_calls_per_minute: c.http_calls_per_minute,
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::envelope::EventKind;

    fn manifest_with(scopes: &[&str]) -> PluginManifest {
        PluginManifest {
            name: "test".into(),
            vendor: "Acme".into(),
            version: "0.0.1".into(),
            webhook_url: "https://example.test/hook".into(),
            supported_events: vec![EventKind::FindingCreated],
            required_scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn limits_default_matches_spec() {
        let l = PluginLimits::default();
        assert_eq!(l.memory_limit_bytes, 64 * 1024 * 1024);
        assert_eq!(l.cpu_fuel_per_invoke, 30_000_000_000);
        assert_eq!(l.http_calls_per_minute, 100);
    }

    #[test]
    fn limits_config_round_trips() {
        let raw = r#"{
            "memory_limit_mb": 32,
            "cpu_fuel_per_invoke": 1000000,
            "http_calls_per_minute": 10
        }"#;
        let cfg: PluginLimitsConfig = serde_json::from_str(raw).unwrap();
        let limits: PluginLimits = cfg.into();
        assert_eq!(limits.memory_limit_bytes, 32 * 1024 * 1024);
        assert_eq!(limits.cpu_fuel_per_invoke, 1_000_000);
        assert_eq!(limits.http_calls_per_minute, 10);
    }

    #[test]
    fn load_mode_from_env_recognises_production() {
        assert_eq!(LoadMode::from_env(Some("production")), LoadMode::Production);
        assert_eq!(LoadMode::from_env(Some("PRODUCTION")), LoadMode::Production);
        assert_eq!(
            LoadMode::from_env(Some("development")),
            LoadMode::Development
        );
        assert_eq!(LoadMode::from_env(None), LoadMode::Development);
    }

    #[test]
    fn capabilities_project_from_manifest() {
        let m = manifest_with(&[Scope::FINDINGS_READ, Scope::HTTP_FETCH]);
        let caps = Capabilities::from_manifest(
            "tenant-a",
            &m,
            HostFetchPolicy::default(),
            PluginLimits::default(),
        );
        assert_eq!(caps.tenant_id, "tenant-a");
        assert!(caps.has_scope(Scope::FINDINGS_READ));
        assert!(caps.has_scope(Scope::HTTP_FETCH));
        assert!(!caps.has_scope(Scope::FINDINGS_ANNOTATE));
    }

    #[test]
    fn is_legacy_manifest_recognises_marker() {
        let m = manifest_with(&["legacy:cdylib"]);
        assert!(is_legacy_manifest(&m));
        let m2 = manifest_with(&[Scope::FINDINGS_READ]);
        assert!(!is_legacy_manifest(&m2));
    }

    #[test]
    fn rate_limiter_denies_after_budget() {
        let mut data = PluginStoreData::new(
            Capabilities::from_manifest(
                "t",
                &manifest_with(&[Scope::HTTP_FETCH]),
                HostFetchPolicy::default(),
                PluginLimits {
                    http_calls_per_minute: 2,
                    ..PluginLimits::default()
                },
            ),
            Arc::new(InMemoryFindingsStore::new()),
            Arc::new(InMemoryHttpBackend::with_response(b"ok".to_vec())),
        );
        assert!(data.check_http_rate().is_ok());
        assert!(data.check_http_rate().is_ok());
        let err = data.check_http_rate().expect_err("3rd must be denied");
        assert!(matches!(err, HostFnError::RateLimited { .. }));
    }

    #[test]
    fn resource_limiter_rejects_over_cap_grow() {
        let mut l = PluginResourceLimiter {
            memory_limit_bytes: 1024 * 1024,
            denied_memory_grows: 0,
        };
        assert!(l.memory_growing(0, 512 * 1024, None).unwrap());
        assert!(!l.memory_growing(0, 8 * 1024 * 1024, None).unwrap());
        assert_eq!(l.denied_memory_grows, 1);
    }

    #[test]
    fn in_memory_findings_store_segregates_tenants() {
        let store = InMemoryFindingsStore::new();
        store.seed(
            "tenant-a",
            vec![PluginFindingView {
                id: "f-1".into(),
                severity: "high".into(),
                title: "demo".into(),
                status: "open".into(),
            }],
        );
        let a = store.list_findings("tenant-a", 10).unwrap();
        let b = store.list_findings("tenant-b", 10).unwrap();
        assert_eq!(a.len(), 1);
        assert!(b.is_empty());
    }

    #[test]
    fn host_namespace_is_stable() {
        assert_eq!(HOST_NAMESPACE, "sentinelx");
    }

    #[test]
    fn wasm_host_rejects_disallowed_import() {
        let host = WasmPluginHost::new(
            Arc::new(InMemoryFindingsStore::new()),
            Arc::new(InMemoryHttpBackend::with_response(b"ok".to_vec())),
            LoadMode::Development,
        )
        .unwrap();
        let bytes = wat::parse_str(
            r#"(module
                (import "wasi_snapshot_preview1" "fd_write"
                    (func (param i32 i32 i32 i32) (result i32)))
            )"#,
        )
        .unwrap();
        let err = host.compile_module(&bytes).expect_err("must reject WASI");
        assert!(matches!(err, LoadError::DisallowedImport { .. }));
    }

    #[test]
    fn wasm_host_accepts_empty_module() {
        let host = WasmPluginHost::new(
            Arc::new(InMemoryFindingsStore::new()),
            Arc::new(InMemoryHttpBackend::with_response(b"ok".to_vec())),
            LoadMode::Development,
        )
        .unwrap();
        let bytes = wat::parse_str("(module)").unwrap();
        host.compile_module(&bytes).expect("empty module ok");
    }

    #[test]
    fn wasm_host_rejects_legacy_in_production() {
        let host = WasmPluginHost::new(
            Arc::new(InMemoryFindingsStore::new()),
            Arc::new(InMemoryHttpBackend::with_response(b"ok".to_vec())),
            LoadMode::Production,
        )
        .unwrap();
        let bytes = wat::parse_str("(module)").unwrap();
        let manifest = manifest_with(&["legacy:cdylib"]);
        let err = host
            .load_manifest(
                "t",
                &manifest,
                &bytes,
                HostFetchPolicy::default(),
                PluginLimits::default(),
            )
            .expect_err("legacy in production must be rejected");
        assert!(matches!(err, LoadError::LegacyInProduction));
    }

    #[test]
    fn wasm_host_loads_legacy_in_development() {
        let host = WasmPluginHost::new(
            Arc::new(InMemoryFindingsStore::new()),
            Arc::new(InMemoryHttpBackend::with_response(b"ok".to_vec())),
            LoadMode::Development,
        )
        .unwrap();
        let bytes = wat::parse_str("(module)").unwrap();
        let manifest = manifest_with(&["legacy:cdylib"]);
        host.load_manifest(
            "t",
            &manifest,
            &bytes,
            HostFetchPolicy::default(),
            PluginLimits::default(),
        )
        .expect("dev should accept legacy");
    }
}
