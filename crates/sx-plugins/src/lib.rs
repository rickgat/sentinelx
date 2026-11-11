//! # sx-plugins
//!
//! Plugin SDK + outbound webhook dispatcher + WASM-sandboxed host
//! (CRIT-001, builds on P3-007).
//!
//! Third-party developers ship a small HTTP service that subscribes to
//! one or more `SentinelX` event kinds (`FindingCreated`, `AssetDiscovered`,
//! `BasCompleted`) or query kinds (`RemediationVendorLookup`). They
//! register the service through the marketplace API by posting a
//! [`manifest::PluginManifest`]; on every matching event the dispatcher
//! signs a versioned [`envelope::PluginEnvelope`] with HMAC-SHA256 and
//! POSTs it to the plugin's webhook URL.
//!
//! Plugins that need to **call back** into the host (read findings,
//! annotate, fetch URLs) ship as a **WebAssembly module** loaded
//! through [`wasm_host::WasmPluginHost`]. The host registers a fixed
//! capability-scoped host-function surface
//! (`sentinelx::findings_read`, `sentinelx::findings_annotate`,
//! `sentinelx::http_fetch`); each fn first verifies the plugin's
//! load-time scope and *then* enforces the tenant binding. See
//! [`wasm_host`] for the threat model.
//!
//! ## Legacy in-process trait — development only
//!
//! The original P3-007 in-process [`sdk::Plugin`] trait is **opt-in**
//! behind the `legacy-cdylib` crate feature. It is intended for the
//! dev loop and integration tests only — the WASM host actively
//! **rejects** any manifest tagged `legacy:cdylib` when
//! `APP_ENV=production`
//! ([`wasm_host::LoadError::LegacyInProduction`]). Production
//! marketplace launch (CRIT-001) ships exclusively over WASM.
//!
//! ## Quality bar
//!
//! - `unsafe_code = "forbid"` at the workspace level. We use
//!   `wasmtime`, which has `unsafe` internally — that's their
//!   guarantee.
//! - No `.unwrap()` / `.expect()` in production paths (only inside
//!   `#[cfg(test)]`).
//! - HMAC verification uses constant-time comparison.
//! - WASM modules are validated (`Module::validate`) before
//!   compilation; only the [`wasm_host::HOST_NAMESPACE`] import
//!   module is accepted — `wasi_snapshot_preview1`, `env` and other
//!   syscall-adjacent namespaces are rejected at load time.

#![doc(html_root_url = "https://docs.rs/sx-plugins/0.1.0")]

pub mod dispatcher;
pub mod envelope;
pub mod manifest;
pub mod sdk;
pub mod service;

#[cfg(feature = "wasm-host")]
pub mod wasm_host;

pub use dispatcher::{
    sign_body, verify_signature, DispatchError, DispatchOutcome, DispatchRecord, DispatchStatus,
    DispatcherConfig, PluginDispatcher, SIGNATURE_HEADER, TIMESTAMP_HEADER,
};
pub use envelope::{EventKind, PluginEnvelope, ENVELOPE_VERSION};
pub use manifest::{PluginId, PluginManifest, RegisteredPlugin};
pub use sdk::{HostContext, HostError, HostFetchPolicy, Plugin, PluginFindingView, Scope};
pub use service::{InMemoryPluginService, PluginService, PluginServiceError};

#[cfg(feature = "wasm-host")]
pub use wasm_host::{
    Capabilities, FindingsBackend, HostFnError, HttpBackend, InMemoryFindingsStore,
    InMemoryHttpBackend, InvokeError, InvokeReport, LoadError, LoadMode, LoadedPlugin,
    PluginLimits, PluginLimitsConfig, PluginStoreData, TrapKind, WasmPluginHost, HOST_NAMESPACE,
};
