//! # sx-mtls
//!
//! Mutual TLS (mTLS) plumbing for `SentinelX` inter-service listeners.
//!
//! This crate is a small bridge between the typed [`sx_config::MtlsConfig`]
//! struct and a runtime-ready [`rustls::ServerConfig`]. It additionally
//! ships a [`CertReloader`] that watches the configured certificate file
//! on disk and atomically swaps the loaded chain when it changes, so an
//! operator rotating a certificate never has to restart the host process.
//!
//! ## Quality bar
//!
//! * `#![forbid(unsafe_code)]`.
//! * Tracing only ever surfaces the SHA-256 fingerprint + expiry of the
//!   loaded certificate — **never** any private-key bytes.
//! * Refuses to load certificates that have already expired, or whose
//!   `not_after` lands less than 30 days from now.
//!
//! ## Example
//!
//! ```no_run
//! # use sx_config::MtlsConfig;
//! # use sx_mtls::build_server_config;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let cfg = MtlsConfig {
//!     enabled: true,
//!     cert_path: "/etc/sentinelx/server.crt".into(),
//!     key_path: "/etc/sentinelx/server.key".into(),
//!     client_ca_path: String::new(),
//!     require_client_cert: false,
//!     reload_interval_secs: 60,
//! };
//! let server_config = build_server_config(&cfg)?;
//! # let _ = server_config;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod load;
mod reloader;

#[cfg(test)]
mod test_support;

pub use crate::error::MtlsError;
pub use crate::load::{build_server_config, load_client_ca_roots, load_pem_chain, CertMaterial};
pub use crate::reloader::CertReloader;
