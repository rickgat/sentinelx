//! Service layer for the OOB Collaborator.
//!
//! Each receiver is a separately-spawnable async task.  The orchestrating
//! controller fans them out and joins them under a [`CollabHandle`].
//!
//! ## SMTP receiver
//!
//! The crate-level surface deliberately omits an SMTP receiver in this
//! phase: the listener is scheduled for a follow-up wire pass that adds
//! `smtp_server.rs` and re-exports `spawn_smtp_server` / `SmtpServerHandle`
//! from this module.

pub mod dns_server;
pub mod encrypter;
pub mod http_server;
pub mod purge_task;
pub mod sink;
pub mod token_alloc;

pub use dns_server::{spawn_dns_server, DnsServerHandle, OobAuthority};
pub use encrypter::{CallbackEncrypter, NoOpEncrypter};
pub use http_server::{spawn_http_server, HttpServerHandle};
pub use purge_task::spawn_purge_task;
pub use sink::{CallbackSink, InMemoryCallbackSink};
pub use token_alloc::{TenantBinding, TokenAllocator};

/// Tracing target for every collaborator subsystem.
pub const TRACING_TARGET: &str = "sx_collab";
