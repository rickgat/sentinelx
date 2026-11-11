//! `sx-collab` — out-of-band collaborator subsystem.
//!
//! This crate implements the receivers and persistence used to verify
//! blind vulnerabilities by inducing the target to reach a SentinelX-
//! controlled DNS / HTTP / SMTP endpoint and recording the interaction.
//!
//! ## Public surface
//!
//! * [`error`] — the crate-level [`CollabError`] enum every fallible API
//!   returns, plus its convenience constructors.
//! * [`model`] — the domain types: [`model::Token`] (the 16-hex-char
//!   per-finding identifier), [`model::Callback`] (a recorded receiver
//!   event), and [`model::CollabConfig`] (static configuration).
//! * [`service`] — the runtime components: DNS / HTTP receivers, the
//!   in-memory [`service::CallbackSink`], the background TTL purge task,
//!   the [`service::TokenAllocator`], and the at-rest encrypter port.
//!
//! ## Security posture
//!
//! `#![forbid(unsafe_code)]` is enforced crate-wide. No production code
//! path uses `unwrap`, `expect`, or `panic!`. Tests retain the workspace's
//! `#[allow(clippy::unwrap_used)]` opt-ins for ergonomic assertions only.

#![forbid(unsafe_code)]
// Nursery / pedantic lints tolerated inside the long-lived service code:
//
// * `significant_drop_tightening` fires across every `RwLock` / `Mutex`
//   guard that the receiver loops keep alive intentionally.
// * `single_match_else` and `option_if_let_else` fight with the idiom the
//   service modules already use for short fallible branches.
// * `cognitive_complexity` is exercised by the HTTP receiver's
//   request-handler match arms — they are individually trivial.
// * `items_after_statements` is fine for the small helper modules nested
//   under `service::http_server`.
// * `io_other_error` is a 1.74-only sugar that does not buy clarity.
// * `redundant_closure_for_method_calls` and `doc_markdown` are pedantic
//   nits the original surface already accepts.
#![allow(
    clippy::significant_drop_tightening,
    clippy::single_match_else,
    clippy::option_if_let_else,
    clippy::cognitive_complexity,
    clippy::items_after_statements,
    clippy::io_other_error,
    clippy::redundant_closure_for_method_calls,
    clippy::doc_markdown,
    clippy::manual_let_else
)]
// Tests use idiomatic `.unwrap()` / `panic!` / `expect_err` / indexing.
#![cfg_attr(
    test,
    allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::panic,
        clippy::expect_used,
        clippy::redundant_clone
    )
)]

pub mod copilot_approval;
pub mod error;
pub mod model;
pub mod service;

pub use error::CollabError;
