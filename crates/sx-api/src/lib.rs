//! # sx-api — SentinelX HTTP gateway
//!
//! The API gateway crate is organised explicitly around **Model — View —
//! Controller** with a thin port layer that decouples the HTTP surface from
//! every downstream domain service.
//!
//! ## Layout
//!
//! - [`controller`] — `axum` handler functions per resource.
//! - [`view`] — request/response DTOs and the standard JSON envelope.
//! - [`middleware`] — request-id, auth, rate-limit, tracing span, sensitive
//!   header redaction, CORS.
//! - [`extractor`] — typed extractors that pull `AuthenticatedUser`,
//!   `TenantScope`, the request id, and validate request bodies.
//! - [`port`] — local trait abstractions for use cases & repositories. Each
//!   `Arc<dyn Port>` slot on [`AppState`] is the only thing controllers know
//!   about; concrete implementations from sibling crates plug in at the
//!   service composition root (`services/sx-monolith`).
//! - [`error::ApiError`] — `thiserror` enum mapped to HTTP status codes via
//!   [`axum::response::IntoResponse`].
//! - [`state::AppState`] — clonable, `Arc`-based shared state passed to every
//!   handler.
//! - [`router::build_router`] — composes middleware + routes into an
//!   `axum::Router<()>`.
//! - [`server::serve`] — binds a TCP listener and runs the router with a
//!   graceful shutdown driven by SIGINT/SIGTERM.
//!
//! ## Security posture
//!
//! - `#![forbid(unsafe_code)]` — no `unsafe` blocks anywhere in this crate.
//! - No `.unwrap()`, `.expect()`, or `panic!()` in non-test code (enforced by
//!   workspace clippy gates).
//! - Sensitive headers (`Authorization`, `Cookie`, `X-API-Key`) are flagged
//!   as sensitive at the tower-http layer so they cannot accidentally appear
//!   in structured logs.
//! - The `ApiError -> IntoResponse` mapping never leaks internal error
//!   details to the client. A request id is always returned so an operator
//!   can correlate the public response with private logs.
//!
//! ## Error contract
//!
//! Every successful response is shaped as
//! `{"data": <T>, "meta": {"request_id": "...", "ts": "..."}}` (see
//! [`view::envelope::ApiResponse`]). Every error response is
//! `{"error": {"code": "...", "message": "...", "request_id": "..."}}`
//! (see [`view::envelope::ApiErrorBody`]). Codes are stable strings the API
//! layer commits to — never raw debug output.

#![forbid(unsafe_code)]
// Nursery / pedantic lints we deliberately tolerate inside this crate:
//
// * `similar_names` fires on `req`/`res`/`request_id` triples that are
//   idiomatic in middleware.
// * `missing_const_for_fn` and `redundant_pub_crate` are noisy for an
//   evolving HTTP surface.
// * `option_if_let_else` prefers `Option::map_or_else`, which makes
//   middleware harder to read here.
// * `cognitive_complexity` and `too_many_lines` are fine for these
//   helpers; they are exercised by tests.
// * `needless_pass_by_value` would force borrowed `axum::extract::State`
//   handles in handlers — the actual idiom is by-value.
// * `doc_markdown` fires on words like `JWT`, `CORS`, `SIGTERM`.
// * `must_use_candidate` is workspace-allowed already; the explicit
//   `#[must_use]` annotations are noise-cancelled here when the return
//   type is already `#[must_use]`.
#![allow(
    clippy::similar_names,
    clippy::missing_const_for_fn,
    clippy::redundant_pub_crate,
    clippy::option_if_let_else,
    clippy::cognitive_complexity,
    clippy::too_many_lines,
    clippy::needless_pass_by_value,
    clippy::single_match_else,
    clippy::module_name_repetitions,
    clippy::doc_markdown,
    clippy::struct_field_names,
    clippy::return_self_not_must_use,
    clippy::must_use_candidate
)]
// Tests use idiomatic `serde_json::Value` indexing and `.unwrap()` which
// the workspace lints normally deny.
#![cfg_attr(
    test,
    allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::panic,
        clippy::missing_panics_doc,
        clippy::missing_assert_message
    )
)]

pub mod error;
pub mod extractor;
pub mod middleware;
pub mod port;
pub mod prelude;
pub mod router;
pub mod server;
pub mod state;
pub mod view;

pub mod controller;
pub mod metrics;

pub use crate::error::ApiError;
pub use crate::router::build_router;
pub use crate::server::serve;
pub use crate::state::AppState;
