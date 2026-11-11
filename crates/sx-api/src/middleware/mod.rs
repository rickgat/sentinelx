//! HTTP middleware stack.
//!
//! The middlewares are applied in [`crate::router::build_router`] from
//! outermost to innermost:
//!
//! 1. [`sensitive_headers`] — mark `Authorization`, `Cookie`, `X-API-Key`
//!    as sensitive so the trace layer cannot log them.
//! 2. [`request_id`] — ensure every request carries a request id; mirror
//!    it onto the response.
//! 3. [`trace`] — open a [`tracing::Span`] with `method`, `path`,
//!    `request_id`, `trace_id`.
//! 4. [`cors`] — allowed origins from config; never `*`.
//! 5. [`rate_limit`] — token-bucket per (tenant, route) or per IP.
//! 6. [`auth`] — bearer-token authentication (excluding healthz / login).
//! 7. [`anti_abuse`] — observation-only abuse detector (JWT replay,
//!    per-IP rate anomaly, UA rotation) that emits structured audit
//!    events. Not registered in the router yet — exposed as a layer so
//!    future composition can opt-in.

pub mod anti_abuse;
pub mod auth;
pub mod cors;
pub mod device_posture;
pub mod policy;
pub mod rate_limit;
pub mod request_id;
pub mod sensitive_headers;
pub mod trace;
