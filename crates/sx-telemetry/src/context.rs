//! Request-scoped identifier helpers.
//!
//! * [`new_request_id`] returns a lowercase hex UUID v7 — sortable by time
//!   yet unguessable. Suitable for inclusion in span and log fields.
//! * [`current_trace_id`] extracts the active `OTel` trace id (if any) from
//!   the `tracing` span stack. Used by HTTP middleware to surface a
//!   correlation header back to the client.

use opentelemetry::trace::TraceContextExt;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use uuid::Uuid;

/// Generate a fresh request id encoded as a 32-character lowercase hex
/// string (UUID v7 without hyphens).
pub fn new_request_id() -> String {
    Uuid::now_v7().simple().to_string()
}

/// Return the OpenTelemetry trace id of the currently active `tracing` span,
/// formatted as a 32-character lowercase hex string.
///
/// Returns `None` when:
/// * no span is currently active, or
/// * the active span has no associated `OTel` context (e.g. the tracing-opentelemetry
///   layer is not installed), or
/// * the `OTel` span context is invalid (e.g. all-zero trace id).
pub fn current_trace_id() -> Option<String> {
    let span = tracing::Span::current();
    let cx = span.context();
    let span_ref = cx.span();
    let span_ctx = span_ref.span_context();
    if span_ctx.is_valid() {
        Some(format!(
            "{:032x}",
            u128::from_be_bytes(span_ctx.trace_id().to_bytes())
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_is_32_lowercase_hex() {
        let id = new_request_id();
        assert_eq!(id.len(), 32, "id={id}");
        assert!(
            id.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "id={id}"
        );
    }

    #[test]
    fn request_ids_are_unique() {
        let a = new_request_id();
        let b = new_request_id();
        assert_ne!(a, b);
    }

    #[test]
    fn trace_id_none_without_otel_layer() {
        // No tracing-opentelemetry layer installed in this unit test — the
        // helper must return None rather than panicking.
        assert!(current_trace_id().is_none());
    }
}
