//! Structured log formatting helpers.
//!
//! Two layers are produced from a [`TelemetryConfig`](crate::TelemetryConfig):
//!
//! * an [`EnvFilter`] built from the config's `log_level` directive, and
//! * an fmt layer that emits either JSON or compact text — chosen by
//!   [`LogFormat`].
//!
//! The fmt layer always includes file, line, target and span fields, and
//! uses UTC RFC3339 timestamps so the output is unambiguous regardless of
//! the host time zone.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use tracing::Subscriber;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{EnvFilter, Layer};

use crate::error::TelemetryError;

/// Format selector for the fmt layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Newline-delimited JSON, one event per line. Suitable for production
    /// log shippers.
    #[default]
    Json,
    /// Human-readable compact text. Intended for local development.
    Text,
}

impl fmt::Display for LogFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json => f.write_str("json"),
            Self::Text => f.write_str("text"),
        }
    }
}

impl FromStr for LogFormat {
    type Err = TelemetryError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "text" | "plain" | "compact" => Ok(Self::Text),
            other => Err(TelemetryError::InvalidFilter(format!(
                "unknown log format: {other}"
            ))),
        }
    }
}

/// Build an [`EnvFilter`] from a directive string.
///
/// # Errors
///
/// Returns [`TelemetryError::InvalidFilter`] if `directive` cannot be parsed
/// by `tracing_subscriber`.
pub fn build_env_filter(directive: &str) -> Result<EnvFilter, TelemetryError> {
    EnvFilter::try_new(directive).map_err(|e| TelemetryError::InvalidFilter(e.to_string()))
}

/// Build the fmt layer matching the selected [`LogFormat`].
///
/// The returned layer is type-erased so callers can store either flavour in
/// the same variable.
pub fn build_fmt_layer<S>(format: LogFormat) -> Box<dyn Layer<S> + Send + Sync + 'static>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let timer = SystemTime;
    let base = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_level(true)
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_timer(timer);

    match format {
        LogFormat::Json => base
            .json()
            .with_current_span(true)
            .with_span_list(true)
            .flatten_event(false)
            .boxed(),
        LogFormat::Text => base.compact().boxed(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_json_variants() {
        for input in ["json", "JSON", " json "] {
            assert!(
                matches!(LogFormat::from_str(input), Ok(LogFormat::Json)),
                "input={input}"
            );
        }
    }

    #[test]
    fn parse_text_variants() {
        for input in ["text", "plain", "compact", "TEXT"] {
            assert!(
                matches!(LogFormat::from_str(input), Ok(LogFormat::Text)),
                "input={input}"
            );
        }
    }

    #[test]
    fn parse_rejects_unknown() {
        let err = LogFormat::from_str("yaml");
        assert!(matches!(err, Err(TelemetryError::InvalidFilter(_))));
    }

    #[test]
    fn build_filter_accepts_valid() {
        assert!(build_env_filter("info").is_ok());
        assert!(build_env_filter("info,sx_api=debug,hyper=warn").is_ok());
    }

    #[test]
    fn build_filter_rejects_invalid() {
        // A directive with an invalid level token after the `=` is one of
        // the few inputs `EnvFilter::try_new` reliably rejects — bare
        // unknown identifiers are accepted as target filters.
        let err = build_env_filter("foo=NOT_A_LEVEL");
        assert!(matches!(err, Err(TelemetryError::InvalidFilter(_))));
    }

    #[test]
    fn display_round_trips() {
        assert_eq!(LogFormat::Json.to_string(), "json");
        assert_eq!(LogFormat::Text.to_string(), "text");
    }
}
