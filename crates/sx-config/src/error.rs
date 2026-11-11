//! Configuration error types.
//!
//! All loader and validator failures are converted into the strongly typed
//! [`ConfigError`] enum. Error messages **never** contain secret material
//! (database URLs, signing keys, etc.) — only the offending configuration
//! key and a short reason.

use std::borrow::Cow;
use std::fmt::Write as _;

use figment::error::{Error as FigmentError, Kind as FigmentKind};
use validator::ValidationErrors;

/// All failures that can occur while loading or validating `SentinelX`
/// configuration.
///
/// Errors are intentionally coarse: callers should bubble them up to
/// process startup and exit, since a malformed configuration is a fatal
/// boot condition.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A required configuration value was not supplied by any source.
    #[error("missing required configuration: {key}")]
    MissingValue {
        /// Dotted path to the missing key (e.g. `database.url`).
        key: String,
    },

    /// A configuration value was present but failed semantic validation.
    #[error("invalid configuration at {key}: {reason}")]
    InvalidValue {
        /// Dotted path to the offending key.
        key: String,
        /// Human-readable reason. Never contains secret material.
        reason: String,
    },

    /// A configuration source (file, env) could not be read or parsed.
    #[error("failed to read config source: {0}")]
    Source(String),

    /// One or more validator-derived field validations failed.
    #[error("validation failed: {0}")]
    Validation(String),

    /// An I/O error occurred while accessing a configuration file.
    #[error("io error: {0}")]
    Io(String),
}

impl ConfigError {
    /// Constructs a [`ConfigError::MissingValue`] from any displayable key.
    pub fn missing(key: impl Into<String>) -> Self {
        Self::MissingValue { key: key.into() }
    }

    /// Constructs a [`ConfigError::InvalidValue`] from a key and reason.
    pub fn invalid(key: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidValue {
            key: key.into(),
            reason: reason.into(),
        }
    }
}

impl From<std::io::Error> for ConfigError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

impl From<FigmentError> for ConfigError {
    // `map_or_else` chains would nest 3 deep here and obscure the
    // priority order (missing > invalid > generic). Plain `if let`
    // is clearer.
    #[allow(clippy::option_if_let_else)]
    fn from(err: FigmentError) -> Self {
        // Walk the figment error chain. The first MissingField wins, followed
        // by the first InvalidType / InvalidValue. Anything else collapses to
        // Source.
        let mut missing: Option<String> = None;
        let mut invalid: Option<(String, String)> = None;
        let mut generic: Option<String> = None;

        for e in err {
            let path = if e.path.is_empty() {
                None
            } else {
                // figment surfaces env-driven keys uppercase (SERVER.BIND_ADDR).
                // Normalize to the lowercase form callers will recognize.
                Some(e.path.join(".").to_ascii_lowercase())
            };
            match &e.kind {
                FigmentKind::MissingField(name) => {
                    if missing.is_none() {
                        let key = path.unwrap_or_else(|| name.clone().into_owned());
                        missing = Some(key);
                    }
                }
                FigmentKind::InvalidType(actual, expected) => {
                    if invalid.is_none() {
                        let key = path.unwrap_or_else(|| "<unknown>".to_string());
                        let reason = format!("expected {expected}, got {actual}");
                        invalid = Some((key, reason));
                    }
                }
                FigmentKind::InvalidValue(actual, expected) => {
                    if invalid.is_none() {
                        let key = path.unwrap_or_else(|| "<unknown>".to_string());
                        let reason = format!("expected {expected}, got {actual}");
                        invalid = Some((key, reason));
                    }
                }
                FigmentKind::UnknownField(name, _) => {
                    if invalid.is_none() {
                        let key = path.unwrap_or_else(|| name.clone());
                        invalid = Some((key, "unknown field (typo?)".to_string()));
                    }
                }
                FigmentKind::DuplicateField(name) => {
                    if invalid.is_none() {
                        let key = path.unwrap_or_else(|| (*name).to_string());
                        invalid = Some((key, "duplicate field".to_string()));
                    }
                }
                FigmentKind::InvalidLength(actual, expected) => {
                    if invalid.is_none() {
                        let key = path.unwrap_or_else(|| "<unknown>".to_string());
                        let reason = format!("expected length {expected}, got {actual}");
                        invalid = Some((key, reason));
                    }
                }
                FigmentKind::Message(msg) => {
                    if invalid.is_none() {
                        if let Some(key) = path {
                            invalid = Some((key, scrub(msg)));
                        } else if generic.is_none() {
                            generic = Some(scrub(msg));
                        }
                    }
                }
                _ => {
                    if generic.is_none() {
                        generic = Some(scrub(&e.to_string()));
                    }
                }
            }
        }

        if let Some(key) = missing {
            Self::MissingValue { key }
        } else if let Some((key, reason)) = invalid {
            Self::InvalidValue { key, reason }
        } else if let Some(msg) = generic {
            Self::Source(msg)
        } else {
            Self::Source("unknown figment error".to_string())
        }
    }
}

impl From<ValidationErrors> for ConfigError {
    fn from(err: ValidationErrors) -> Self {
        Self::Validation(format_validation_errors(&err))
    }
}

/// Renders [`ValidationErrors`] into a stable, single-line, secret-free
/// summary.
fn format_validation_errors(errors: &ValidationErrors) -> String {
    let mut buf = String::new();
    let mut first = true;
    for (field, kind) in errors.errors() {
        if first {
            first = false;
        } else {
            buf.push_str("; ");
        }
        match kind {
            validator::ValidationErrorsKind::Field(field_errs) => {
                let codes: Vec<Cow<'_, str>> = field_errs
                    .iter()
                    .map(|e| {
                        e.message.as_ref().map_or_else(
                            || Cow::Borrowed(e.code.as_ref()),
                            |msg| Cow::Borrowed(msg.as_ref()),
                        )
                    })
                    .collect();
                let _ = write!(buf, "{field}: {}", codes.join(", "));
            }
            validator::ValidationErrorsKind::Struct(nested) => {
                let _ = write!(buf, "{field}: {{{}}}", format_validation_errors(nested));
            }
            validator::ValidationErrorsKind::List(items) => {
                let mut parts: Vec<String> = items
                    .iter()
                    .map(|(idx, nested)| {
                        format!("[{idx}]: {{{}}}", format_validation_errors(nested))
                    })
                    .collect();
                parts.sort();
                let _ = write!(buf, "{field}: {}", parts.join(", "));
            }
        }
    }
    buf
}

/// Removes any text that looks like a secret URL component before placing it
/// into a user-visible error message. Best-effort — secrets should never reach
/// figment errors in the first place, but defence in depth is cheap.
fn scrub(msg: &str) -> String {
    // Replace anything matching `proto://user:pass@host` with `proto://***@host`.
    let Ok(re) = regex::Regex::new(r"([a-zA-Z][a-zA-Z0-9+.-]*://)[^@\s]+@") else {
        return msg.to_string();
    };
    re.replace_all(msg, "$1***@").into_owned()
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn missing_constructor_round_trips() {
        let err = ConfigError::missing("database.url");
        assert!(matches!(err, ConfigError::MissingValue { ref key } if key == "database.url"));
    }

    #[test]
    fn invalid_constructor_round_trips() {
        let err = ConfigError::invalid("server.bind_addr", "not a socket addr");
        match err {
            ConfigError::InvalidValue { key, reason } => {
                assert_eq!(key, "server.bind_addr");
                assert_eq!(reason, "not a socket addr");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn scrub_redacts_credentials_in_url() {
        let out = scrub("error at postgres://user:hunter2@db.example.com/app");
        assert!(!out.contains("hunter2"));
        assert!(out.contains("***"));
    }

    #[test]
    fn display_messages_are_stable() {
        let err = ConfigError::missing("redis.url");
        assert_eq!(err.to_string(), "missing required configuration: redis.url");

        let err = ConfigError::invalid("server.bind_addr", "bad");
        assert_eq!(
            err.to_string(),
            "invalid configuration at server.bind_addr: bad"
        );
    }
}
