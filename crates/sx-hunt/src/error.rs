//! Error types for the hunt pipeline.
//!
//! The crate separates errors by stage:
//!
//! * [`ParseError`] — lexing / parsing failures.
//! * [`CompileError`] — semantic-level failures (unknown column, bad
//!   aggregation arity, oversize literals).
//! * [`ExecError`] — surfaces failures from the underlying SQL transport.
//! * [`HuntError`] — convenience umbrella used by the service.
//!
//! Every variant carries a `Display` rendering that is safe for inclusion
//! in HTTP responses — no secrets, no internal connection strings.
//!
//! # HIGH-005 stable error codes
//!
//! Every [`ParseError`] variant resolves to a short stable string via
//! [`ParseError::code`]. The codes are part of the public API contract
//! and are used by the hunt UI to drive specific remediation messages.
//! New codes for the HIGH-005 hardening:
//!
//! | Code | Variant | When |
//! |---|---|---|
//! | `HUNT_DENIED_TABLE` | [`ParseError::DeniedTable`] | source token not in [`crate::schema::KQL_ALLOWED_TABLES`] |
//! | `HUNT_DENIED_FN`    | [`ParseError::DeniedFunction`] | function call (aggregate or value-position) not in [`crate::schema::KQL_ALLOWED_FUNCTIONS`] |

use thiserror::Error;

/// Parse-time errors. Returned by [`crate::parser::parse`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseError {
    /// Tokenizer rejected a character outside the accepted alphabet.
    #[error("lexer: unexpected character {ch:?} at byte {pos}")]
    UnexpectedChar {
        /// Offending character.
        ch: char,
        /// Byte offset into the source string.
        pos: usize,
    },
    /// Unterminated string literal.
    #[error("lexer: unterminated string literal starting at byte {pos}")]
    UnterminatedString {
        /// Byte offset of the opening quote.
        pos: usize,
    },
    /// Numeric literal could not be parsed.
    #[error("lexer: invalid numeric literal {lexeme:?} at byte {pos}")]
    InvalidNumber {
        /// Offending lexeme.
        lexeme: String,
        /// Byte offset of the lexeme.
        pos: usize,
    },
    /// Parser encountered an unexpected token (mismatch / missing keyword).
    #[error("parser: unexpected token {found:?}; expected {expected}")]
    UnexpectedToken {
        /// What the parser saw.
        found: String,
        /// Human description of what was expected.
        expected: String,
    },
    /// Source name not in the allowlist. **Deprecated alias** —
    /// [`ParseError::DeniedTable`] is the canonical post-HIGH-005 variant
    /// and carries the stable `HUNT_DENIED_TABLE` code. This variant is
    /// retained for back-compat with any caller that pattern-matched on
    /// it; it is no longer emitted by [`crate::parser::parse`].
    #[error("parser: unknown source {0:?}")]
    UnknownSource(String),
    /// Source token does not appear in
    /// [`crate::schema::KQL_ALLOWED_TABLES`].
    ///
    /// **Error code:** `HUNT_DENIED_TABLE`. Returned for any analyst
    /// attempt to read from a table outside the allow-list (including
    /// `system.users`, `system.parts`, `file()`-style targets, or any
    /// future tenant-private table the analyst has not been granted).
    #[error("parser: table {name:?} is not in the hunt allow-list (code: HUNT_DENIED_TABLE)")]
    DeniedTable {
        /// Offending table name as the analyst typed it.
        name: String,
    },
    /// Function call is not in [`crate::schema::KQL_ALLOWED_FUNCTIONS`].
    ///
    /// **Error code:** `HUNT_DENIED_FN`. Returned for any analyst
    /// attempt to call a function outside the documented whitelist —
    /// including `file()`, `url()`, `format()`, `system()`, and the
    /// previously-shipped aggregates `sum`, `min`, `max` that HIGH-005
    /// removed.
    #[error("parser: function {name:?} is not in the hunt whitelist (code: HUNT_DENIED_FN)")]
    DeniedFunction {
        /// Offending function name.
        name: String,
    },
    /// Query exhausted before the parser finished.
    #[error("parser: unexpected end of query; expected {0}")]
    UnexpectedEof(String),
    /// Duration suffix not in {s, m, h, d}.
    #[error("parser: invalid duration suffix {0:?}")]
    InvalidDurationSuffix(String),
    /// `ago(0d)` and similar zero / negative durations.
    #[error("parser: invalid duration value (must be > 0)")]
    InvalidDurationValue,
    /// Query length exceeds the hard cap.
    #[error("parser: query too long ({len} bytes, max {max})")]
    QueryTooLong {
        /// Observed byte length.
        len: usize,
        /// Hard cap.
        max: usize,
    },
}

impl ParseError {
    /// Stable machine-readable error code.
    ///
    /// Callers (HTTP layer, dashboard, audit pipeline) MUST consume this
    /// code rather than `Display`-format the variant: the wording is not
    /// guaranteed to be stable, the code is.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnexpectedChar { .. } => "HUNT_LEX_UNEXPECTED_CHAR",
            Self::UnterminatedString { .. } => "HUNT_LEX_UNTERMINATED_STRING",
            Self::InvalidNumber { .. } => "HUNT_LEX_INVALID_NUMBER",
            Self::UnexpectedToken { .. } => "HUNT_PARSE_UNEXPECTED_TOKEN",
            // Both the legacy `UnknownSource(_)` and the new
            // `DeniedTable { .. }` map to the same wire code so back-compat
            // callers receive the canonical `HUNT_DENIED_TABLE`. We group
            // them into a single arm to keep the clippy `match_same_arms`
            // lint happy without splitting the documentation.
            Self::UnknownSource(_) | Self::DeniedTable { .. } => "HUNT_DENIED_TABLE",
            Self::DeniedFunction { .. } => "HUNT_DENIED_FN",
            Self::UnexpectedEof(_) => "HUNT_PARSE_UNEXPECTED_EOF",
            Self::InvalidDurationSuffix(_) => "HUNT_PARSE_INVALID_DURATION_SUFFIX",
            Self::InvalidDurationValue => "HUNT_PARSE_INVALID_DURATION_VALUE",
            Self::QueryTooLong { .. } => "HUNT_PARSE_QUERY_TOO_LONG",
        }
    }
}

/// Compile-time errors. Returned by [`crate::compile::compile`].
///
/// Does not derive `Eq` because [`Self::InvalidPercentile`] carries an
/// `f64` (which is not `Eq`).
#[derive(Debug, Clone, PartialEq, Error)]
pub enum CompileError {
    /// Column not in the allowlist.
    #[error("compile: unknown or disallowed column {0:?}")]
    UnknownColumn(String),
    /// Value too long for safety budget.
    #[error("compile: value exceeds maximum byte budget ({0})")]
    ValueTooLong(usize),
    /// `top N` must be positive and bounded.
    #[error("compile: top N must be in 1..={max} (got {got})")]
    TopOutOfRange {
        /// Observed value.
        got: i64,
        /// Hard cap.
        max: i64,
    },
    /// Aggregation referenced a non-numeric column.
    #[error("compile: aggregation {agg} requires numeric column (got {col:?})")]
    NonNumericAggregation {
        /// Aggregation kind label.
        agg: &'static str,
        /// Offending column.
        col: String,
    },
    /// A `between` window has `from >= to`.
    #[error("compile: between(from, to) — from must be earlier than to")]
    InvalidBetweenRange,
    /// Tenant id was empty — refuse to emit SQL without one.
    #[error("compile: tenant_id must be non-empty")]
    MissingTenant,
    /// `percentile(field, q)` was supplied with an out-of-range quantile.
    #[error("compile: percentile quantile must be in (0.0, 1.0) — got {got}")]
    InvalidPercentile {
        /// Offending quantile value.
        got: f64,
    },
}

impl CompileError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnknownColumn(_) => "HUNT_COMPILE_UNKNOWN_COLUMN",
            Self::ValueTooLong(_) => "HUNT_COMPILE_VALUE_TOO_LONG",
            Self::TopOutOfRange { .. } => "HUNT_COMPILE_TOP_OUT_OF_RANGE",
            Self::NonNumericAggregation { .. } => "HUNT_COMPILE_NON_NUMERIC_AGG",
            Self::InvalidBetweenRange => "HUNT_COMPILE_INVALID_BETWEEN",
            Self::MissingTenant => "HUNT_COMPILE_MISSING_TENANT",
            Self::InvalidPercentile { .. } => "HUNT_COMPILE_INVALID_PERCENTILE",
        }
    }
}

/// Execution-time errors. Returned by [`crate::executor::HuntExecutor`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ExecError {
    /// Transport-level failure (DNS, TCP, TLS, etc).
    #[error("exec: transport: {0}")]
    Transport(String),
    /// Backend returned a non-success HTTP status.
    #[error("exec: backend status {status}: {body}")]
    Backend {
        /// HTTP status code.
        status: u16,
        /// Response body (truncated by callers if needed).
        body: String,
    },
    /// Response did not parse into the expected row shape.
    #[error("exec: response parse: {0}")]
    Parse(String),
    /// Wall-clock budget (`max_execution_time`) exhausted server-side.
    #[error("exec: max_execution_time exceeded ({secs}s)")]
    Timeout {
        /// Configured cap in seconds.
        secs: u32,
    },
}

impl ExecError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Transport(_) => "HUNT_EXEC_TRANSPORT",
            Self::Backend { .. } => "HUNT_EXEC_BACKEND",
            Self::Parse(_) => "HUNT_EXEC_PARSE",
            Self::Timeout { .. } => "HUNT_EXEC_TIMEOUT",
        }
    }
}

/// Convenience umbrella for the service layer.
///
/// Does not derive `Eq` because [`CompileError`] carries an `f64`.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum HuntError {
    /// Parse stage failed.
    #[error(transparent)]
    Parse(#[from] ParseError),
    /// Compile stage failed.
    #[error(transparent)]
    Compile(#[from] CompileError),
    /// Execution stage failed.
    #[error(transparent)]
    Exec(#[from] ExecError),
}

impl HuntError {
    /// Stable machine-readable error code (delegates to the inner variant).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Parse(e) => e.code(),
            Self::Compile(e) => e.code(),
            Self::Exec(e) => e.code(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_error_codes_are_stable() {
        let e = ParseError::DeniedTable {
            name: "system.users".to_string(),
        };
        assert_eq!(e.code(), "HUNT_DENIED_TABLE");

        let e = ParseError::DeniedFunction {
            name: "file".to_string(),
        };
        assert_eq!(e.code(), "HUNT_DENIED_FN");

        // back-compat: UnknownSource still maps to HUNT_DENIED_TABLE.
        let e = ParseError::UnknownSource("logins".into());
        assert_eq!(e.code(), "HUNT_DENIED_TABLE");
    }

    #[test]
    fn hunt_error_delegates_code() {
        let err = HuntError::Parse(ParseError::DeniedFunction { name: "url".into() });
        assert_eq!(err.code(), "HUNT_DENIED_FN");

        let err = HuntError::Compile(CompileError::MissingTenant);
        assert_eq!(err.code(), "HUNT_COMPILE_MISSING_TENANT");
    }

    #[test]
    fn exec_timeout_has_code() {
        let e = ExecError::Timeout { secs: 30 };
        assert_eq!(e.code(), "HUNT_EXEC_TIMEOUT");
    }
}
