//! Identifier and function allowlists (HIGH-005 hardening).
//!
//! Every table, column, and function name the parser/compiler is permitted
//! to emit is enumerated here. The lists are intentionally short; expanding
//! them is a deliberate code change that must go through review.
//!
//! Why an allowlist?
//!
//! `ClickHouse` does **not** allow named parameters for identifiers — only
//! for values. Tables, columns, and aggregate functions therefore have to
//! be string-interpolated into the SQL. Allowing arbitrary identifier text
//! would re-open the SQL-injection / data-exfiltration surface
//! (`system.users`, `file()`, `url()`, `format()` etc), so the
//! parser refuses anything that is not in these lists.
//!
//! # HIGH-005 invariants
//!
//! 1. [`KQL_ALLOWED_TABLES`] is the authoritative list of analyst-facing
//!    source tokens. Anything else — including `system.users`, `system.*`,
//!    or any table the analyst has not been granted — produces
//!    [`crate::error::ParseError::DeniedTable`] with stable code
//!    `HUNT_DENIED_TABLE`.
//! 2. [`KQL_ALLOWED_FUNCTIONS`] is the authoritative list of callable
//!    functions in the analyst grammar. Anything else — including
//!    `file()`, `url()`, `format()`, `system()`, and the aggregate names
//!    `sum`, `min`, `max` that previously slipped through — produces
//!    [`crate::error::ParseError::DeniedFunction`] with stable code
//!    `HUNT_DENIED_FN`.

/// Permitted source tables, mapped to their `ClickHouse` identifier.
///
/// Indices into the OCSF projection landed by `sx-log-ingest` (see
/// `clickhouse/projections.sql`). The wire-side token (left-hand side)
/// is the name analysts type; the right-hand side is the actual table
/// name in the database.
///
/// **HIGH-005:** this is the *only* set of tables the compiler will
/// emit. Anything else, including `system.users`, fails parse-time with
/// [`crate::error::ParseError::DeniedTable`].
pub const KQL_ALLOWED_TABLES: &[(&str, &str)] = &[
    ("events_raw", "events_raw"),
    ("events_normalized", "events_normalized"),
];

/// Back-compat alias for [`KQL_ALLOWED_TABLES`]. Kept so external callers
/// that still reference `SOURCES` continue to compile.
pub const SOURCES: &[(&str, &str)] = KQL_ALLOWED_TABLES;

/// Allowed column identifiers.
///
/// Every column that may appear in a `where`, `project`, `summarize`,
/// `top`, or aggregation clause must be listed here exactly. The
/// second element marks whether the column is numeric — aggregations
/// like `avg()` and `percentile()` require numeric.
pub const ALLOWED_COLUMNS: &[(&str, bool)] = &[
    // Tenant binding — synthetic, always emitted.
    ("tenant_id", false),
    // Time + identity.
    ("event_time", false),
    ("event_id", false),
    // OCSF taxonomy.
    ("class_uid", true),
    ("category_uid", true),
    ("severity_id", true),
    // Source binding.
    ("source_type", false),
    ("product", false),
    // Network observable shorthands.
    ("src_ip", false),
    ("dst_ip", false),
    ("src_port", true),
    ("dst_port", true),
    // Identity observable shorthands.
    ("user_name", false),
    ("hostname", false),
    // Free-text payload.
    ("raw", false),
    // Generic numeric counters used by summarize/top-by surfaces.
    ("bytes_in", true),
    ("bytes_out", true),
    ("duration_ms", true),
];

/// Function whitelist enforced by the parser (HIGH-005).
///
/// The list is the union of:
///
/// * **Aggregate functions** — `count`, `avg`, `percentile`, `dcount`,
///   `make_set`. These compile into `ClickHouse` `count() / avg() /
///   quantile() / uniqExact() / groupUniqArray()` respectively.
/// * **Pipeline operators** — `where`, `project`, `summarize`, `top`,
///   `join`. These are stage keywords the parser handles directly. They
///   are listed here for documentation completeness; the parser
///   enforces the stage-keyword whitelist independently in
///   [`crate::parser::Parser::parse_stage`].
///
/// Anything not in this list — `file`, `url`, `format`, `system`, `sum`,
/// `min`, `max`, raw `count_distinct` (renamed to `dcount`), etc — is
/// rejected with [`crate::error::ParseError::DeniedFunction`] carrying
/// the stable code `HUNT_DENIED_FN`.
pub const KQL_ALLOWED_FUNCTIONS: &[&str] = &[
    // aggregates
    "count",
    "avg",
    "percentile",
    "dcount",
    "make_set",
    // pipeline operators (documented here for traceability)
    "where",
    "project",
    "summarize",
    "top",
    "join",
];

/// Whitelist check — true if `name` is in the column allow-list.
///
/// Comparison is case-sensitive on purpose: analysts pasting
/// `Severity_ID` after reading a vendor manual deserve a parse error,
/// not a column rename.
#[must_use]
pub fn column_allowed(name: &str) -> bool {
    ALLOWED_COLUMNS.iter().any(|(c, _)| *c == name)
}

/// True when the named column is numeric (eligible for `avg` /
/// `percentile`).
#[must_use]
pub fn column_is_numeric(name: &str) -> bool {
    ALLOWED_COLUMNS
        .iter()
        .find(|(c, _)| *c == name)
        .is_some_and(|(_, num)| *num)
}

/// Resolve the analyst-facing source token to a backend table name.
///
/// Returns `None` for sources outside [`KQL_ALLOWED_TABLES`].
#[must_use]
pub fn source_table(name: &str) -> Option<&'static str> {
    KQL_ALLOWED_TABLES
        .iter()
        .find(|(tok, _)| *tok == name)
        .map(|(_, table)| *table)
}

/// True if `name` is in [`KQL_ALLOWED_FUNCTIONS`].
#[must_use]
pub fn function_allowed(name: &str) -> bool {
    KQL_ALLOWED_FUNCTIONS.contains(&name)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn known_sources_resolve() {
        assert_eq!(source_table("events_raw"), Some("events_raw"));
        assert_eq!(source_table("events_normalized"), Some("events_normalized"));
    }

    #[test]
    fn unknown_sources_rejected() {
        assert_eq!(source_table("system.users"), None);
        assert_eq!(source_table("events_raw;"), None);
        assert_eq!(source_table(""), None);
    }

    #[test]
    fn tenant_id_is_listed() {
        // Required because the compiler emits a `tenant_id = ?` predicate
        // unconditionally; if a future refactor drops the entry the
        // tenant-isolation tests catch it, but better to assert here too.
        assert!(column_allowed("tenant_id"));
    }

    #[test]
    fn numeric_classification_matches_table() {
        assert!(column_is_numeric("severity_id"));
        assert!(column_is_numeric("dst_port"));
        assert!(!column_is_numeric("user_name"));
        assert!(!column_is_numeric("missing"));
    }

    #[test]
    fn allowed_tables_are_explicit() {
        // The HIGH-005 hardening contract: the list is exactly two
        // analyst-facing tables, and SOURCES is an alias.
        assert_eq!(KQL_ALLOWED_TABLES.len(), 2);
        assert!(std::ptr::eq(SOURCES, KQL_ALLOWED_TABLES));
    }

    #[test]
    fn function_whitelist_membership() {
        assert!(function_allowed("count"));
        assert!(function_allowed("avg"));
        assert!(function_allowed("percentile"));
        assert!(function_allowed("dcount"));
        assert!(function_allowed("make_set"));
        // pipeline operators
        assert!(function_allowed("where"));
        assert!(function_allowed("summarize"));
        assert!(function_allowed("join"));
        // explicitly denied — previously-shipped aggregates removed by
        // HIGH-005 hardening.
        assert!(!function_allowed("sum"));
        assert!(!function_allowed("min"));
        assert!(!function_allowed("max"));
        // disk / network / format escapes that motivated the hardening
        assert!(!function_allowed("file"));
        assert!(!function_allowed("url"));
        assert!(!function_allowed("format"));
        assert!(!function_allowed("system"));
    }
}
