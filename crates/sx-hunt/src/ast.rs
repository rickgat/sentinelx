//! AST for the hunt query language.
//!
//! The AST is intentionally tiny: every node is `Clone`, `PartialEq`,
//! `serde::Serialize`. Round-tripping through JSON is used by the parser
//! tests so the AST has to be stable on the wire.

use serde::{Deserialize, Serialize};

/// A parsed, validated hunt query — root of the AST.
///
/// Carries the source table token and an ordered list of pipeline
/// [`Stage`]s. The parser preserves stage order; the compiler is free to
/// reorder commutative stages (e.g. coalescing two `where` stages).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HuntQuery {
    /// Analyst-facing source token (e.g. `events_raw`). The compiler
    /// re-resolves this through [`crate::schema::source_table`].
    pub source: Source,
    /// Ordered pipeline stages, left-to-right.
    pub stages: Vec<Stage>,
}

/// A source-table reference. Pure wrapper so the AST stays type-safe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    /// Token typed by the analyst.
    pub name: String,
}

/// One pipeline stage. Variants match the supported `|` operators.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "stage", rename_all = "snake_case")]
pub enum Stage {
    /// `| where <predicate>` — boolean filter.
    Where(WhereStage),
    /// `| summarize <agg> [, agg]* [by field [, field]*]` — group / aggregate.
    Summarize(SummarizeStage),
    /// `| project <field>[, field]*` — column projection.
    Project(ProjectStage),
    /// `| top N by <field> [asc|desc]` — order + limit.
    Top(TopStage),
    /// `| timeWindow ago(<duration>)` or `| between(t1, t2)`.
    TimeWindow(TimeBound),
}

/// `where` stage payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WhereStage {
    /// Boolean predicate tree.
    pub predicate: Predicate,
}

/// `summarize` stage payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SummarizeStage {
    /// Aggregation calls.
    pub aggregations: Vec<AggCall>,
    /// Group-by fields (may be empty).
    pub by: Vec<String>,
}

/// `project` stage payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProjectStage {
    /// Projected fields (in selection order).
    pub fields: Vec<String>,
}

/// `top` stage payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopStage {
    /// `N` — row limit. Must be > 0; compile-time hard cap applies.
    pub n: i64,
    /// Field to order by.
    pub by: String,
    /// `true` = descending (default for `top`).
    pub descending: bool,
}

/// Time-window scoping. Compiled into a `event_time` predicate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TimeBound {
    /// `| timeWindow ago(24h)` — last `duration` window relative to "now".
    Ago(Duration),
    /// `| between(t1, t2)` — ISO 8601 absolute range.
    Between {
        /// Inclusive start (RFC 3339).
        from: String,
        /// Exclusive end (RFC 3339).
        to: String,
    },
}

/// Relative-time duration. Always positive at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Duration {
    /// Magnitude.
    pub value: u64,
    /// One of `s`/`m`/`h`/`d`.
    pub unit: DurationUnit,
}

/// Duration unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurationUnit {
    /// Seconds.
    Second,
    /// Minutes.
    Minute,
    /// Hours.
    Hour,
    /// Days.
    Day,
}

impl DurationUnit {
    /// Convert the unit + magnitude into seconds, saturating at `i64::MAX`.
    #[must_use]
    pub const fn to_seconds(self, value: u64) -> u64 {
        match self {
            Self::Second => value,
            Self::Minute => value.saturating_mul(60),
            Self::Hour => value.saturating_mul(3_600),
            Self::Day => value.saturating_mul(86_400),
        }
    }

    /// `ClickHouse` interval keyword.
    #[must_use]
    pub const fn clickhouse_keyword(self) -> &'static str {
        match self {
            Self::Second => "SECOND",
            Self::Minute => "MINUTE",
            Self::Hour => "HOUR",
            Self::Day => "DAY",
        }
    }
}

/// A boolean predicate tree.
///
/// Note: the enum uses the default (externally tagged) serde
/// representation rather than `#[serde(tag = "op")]` because the inner
/// `Vec<Predicate>` / `Box<Predicate>` variants would otherwise force
/// `serde_derive` into a deeply recursive trait-resolution path during
/// monomorphisation, blowing the compiler's recursion limit. External
/// tagging keeps the wire shape stable and avoids the explosion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Predicate {
    /// Leaf: `field <op> value`.
    Compare {
        /// Column.
        field: String,
        /// Comparison operator.
        cmp: Comparison,
        /// Bound value.
        value: Value,
    },
    /// Leaf: `field in (v1, v2, ...)`.
    In {
        /// Column.
        field: String,
        /// Allowed values (non-empty after parsing).
        values: Vec<Value>,
    },
    /// `predicate and predicate`.
    And(Vec<Self>),
    /// `predicate or predicate`.
    Or(Vec<Self>),
    /// `not predicate`.
    Not(Box<Self>),
}

/// Comparison operator on a [`Predicate::Compare`] node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Comparison {
    /// `==`.
    Eq,
    /// `!=`.
    Neq,
    /// `>`.
    Gt,
    /// `<`.
    Lt,
    /// `contains` — substring on string columns.
    Contains,
    /// `startswith` — prefix match on string columns.
    StartsWith,
}

impl Comparison {
    /// Render the operator as the wire-side analyst token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "==",
            Self::Neq => "!=",
            Self::Gt => ">",
            Self::Lt => "<",
            Self::Contains => "contains",
            Self::StartsWith => "startswith",
        }
    }
}

/// A bound literal value. The compiler maps these to `ClickHouse` named
/// parameters with the matching SQL type tag.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Value {
    /// Quoted string. Cap enforced by the lexer.
    String(String),
    /// Integer literal.
    Int(i64),
    /// Floating-point literal.
    Float(f64),
}

impl Value {
    /// True if the value is a string literal.
    #[must_use]
    pub const fn is_string(&self) -> bool {
        matches!(self, Self::String(_))
    }

    /// Length in bytes for `String`, `0` for numeric.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        match self {
            Self::String(s) => s.len(),
            Self::Int(_) | Self::Float(_) => 0,
        }
    }
}

/// An aggregation call inside a `summarize` stage.
///
/// **HIGH-005:** the accepted aggregation set is exactly the union of
/// [`AggKind`] variants below — `count`, `avg`, `dcount`, `make_set`,
/// `percentile`. Anything else (`sum`, `min`, `max`, `file`, etc.) is
/// rejected at parse-time with
/// [`crate::error::ParseError::DeniedFunction`] (code `HUNT_DENIED_FN`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AggCall {
    /// Aggregation kind.
    pub kind: AggKind,
    /// Argument column, when the aggregation takes one (`None` for `count()`).
    pub field: Option<String>,
    /// Output alias. `None` defers to a compiler-generated name.
    pub alias: Option<String>,
    /// Optional second argument — currently only used by `percentile(field, q)`
    /// where `q` is a float in `(0.0, 1.0)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg2: Option<Value>,
}

/// Aggregation kind. Matches the HIGH-005 function whitelist.
///
/// See [`crate::schema::KQL_ALLOWED_FUNCTIONS`] for the authoritative list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggKind {
    /// `count()`.
    Count,
    /// `dcount(field)` — distinct count. Compiles to `ClickHouse` `uniqExact`.
    Dcount,
    /// `avg(field)` — numeric field required.
    Avg,
    /// `percentile(field, q)` — numeric field required;
    /// `q ∈ (0.0, 1.0)`. Compiles to `ClickHouse` `quantile(q)(field)`.
    Percentile,
    /// `make_set(field)` — distinct values rolled up into an array.
    /// Compiles to `ClickHouse` `groupUniqArray`.
    MakeSet,
}

impl AggKind {
    /// `ClickHouse` aggregate-function name (without arguments).
    ///
    /// `Percentile` returns `quantile`; the actual emitted form is
    /// `quantile({q})({field})` — the compiler handles that in
    /// [`crate::compile::write_agg`].
    #[must_use]
    pub const fn sql(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::Dcount => "uniqExact",
            Self::Avg => "avg",
            Self::Percentile => "quantile",
            Self::MakeSet => "groupUniqArray",
        }
    }

    /// Wire-side analyst label (for error messages and the default alias).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::Dcount => "dcount",
            Self::Avg => "avg",
            Self::Percentile => "percentile",
            Self::MakeSet => "make_set",
        }
    }

    /// True when the function requires a numeric argument column.
    #[must_use]
    pub const fn requires_numeric(self) -> bool {
        matches!(self, Self::Avg | Self::Percentile)
    }

    /// True when the function takes a second argument (currently only
    /// `percentile`, which takes the quantile fraction).
    #[must_use]
    pub const fn takes_second_arg(self) -> bool {
        matches!(self, Self::Percentile)
    }
}
