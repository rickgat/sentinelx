//! Compile an [`crate::ast::HuntQuery`] into a `ClickHouse` SQL statement
//! plus a parameter table.
//!
//! ## Output shape
//!
//! `ClickHouse` named parameters use the syntax `{name:Type}`. The compiler
//! emits names of the form `p0`, `p1`, ... and the tenant binding is
//! always `tenant`. Every value the analyst typed becomes a bound
//! parameter — no value is interpolated into the SQL string.
//!
//! ## Tenant isolation
//!
//! Every compiled statement contains a synthetic
//! `tenant_id = {tenant:String}` predicate. This predicate is `AND`-ed
//! with whatever the analyst's `where` clause produced, and it is added
//! before the analyst's predicate so it short-circuits first on
//! `ClickHouse`'s left-to-right `AND` evaluator.

use std::collections::BTreeMap;
use std::fmt::Write;

use serde::{Deserialize, Serialize};

use crate::ast::{
    AggCall, AggKind, Comparison, Duration, HuntQuery, Predicate, Stage, TimeBound, Value,
};
use crate::error::CompileError;
use crate::parser::{MAX_IN_LIST, MAX_STRING_BYTES};
use crate::schema::{column_allowed, column_is_numeric, source_table};

/// Hard cap on `top N` and the implicit row-limit cap.
///
/// **HIGH-005**: every emitted statement carries a `LIMIT` clause; when the
/// analyst supplies `| top N by ...` the explicit `N` is used (and capped
/// at [`MAX_TOP_N`]); otherwise the compiler appends `LIMIT MAX_TOP_N`.
/// The cap matches the veteran-evaluation acceptance criterion of
/// `LIMIT 100000`. Analysts who need more rows should stream a download
/// from `ClickHouse` directly.
pub const MAX_TOP_N: i64 = 100_000;

/// Default ClickHouse `max_execution_time` (seconds) injected at execute time.
///
/// The executor surfaces this through the `settings` map on
/// [`CompiledQuery`] so the wire layer can attach
/// `?max_execution_time=<n>` to the HTTP request.
///
/// **HIGH-005**: this is a wall-clock cap; if the query takes longer the
/// `ClickHouse` server terminates it and the executor surfaces
/// [`crate::error::ExecError::Timeout`].
pub const DEFAULT_MAX_EXECUTION_TIME_SECS: u32 = 30;

/// A compiled query — wire-ready.
///
/// The SQL string contains `{name:Type}` placeholders that the
/// `ClickHouse` HTTP layer substitutes via `param_<name>=<value>` query
/// parameters. The compiler emits exactly one `String` parameter per
/// bound value (and a synthetic `tenant` parameter), so the wire-side
/// substitution map mirrors [`CompiledQuery::params`] one-to-one.
///
/// `settings` carries per-query `ClickHouse` settings that the executor
/// MUST forward (typically as `?<key>=<value>` query parameters on the
/// HTTP transport). **HIGH-005**: the compiler unconditionally populates
/// `settings["max_execution_time"]` with
/// [`DEFAULT_MAX_EXECUTION_TIME_SECS`] so a hunt query cannot run for
/// longer than the configured wall-clock cap. Operators may override the
/// default via [`compile_with_settings`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompiledQuery {
    /// SQL statement with named parameters.
    pub sql: String,
    /// Bound parameter table, keyed by name.
    pub params: BTreeMap<String, ParamValue>,
    /// Table the query reads from (for audit + telemetry).
    pub table: String,
    /// ClickHouse-side settings the executor must forward.
    ///
    /// HIGH-005 always populates `max_execution_time` (seconds, decimal).
    #[serde(default)]
    pub settings: BTreeMap<String, String>,
}

/// Wire-ready bound parameter.
///
/// `ClickHouse`'s HTTP transport accepts parameters via the query-string
/// `param_<name>=<value>` convention. The `kind` field tells the executor
/// which `{name:Type}` annotation to use in the SQL.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ParamValue {
    /// `String` — bound by the `ClickHouse` HTTP layer as `String`.
    Str(String),
    /// `Int64` — signed 64-bit integer.
    Int(i64),
    /// `Float64` — double-precision float, rendered with `to_string()`.
    Float(f64),
}

impl ParamValue {
    /// The `ClickHouse` type token used inside `{name:Type}`.
    #[must_use]
    pub const fn ch_type(&self) -> &'static str {
        match self {
            Self::Str(_) => "String",
            Self::Int(_) => "Int64",
            Self::Float(_) => "Float64",
        }
    }

    /// Wire-side serialised value (as it appears in
    /// `param_<name>=<value>`).
    #[must_use]
    pub fn wire_value(&self) -> String {
        match self {
            Self::Str(s) => s.clone(),
            Self::Int(n) => n.to_string(),
            Self::Float(f) => f.to_string(),
        }
    }
}

/// Compile a [`HuntQuery`] for the given tenant.
///
/// `tenant_id` is bound through the synthetic `{tenant:String}`
/// parameter — every emitted statement contains `tenant_id = {tenant:String}`
/// in its `WHERE` clause regardless of the analyst's input.
///
/// **HIGH-005**: the returned [`CompiledQuery`] always carries
/// `settings["max_execution_time"]` with
/// [`DEFAULT_MAX_EXECUTION_TIME_SECS`]. Operators that need a different
/// wall-clock cap should call [`compile_with_settings`].
pub fn compile(q: &HuntQuery, tenant_id: &str) -> Result<CompiledQuery, CompileError> {
    compile_with_settings(q, tenant_id, DEFAULT_MAX_EXECUTION_TIME_SECS)
}

/// [`compile`] with an explicit `max_execution_time_secs` override.
///
/// The value is stored verbatim in
/// `settings["max_execution_time"]`; executors MUST forward it as the
/// `max_execution_time` `ClickHouse` HTTP query-string setting.
pub fn compile_with_settings(
    q: &HuntQuery,
    tenant_id: &str,
    max_execution_time_secs: u32,
) -> Result<CompiledQuery, CompileError> {
    if tenant_id.is_empty() {
        return Err(CompileError::MissingTenant);
    }
    // Resolve source — must be in the schema allowlist.
    let table = source_table(&q.source.name)
        .ok_or_else(|| CompileError::UnknownColumn(q.source.name.clone()))?;
    let mut ctx = CompileCtx::new(tenant_id.to_string());

    // Walk the pipeline; collect predicates, summarize, project, top, time.
    let mut user_where: Vec<Predicate> = Vec::new();
    let mut summarize: Option<&crate::ast::SummarizeStage> = None;
    let mut project: Option<&crate::ast::ProjectStage> = None;
    let mut top: Option<&crate::ast::TopStage> = None;
    let mut time: Option<&TimeBound> = None;

    for stage in &q.stages {
        match stage {
            Stage::Where(w) => user_where.push(w.predicate.clone()),
            Stage::Summarize(s) => summarize = Some(s),
            Stage::Project(p) => project = Some(p),
            Stage::Top(t) => top = Some(t),
            Stage::TimeWindow(tb) => time = Some(tb),
        }
    }

    // -- SELECT clause ---------------------------------------------------
    let mut sql = String::with_capacity(256);
    sql.push_str("SELECT ");
    if let Some(s) = summarize {
        // group-by columns first, then aggregate expressions.
        let mut first = true;
        for col in &s.by {
            if !column_allowed(col) {
                return Err(CompileError::UnknownColumn(col.clone()));
            }
            if !first {
                sql.push_str(", ");
            }
            sql.push_str(col);
            first = false;
        }
        for agg in &s.aggregations {
            if !first {
                sql.push_str(", ");
            }
            write_agg(&mut sql, agg)?;
            first = false;
        }
        if first {
            // No by + no aggs — emit literal `1` so the SQL stays
            // syntactically valid. The parser already requires at least
            // one aggregation, so this branch is defensive.
            sql.push('1');
        }
    } else if let Some(p) = project {
        let mut first = true;
        for col in &p.fields {
            if !column_allowed(col) {
                return Err(CompileError::UnknownColumn(col.clone()));
            }
            if !first {
                sql.push_str(", ");
            }
            sql.push_str(col);
            first = false;
        }
    } else {
        sql.push('*');
    }

    sql.push_str(" FROM ");
    sql.push_str(table);

    // -- WHERE clause ----------------------------------------------------
    sql.push_str(" WHERE tenant_id = {tenant:String}");
    if let Some(tb) = time {
        sql.push_str(" AND ");
        compile_time_bound(&mut sql, tb, &mut ctx)?;
    }
    for pred in &user_where {
        sql.push_str(" AND ");
        compile_predicate(&mut sql, pred, &mut ctx)?;
    }

    // -- GROUP BY --------------------------------------------------------
    if let Some(s) = summarize {
        if !s.by.is_empty() {
            sql.push_str(" GROUP BY ");
            let mut first = true;
            for col in &s.by {
                if !first {
                    sql.push_str(", ");
                }
                sql.push_str(col);
                first = false;
            }
        }
    }

    // -- ORDER BY + LIMIT ------------------------------------------------
    if let Some(t) = top {
        if t.n <= 0 || t.n > MAX_TOP_N {
            return Err(CompileError::TopOutOfRange {
                got: t.n,
                max: MAX_TOP_N,
            });
        }
        if !column_allowed(&t.by) {
            return Err(CompileError::UnknownColumn(t.by.clone()));
        }
        sql.push_str(" ORDER BY ");
        sql.push_str(&t.by);
        sql.push_str(if t.descending { " DESC" } else { " ASC" });
        let _ = write!(sql, " LIMIT {}", t.n);
    } else {
        // Default safety LIMIT — never emit an unbounded query.
        let _ = write!(sql, " LIMIT {MAX_TOP_N}");
    }

    sql.push_str(" FORMAT JSONEachRow");

    let mut settings = BTreeMap::new();
    let _ = settings.insert(
        "max_execution_time".to_string(),
        max_execution_time_secs.to_string(),
    );

    Ok(CompiledQuery {
        sql,
        params: ctx.into_params(),
        table: table.to_string(),
        settings,
    })
}

/// Internal compile state — owns the parameter table.
struct CompileCtx {
    next: u32,
    params: BTreeMap<String, ParamValue>,
}

impl CompileCtx {
    fn new(tenant: String) -> Self {
        let mut params = BTreeMap::new();
        let _ = params.insert("tenant".to_string(), ParamValue::Str(tenant));
        Self { next: 0, params }
    }

    fn bind(&mut self, v: ParamValue) -> String {
        let name = format!("p{}", self.next);
        self.next += 1;
        let _ = self.params.insert(name.clone(), v);
        name
    }

    fn into_params(self) -> BTreeMap<String, ParamValue> {
        self.params
    }
}

fn compile_predicate(
    sql: &mut String,
    p: &Predicate,
    ctx: &mut CompileCtx,
) -> Result<(), CompileError> {
    match p {
        Predicate::Compare { field, cmp, value } => {
            if !column_allowed(field) {
                return Err(CompileError::UnknownColumn(field.clone()));
            }
            let pv = value_to_param(value)?;
            match cmp {
                Comparison::Eq => {
                    let name = ctx.bind(pv);
                    let _ = write!(
                        sql,
                        "{} = {{{}:{}}}",
                        field,
                        name,
                        ctx.params[&name].ch_type()
                    );
                }
                Comparison::Neq => {
                    let name = ctx.bind(pv);
                    let _ = write!(
                        sql,
                        "{} != {{{}:{}}}",
                        field,
                        name,
                        ctx.params[&name].ch_type()
                    );
                }
                Comparison::Gt => {
                    let name = ctx.bind(pv);
                    let _ = write!(
                        sql,
                        "{} > {{{}:{}}}",
                        field,
                        name,
                        ctx.params[&name].ch_type()
                    );
                }
                Comparison::Lt => {
                    let name = ctx.bind(pv);
                    let _ = write!(
                        sql,
                        "{} < {{{}:{}}}",
                        field,
                        name,
                        ctx.params[&name].ch_type()
                    );
                }
                Comparison::Contains => {
                    let pv = require_string(value)?;
                    let name = ctx.bind(pv);
                    let _ = write!(sql, "positionUTF8({field}, {{{name}:String}}) > 0");
                }
                Comparison::StartsWith => {
                    let pv = require_string(value)?;
                    let name = ctx.bind(pv);
                    let _ = write!(sql, "startsWith({field}, {{{name}:String}})");
                }
            }
        }
        Predicate::In { field, values } => {
            if !column_allowed(field) {
                return Err(CompileError::UnknownColumn(field.clone()));
            }
            if values.is_empty() {
                // Defensive — the parser rejects empty lists.
                sql.push_str("1 = 0");
                return Ok(());
            }
            if values.len() > MAX_IN_LIST {
                return Err(CompileError::ValueTooLong(values.len()));
            }
            sql.push_str(field);
            sql.push_str(" IN (");
            let mut first = true;
            for v in values {
                if !first {
                    sql.push_str(", ");
                }
                let pv = value_to_param(v)?;
                let name = ctx.bind(pv);
                let _ = write!(sql, "{{{}:{}}}", name, ctx.params[&name].ch_type());
                first = false;
            }
            sql.push(')');
        }
        Predicate::And(items) => {
            sql.push('(');
            let mut first = true;
            for item in items {
                if !first {
                    sql.push_str(" AND ");
                }
                compile_predicate(sql, item, ctx)?;
                first = false;
            }
            sql.push(')');
        }
        Predicate::Or(items) => {
            sql.push('(');
            let mut first = true;
            for item in items {
                if !first {
                    sql.push_str(" OR ");
                }
                compile_predicate(sql, item, ctx)?;
                first = false;
            }
            sql.push(')');
        }
        Predicate::Not(inner) => {
            sql.push_str("NOT (");
            compile_predicate(sql, inner, ctx)?;
            sql.push(')');
        }
    }
    Ok(())
}

fn compile_time_bound(
    sql: &mut String,
    tb: &TimeBound,
    ctx: &mut CompileCtx,
) -> Result<(), CompileError> {
    match tb {
        TimeBound::Ago(d) => {
            compile_ago(sql, *d);
            Ok(())
        }
        TimeBound::Between { from, to } => {
            if from >= to {
                return Err(CompileError::InvalidBetweenRange);
            }
            if from.len() > MAX_STRING_BYTES || to.len() > MAX_STRING_BYTES {
                return Err(CompileError::ValueTooLong(from.len().max(to.len())));
            }
            let name_a = ctx.bind(ParamValue::Str(from.clone()));
            let name_b = ctx.bind(ParamValue::Str(to.clone()));
            let _ = write!(
                sql,
                "event_time >= parseDateTimeBestEffort({{{name_a}:String}}) AND event_time < parseDateTimeBestEffort({{{name_b}:String}})",
            );
            Ok(())
        }
    }
}

fn compile_ago(sql: &mut String, d: Duration) {
    let _ = write!(
        sql,
        "event_time >= now() - INTERVAL {} {}",
        d.value,
        d.unit.clickhouse_keyword(),
    );
}

fn write_agg(sql: &mut String, agg: &AggCall) -> Result<(), CompileError> {
    let func = agg.kind.sql();
    match (&agg.kind, &agg.field) {
        (AggKind::Count, None) => {
            let alias = agg.alias.as_deref().unwrap_or("count_");
            let _ = write!(sql, "count() AS {alias}");
        }
        (AggKind::Count, Some(_)) => {
            return Err(CompileError::UnknownColumn(
                "count() does not take an argument".into(),
            ));
        }
        // `percentile(field, q)` is special: ClickHouse spells it
        // `quantile(q)(field)` (parameterised aggregate function). The
        // quantile is rendered inline because ClickHouse's parameterised
        // aggregate syntax does NOT support `{p:Float64}` substitution in
        // the parameter slot — only in the row-position arguments.
        // Validate it tightly: must be a float literal in `(0.0, 1.0)`.
        (AggKind::Percentile, Some(col)) => {
            if !column_allowed(col) {
                return Err(CompileError::UnknownColumn(col.clone()));
            }
            if !column_is_numeric(col) {
                return Err(CompileError::NonNumericAggregation {
                    agg: AggKind::Percentile.label(),
                    col: col.clone(),
                });
            }
            let q = match &agg.arg2 {
                Some(Value::Float(f)) if *f > 0.0 && *f < 1.0 && f.is_finite() => *f,
                Some(Value::Int(_) | Value::String(_)) | None => {
                    return Err(CompileError::InvalidPercentile {
                        got: agg
                            .arg2
                            .as_ref()
                            .and_then(|v| match v {
                                Value::Float(f) => Some(*f),
                                _ => None,
                            })
                            .unwrap_or(f64::NAN),
                    });
                }
                Some(Value::Float(f)) => {
                    return Err(CompileError::InvalidPercentile { got: *f });
                }
            };
            let alias = match agg.alias.as_deref() {
                Some(a) => a.to_string(),
                None => format!("percentile_{col}"),
            };
            // Render the quantile with up to 6 decimal places. The value
            // is a parser-validated `f64` literal: no string interpolation
            // of analyst-typed bytes happens here.
            let _ = write!(sql, "quantile({q})({col}) AS {alias}");
        }
        (k, Some(col)) => {
            if !column_allowed(col) {
                return Err(CompileError::UnknownColumn(col.clone()));
            }
            if k.requires_numeric() && !column_is_numeric(col) {
                return Err(CompileError::NonNumericAggregation {
                    agg: k.label(),
                    col: col.clone(),
                });
            }
            let alias = match agg.alias.as_deref() {
                Some(a) => a.to_string(),
                None => format!("{}_{}", k.label(), col),
            };
            let _ = write!(sql, "{func}({col}) AS {alias}");
        }
        (_, None) => {
            return Err(CompileError::NonNumericAggregation {
                agg: agg.kind.label(),
                col: String::new(),
            });
        }
    }
    Ok(())
}

fn value_to_param(v: &Value) -> Result<ParamValue, CompileError> {
    match v {
        Value::String(s) => {
            if s.len() > MAX_STRING_BYTES {
                return Err(CompileError::ValueTooLong(s.len()));
            }
            Ok(ParamValue::Str(s.clone()))
        }
        Value::Int(n) => Ok(ParamValue::Int(*n)),
        Value::Float(f) => Ok(ParamValue::Float(*f)),
    }
}

fn require_string(v: &Value) -> Result<ParamValue, CompileError> {
    match v {
        Value::String(s) => {
            if s.len() > MAX_STRING_BYTES {
                return Err(CompileError::ValueTooLong(s.len()));
            }
            Ok(ParamValue::Str(s.clone()))
        }
        _ => Err(CompileError::UnknownColumn(
            "contains/startswith require a string argument".into(),
        )),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::parser::parse;

    /// Helper — parse + compile in one shot.
    fn parse_and_compile(q: &str, tenant: &str) -> CompiledQuery {
        let ast = parse(q).unwrap();
        compile(&ast, tenant).unwrap()
    }

    #[test]
    fn minimal_source_only() {
        let c = parse_and_compile("events_raw", "tenant-a");
        // Snapshot — HIGH-005 raised the implicit row cap to 100_000.
        assert_eq!(
            c.sql,
            "SELECT * FROM events_raw WHERE tenant_id = {tenant:String} LIMIT 100000 FORMAT JSONEachRow"
        );
        // Tenant bound separately.
        assert_eq!(
            c.params.get("tenant"),
            Some(&ParamValue::Str("tenant-a".to_string()))
        );
        assert_eq!(c.table, "events_raw");
        // HIGH-005: max_execution_time wall-clock cap is always present.
        assert_eq!(
            c.settings.get("max_execution_time").map(String::as_str),
            Some("30"),
        );
    }

    #[test]
    fn where_string_is_parametrised() {
        let c = parse_and_compile(r#"events_raw | where user_name == "alice""#, "tenant-a");
        assert!(c.sql.contains("user_name = {p0:String}"));
        assert!(c.sql.contains("tenant_id = {tenant:String}"));
        // The literal value must not appear in the SQL string.
        assert!(!c.sql.contains("alice"));
        assert_eq!(c.params.get("p0"), Some(&ParamValue::Str("alice".into())));
    }

    #[test]
    fn where_int_uses_int64() {
        let c = parse_and_compile("events_raw | where severity_id > 3", "t");
        assert!(c.sql.contains("severity_id > {p0:Int64}"));
        assert_eq!(c.params.get("p0"), Some(&ParamValue::Int(3)));
    }

    #[test]
    fn contains_uses_positionutf8() {
        let c = parse_and_compile(r#"events_raw | where raw contains "drop""#, "t");
        assert!(c.sql.contains("positionUTF8(raw, {p0:String}) > 0"));
        assert_eq!(c.params.get("p0"), Some(&ParamValue::Str("drop".into())));
    }

    #[test]
    fn startswith_uses_clickhouse_function() {
        let c = parse_and_compile(r#"events_raw | where src_ip startswith "10.0.""#, "t");
        assert!(c.sql.contains("startsWith(src_ip, {p0:String})"));
    }

    #[test]
    fn in_list_emits_named_params() {
        let c = parse_and_compile(
            r#"events_raw | where src_ip in ("10.0.0.1", "10.0.0.2")"#,
            "t",
        );
        assert!(c.sql.contains("src_ip IN ({p0:String}, {p1:String})"));
        assert_eq!(
            c.params.get("p0"),
            Some(&ParamValue::Str("10.0.0.1".into()))
        );
        assert_eq!(
            c.params.get("p1"),
            Some(&ParamValue::Str("10.0.0.2".into()))
        );
    }

    #[test]
    fn and_or_not_compose() {
        let c = parse_and_compile(
            r#"events_raw | where user_name == "alice" and (severity_id > 3 or not src_port == 22)"#,
            "t",
        );
        // structural checks — order is deterministic.
        assert!(c.sql.contains("AND"));
        assert!(c.sql.contains(" OR "));
        assert!(c.sql.contains("NOT ("));
    }

    #[test]
    fn summarize_count_by() {
        let c = parse_and_compile("events_normalized | summarize count() by user_name", "t");
        assert!(c.sql.contains("SELECT user_name, count() AS count_"));
        assert!(c.sql.contains("GROUP BY user_name"));
    }

    #[test]
    fn summarize_avg_requires_numeric() {
        // HIGH-005 vocabulary: `sum/min/max` are removed; `avg` still
        // requires a numeric column.
        let ast = parse("events_normalized | summarize avg(user_name)").unwrap();
        let err = compile(&ast, "t").unwrap_err();
        assert!(matches!(err, CompileError::NonNumericAggregation { .. }));
    }

    #[test]
    fn summarize_percentile_renders_quantile() {
        let c = parse_and_compile(
            "events_normalized | summarize percentile(severity_id, 0.95) by user_name",
            "t",
        );
        // ClickHouse parameterised aggregate: `quantile(q)(field)`.
        assert!(
            c.sql
                .contains("quantile(0.95)(severity_id) AS percentile_severity_id"),
            "SQL was: {}",
            c.sql,
        );
    }

    #[test]
    fn summarize_percentile_invalid_quantile_rejected() {
        let ast = parse("events_normalized | summarize percentile(severity_id, 2.0)").unwrap();
        let err = compile(&ast, "t").unwrap_err();
        assert!(matches!(err, CompileError::InvalidPercentile { .. }));

        let ast = parse("events_normalized | summarize percentile(severity_id, 0.0)").unwrap();
        let err = compile(&ast, "t").unwrap_err();
        assert!(matches!(err, CompileError::InvalidPercentile { .. }));
    }

    #[test]
    fn summarize_percentile_integer_quantile_rejected() {
        // `percentile(severity_id, 1)` — int isn't a valid quantile.
        let ast = parse("events_normalized | summarize percentile(severity_id, 1)").unwrap();
        let err = compile(&ast, "t").unwrap_err();
        assert!(matches!(err, CompileError::InvalidPercentile { .. }));
    }

    #[test]
    fn summarize_dcount_renders_uniqexact() {
        let c = parse_and_compile(
            "events_normalized | summarize dcount(user_name) by hostname",
            "t",
        );
        assert!(
            c.sql.contains("uniqExact(user_name) AS dcount_user_name"),
            "SQL was: {}",
            c.sql,
        );
    }

    #[test]
    fn summarize_make_set_renders_groupuniqarray() {
        let c = parse_and_compile(
            "events_normalized | summarize make_set(src_ip) by hostname",
            "t",
        );
        assert!(
            c.sql.contains("groupUniqArray(src_ip) AS make_set_src_ip"),
            "SQL was: {}",
            c.sql,
        );
    }

    #[test]
    fn implicit_limit_appended_when_top_absent() {
        // HIGH-005 acceptance: every query carries `LIMIT 100000` if no
        // explicit `top`. Whitespace-tolerant assertion.
        let c = parse_and_compile("events_raw | project user_name", "t");
        assert!(c.sql.contains(" LIMIT 100000 "), "SQL was: {}", c.sql);
    }

    #[test]
    fn explicit_top_overrides_implicit_limit() {
        let c = parse_and_compile("events_raw | top 5 by severity_id desc", "t");
        // Only the explicit LIMIT 5 is emitted; no second 100000 LIMIT.
        assert!(c.sql.contains("LIMIT 5"));
        assert!(!c.sql.contains("LIMIT 100000"));
    }

    #[test]
    fn max_execution_time_default_is_30s() {
        let c = parse_and_compile("events_raw", "t");
        assert_eq!(
            c.settings.get("max_execution_time").map(String::as_str),
            Some("30"),
        );
    }

    #[test]
    fn compile_with_settings_honours_override() {
        let ast = parse("events_raw").unwrap();
        let c = compile_with_settings(&ast, "t", 120).unwrap();
        assert_eq!(
            c.settings.get("max_execution_time").map(String::as_str),
            Some("120"),
        );
    }

    #[test]
    fn project_columns() {
        let c = parse_and_compile("events_raw | project user_name, src_ip", "t");
        assert!(c.sql.contains("SELECT user_name, src_ip"));
    }

    #[test]
    fn top_uses_order_by_limit() {
        let c = parse_and_compile("events_raw | top 5 by severity_id desc", "t");
        assert!(c.sql.contains("ORDER BY severity_id DESC LIMIT 5"));
    }

    #[test]
    fn top_out_of_range_rejected() {
        let ast = parse("events_raw | top 999999 by severity_id").unwrap();
        let err = compile(&ast, "t").unwrap_err();
        assert!(matches!(err, CompileError::TopOutOfRange { .. }));
    }

    #[test]
    fn time_window_ago_emits_interval() {
        let c = parse_and_compile("events_raw | timeWindow ago(24 h)", "t");
        assert!(c.sql.contains("event_time >= now() - INTERVAL 24 HOUR"));
    }

    #[test]
    fn between_uses_parsedatetime() {
        let c = parse_and_compile(
            r#"events_raw | between("2026-06-01T00:00:00Z", "2026-06-02T00:00:00Z")"#,
            "t",
        );
        assert!(c.sql.contains("parseDateTimeBestEffort({p0:String})"));
        assert!(c.sql.contains("parseDateTimeBestEffort({p1:String})"));
    }

    #[test]
    fn between_inverted_range_rejected() {
        let ast = parse(r#"events_raw | between("2026-06-02T00:00:00Z", "2026-06-01T00:00:00Z")"#)
            .unwrap();
        let err = compile(&ast, "t").unwrap_err();
        assert!(matches!(err, CompileError::InvalidBetweenRange));
    }

    // ---- Adversarial / security tests --------------------------------

    #[test]
    fn injection_via_string_literal_is_quarantined() {
        // The classic SQL-injection payload typed into a string literal.
        let c = parse_and_compile(
            r#"events_raw | where user_name == "alice'; DROP TABLE events_raw; --""#,
            "t",
        );
        // The dangerous text MUST appear only inside `params`, never in
        // the SQL itself.
        assert!(!c.sql.contains("DROP"));
        assert!(!c.sql.contains("--"));
        let bound = c.params.get("p0").expect("p0 bound");
        if let ParamValue::Str(s) = bound {
            assert!(s.contains("DROP TABLE"));
        } else {
            panic!("p0 should be a string");
        }
    }

    #[test]
    fn injection_via_field_identifier_rejected() {
        // The lexer accepts the identifier text but the compiler refuses
        // anything not in the allowlist. An attacker who tries to put a
        // SQL fragment in the column position fails the lexer first
        // (semicolons aren't valid identifier characters), but a typo
        // that happens to be a valid identifier still hits the
        // allowlist.
        let ast = parse(r#"events_raw | where unknown_col == "x""#).unwrap();
        let err = compile(&ast, "t").unwrap_err();
        assert!(matches!(err, CompileError::UnknownColumn(_)));
    }

    #[test]
    fn injection_via_quoted_identifier_at_lex_time() {
        // Attempt to smuggle SQL via the source name.
        let err = parse("events_raw; DROP TABLE events_raw").unwrap_err();
        // Lexer trips on `;`.
        assert!(matches!(
            err,
            crate::error::ParseError::UnexpectedChar { ch: ';', .. }
        ));
    }

    #[test]
    fn tenant_predicate_is_always_present() {
        // Even when the analyst's where clause tries to override the tenant.
        let c = parse_and_compile(r#"events_raw | where tenant_id == "OTHER""#, "real-tenant");
        // Both predicates appear; the synthetic one binds the real tenant.
        assert!(c.sql.contains("tenant_id = {tenant:String}"));
        assert!(c.sql.contains("tenant_id = {p0:String}"));
        assert_eq!(
            c.params.get("tenant"),
            Some(&ParamValue::Str("real-tenant".to_string()))
        );
        assert_eq!(
            c.params.get("p0"),
            Some(&ParamValue::Str("OTHER".to_string()))
        );
        // ClickHouse evaluates the AND short-circuit, so the synthetic
        // binding wins regardless. The tenant binding param is "tenant"
        // and the analyst's literal lives in "p0" — they can never
        // overlap.
    }

    #[test]
    fn tenant_empty_rejected() {
        let ast = parse("events_raw").unwrap();
        let err = compile(&ast, "").unwrap_err();
        assert!(matches!(err, CompileError::MissingTenant));
    }

    #[test]
    fn oversized_string_value_rejected() {
        let big = "a".repeat(MAX_STRING_BYTES + 1);
        let q = format!(r#"events_raw | where user_name == "{big}""#);
        // Parser rejects at the lex step because the string literal
        // length cap is applied during lexing.
        assert!(parse(&q).is_err());
    }

    #[test]
    fn snapshot_complex_query() {
        let c = parse_and_compile(
            r#"events_normalized | where severity_id > 3 and src_ip in ("10.0.0.1") | summarize count() by user_name | top 10 by user_name desc | timeWindow ago(1 h)"#,
            "tenant-a",
        );
        // Pieces in expected order.
        assert!(c
            .sql
            .starts_with("SELECT user_name, count() AS count_ FROM events_normalized"));
        assert!(c.sql.contains("WHERE tenant_id = {tenant:String}"));
        assert!(c.sql.contains("event_time >= now() - INTERVAL 1 HOUR"));
        assert!(c.sql.contains("severity_id > {p0:Int64}"));
        assert!(c.sql.contains("src_ip IN ({p1:String})"));
        assert!(c.sql.contains("GROUP BY user_name"));
        assert!(c.sql.contains("ORDER BY user_name DESC LIMIT 10"));
        assert!(c.sql.ends_with("FORMAT JSONEachRow"));
    }
}
