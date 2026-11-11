//! `sx-hunt` — threat-hunting query language (KQL/SPL-like) for `SentinelX`.
//!
//! The crate ships a small, opinionated query language that analysts can
//! use to interrogate the OCSF events landed by `sx-log-ingest` into
//! `ClickHouse`. It owns:
//!
//! * The query **AST** ([`ast`]).
//! * The **lexer + parser** ([`parser`]) that turns text into the AST.
//! * The **compiler** ([`compile`]) that lowers the AST into a parametrised
//!   `ClickHouse` SQL statement plus a bound-parameter table.
//! * The **executor** trait ([`executor`]) — a tiny abstraction over an SQL
//!   client so the higher-level service can stay HTTP-agnostic for tests.
//! * The hunt **service** ([`service`]) that ties parser → compiler →
//!   executor → audit hook together.
//!
//! # Grammar (informal)
//!
//! ```text
//! query     := source ( "|" stage )*
//! source    := "events_raw" | "events_normalized"
//! stage     := "where" predicate
//!            | "summarize" agg ( "," agg )* [ "by" field ( "," field )* ]
//!            | "project"   field ( "," field )*
//!            | "top"       integer "by" field [ ("asc"|"desc") ]
//!            | "timeWindow" "ago" "(" duration ")"
//!            | "between" "(" iso8601 "," iso8601 ")"
//! predicate := term ( ("and"|"or") term )*
//! term      := "not"? atom
//! atom      := field op value | field "in" "(" value ("," value)* ")" | "(" predicate ")"
//! op        := "==" | "!=" | ">" | "<" | "contains" | "startswith"
//! agg       := "count()" | "count_distinct(" field ")" | "sum(" field ")"
//!            | "avg(" field ")" | "min(" field ")" | "max(" field ")"
//! value     := string | integer | float
//! duration  := integer ("s"|"m"|"h"|"d")
//! ```
//!
//! # Engineering bar
//!
//! * **Parametrised output only.** Identifiers (table + column names) are
//!   matched against a small allowlist; values are bound through
//!   `ClickHouse` named parameters (`{p0:String}` / `{p0:Int64}` /
//!   `{p0:Float64}`). The compiler never interpolates raw user strings
//!   into SQL.
//! * **Tenant isolation.** The compiler injects a synthetic
//!   `tenant_id = {tenant:String}` predicate into the `WHERE` clause —
//!   regardless of whatever filter the analyst typed. There is no way to
//!   produce SQL from this crate that does not include the tenant
//!   binding.
//! * **No raw SQL leakage.** The `String` returned by the compiler is the
//!   verbatim statement; the bind map carries every value. The
//!   [`executor::HuntExecutor`] trait owns the wire protocol.
//!
//! # Safety
//!
//! * `#![forbid(unsafe_code)]`.
//! * No panics, no `unwrap`/`expect` outside `#[cfg(test)]`.

#![forbid(unsafe_code)]
#![recursion_limit = "256"]
// Lint relaxations local to this crate. Each allow is the minimum
// necessary for the hand-written parser / compiler shape.
//
// * `doc_markdown` fires on `ClickHouse`, `KQL`, `JSON`, etc.
// * `module_name_repetitions` fires on `HuntService` inside `service`,
//   `HuntExecutor` inside `executor` — those names are part of the
//   public API.
// * `derive_partial_eq_without_eq` would require deriving `Eq` on AST
//   nodes that carry `f64` literals (and therefore cannot be `Eq`).
// * `missing_const_for_fn` flags helpers like `Value::byte_len` whose
//   bodies could be `const fn` in theory but aren't worth the churn.
// * `too_many_lines` fires on the parser's `lex` and the compiler's
//   `compile` — both are deliberately a single function so the SQL
//   skeleton + bound-parameter sequence reads end-to-end.
// * `literal_string_with_formatting_args` is a *false positive* on the
//   `{tenant:String}` / `{p0:Int64}` placeholders — they are
//   ClickHouse named-parameter syntax, NOT `format!` arguments. This
//   crate's whole reason for being is that those placeholders are
//   emitted literally so the wire layer can substitute them via
//   `param_<name>=`.
// * `indexing_slicing` fires on `ctx.params[&name]` lookups that
//   happen one line after `ctx.bind(...)` — the key's existence is a
//   local invariant.
// * `option_if_let_else` prefers `map_or_else`, which would force a
//   closure allocation in the hot compile path.
// * `needless_bool` fires on the explicit `if/else { true } else { false }`
//   in the `top N by field [asc|desc]` helper where the form mirrors
//   the grammar.
// * `significant_drop_tightening` fires inside the `NullExecutor`
//   mutex guard scope — kept wide on purpose so the recorded snapshot
//   is serialised against the response.
// * `manual_let_else` fires on a couple of tokens-or-fail branches in
//   the lexer where the `else` arm constructs a contextual error.
#![allow(
    clippy::doc_markdown,
    clippy::module_name_repetitions,
    clippy::derive_partial_eq_without_eq,
    clippy::missing_const_for_fn,
    clippy::too_many_lines,
    clippy::literal_string_with_formatting_args,
    clippy::indexing_slicing,
    clippy::option_if_let_else,
    clippy::needless_bool,
    clippy::significant_drop_tightening,
    clippy::manual_let_else
)]
// Tests use `expect`, `panic!`, and `unwrap` idiomatically.
// `indexing_slicing` is already allowed crate-wide above; no need to repeat
// it inside the `cfg(test)` block.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::missing_panics_doc,
        clippy::missing_assert_message
    )
)]

pub mod ast;
pub mod audit_bridge;
pub mod compile;
pub mod error;
pub mod executor;
pub mod parser;
pub mod schema;
pub mod service;

pub use ast::{
    AggCall, AggKind, Comparison, Duration, HuntQuery, Predicate, ProjectStage, Source, Stage,
    SummarizeStage, TimeBound, TopStage, Value, WhereStage,
};
pub use audit_bridge::{
    SxAuditHook, ACTION_CODE_COMPILE_FAILED, ACTION_CODE_EXECUTED, ACTION_CODE_EXEC_FAILED,
    ACTION_CODE_PARSE_FAILED, ACTION_CODE_UNKNOWN, HUNT_RESOURCE_KIND,
};
pub use compile::{
    compile, compile_with_settings, CompiledQuery, ParamValue, DEFAULT_MAX_EXECUTION_TIME_SECS,
    MAX_TOP_N,
};
pub use error::{CompileError, ExecError, HuntError, ParseError};
pub use executor::{HuntExecutor, NullExecutor, RowMap};
pub use parser::parse;
pub use schema::{
    column_allowed, function_allowed, source_table, ALLOWED_COLUMNS, KQL_ALLOWED_FUNCTIONS,
    KQL_ALLOWED_TABLES, SOURCES,
};
pub use service::{
    AuditHook, HuntAuditEntry, HuntResult, HuntService, InMemoryAuditHook, NoopAuditHook,
    NullHuntService,
};
