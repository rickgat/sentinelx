//! Hand-written recursive-descent parser for the hunt query language.
//!
//! The lexer is byte-oriented and emits a small token stream the parser
//! consumes with one-symbol look-ahead. The parser never recurses
//! unboundedly: predicate depth is capped at [`MAX_PREDICATE_DEPTH`] so
//! adversarial inputs cannot exhaust the call stack.
//!
//! # Tokens (informal)
//!
//! * **Keywords**: `where`, `summarize`, `project`, `top`, `by`, `asc`,
//!   `desc`, `and`, `or`, `not`, `in`, `contains`, `startswith`,
//!   `timeWindow`, `ago`, `between`, `true`, `false`, plus the aggregate
//!   names.
//! * **Punctuation**: `|`, `(`, `)`, `,`, `==`, `!=`, `>`, `<`.
//! * **Literals**: integer (decimal), float, double-quoted string with
//!   `\\` / `\"` escapes.
//! * **Identifiers**: `[A-Za-z_][A-Za-z0-9_]*` — same charset as
//!   `ClickHouse` unquoted column names.

use crate::ast::{
    AggCall, AggKind, Comparison, Duration, DurationUnit, HuntQuery, Predicate, ProjectStage,
    Source, Stage, SummarizeStage, TimeBound, TopStage, Value, WhereStage,
};
use crate::error::ParseError;

/// Hard byte cap on the raw query — keeps the lexer + parser bounded.
pub const MAX_QUERY_BYTES: usize = 8 * 1024;
/// Hard cap on `where` predicate nesting depth (matches OWASP guidance).
pub const MAX_PREDICATE_DEPTH: usize = 32;
/// Maximum number of stages in one pipeline. Hunting analysts virtually
/// never write more than a handful; we cap at 16 to bound compiler work.
pub const MAX_STAGES: usize = 16;
/// Maximum number of items in an `in (...)` list.
pub const MAX_IN_LIST: usize = 128;
/// Maximum byte length of a single string literal.
pub const MAX_STRING_BYTES: usize = 1024;

/// Parse a hunt query string into an AST.
///
/// Returns a [`ParseError`] for any syntactic violation, including
/// over-long queries, over-deep predicates, and unknown source tokens.
pub fn parse(input: &str) -> Result<HuntQuery, ParseError> {
    if input.len() > MAX_QUERY_BYTES {
        return Err(ParseError::QueryTooLong {
            len: input.len(),
            max: MAX_QUERY_BYTES,
        });
    }
    let tokens = lex(input)?;
    let mut p = Parser::new(tokens);
    let q = p.parse_query()?;
    p.expect_eof()?;
    Ok(q)
}

// -- Tokens -----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Int(i64),
    Float(f64),
    Pipe,
    LParen,
    RParen,
    Comma,
    EqEq,
    NotEq,
    Gt,
    Lt,
    Eof,
}

impl Tok {
    fn describe(&self) -> String {
        match self {
            Self::Ident(s) => format!("ident({s})"),
            Self::Str(s) => format!("string({s:?})"),
            Self::Int(i) => format!("int({i})"),
            Self::Float(f) => format!("float({f})"),
            Self::Pipe => "|".into(),
            Self::LParen => "(".into(),
            Self::RParen => ")".into(),
            Self::Comma => ",".into(),
            Self::EqEq => "==".into(),
            Self::NotEq => "!=".into(),
            Self::Gt => ">".into(),
            Self::Lt => "<".into(),
            Self::Eof => "<eof>".into(),
        }
    }
}

fn lex(input: &str) -> Result<Vec<Tok>, ParseError> {
    let bytes = input.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            // whitespace
            b' ' | b'\t' | b'\n' | b'\r' => {
                i += 1;
            }
            b'|' => {
                out.push(Tok::Pipe);
                i += 1;
            }
            b'(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            b')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            b',' => {
                out.push(Tok::Comma);
                i += 1;
            }
            b'=' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
                    out.push(Tok::EqEq);
                    i += 2;
                } else {
                    return Err(ParseError::UnexpectedChar { ch: '=', pos: i });
                }
            }
            b'!' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
                    out.push(Tok::NotEq);
                    i += 2;
                } else {
                    return Err(ParseError::UnexpectedChar { ch: '!', pos: i });
                }
            }
            b'>' => {
                out.push(Tok::Gt);
                i += 1;
            }
            b'<' => {
                out.push(Tok::Lt);
                i += 1;
            }
            b'"' => {
                let start = i;
                i += 1;
                let mut buf = String::new();
                let mut closed = false;
                while i < bytes.len() {
                    let c = bytes[i];
                    if c == b'\\' && i + 1 < bytes.len() {
                        let esc = bytes[i + 1];
                        match esc {
                            b'\\' => buf.push('\\'),
                            b'"' => buf.push('"'),
                            b'n' => buf.push('\n'),
                            b't' => buf.push('\t'),
                            other => {
                                return Err(ParseError::UnexpectedChar {
                                    ch: other as char,
                                    pos: i + 1,
                                });
                            }
                        }
                        i += 2;
                    } else if c == b'"' {
                        closed = true;
                        i += 1;
                        break;
                    } else {
                        // Push the next UTF-8 char rather than the byte so
                        // multi-byte strings round-trip correctly.
                        let ch_start = i;
                        let mut end = i + 1;
                        while end < bytes.len() && !input.is_char_boundary(end) {
                            end += 1;
                        }
                        if end > bytes.len() {
                            end = bytes.len();
                        }
                        let slice = input.get(ch_start..end).ok_or(ParseError::UnexpectedChar {
                            ch: c as char,
                            pos: ch_start,
                        })?;
                        buf.push_str(slice);
                        i = end;
                    }
                }
                if !closed {
                    return Err(ParseError::UnterminatedString { pos: start });
                }
                if buf.len() > MAX_STRING_BYTES {
                    return Err(ParseError::QueryTooLong {
                        len: buf.len(),
                        max: MAX_STRING_BYTES,
                    });
                }
                out.push(Tok::Str(buf));
            }
            b'0'..=b'9' | b'-' => {
                let start = i;
                if b == b'-' {
                    i += 1;
                    if i >= bytes.len() || !bytes[i].is_ascii_digit() {
                        return Err(ParseError::UnexpectedChar {
                            ch: '-',
                            pos: start,
                        });
                    }
                }
                let mut saw_dot = false;
                while i < bytes.len()
                    && (bytes[i].is_ascii_digit() || (bytes[i] == b'.' && !saw_dot))
                {
                    if bytes[i] == b'.' {
                        saw_dot = true;
                    }
                    i += 1;
                }
                let lexeme = input.get(start..i).ok_or(ParseError::InvalidNumber {
                    lexeme: String::new(),
                    pos: start,
                })?;
                if saw_dot {
                    let f: f64 = lexeme.parse().map_err(|_| ParseError::InvalidNumber {
                        lexeme: lexeme.to_string(),
                        pos: start,
                    })?;
                    out.push(Tok::Float(f));
                } else {
                    let n: i64 = lexeme.parse().map_err(|_| ParseError::InvalidNumber {
                        lexeme: lexeme.to_string(),
                        pos: start,
                    })?;
                    out.push(Tok::Int(n));
                }
            }
            c if c == b'_' || c.is_ascii_alphabetic() => {
                let start = i;
                while i < bytes.len() && (bytes[i] == b'_' || bytes[i].is_ascii_alphanumeric()) {
                    i += 1;
                }
                let lexeme = input.get(start..i).ok_or(ParseError::UnexpectedChar {
                    ch: c as char,
                    pos: start,
                })?;
                out.push(Tok::Ident(lexeme.to_string()));
            }
            other => {
                return Err(ParseError::UnexpectedChar {
                    ch: other as char,
                    pos: i,
                });
            }
        }
    }
    out.push(Tok::Eof);
    Ok(out)
}

// -- Parser -----------------------------------------------------------------

struct Parser {
    tokens: Vec<Tok>,
    cursor: usize,
    depth: usize,
}

impl Parser {
    fn new(tokens: Vec<Tok>) -> Self {
        Self {
            tokens,
            cursor: 0,
            depth: 0,
        }
    }

    fn peek(&self) -> &Tok {
        self.tokens.get(self.cursor).unwrap_or(&Tok::Eof)
    }

    fn bump(&mut self) -> Tok {
        let t = self.tokens.get(self.cursor).cloned().unwrap_or(Tok::Eof);
        if !matches!(t, Tok::Eof) {
            self.cursor += 1;
        }
        t
    }

    fn expect_eof(&self) -> Result<(), ParseError> {
        if matches!(self.peek(), Tok::Eof) {
            Ok(())
        } else {
            Err(ParseError::UnexpectedToken {
                found: self.peek().describe(),
                expected: "end of query".into(),
            })
        }
    }

    fn expect_ident(&mut self) -> Result<String, ParseError> {
        match self.bump() {
            Tok::Ident(s) => Ok(s),
            other => Err(ParseError::UnexpectedToken {
                found: other.describe(),
                expected: "identifier".into(),
            }),
        }
    }

    fn expect_keyword(&mut self, kw: &str) -> Result<(), ParseError> {
        match self.bump() {
            Tok::Ident(s) if s == kw => Ok(()),
            other => Err(ParseError::UnexpectedToken {
                found: other.describe(),
                expected: format!("keyword `{kw}`"),
            }),
        }
    }

    fn eat_keyword(&mut self, kw: &str) -> bool {
        if let Tok::Ident(s) = self.peek() {
            if s == kw {
                self.cursor += 1;
                return true;
            }
        }
        false
    }

    fn expect_lparen(&mut self) -> Result<(), ParseError> {
        match self.bump() {
            Tok::LParen => Ok(()),
            other => Err(ParseError::UnexpectedToken {
                found: other.describe(),
                expected: "(".into(),
            }),
        }
    }

    fn expect_rparen(&mut self) -> Result<(), ParseError> {
        match self.bump() {
            Tok::RParen => Ok(()),
            other => Err(ParseError::UnexpectedToken {
                found: other.describe(),
                expected: ")".into(),
            }),
        }
    }

    fn expect_comma(&mut self) -> Result<(), ParseError> {
        match self.bump() {
            Tok::Comma => Ok(()),
            other => Err(ParseError::UnexpectedToken {
                found: other.describe(),
                expected: ",".into(),
            }),
        }
    }

    fn parse_query(&mut self) -> Result<HuntQuery, ParseError> {
        let source = self.parse_source()?;
        let mut stages = Vec::new();
        while matches!(self.peek(), Tok::Pipe) {
            if stages.len() >= MAX_STAGES {
                return Err(ParseError::UnexpectedToken {
                    found: "|".into(),
                    expected: format!("at most {MAX_STAGES} pipeline stages"),
                });
            }
            let _ = self.bump(); // pipe
            stages.push(self.parse_stage()?);
        }
        Ok(HuntQuery { source, stages })
    }

    fn parse_source(&mut self) -> Result<Source, ParseError> {
        let name = self.expect_ident()?;
        // HIGH-005: emit the specific `HUNT_DENIED_TABLE` code rather
        // than the generic `UnknownSource`. The allowlist enforcement is
        // intentionally re-checked at compile time as defence in depth.
        if crate::schema::source_table(&name).is_none() {
            return Err(ParseError::DeniedTable { name });
        }
        Ok(Source { name })
    }

    fn parse_stage(&mut self) -> Result<Stage, ParseError> {
        let kw = self.expect_ident()?;
        match kw.as_str() {
            "where" => Ok(Stage::Where(self.parse_where()?)),
            "summarize" => Ok(Stage::Summarize(self.parse_summarize()?)),
            "project" => Ok(Stage::Project(self.parse_project()?)),
            "top" => Ok(Stage::Top(self.parse_top()?)),
            "timeWindow" => Ok(Stage::TimeWindow(self.parse_time_window()?)),
            "between" => Ok(Stage::TimeWindow(self.parse_between()?)),
            // HIGH-005: if the stage keyword is a function name that the
            // analyst is trying to call as a stage (e.g. `| file(...)`),
            // produce the specific `HUNT_DENIED_FN` code so the UI can
            // render a "function not permitted" remediation.
            other => {
                if !crate::schema::function_allowed(other) {
                    return Err(ParseError::DeniedFunction {
                        name: other.to_string(),
                    });
                }
                Err(ParseError::UnexpectedToken {
                    found: format!("ident({other})"),
                    expected: "where | summarize | project | top | timeWindow | between".into(),
                })
            }
        }
    }

    fn parse_where(&mut self) -> Result<WhereStage, ParseError> {
        let predicate = self.parse_or()?;
        Ok(WhereStage { predicate })
    }

    fn parse_or(&mut self) -> Result<Predicate, ParseError> {
        self.depth += 1;
        if self.depth > MAX_PREDICATE_DEPTH {
            return Err(ParseError::UnexpectedToken {
                found: "<deep predicate>".into(),
                expected: format!("predicate depth <= {MAX_PREDICATE_DEPTH}"),
            });
        }
        let mut lhs = self.parse_and()?;
        let mut acc = vec![lhs];
        while self.eat_keyword("or") {
            lhs = self.parse_and()?;
            acc.push(lhs);
        }
        self.depth -= 1;
        Ok(if acc.len() == 1 {
            acc.remove(0)
        } else {
            Predicate::Or(acc)
        })
    }

    fn parse_and(&mut self) -> Result<Predicate, ParseError> {
        let mut acc = vec![self.parse_not()?];
        while self.eat_keyword("and") {
            acc.push(self.parse_not()?);
        }
        Ok(if acc.len() == 1 {
            acc.remove(0)
        } else {
            Predicate::And(acc)
        })
    }

    fn parse_not(&mut self) -> Result<Predicate, ParseError> {
        if self.eat_keyword("not") {
            let inner = self.parse_atom()?;
            Ok(Predicate::Not(Box::new(inner)))
        } else {
            self.parse_atom()
        }
    }

    fn parse_atom(&mut self) -> Result<Predicate, ParseError> {
        // Parenthesised predicate.
        if matches!(self.peek(), Tok::LParen) {
            let _ = self.bump();
            let inner = self.parse_or()?;
            self.expect_rparen()?;
            return Ok(inner);
        }
        // Field-led comparison or `in` list.
        let field = self.expect_ident()?;
        // `field in (...)`
        if let Tok::Ident(s) = self.peek() {
            if s == "in" {
                let _ = self.bump();
                self.expect_lparen()?;
                let mut values = Vec::new();
                while !matches!(self.peek(), Tok::RParen) {
                    values.push(self.parse_value()?);
                    if values.len() > MAX_IN_LIST {
                        return Err(ParseError::UnexpectedToken {
                            found: ",".into(),
                            expected: format!("at most {MAX_IN_LIST} `in (...)` items"),
                        });
                    }
                    if matches!(self.peek(), Tok::Comma) {
                        let _ = self.bump();
                    } else {
                        break;
                    }
                }
                self.expect_rparen()?;
                if values.is_empty() {
                    return Err(ParseError::UnexpectedToken {
                        found: ")".into(),
                        expected: "non-empty `in (...)` list".into(),
                    });
                }
                return Ok(Predicate::In { field, values });
            }
        }
        // `field <op> value`
        let cmp = match self.peek() {
            Tok::EqEq => {
                let _ = self.bump();
                Comparison::Eq
            }
            Tok::NotEq => {
                let _ = self.bump();
                Comparison::Neq
            }
            Tok::Gt => {
                let _ = self.bump();
                Comparison::Gt
            }
            Tok::Lt => {
                let _ = self.bump();
                Comparison::Lt
            }
            Tok::Ident(s) if s == "contains" => {
                let _ = self.bump();
                Comparison::Contains
            }
            Tok::Ident(s) if s == "startswith" => {
                let _ = self.bump();
                Comparison::StartsWith
            }
            other => {
                return Err(ParseError::UnexpectedToken {
                    found: other.describe(),
                    expected: "==, !=, >, <, contains, startswith, or in".into(),
                });
            }
        };
        let value = self.parse_value()?;
        Ok(Predicate::Compare { field, cmp, value })
    }

    fn parse_value(&mut self) -> Result<Value, ParseError> {
        match self.bump() {
            Tok::Str(s) => Ok(Value::String(s)),
            Tok::Int(n) => Ok(Value::Int(n)),
            Tok::Float(f) => Ok(Value::Float(f)),
            Tok::Ident(s) if s == "true" => Ok(Value::Int(1)),
            Tok::Ident(s) if s == "false" => Ok(Value::Int(0)),
            // HIGH-005: if the analyst typed `where x == file("/etc/passwd")`,
            // the value position sees `Ident("file")` followed by `LParen`.
            // Produce a specific `HUNT_DENIED_FN` error code so the UI can
            // surface a targeted remediation rather than the generic
            // "expected value" message. Any unknown ident in value
            // position followed by `(` is treated as a function-call
            // attempt; idents not followed by `(` fall through to the
            // generic "expected value" error.
            Tok::Ident(s) if matches!(self.peek(), Tok::LParen) => {
                Err(ParseError::DeniedFunction { name: s })
            }
            other => Err(ParseError::UnexpectedToken {
                found: other.describe(),
                expected: "string, integer, float, or boolean".into(),
            }),
        }
    }

    fn parse_summarize(&mut self) -> Result<SummarizeStage, ParseError> {
        let mut aggs = Vec::new();
        aggs.push(self.parse_agg()?);
        while matches!(self.peek(), Tok::Comma) {
            let _ = self.bump();
            aggs.push(self.parse_agg()?);
        }
        let mut by = Vec::new();
        if self.eat_keyword("by") {
            by.push(self.expect_ident()?);
            while matches!(self.peek(), Tok::Comma) {
                let _ = self.bump();
                by.push(self.expect_ident()?);
            }
        }
        Ok(SummarizeStage {
            aggregations: aggs,
            by,
        })
    }

    fn parse_agg(&mut self) -> Result<AggCall, ParseError> {
        let name = self.expect_ident()?;
        // HIGH-005 function-whitelist enforcement (defence-in-depth at
        // aggregation position). The previously-shipped `sum/min/max/
        // count_distinct` aggregates are explicitly removed; anything not
        // in [`crate::schema::KQL_ALLOWED_FUNCTIONS`] is rejected with the
        // stable `HUNT_DENIED_FN` code.
        let kind = match name.as_str() {
            "count" => AggKind::Count,
            "dcount" => AggKind::Dcount,
            "avg" => AggKind::Avg,
            "percentile" => AggKind::Percentile,
            "make_set" => AggKind::MakeSet,
            // Any other identifier in aggregation position is a denied
            // function call (`file`, `url`, `format`, `system`, plus the
            // previously-shipped aggregates `sum/min/max/count_distinct`
            // that HIGH-005 removed).
            other => {
                return Err(ParseError::DeniedFunction {
                    name: other.to_string(),
                });
            }
        };
        self.expect_lparen()?;
        let field = if matches!(self.peek(), Tok::RParen) {
            None
        } else {
            Some(self.expect_ident()?)
        };
        // `percentile(field, q)` takes a second positional float argument.
        let arg2 = if kind.takes_second_arg() {
            self.expect_comma()?;
            Some(self.parse_value()?)
        } else {
            None
        };
        self.expect_rparen()?;
        // Arity check.
        match (kind, &field) {
            (AggKind::Count, Some(_)) => {
                return Err(ParseError::UnexpectedToken {
                    found: "ident".into(),
                    expected: "count() — no argument".into(),
                });
            }
            // Either: count() with no arg (legal), or one of the unary
            // aggregates with its required column argument (also legal).
            (AggKind::Count, None)
            | (AggKind::Dcount | AggKind::Avg | AggKind::Percentile | AggKind::MakeSet, Some(_)) => {
            }
            (AggKind::Dcount | AggKind::Avg | AggKind::Percentile | AggKind::MakeSet, None) => {
                return Err(ParseError::UnexpectedToken {
                    found: ")".into(),
                    expected: format!("argument column for `{}(field)`", kind.label()),
                });
            }
        }
        // `percentile` must have its second arg.
        if kind == AggKind::Percentile && arg2.is_none() {
            return Err(ParseError::UnexpectedToken {
                found: ")".into(),
                expected: "second argument `q` for `percentile(field, q)`".into(),
            });
        }
        Ok(AggCall {
            kind,
            field,
            alias: None,
            arg2,
        })
    }

    fn parse_project(&mut self) -> Result<ProjectStage, ParseError> {
        let mut fields = vec![self.expect_ident()?];
        while matches!(self.peek(), Tok::Comma) {
            let _ = self.bump();
            fields.push(self.expect_ident()?);
        }
        Ok(ProjectStage { fields })
    }

    fn parse_top(&mut self) -> Result<TopStage, ParseError> {
        let n = match self.bump() {
            Tok::Int(n) => n,
            other => {
                return Err(ParseError::UnexpectedToken {
                    found: other.describe(),
                    expected: "integer (top N)".into(),
                });
            }
        };
        self.expect_keyword("by")?;
        let field = self.expect_ident()?;
        let descending = if self.eat_keyword("desc") {
            true
        } else if self.eat_keyword("asc") {
            false
        } else {
            true
        };
        Ok(TopStage {
            n,
            by: field,
            descending,
        })
    }

    fn parse_time_window(&mut self) -> Result<TimeBound, ParseError> {
        self.expect_keyword("ago")?;
        self.expect_lparen()?;
        let duration = self.parse_duration()?;
        self.expect_rparen()?;
        Ok(TimeBound::Ago(duration))
    }

    fn parse_between(&mut self) -> Result<TimeBound, ParseError> {
        self.expect_lparen()?;
        let from = match self.bump() {
            Tok::Str(s) => s,
            other => {
                return Err(ParseError::UnexpectedToken {
                    found: other.describe(),
                    expected: "ISO 8601 string for between(from, to)".into(),
                });
            }
        };
        self.expect_comma()?;
        let to = match self.bump() {
            Tok::Str(s) => s,
            other => {
                return Err(ParseError::UnexpectedToken {
                    found: other.describe(),
                    expected: "ISO 8601 string for between(from, to)".into(),
                });
            }
        };
        self.expect_rparen()?;
        Ok(TimeBound::Between { from, to })
    }

    fn parse_duration(&mut self) -> Result<Duration, ParseError> {
        // Two acceptable forms:
        //   * Int + bare ident suffix: `24 h` or `24h` (`24h` lexes as ident
        //     "24h"? No — the lexer treats `24` as an int and `h` as a
        //     trailing ident. The `24h` form is therefore "Int(24)" then
        //     "Ident("h")".).
        //   * Standalone ident like `24h` would only happen if the prefix
        //     were not numeric; we do not support that.
        let n = match self.bump() {
            Tok::Int(n) if n > 0 => {
                u64::try_from(n).map_err(|_| ParseError::InvalidDurationValue)?
            }
            Tok::Int(_) => return Err(ParseError::InvalidDurationValue),
            other => {
                return Err(ParseError::UnexpectedToken {
                    found: other.describe(),
                    expected: "positive integer (duration magnitude)".into(),
                });
            }
        };
        let suffix = self.expect_ident()?;
        let unit = match suffix.as_str() {
            "s" => DurationUnit::Second,
            "m" => DurationUnit::Minute,
            "h" => DurationUnit::Hour,
            "d" => DurationUnit::Day,
            other => return Err(ParseError::InvalidDurationSuffix(other.to_string())),
        };
        Ok(Duration { value: n, unit })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_source_only() {
        let q = parse("events_raw").unwrap();
        assert_eq!(q.source.name, "events_raw");
        assert!(q.stages.is_empty());
    }

    #[test]
    fn parse_where_equality_string() {
        let q = parse(r#"events_raw | where user_name == "alice""#).unwrap();
        assert_eq!(q.stages.len(), 1);
        match &q.stages[0] {
            Stage::Where(w) => match &w.predicate {
                Predicate::Compare { field, cmp, value } => {
                    assert_eq!(field, "user_name");
                    assert_eq!(*cmp, Comparison::Eq);
                    assert_eq!(value, &Value::String("alice".into()));
                }
                other => panic!("expected Compare, got {other:?}"),
            },
            other => panic!("expected Where, got {other:?}"),
        }
    }

    #[test]
    fn parse_where_and_or_not() {
        let q = parse(
            r#"events_raw | where user_name == "alice" and (src_port > 1024 or not severity_id == 1)"#,
        )
        .unwrap();
        assert!(matches!(q.stages[0], Stage::Where(_)));
    }

    #[test]
    fn parse_where_in_list() {
        let q = parse(r#"events_raw | where src_ip in ("10.0.0.1", "10.0.0.2")"#).unwrap();
        if let Stage::Where(w) = &q.stages[0] {
            if let Predicate::In { field, values } = &w.predicate {
                assert_eq!(field, "src_ip");
                assert_eq!(values.len(), 2);
            } else {
                panic!("expected In");
            }
        }
    }

    #[test]
    fn parse_summarize_count_by() {
        let q = parse("events_normalized | summarize count() by user_name").unwrap();
        if let Stage::Summarize(s) = &q.stages[0] {
            assert_eq!(s.aggregations.len(), 1);
            assert_eq!(s.aggregations[0].kind, AggKind::Count);
            assert_eq!(s.by, vec!["user_name".to_string()]);
        } else {
            panic!("expected Summarize");
        }
    }

    #[test]
    fn parse_project_and_top() {
        let q =
            parse("events_raw | project user_name, src_ip | top 10 by severity_id desc").unwrap();
        assert_eq!(q.stages.len(), 2);
        if let Stage::Top(t) = &q.stages[1] {
            assert_eq!(t.n, 10);
            assert_eq!(t.by, "severity_id");
            assert!(t.descending);
        } else {
            panic!("expected Top");
        }
    }

    #[test]
    fn parse_time_window_ago() {
        let q = parse("events_raw | timeWindow ago(24 h)").unwrap();
        if let Stage::TimeWindow(TimeBound::Ago(d)) = &q.stages[0] {
            assert_eq!(d.value, 24);
            assert_eq!(d.unit, DurationUnit::Hour);
        } else {
            panic!("expected Ago");
        }
    }

    #[test]
    fn parse_between() {
        let q = parse(r#"events_raw | between("2026-06-01T00:00:00Z", "2026-06-02T00:00:00Z")"#)
            .unwrap();
        assert!(matches!(
            q.stages[0],
            Stage::TimeWindow(TimeBound::Between { .. })
        ));
    }

    #[test]
    fn rejects_unknown_source() {
        let err = parse("system.users").unwrap_err();
        // `system.users` lexes as Ident("system") then Ident("users") with
        // an unexpected `.` in between — the lexer rejects `.`.
        assert!(matches!(err, ParseError::UnexpectedChar { .. }));
        // HIGH-005: unknown bare-ident source produces the specific
        // `DeniedTable` variant (code `HUNT_DENIED_TABLE`).
        let err = parse("logins").unwrap_err();
        assert!(matches!(err, ParseError::DeniedTable { .. }));
        assert_eq!(err.code(), "HUNT_DENIED_TABLE");
    }

    #[test]
    fn rejects_denied_function_at_aggregation_position() {
        // The previously-shipped `sum/min/max/count_distinct` aggregates
        // are denied post-HIGH-005.
        for fname in ["sum", "min", "max", "count_distinct"] {
            let q = format!("events_raw | summarize {fname}(severity_id)");
            let err = parse(&q).unwrap_err();
            match &err {
                ParseError::DeniedFunction { name } => assert_eq!(name, fname),
                other => panic!("expected DeniedFunction for {fname}, got {other:?}"),
            }
            assert_eq!(err.code(), "HUNT_DENIED_FN");
        }
        // Disk / network / format escapes that motivated the hardening.
        for fname in ["file", "url", "format", "system"] {
            let q = format!("events_raw | summarize {fname}(raw)");
            let err = parse(&q).unwrap_err();
            match &err {
                ParseError::DeniedFunction { name } => assert_eq!(name, fname),
                other => panic!("expected DeniedFunction for {fname}, got {other:?}"),
            }
            assert_eq!(err.code(), "HUNT_DENIED_FN");
        }
    }

    #[test]
    fn rejects_denied_function_in_value_position() {
        // `where x == file("/etc/passwd")` — the parser sees Ident("file")
        // followed by LParen in value position and produces
        // `DeniedFunction` rather than a generic "expected value" error.
        let err = parse(r#"events_raw | where raw == file("/etc/passwd")"#).unwrap_err();
        match &err {
            ParseError::DeniedFunction { name } => assert_eq!(name, "file"),
            other => panic!("expected DeniedFunction, got {other:?}"),
        }
        assert_eq!(err.code(), "HUNT_DENIED_FN");
    }

    #[test]
    fn rejects_denied_stage_keyword() {
        // `events_raw | file(...)` — the analyst tries to call `file()` as a
        // pipeline stage. The parser must surface `HUNT_DENIED_FN`.
        let err = parse("events_raw | file(raw)").unwrap_err();
        match &err {
            ParseError::DeniedFunction { name } => assert_eq!(name, "file"),
            other => panic!("expected DeniedFunction, got {other:?}"),
        }
        assert_eq!(err.code(), "HUNT_DENIED_FN");
    }

    #[test]
    fn parse_percentile_with_quantile() {
        let q = parse("events_normalized | summarize percentile(severity_id, 0.95) by user_name")
            .unwrap();
        if let Stage::Summarize(s) = &q.stages[0] {
            assert_eq!(s.aggregations.len(), 1);
            let a = &s.aggregations[0];
            assert_eq!(a.kind, AggKind::Percentile);
            assert_eq!(a.field.as_deref(), Some("severity_id"));
            assert_eq!(a.arg2, Some(Value::Float(0.95)));
        } else {
            panic!("expected Summarize");
        }
    }

    #[test]
    fn parse_dcount_and_make_set() {
        let q =
            parse("events_normalized | summarize dcount(user_name), make_set(src_ip) by hostname")
                .unwrap();
        if let Stage::Summarize(s) = &q.stages[0] {
            assert_eq!(s.aggregations.len(), 2);
            assert_eq!(s.aggregations[0].kind, AggKind::Dcount);
            assert_eq!(s.aggregations[1].kind, AggKind::MakeSet);
        } else {
            panic!("expected Summarize");
        }
    }

    #[test]
    fn rejects_oversized_query() {
        let big = format!(
            "events_raw | where user_name == \"{}\"",
            "a".repeat(MAX_QUERY_BYTES)
        );
        assert!(matches!(
            parse(&big).unwrap_err(),
            ParseError::QueryTooLong { .. }
        ));
    }

    #[test]
    fn rejects_unterminated_string() {
        assert!(matches!(
            parse(r#"events_raw | where user_name == "alice"#).unwrap_err(),
            ParseError::UnterminatedString { .. }
        ));
    }

    #[test]
    fn rejects_bad_op() {
        let err = parse("events_raw | where user_name = \"alice\"").unwrap_err();
        // single `=` is not a valid token; lexer rejects it.
        assert!(matches!(err, ParseError::UnexpectedChar { ch: '=', .. }));
    }

    #[test]
    fn round_trip_through_json() {
        let q = parse(
            r#"events_normalized | where severity_id > 3 and src_ip in ("10.0.0.1") | summarize count() by user_name | top 5 by user_name asc"#,
        )
        .unwrap();
        let s = serde_json::to_string(&q).unwrap();
        let back: HuntQuery = serde_json::from_str(&s).unwrap();
        assert_eq!(back, q);
    }

    #[test]
    fn rejects_empty_in_list() {
        assert!(parse("events_raw | where src_ip in ()").is_err());
    }

    #[test]
    fn rejects_count_with_arg() {
        let err = parse("events_raw | summarize count(user_name)").unwrap_err();
        match err {
            ParseError::UnexpectedToken { .. } => {}
            other => panic!("expected UnexpectedToken, got {other:?}"),
        }
    }

    #[test]
    fn rejects_dcount_without_arg() {
        // HIGH-005 vocabulary: `dcount()` requires an argument column. The
        // parser must fail with `UnexpectedToken` on the empty argument
        // list (rather than `DeniedFunction`, which is reserved for
        // unknown function names).
        let err = parse("events_raw | summarize dcount()").unwrap_err();
        match err {
            ParseError::UnexpectedToken { .. } => {}
            other => panic!("expected UnexpectedToken, got {other:?}"),
        }
    }
}
