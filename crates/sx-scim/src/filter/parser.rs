//! Tokeniser + recursive-descent parser for SCIM filter expressions.
//!
//! Grammar (subset of RFC 7644 §3.4.2.2):
//!
//! ```text
//! filter      = or
//! or          = and ( "or" and )*
//! and         = primary ( "and" primary )*
//! primary     = "(" filter ")" | comparison
//! comparison  = attr_path OP string_lit
//! OP          = "eq" | "co" | "sw" | "ew"
//! attr_path   = name ( "." name )*
//! name        = ALPHA ( ALPHA | DIGIT | "_" )*
//! string_lit  = '"' chars '"'
//! ```

use crate::error::ScimError;

/// SCIM comparison operator subset supported by this parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterOp {
    /// Exact equality (case-insensitive).
    Eq,
    /// Contains (case-insensitive substring).
    Co,
    /// Starts with (case-insensitive prefix).
    Sw,
    /// Ends with (case-insensitive suffix).
    Ew,
}

impl FilterOp {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "eq" => Some(Self::Eq),
            "co" => Some(Self::Co),
            "sw" => Some(Self::Sw),
            "ew" => Some(Self::Ew),
            _ => None,
        }
    }

    fn applies(self, lhs: &str, rhs: &str) -> bool {
        let lhs = lhs.to_ascii_lowercase();
        let rhs = rhs.to_ascii_lowercase();
        match self {
            Self::Eq => lhs == rhs,
            Self::Co => lhs.contains(&rhs),
            Self::Sw => lhs.starts_with(&rhs),
            Self::Ew => lhs.ends_with(&rhs),
        }
    }
}

/// Parsed filter AST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    /// `attr OP "value"`.
    Cmp {
        /// Dotted attribute path (e.g. `name.givenName`).
        attr: String,
        /// Comparison operator.
        op: FilterOp,
        /// Right-hand side string literal.
        value: String,
    },
    /// `lhs and rhs`.
    And(Box<Self>, Box<Self>),
    /// `lhs or rhs`.
    Or(Box<Self>, Box<Self>),
}

impl Filter {
    /// Evaluate this filter against a JSON object via dotted attribute paths.
    /// Returns `false` when the path resolves to `null` / missing.
    #[must_use]
    pub fn matches(&self, obj: &serde_json::Value) -> bool {
        match self {
            Self::Cmp { attr, op, value } => {
                let actual = lookup_path(obj, attr);
                actual.as_ref().is_some_and(|a| op.applies(a, value))
            }
            Self::And(l, r) => l.matches(obj) && r.matches(obj),
            Self::Or(l, r) => l.matches(obj) || r.matches(obj),
        }
    }
}

fn lookup_path(obj: &serde_json::Value, attr: &str) -> Option<String> {
    let mut cur = obj;
    for seg in attr.split('.') {
        cur = match cur {
            serde_json::Value::Object(m) => m.get(seg)?,
            serde_json::Value::Array(arr) => {
                // For multi-valued attributes (e.g. `emails.value`), check
                // every element; succeed if any matches downstream.
                for item in arr {
                    if let Some(s) = lookup_path(item, attr_tail(attr, seg)) {
                        return Some(s);
                    }
                }
                return None;
            }
            _ => return None,
        };
    }
    value_as_string(cur)
}

fn attr_tail<'a>(full: &'a str, current: &'a str) -> &'a str {
    // Used only inside `lookup_path`'s array branch; rebuilds the remaining
    // path after the current segment.
    let idx = full.find(current).map_or(full.len(), |i| i + current.len());
    full.get(idx..).unwrap_or("").trim_start_matches('.')
}

fn value_as_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Parse a SCIM filter expression.
///
/// # Errors
///
/// Returns [`ScimError::InvalidFilter`] when the input cannot be tokenised
/// or parsed (unterminated string, unknown operator, trailing tokens, …).
pub fn parse(input: &str) -> Result<Filter, ScimError> {
    let tokens = tokenise(input)?;
    let mut p = Parser {
        tokens: &tokens,
        idx: 0,
    };
    let f = p.parse_or()?;
    if p.idx != tokens.len() {
        return Err(ScimError::invalid_filter(format!(
            "trailing tokens at position {}",
            p.idx
        )));
    }
    Ok(f)
}

// ---------------------------------------------------------------------------
// Tokeniser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Str(String),
    LParen,
    RParen,
}

fn tokenise(input: &str) -> Result<Vec<Tok>, ScimError> {
    let mut out = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        if c == '(' {
            chars.next();
            out.push(Tok::LParen);
            continue;
        }
        if c == ')' {
            chars.next();
            out.push(Tok::RParen);
            continue;
        }
        if c == '"' {
            chars.next();
            let mut buf = String::new();
            loop {
                let Some(ch) = chars.next() else {
                    return Err(ScimError::invalid_filter("unterminated string literal"));
                };
                match ch {
                    '"' => break,
                    '\\' => {
                        let Some(esc) = chars.next() else {
                            return Err(ScimError::invalid_filter(
                                "dangling escape in string literal",
                            ));
                        };
                        match esc {
                            '"' => buf.push('"'),
                            '\\' => buf.push('\\'),
                            'n' => buf.push('\n'),
                            't' => buf.push('\t'),
                            other => buf.push(other),
                        }
                    }
                    other => buf.push(other),
                }
            }
            out.push(Tok::Str(buf));
            continue;
        }
        if is_ident_start(c) {
            let mut buf = String::new();
            while let Some(&ch) = chars.peek() {
                if is_ident_continue(ch) {
                    buf.push(ch);
                    chars.next();
                } else {
                    break;
                }
            }
            out.push(Tok::Ident(buf));
            continue;
        }
        return Err(ScimError::invalid_filter(format!(
            "unexpected character: {c:?}"
        )));
    }
    Ok(out)
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident_continue(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == ':' || c == '-'
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct Parser<'a> {
    tokens: &'a [Tok],
    idx: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.tokens.get(self.idx)
    }

    fn bump(&mut self) -> Option<&Tok> {
        let t = self.tokens.get(self.idx);
        self.idx += 1;
        t
    }

    fn parse_or(&mut self) -> Result<Filter, ScimError> {
        let mut lhs = self.parse_and()?;
        while self.match_keyword("or") {
            let rhs = self.parse_and()?;
            lhs = Filter::Or(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<Filter, ScimError> {
        let mut lhs = self.parse_primary()?;
        while self.match_keyword("and") {
            let rhs = self.parse_primary()?;
            lhs = Filter::And(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_primary(&mut self) -> Result<Filter, ScimError> {
        match self.peek() {
            Some(Tok::LParen) => {
                self.bump();
                let inner = self.parse_or()?;
                match self.bump() {
                    Some(Tok::RParen) => Ok(inner),
                    _ => Err(ScimError::invalid_filter("expected `)`")),
                }
            }
            Some(Tok::Ident(_)) => self.parse_cmp(),
            other => Err(ScimError::invalid_filter(format!(
                "expected attribute or `(`, found {other:?}"
            ))),
        }
    }

    fn parse_cmp(&mut self) -> Result<Filter, ScimError> {
        let attr = match self.bump() {
            Some(Tok::Ident(s)) => s.clone(),
            _ => return Err(ScimError::invalid_filter("expected attribute path")),
        };
        let op = match self.bump() {
            Some(Tok::Ident(s)) => FilterOp::from_str(s)
                .ok_or_else(|| ScimError::invalid_filter(format!("unsupported operator `{s}`")))?,
            _ => return Err(ScimError::invalid_filter("expected comparison operator")),
        };
        let value = match self.bump() {
            Some(Tok::Str(s)) => s.clone(),
            _ => return Err(ScimError::invalid_filter("expected string literal")),
        };
        Ok(Filter::Cmp { attr, op, value })
    }

    fn match_keyword(&mut self, kw: &str) -> bool {
        if let Some(Tok::Ident(s)) = self.peek() {
            if s.eq_ignore_ascii_case(kw) {
                self.idx += 1;
                return true;
            }
        }
        false
    }
}
