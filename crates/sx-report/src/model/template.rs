//! Per-tenant report template DSL (P2-002).
//!
//! A [`ReportTemplate`] holds a Handlebars-like body that renders against
//! a [`TemplateContext`] built from a [`crate::model::ReportContext`].
//!
//! ## Supported syntax
//!
//! - `{{var}}` — scalar substitution. Supports dotted paths
//!   (`{{tenant.name}}`, `{{posture.total}}`).
//! - `{{#each items}}...{{/each}}` — repeats the inner body for every
//!   element of an array. Inside the block, `{{this}}` references the
//!   current element scalar, and dotted paths reference its fields.
//! - `{{#if cond}}...{{/if}}` — renders the inner body when `cond`
//!   resolves to a non-empty / non-zero / non-false value.
//! - `{{! comment }}` — comment, never rendered.
//!
//! ## Sandbox guarantees
//!
//! - No script execution: the engine never `eval`s anything. Substitution
//!   is plain string lookup.
//! - Capped block nesting ([`MAX_BLOCK_DEPTH`]) — protects against
//!   `{{#each}}...{{#each}}...` exponential expansion.
//! - Capped iteration ([`MAX_ITERATIONS_PER_LOOP`]) — protects against
//!   tenants accidentally rendering a million-row table.
//! - Capped output size ([`MAX_OUTPUT_BYTES`]) — protects the API layer
//!   from OOM-style abuse.
//! - Strict syntax: unbalanced `{{#each}}` / `{{/each}}` errors at
//!   render time and is detected at template-compile time too.
//!
//! Templates are *not* trusted Markdown: scalar values pass through a
//! light XML-escaping filter so a value containing `<script>` never
//! reaches the consumer verbatim.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sx_core::value_object::ids::TenantId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ReportError;

/// Maximum nested-block depth the engine accepts.
pub const MAX_BLOCK_DEPTH: usize = 8;

/// Maximum elements iterated per `{{#each}}` block.
pub const MAX_ITERATIONS_PER_LOOP: usize = 10_000;

/// Maximum bytes the engine will produce before aborting.
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

/// Maximum raw template body length (chars).
pub const MAX_TEMPLATE_BYTES: usize = 256 * 1024;

/// Maximum identifier length in a `{{path}}`.
pub const MAX_IDENT_LEN: usize = 128;

/// Stable identifier for a stored template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReportTemplateId(Uuid);

impl ReportTemplateId {
    /// Generate a fresh template id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Construct from a raw UUID — used by the persistence adapter and
    /// the API extractor when restoring an id from the wire.
    #[must_use]
    pub const fn from_uuid(u: Uuid) -> Self {
        Self(u)
    }

    /// Borrow the underlying UUID.
    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for ReportTemplateId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ReportTemplateId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

/// Which output surface a template is targeting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateSurface {
    /// Cover-page paragraph on PDF reports.
    PdfCover,
    /// Footer text on PDF reports.
    PdfFooter,
    /// HTML rendered email body (when `sx-notify` distributes a report).
    HtmlEmail,
    /// Plain-text fallback (chat / CLI summaries).
    PlainText,
}

impl TemplateSurface {
    /// Canonical short form for logging and persistence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PdfCover => "pdf_cover",
            Self::PdfFooter => "pdf_footer",
            Self::HtmlEmail => "html_email",
            Self::PlainText => "plain_text",
        }
    }
}

impl std::fmt::Display for TemplateSurface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A tenant-owned, named, versioned template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportTemplate {
    /// Stable identifier.
    pub id: ReportTemplateId,
    /// Owning tenant — every read / write call MUST filter by this.
    pub tenant_id: TenantId,
    /// Human-readable name (unique per `(tenant_id, surface)`).
    pub name: String,
    /// Which surface this template targets.
    pub surface: TemplateSurface,
    /// Raw Handlebars-like body. See module docs for the grammar.
    pub body: String,
    /// Optional description for the UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Monotonically increasing version, bumped on every update.
    pub version: u32,
    /// Audit metadata — who last touched this row.
    pub updated_by: String,
    /// Audit metadata — when this row was last touched.
    pub updated_at: OffsetDateTime,
}

impl ReportTemplate {
    /// Build + validate a [`ReportTemplate`].
    ///
    /// Performs a compile-time pass over `body` to confirm braces are
    /// balanced and identifiers are well-formed before the template can
    /// ever be persisted.
    ///
    /// # Errors
    /// - [`ReportError::InvalidContext`] when `name` is empty after
    ///   trimming, when `body` exceeds [`MAX_TEMPLATE_BYTES`], or when
    ///   the body fails [`compile`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: ReportTemplateId,
        tenant_id: TenantId,
        name: impl Into<String>,
        surface: TemplateSurface,
        body: impl Into<String>,
        description: Option<String>,
        version: u32,
        updated_by: impl Into<String>,
        updated_at: OffsetDateTime,
    ) -> Result<Self, ReportError> {
        let name = name.into().trim().to_owned();
        if name.is_empty() {
            return Err(ReportError::invalid_context(
                "template name cannot be empty",
            ));
        }
        if name.len() > 200 {
            return Err(ReportError::invalid_context("template name too long"));
        }
        let body = body.into();
        if body.len() > MAX_TEMPLATE_BYTES {
            return Err(ReportError::invalid_context(format!(
                "template body exceeds {MAX_TEMPLATE_BYTES} bytes",
            )));
        }
        // Compile-time pass — proves the syntax is balanced.
        let _ast = compile(&body)?;
        let updated_by = updated_by.into().trim().to_owned();
        if updated_by.is_empty() {
            return Err(ReportError::invalid_context("updated_by cannot be empty"));
        }
        Ok(Self {
            id,
            tenant_id,
            name,
            surface,
            body,
            description,
            version,
            updated_by,
            updated_at,
        })
    }

    /// Render the template against `ctx`.
    ///
    /// # Errors
    /// Returns [`ReportError::InvalidContext`] when the engine exceeds
    /// recursion / output / iteration caps, or when a value is missing
    /// and the caller did not provide a default.
    pub fn render(&self, ctx: &TemplateContext) -> Result<String, ReportError> {
        let ast = compile(&self.body)?;
        let mut out = String::with_capacity(self.body.len());
        render_nodes(&ast, ctx, &mut out, 0)?;
        Ok(out)
    }
}

/// Dynamic value passed into the template engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TemplateValue {
    /// JSON-like null.
    Null,
    /// Boolean truthy / falsy.
    Bool(bool),
    /// Numeric.
    Number(f64),
    /// String scalar.
    String(String),
    /// Repeatable element list.
    List(Vec<Self>),
    /// Named-field map.
    Map(BTreeMap<String, Self>),
}

impl TemplateValue {
    /// Is this value "truthy" for `{{#if}}` purposes?
    #[must_use]
    pub fn is_truthy(&self) -> bool {
        match self {
            Self::Null => false,
            Self::Bool(b) => *b,
            Self::Number(n) => n.abs() > f64::EPSILON,
            Self::String(s) => !s.is_empty(),
            Self::List(v) => !v.is_empty(),
            Self::Map(m) => !m.is_empty(),
        }
    }

    /// Render as a flat scalar string.
    #[must_use]
    pub fn as_scalar(&self) -> String {
        match self {
            Self::Null => String::new(),
            Self::Bool(b) => b.to_string(),
            Self::Number(n) => format_number(*n),
            Self::String(s) => s.clone(),
            // Lists / maps in scalar position become their length —
            // useful for `{{posture.findings.len}}` style templates.
            Self::List(v) => v.len().to_string(),
            Self::Map(m) => m.len().to_string(),
        }
    }
}

/// Format a [`f64`] for template substitution without a trailing `.0` for
/// whole numbers that round-trip through [`i64`].
#[allow(clippy::cast_possible_truncation)]
fn format_number(n: f64) -> String {
    // The two boundary constants are exact integer powers of two, so the
    // narrowing conversion to `f64` does not lose precision in practice;
    // the explicit allow exists to satisfy the clippy lint on platforms
    // that flag the cast unconditionally.
    #[allow(clippy::cast_precision_loss)]
    let min_i64_f = i64::MIN as f64;
    #[allow(clippy::cast_precision_loss)]
    let max_i64_f = i64::MAX as f64;
    if n.is_finite() && n.fract().abs() < f64::EPSILON && n >= min_i64_f && n <= max_i64_f {
        let as_int = n as i64;
        format!("{as_int}")
    } else {
        format!("{n}")
    }
}

/// Variable resolution context.
///
/// Built from a [`crate::model::ReportContext`] via
/// [`TemplateContext::from_report`], or constructed manually for unit
/// tests and the API preview endpoint.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TemplateContext {
    root: BTreeMap<String, TemplateValue>,
}

impl TemplateContext {
    /// Empty context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: insert a named scalar / list / map.
    #[must_use]
    pub fn with(mut self, key: impl Into<String>, value: TemplateValue) -> Self {
        self.root.insert(key.into(), value);
        self
    }

    /// Build from a [`crate::model::ReportContext`].
    ///
    /// Exposes the following top-level keys:
    ///
    /// - `tenant.id`, `tenant.name`
    /// - `engagement.id`, `engagement.name`
    /// - `generated_by`, `generated_at`
    /// - `posture.total`, `posture.critical`, `posture.high`,
    ///   `posture.medium`, `posture.low`, `posture.info`
    /// - `findings` — list of `{ title, severity, asset, status }`
    /// - `top_risks` — list of `{ title, severity, cvss }`
    /// - `branding.primary_color_hex`, `branding.has_logo`
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn from_report(ctx: &crate::model::ReportContext) -> Self {
        let mut tenant = BTreeMap::new();
        tenant.insert(
            "id".to_owned(),
            TemplateValue::String(ctx.tenant_id.to_string()),
        );
        tenant.insert(
            "name".to_owned(),
            TemplateValue::String(ctx.tenant_name.clone()),
        );

        let mut engagement = BTreeMap::new();
        engagement.insert(
            "id".to_owned(),
            TemplateValue::String(ctx.engagement_id.to_string()),
        );
        engagement.insert(
            "name".to_owned(),
            TemplateValue::String(ctx.engagement_name.clone()),
        );

        let breakdown = &ctx.posture.scores_by_severity;
        let mut posture = BTreeMap::new();
        posture.insert(
            "total".to_owned(),
            TemplateValue::Number(f64::from(breakdown.total())),
        );
        posture.insert(
            "critical".to_owned(),
            TemplateValue::Number(f64::from(breakdown.critical)),
        );
        posture.insert(
            "high".to_owned(),
            TemplateValue::Number(f64::from(breakdown.high)),
        );
        posture.insert(
            "medium".to_owned(),
            TemplateValue::Number(f64::from(breakdown.medium)),
        );
        posture.insert(
            "low".to_owned(),
            TemplateValue::Number(f64::from(breakdown.low)),
        );
        posture.insert(
            "info".to_owned(),
            TemplateValue::Number(f64::from(breakdown.info)),
        );

        let findings: Vec<TemplateValue> = ctx
            .findings
            .iter()
            .map(|f| {
                let mut m = BTreeMap::new();
                m.insert("title".to_owned(), TemplateValue::String(f.title.clone()));
                m.insert(
                    "severity".to_owned(),
                    TemplateValue::String(f.severity.to_string()),
                );
                m.insert(
                    "asset".to_owned(),
                    TemplateValue::String(f.asset_label.clone()),
                );
                m.insert("status".to_owned(), TemplateValue::String(f.status.clone()));
                TemplateValue::Map(m)
            })
            .collect();

        let top_risks: Vec<TemplateValue> = ctx
            .posture
            .top_risks
            .iter()
            .map(|r| {
                let mut m = BTreeMap::new();
                m.insert("title".to_owned(), TemplateValue::String(r.title.clone()));
                m.insert(
                    "severity".to_owned(),
                    TemplateValue::String(r.severity.to_string()),
                );
                m.insert(
                    "cvss".to_owned(),
                    r.cvss
                        .map_or(TemplateValue::Null, |v| TemplateValue::Number(f64::from(v))),
                );
                TemplateValue::Map(m)
            })
            .collect();

        let mut branding = BTreeMap::new();
        branding.insert(
            "primary_color_hex".to_owned(),
            TemplateValue::String(ctx.branding.primary_color_hex.clone()),
        );
        branding.insert(
            "has_logo".to_owned(),
            TemplateValue::Bool(ctx.branding.logo_png.is_some()),
        );

        let mut root = BTreeMap::new();
        root.insert("tenant".to_owned(), TemplateValue::Map(tenant));
        root.insert("engagement".to_owned(), TemplateValue::Map(engagement));
        root.insert("posture".to_owned(), TemplateValue::Map(posture));
        root.insert(
            "generated_by".to_owned(),
            TemplateValue::String(ctx.generated_by.clone()),
        );
        root.insert(
            "generated_at".to_owned(),
            TemplateValue::String(ctx.generated_at.to_string()),
        );
        root.insert("findings".to_owned(), TemplateValue::List(findings));
        root.insert("top_risks".to_owned(), TemplateValue::List(top_risks));
        root.insert("branding".to_owned(), TemplateValue::Map(branding));
        Self { root }
    }

    /// Resolve a dotted path against the root, then a scope, then the
    /// current `this` value.
    fn lookup(
        &self,
        path: &str,
        scope: &[(String, TemplateValue)],
        this: Option<&TemplateValue>,
    ) -> Option<TemplateValue> {
        if path == "this" {
            return this.cloned();
        }
        // 1) Try scope from innermost outward.
        for (k, v) in scope.iter().rev() {
            if let Some(out) =
                resolve_in(v, path).or_else(|| {
                    path.split_once('.').and_then(|(head, rest)| {
                        if head == k {
                            resolve_in(v, rest)
                        } else {
                            None
                        }
                    })
                })
            {
                return Some(out);
            }
            if k == path {
                return Some(v.clone());
            }
        }
        // 2) Walk the root.
        let mut parts = path.split('.');
        let first = parts.next()?;
        let mut cursor: TemplateValue = self.root.get(first)?.clone();
        for part in parts {
            cursor = match cursor {
                TemplateValue::Map(m) => m.get(part).cloned()?,
                _ => return None,
            };
        }
        Some(cursor)
    }
}

fn resolve_in(value: &TemplateValue, path: &str) -> Option<TemplateValue> {
    let mut cursor = value.clone();
    for part in path.split('.') {
        cursor = match cursor {
            TemplateValue::Map(m) => m.get(part).cloned()?,
            _ => return None,
        };
    }
    Some(cursor)
}

/// Parsed AST node.
#[derive(Debug, Clone, PartialEq)]
enum Node {
    Text(String),
    Var(String),
    Each { path: String, body: Vec<Self> },
    If { path: String, body: Vec<Self> },
    Comment,
}

/// Compile a raw template body into AST nodes.
///
/// Internal helper used by [`ReportTemplate::new`] and
/// [`ReportTemplate::render`]. External callers should validate via
/// [`ReportTemplate::new`] which runs this pass + the model checks.
fn compile(body: &str) -> Result<Vec<Node>, ReportError> {
    let tokens = tokenise(body)?;
    let mut iter = tokens.into_iter().peekable();
    parse_block(&mut iter, None, 0)
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Text(String),
    Var(String),
    OpenEach(String),
    CloseEach,
    OpenIf(String),
    CloseIf,
    Comment,
}

fn tokenise(body: &str) -> Result<Vec<Token>, ReportError> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let here = bytes.get(i).copied();
        let next = bytes.get(i + 1).copied();
        if here == Some(b'{') && next == Some(b'{') {
            if !buf.is_empty() {
                out.push(Token::Text(std::mem::take(&mut buf)));
            }
            // Find matching `}}`.
            let rest = body
                .get(i + 2..)
                .ok_or_else(|| ReportError::invalid_context("template ended inside `{{` token"))?;
            let end = rest
                .find("}}")
                .ok_or_else(|| ReportError::invalid_context("unterminated `{{...}}` tag"))?;
            let inner = rest.get(..end).unwrap_or("").trim();
            i += 2 + end + 2;
            if let Some(rest) = inner.strip_prefix('!') {
                let _ = rest;
                out.push(Token::Comment);
            } else if let Some(rest) = inner.strip_prefix("#each ") {
                let path = rest.trim();
                validate_path(path)?;
                out.push(Token::OpenEach(path.to_owned()));
            } else if let Some(rest) = inner.strip_prefix("#if ") {
                let path = rest.trim();
                validate_path(path)?;
                out.push(Token::OpenIf(path.to_owned()));
            } else if inner == "/each" {
                out.push(Token::CloseEach);
            } else if inner == "/if" {
                out.push(Token::CloseIf);
            } else if inner.starts_with('#') || inner.starts_with('/') {
                return Err(ReportError::invalid_context(format!(
                    "unknown directive `{{{{{inner}}}}}`",
                )));
            } else {
                validate_path(inner)?;
                out.push(Token::Var(inner.to_owned()));
            }
        } else {
            // SAFETY: bytes[i] originates from a valid UTF-8 string,
            // we only step forward through char boundaries via the
            // explicit byte fetch below.
            let ch = body[i..]
                .chars()
                .next()
                .ok_or_else(|| ReportError::invalid_context("template body ended mid-character"))?;
            buf.push(ch);
            i += ch.len_utf8();
        }
    }
    if !buf.is_empty() {
        out.push(Token::Text(buf));
    }
    Ok(out)
}

fn validate_path(path: &str) -> Result<(), ReportError> {
    if path.is_empty() {
        return Err(ReportError::invalid_context("template path is empty"));
    }
    if path.len() > MAX_IDENT_LEN {
        return Err(ReportError::invalid_context(format!(
            "template path exceeds {MAX_IDENT_LEN} chars",
        )));
    }
    for part in path.split('.') {
        if part.is_empty() {
            return Err(ReportError::invalid_context(format!(
                "empty segment in path `{path}`",
            )));
        }
        for ch in part.chars() {
            if !(ch.is_ascii_alphanumeric() || ch == '_') {
                return Err(ReportError::invalid_context(format!(
                    "illegal character `{ch}` in path `{path}`",
                )));
            }
        }
    }
    Ok(())
}

fn parse_block(
    iter: &mut std::iter::Peekable<std::vec::IntoIter<Token>>,
    terminator: Option<&Token>,
    depth: usize,
) -> Result<Vec<Node>, ReportError> {
    if depth > MAX_BLOCK_DEPTH {
        return Err(ReportError::invalid_context(format!(
            "template block nesting exceeds {MAX_BLOCK_DEPTH}",
        )));
    }
    let mut nodes = Vec::new();
    while let Some(tok) = iter.next() {
        if let Some(t) = terminator {
            if t == &tok {
                return Ok(nodes);
            }
        }
        match tok {
            Token::Text(t) => nodes.push(Node::Text(t)),
            Token::Var(p) => nodes.push(Node::Var(p)),
            Token::Comment => nodes.push(Node::Comment),
            Token::OpenEach(path) => {
                let body = parse_block(iter, Some(&Token::CloseEach), depth + 1)?;
                nodes.push(Node::Each { path, body });
            }
            Token::OpenIf(path) => {
                let body = parse_block(iter, Some(&Token::CloseIf), depth + 1)?;
                nodes.push(Node::If { path, body });
            }
            Token::CloseEach => {
                return Err(ReportError::invalid_context(
                    "unexpected `{{/each}}` without matching `{{#each ...}}`",
                ));
            }
            Token::CloseIf => {
                return Err(ReportError::invalid_context(
                    "unexpected `{{/if}}` without matching `{{#if ...}}`",
                ));
            }
        }
    }
    if terminator.is_some() {
        return Err(ReportError::invalid_context(
            "template ended inside an unterminated block",
        ));
    }
    Ok(nodes)
}

fn render_nodes(
    nodes: &[Node],
    ctx: &TemplateContext,
    out: &mut String,
    depth: usize,
) -> Result<(), ReportError> {
    render_with_scope(nodes, ctx, &mut Vec::new(), None, out, depth)
}

fn render_with_scope(
    nodes: &[Node],
    ctx: &TemplateContext,
    scope: &mut Vec<(String, TemplateValue)>,
    this: Option<&TemplateValue>,
    out: &mut String,
    depth: usize,
) -> Result<(), ReportError> {
    if depth > MAX_BLOCK_DEPTH {
        return Err(ReportError::invalid_context(format!(
            "template render exceeded depth {MAX_BLOCK_DEPTH}",
        )));
    }
    for node in nodes {
        if out.len() > MAX_OUTPUT_BYTES {
            return Err(ReportError::invalid_context(format!(
                "template output exceeded {MAX_OUTPUT_BYTES} bytes",
            )));
        }
        match node {
            Node::Comment => {}
            Node::Text(t) => out.push_str(t),
            Node::Var(path) => {
                let resolved = ctx.lookup(path, scope, this);
                if let Some(v) = resolved {
                    out.push_str(&escape_xml(&v.as_scalar()));
                }
                // Missing values render as empty by design — keeps the
                // surface forgiving for optional fields.
            }
            Node::Each { path, body } => {
                let value = ctx.lookup(path, scope, this);
                let Some(TemplateValue::List(list)) = value else {
                    continue;
                };
                if list.len() > MAX_ITERATIONS_PER_LOOP {
                    return Err(ReportError::invalid_context(format!(
                        "`{{{{#each {path}}}}}` would iterate {} entries; cap is {MAX_ITERATIONS_PER_LOOP}",
                        list.len(),
                    )));
                }
                for item in list {
                    scope.push((path.clone(), item.clone()));
                    render_with_scope(body, ctx, scope, Some(&item), out, depth + 1)?;
                    scope.pop();
                }
            }
            Node::If { path, body } => {
                let cond = ctx.lookup(path, scope, this).is_some_and(|v| v.is_truthy());
                if cond {
                    render_with_scope(body, ctx, scope, this, out, depth + 1)?;
                }
            }
        }
    }
    Ok(())
}

/// Conservative XML escape (also covers HTML).
///
/// Public so the email-render adapter can apply the same projection on
/// values that bypass the engine (e.g. subject lines).
#[must_use]
pub fn escape_xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn ctx_with_items() -> TemplateContext {
        let mut item1 = BTreeMap::new();
        item1.insert(
            "title".to_owned(),
            TemplateValue::String("Finding A".to_owned()),
        );
        item1.insert(
            "severity".to_owned(),
            TemplateValue::String("high".to_owned()),
        );
        let mut item2 = BTreeMap::new();
        item2.insert(
            "title".to_owned(),
            TemplateValue::String("Finding B".to_owned()),
        );
        item2.insert(
            "severity".to_owned(),
            TemplateValue::String("low".to_owned()),
        );
        TemplateContext::new()
            .with(
                "tenant",
                TemplateValue::Map({
                    let mut m = BTreeMap::new();
                    m.insert("name".to_owned(), TemplateValue::String("Acme".to_owned()));
                    m
                }),
            )
            .with(
                "findings",
                TemplateValue::List(vec![TemplateValue::Map(item1), TemplateValue::Map(item2)]),
            )
            .with("show_summary", TemplateValue::Bool(true))
            .with("hidden", TemplateValue::Bool(false))
    }

    fn template_for(body: &str) -> ReportTemplate {
        ReportTemplate::new(
            ReportTemplateId::new(),
            TenantId::new(),
            "Test",
            TemplateSurface::PlainText,
            body,
            None,
            1,
            "ops",
            datetime!(2026-06-01 00:00:00 UTC),
        )
        .unwrap()
    }

    #[test]
    fn substitutes_scalar_path() {
        let t = template_for("Hello {{tenant.name}}!");
        assert_eq!(t.render(&ctx_with_items()).unwrap(), "Hello Acme!");
    }

    #[test]
    fn each_block_repeats_for_every_item() {
        let t = template_for("{{#each findings}}- {{title}} ({{severity}})\n{{/each}}");
        let out = t.render(&ctx_with_items()).unwrap();
        assert_eq!(out, "- Finding A (high)\n- Finding B (low)\n");
    }

    #[test]
    fn if_block_renders_only_when_truthy() {
        let t = template_for("[{{#if show_summary}}SHOW{{/if}}][{{#if hidden}}NO{{/if}}]");
        assert_eq!(t.render(&ctx_with_items()).unwrap(), "[SHOW][]");
    }

    #[test]
    fn comment_is_stripped() {
        let t = template_for("A{{! a comment }}B");
        assert_eq!(t.render(&ctx_with_items()).unwrap(), "AB");
    }

    #[test]
    fn missing_variable_renders_empty() {
        let t = template_for("[{{tenant.unknown}}]");
        assert_eq!(t.render(&ctx_with_items()).unwrap(), "[]");
    }

    #[test]
    fn xml_escapes_scalars() {
        let t = template_for("{{tenant.name}}");
        let ctx = TemplateContext::new().with(
            "tenant",
            TemplateValue::Map({
                let mut m = BTreeMap::new();
                m.insert(
                    "name".to_owned(),
                    TemplateValue::String("<script>".to_owned()),
                );
                m
            }),
        );
        let out = t.render(&ctx).unwrap();
        assert!(!out.contains("<script>"));
        assert!(out.contains("&lt;script&gt;"));
    }

    #[test]
    fn rejects_unterminated_tag() {
        let r = ReportTemplate::new(
            ReportTemplateId::new(),
            TenantId::new(),
            "t",
            TemplateSurface::PlainText,
            "Hello {{name",
            None,
            1,
            "ops",
            datetime!(2026-06-01 00:00:00 UTC),
        );
        assert!(r.is_err());
    }

    #[test]
    fn rejects_unbalanced_each() {
        let r = ReportTemplate::new(
            ReportTemplateId::new(),
            TenantId::new(),
            "t",
            TemplateSurface::PlainText,
            "{{#each items}}no close",
            None,
            1,
            "ops",
            datetime!(2026-06-01 00:00:00 UTC),
        );
        assert!(r.is_err());
    }

    #[test]
    fn rejects_unknown_directive() {
        let r = ReportTemplate::new(
            ReportTemplateId::new(),
            TenantId::new(),
            "t",
            TemplateSurface::PlainText,
            "{{#unless x}}{{/unless}}",
            None,
            1,
            "ops",
            datetime!(2026-06-01 00:00:00 UTC),
        );
        assert!(r.is_err());
    }

    #[test]
    fn rejects_illegal_identifier() {
        let r = ReportTemplate::new(
            ReportTemplateId::new(),
            TenantId::new(),
            "t",
            TemplateSurface::PlainText,
            "{{foo$bar}}",
            None,
            1,
            "ops",
            datetime!(2026-06-01 00:00:00 UTC),
        );
        assert!(r.is_err());
    }

    #[test]
    fn rejects_excessive_nesting_at_compile_time() {
        let mut body = String::new();
        for _ in 0..(MAX_BLOCK_DEPTH + 2) {
            body.push_str("{{#each findings}}");
        }
        body.push('x');
        for _ in 0..(MAX_BLOCK_DEPTH + 2) {
            body.push_str("{{/each}}");
        }
        let r = ReportTemplate::new(
            ReportTemplateId::new(),
            TenantId::new(),
            "t",
            TemplateSurface::PlainText,
            body,
            None,
            1,
            "ops",
            datetime!(2026-06-01 00:00:00 UTC),
        );
        assert!(r.is_err());
    }

    #[test]
    fn rejects_oversize_body() {
        let big = "A".repeat(MAX_TEMPLATE_BYTES + 1);
        let r = ReportTemplate::new(
            ReportTemplateId::new(),
            TenantId::new(),
            "t",
            TemplateSurface::PlainText,
            big,
            None,
            1,
            "ops",
            datetime!(2026-06-01 00:00:00 UTC),
        );
        assert!(r.is_err());
    }

    #[test]
    fn caps_iteration_count() {
        // Build a huge list and assert the engine refuses to iterate it.
        let list = TemplateValue::List(
            (0..=MAX_ITERATIONS_PER_LOOP)
                .map(|i| {
                    let as_u32 = u32::try_from(i).unwrap_or(u32::MAX);
                    TemplateValue::Number(f64::from(as_u32))
                })
                .collect(),
        );
        let ctx = TemplateContext::new().with("xs", list);
        let t = template_for("{{#each xs}}.{{/each}}");
        let r = t.render(&ctx);
        assert!(r.is_err());
    }

    #[test]
    fn from_report_exposes_expected_keys() {
        use crate::model::posture::{PostureSummary, SeverityBreakdown};
        use crate::model::report::ReportContext;
        use sx_core::value_object::ids::{EngagementId, TenantId};

        let posture = PostureSummary {
            scores_by_severity: SeverityBreakdown {
                critical: 1,
                high: 2,
                medium: 3,
                low: 4,
                info: 5,
            },
            trend_7d: vec![],
            top_risks: vec![],
        };
        let ctx = ReportContext::new(
            TenantId::new(),
            EngagementId::new(),
            "Acme",
            "Q2",
            "ops",
            datetime!(2026-06-01 00:00:00 UTC),
            posture,
            vec![],
        )
        .unwrap();
        let tctx = TemplateContext::from_report(&ctx);
        let t = template_for(
            "T={{tenant.name}};E={{engagement.name}};C={{posture.critical}};HAS={{branding.has_logo}}",
        );
        assert_eq!(t.render(&tctx).unwrap(), "T=Acme;E=Q2;C=1;HAS=false",);
    }

    /// Snapshot test (P2-002): pin the byte-exact rendered output of a
    /// header/footer template that exercises scalar substitution, an
    /// `{{#each}}` loop over findings, an `{{#if}}` branch, XML escaping,
    /// and the branding surface — every customisation knob in one
    /// fixture. Any future regression in the substitution engine breaks
    /// this string-equal assertion.
    #[test]
    fn snapshot_substituted_header_footer_output() {
        use crate::model::branding::BrandConfig;
        use crate::model::posture::{PostureSummary, SeverityBreakdown, TopRisk};
        use crate::model::report::ReportContext;
        use crate::model::report_finding::ReportFinding;
        use sx_core::value_object::cvss::CvssScore;
        use sx_core::value_object::ids::{EngagementId, FindingId, TenantId};
        use sx_core::value_object::severity::Severity;
        use uuid::Uuid;

        let posture = PostureSummary {
            scores_by_severity: SeverityBreakdown {
                critical: 1,
                high: 2,
                medium: 0,
                low: 0,
                info: 0,
            },
            trend_7d: vec![],
            top_risks: vec![TopRisk {
                finding_id: FindingId::from_uuid(Uuid::from_u128(1)),
                title: "Public S3 bucket".to_owned(),
                severity: Severity::Critical,
                cvss: Some(9.8),
            }],
        };
        let findings = vec![
            ReportFinding::new(
                FindingId::from_uuid(Uuid::from_u128(0xF1)),
                "host-a",
                Severity::Critical,
                "<script> Inject",
                "desc",
                Some(CvssScore::v3_only(9.8).unwrap()),
                "open",
                vec![],
            )
            .unwrap(),
            ReportFinding::new(
                FindingId::from_uuid(Uuid::from_u128(0xF2)),
                "host-b",
                Severity::High,
                "Stale TLS cert",
                "desc",
                Some(CvssScore::v3_only(7.5).unwrap()),
                "open",
                vec![],
            )
            .unwrap(),
        ];
        let branding = BrandConfig::new(
            None,
            "#1A2B3C",
            Some("Confidential - {{tenant.name}}".into()),
            Some("Cover for {{tenant.name}}".into()),
        )
        .unwrap();
        let ctx = ReportContext::new(
            TenantId::from_uuid(Uuid::from_u128(0xAA)),
            EngagementId::from_uuid(Uuid::from_u128(0xBB)),
            "Acme & Co",
            "Q2 Engagement",
            "ops",
            datetime!(2026-06-01 00:00:00 UTC),
            posture,
            findings,
        )
        .unwrap()
        .with_branding(branding);

        let tctx = TemplateContext::from_report(&ctx);

        // The fixture body is the precise header/footer template the API
        // will pass in. Every substitution path is covered.
        let body = "\
HEADER: {{tenant.name}} | {{engagement.name}}\n\
TOTAL={{posture.total}}, CRIT={{posture.critical}}\n\
{{#if branding.has_logo}}LOGO=yes\n{{/if}}\
COLOR={{branding.primary_color_hex}}\n\
FINDINGS:\n\
{{#each findings}}- [{{severity}}] {{title}} on {{asset}}\n{{/each}}\
TOP:\n\
{{#each top_risks}}* {{title}} ({{severity}}/{{cvss}})\n{{/each}}\
FOOTER: by {{generated_by}}";
        let t = template_for(body);

        // CVSS values originate as f32 and are widened to f64 — the
        // resulting digits intentionally pin the f32 precision so a
        // future refactor that bumps the type signals up here.
        let expected = "\
HEADER: Acme &amp; Co | Q2 Engagement\n\
TOTAL=3, CRIT=1\n\
COLOR=#1A2B3C\n\
FINDINGS:\n\
- [critical] &lt;script&gt; Inject on host-a\n\
- [high] Stale TLS cert on host-b\n\
TOP:\n\
* Public S3 bucket (critical/9.800000190734863)\n\
FOOTER: by ops";

        let actual = t.render(&tctx).unwrap();
        assert_eq!(
            actual, expected,
            "substitution snapshot drift\n--- expected ---\n{expected}\n--- actual ---\n{actual}",
        );
    }
}
