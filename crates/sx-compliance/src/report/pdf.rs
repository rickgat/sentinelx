//! Markdown → PDF renderer for compliance framework documents.
//!
//! Entry point: [`render_pci_dss`].
//!
//! Pipeline:
//!
//! 1. Read the source markdown via [`std::fs::read_to_string`].
//! 2. Parse it with [`pulldown_cmark::Parser`].
//! 3. Walk the event stream and emit text blocks via `printpdf`:
//!    - `H1` → 24pt bold
//!    - `H2` → 18pt bold
//!    - `H3` → 14pt bold
//!    - body → 11pt regular
//!    - tables → bordered cells drawn with `printpdf::Line`.
//! 4. Prepend a cover page with the document title, framework name, a
//!    "Generated at <now>" line, and the maintainer.
//! 5. Add a right-aligned page-number footer to every page.
//!
//! The output is pure PDF 1.4 bytes; no external system dependencies
//! beyond the workspace `printpdf`/`pulldown-cmark` crates.

use std::fmt;
use std::path::{Path, PathBuf};

use printpdf::{
    BuiltinFont, Color, IndirectFontRef, Line, Mm, PdfDocument, PdfDocumentReference,
    PdfLayerReference, Point, Rgb,
};
use pulldown_cmark::{Event, HeadingLevel, Parser, Tag, TagEnd};
use thiserror::Error;
use time::OffsetDateTime;

/// All errors produced by the compliance PDF renderer.
#[derive(Debug, Error)]
pub enum ReportError {
    /// Reading the markdown source from disk failed.
    #[error("read markdown {path}: {source}")]
    ReadSource {
        /// Source path that we attempted to read.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Writing the PDF bytes to the destination path failed.
    #[error("write pdf {path}: {source}")]
    WriteOutput {
        /// Destination path that we attempted to write to.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The `printpdf` engine returned an error during font registration
    /// or serialisation.
    #[error("pdf engine: {0}")]
    Pdf(String),

    /// An invariant in the renderer was violated. Treat as a bug.
    #[error("internal: {0}")]
    Internal(String),
}

impl ReportError {
    /// Convenience constructor for [`ReportError::Pdf`].
    #[must_use]
    pub fn pdf(msg: impl Into<String>) -> Self {
        Self::Pdf(msg.into())
    }

    /// Convenience constructor for [`ReportError::Internal`].
    #[must_use]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Render the PCI DSS markdown mapping at `source_md_path` to a PDF at
/// `out_pdf_path`. Includes a cover page citing `maintainer` and a
/// `Generated at` timestamp.
///
/// # Errors
///
/// Returns [`ReportError::ReadSource`] if the markdown file cannot be
/// read, [`ReportError::Pdf`] if `printpdf` fails to allocate fonts /
/// serialise the document, and [`ReportError::WriteOutput`] if the
/// produced PDF cannot be written to disk.
pub fn render_pci_dss(
    source_md_path: &Path,
    out_pdf_path: &Path,
    maintainer: &str,
) -> Result<(), ReportError> {
    let markdown =
        std::fs::read_to_string(source_md_path).map_err(|e| ReportError::ReadSource {
            path: source_md_path.to_path_buf(),
            source: e,
        })?;
    let bytes = render_to_bytes(&markdown, "PCI DSS v4.0", maintainer)?;
    std::fs::write(out_pdf_path, bytes).map_err(|e| ReportError::WriteOutput {
        path: out_pdf_path.to_path_buf(),
        source: e,
    })
}

/// Render markdown directly to PDF bytes without touching the filesystem.
///
/// Exposed for tests and downstream callers that want to stream PDF
/// bytes (e.g. HTTP responses) without the read/write detour.
///
/// # Errors
///
/// Propagates any [`ReportError::Pdf`] surfaced by the underlying engine.
pub fn render_to_bytes(
    markdown: &str,
    framework_label: &str,
    maintainer: &str,
) -> Result<Vec<u8>, ReportError> {
    let now = OffsetDateTime::now_utc();
    render_to_bytes_at(markdown, framework_label, maintainer, now)
}

/// Variant of [`render_to_bytes`] with an explicit "generated at"
/// timestamp; used by tests to assert deterministic output.
///
/// # Errors
///
/// Propagates any [`ReportError::Pdf`] surfaced by the underlying engine.
pub fn render_to_bytes_at(
    markdown: &str,
    framework_label: &str,
    maintainer: &str,
    generated_at: OffsetDateTime,
) -> Result<Vec<u8>, ReportError> {
    let (doc, cover_page_idx, cover_layer_idx) = PdfDocument::new(
        "SentinelX Compliance Report",
        Mm(PAGE_W_MM),
        Mm(PAGE_H_MM),
        "cover",
    );
    let fonts = add_fonts(&doc)?;

    // Cover page.
    {
        let layer = doc.get_page(cover_page_idx).get_layer(cover_layer_idx);
        draw_cover(&layer, &fonts, framework_label, maintainer, generated_at);
    }

    // Body pages.
    let mut state = RenderState::new(&doc, &fonts);
    let parser = Parser::new(markdown);
    state.walk(parser);
    // Make sure any in-progress paragraph / table is flushed.
    state.finalise();

    // Footer (page numbers) — printpdf does not expose a way to query
    // the live page list, so we keep a record of every page we touched
    // (cover + body) and write the footer at the end.
    let mut pages = vec![cover_page_idx];
    pages.extend(state.body_pages.iter().copied());
    let total = pages.len();
    for (i, page) in pages.into_iter().enumerate() {
        let layer = doc.get_page(page).get_layer(cover_layer_idx);
        draw_footer(&layer, &fonts, i + 1, total);
    }

    let raw = doc
        .save_to_bytes()
        .map_err(|e| ReportError::pdf(e.to_string()))?;
    Ok(promote_pdf_version_to_1_4(raw))
}

/// `printpdf 0.7` hard-codes the underlying `lopdf` document at PDF 1.3.
/// Our compliance deliverable is contractually PDF 1.4, and the upgrade
/// is purely additive in the wire format (the 1.4 header is byte-for-byte
/// the same length as 1.3). Patch the leading `%PDF-1.3` signature in
/// place; any other occurrence later in the stream (in comments etc.) is
/// left untouched.
fn promote_pdf_version_to_1_4(mut raw: Vec<u8>) -> Vec<u8> {
    const FROM: &[u8] = b"%PDF-1.3";
    const TO: &[u8] = b"%PDF-1.4";
    if raw.get(..FROM.len()) == Some(FROM) {
        if let Some(prefix) = raw.get_mut(..FROM.len()) {
            prefix.copy_from_slice(TO);
        }
    }
    raw
}

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

/// A4 portrait dimensions in millimetres.
const PAGE_W_MM: f32 = 210.0;
const PAGE_H_MM: f32 = 297.0;

const MARGIN_X_MM: f32 = 18.0;
const MARGIN_TOP_MM: f32 = 18.0;
const MARGIN_BOTTOM_MM: f32 = 22.0;

const H1_PT: f32 = 24.0;
const H2_PT: f32 = 18.0;
const H3_PT: f32 = 14.0;
const H4_PT: f32 = 12.0;
const BODY_PT: f32 = 11.0;
const FOOTER_PT: f32 = 9.0;

// Line spacing factor (multiplied by font size in pt → mm-ish).
// printpdf measures in mm; 1pt = 0.3528 mm. We pick a simple multiplier
// for legibility rather than a perfectly typographic computation.
const LINE_HEIGHT_FACTOR: f32 = 0.55;

const TABLE_ROW_HEIGHT_MM: f32 = 6.0;
const TABLE_CELL_PADDING_MM: f32 = 1.5;
const TABLE_BORDER_THICKNESS_PT: f32 = 0.5;

// Approx character width for built-in Helvetica at body size; used by
// the word-wrap helper. We err on the small side to avoid overflow.
const BODY_CHAR_WIDTH_MM: f32 = 1.9;

/// Maximum character count per body line after wrapping. Saturates to a
/// safe non-zero `usize` so the wrap helper never divides by zero.
fn body_max_chars() -> usize {
    let usable = 2.0_f32.mul_add(-MARGIN_X_MM, PAGE_W_MM);
    let chars_f = (usable / BODY_CHAR_WIDTH_MM).floor();
    let bounded = chars_f.clamp(1.0, 1024.0);
    // Clamped to [1, 1024]; the float→usize cast cannot lose precision.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let v = bounded as usize;
    v
}

// ---------------------------------------------------------------------------
// Font bundle
// ---------------------------------------------------------------------------

struct Fonts {
    regular: IndirectFontRef,
    bold: IndirectFontRef,
}

fn add_fonts(doc: &PdfDocumentReference) -> Result<Fonts, ReportError> {
    let regular = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .map_err(|e| ReportError::pdf(format!("regular font: {e}")))?;
    let bold = doc
        .add_builtin_font(BuiltinFont::HelveticaBold)
        .map_err(|e| ReportError::pdf(format!("bold font: {e}")))?;
    Ok(Fonts { regular, bold })
}

// ---------------------------------------------------------------------------
// Cover page
// ---------------------------------------------------------------------------

fn draw_cover(
    layer: &PdfLayerReference,
    fonts: &Fonts,
    framework_label: &str,
    maintainer: &str,
    generated_at: OffsetDateTime,
) {
    // Title centred horizontally near the top third.
    let title = "SentinelX Compliance Report";
    let title_y = PAGE_H_MM - 80.0;
    draw_centered(layer, title, H1_PT, title_y, &fonts.bold);

    // Framework subtitle.
    let subtitle = format!("Framework: {framework_label}");
    draw_centered(layer, &subtitle, H2_PT, title_y - 14.0, &fonts.regular);

    // Generated at.
    let when = format!("Generated at {}", fmt_timestamp(generated_at));
    draw_centered(layer, &when, BODY_PT, title_y - 30.0, &fonts.regular);

    // Maintainer.
    let m = format!("Maintainer: {maintainer}");
    draw_centered(layer, &m, BODY_PT, title_y - 38.0, &fonts.regular);
}

// ---------------------------------------------------------------------------
// Body rendering — event walker
// ---------------------------------------------------------------------------

/// Header kinds we recognise from `pulldown-cmark`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeadingKind {
    H1,
    H2,
    H3,
    H4OrLower,
}

impl HeadingKind {
    const fn from(level: HeadingLevel) -> Self {
        match level {
            HeadingLevel::H1 => Self::H1,
            HeadingLevel::H2 => Self::H2,
            HeadingLevel::H3 => Self::H3,
            HeadingLevel::H4 | HeadingLevel::H5 | HeadingLevel::H6 => Self::H4OrLower,
        }
    }

    const fn font_size(self) -> f32 {
        match self {
            Self::H1 => H1_PT,
            Self::H2 => H2_PT,
            Self::H3 => H3_PT,
            Self::H4OrLower => H4_PT,
        }
    }
}

impl fmt::Display for HeadingKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::H1 => f.write_str("h1"),
            Self::H2 => f.write_str("h2"),
            Self::H3 => f.write_str("h3"),
            Self::H4OrLower => f.write_str("h4+"),
        }
    }
}

/// What we are currently accumulating text into.
#[derive(Debug, Clone, Copy)]
enum TextMode {
    Paragraph,
    Heading(HeadingKind),
    ListItem,
    CodeBlock,
}

struct RenderState<'a> {
    doc: &'a PdfDocumentReference,
    fonts: &'a Fonts,
    body_pages: Vec<printpdf::PdfPageIndex>,
    current_page: printpdf::PdfPageIndex,
    current_layer: printpdf::PdfLayerIndex,
    cursor_y_mm: f32,
    // Text accumulation.
    buf: String,
    mode: Option<TextMode>,
    // Table accumulation.
    table_rows: Vec<Vec<String>>,
    current_row: Vec<String>,
    in_table: bool,
    in_table_cell: bool,
}

impl<'a> RenderState<'a> {
    fn new(doc: &'a PdfDocumentReference, fonts: &'a Fonts) -> Self {
        let (page, layer) = doc.add_page(Mm(PAGE_W_MM), Mm(PAGE_H_MM), "body");
        Self {
            doc,
            fonts,
            body_pages: vec![page],
            current_page: page,
            current_layer: layer,
            cursor_y_mm: PAGE_H_MM - MARGIN_TOP_MM,
            buf: String::new(),
            mode: None,
            table_rows: Vec::new(),
            current_row: Vec::new(),
            in_table: false,
            in_table_cell: false,
        }
    }

    fn layer(&self) -> PdfLayerReference {
        self.doc
            .get_page(self.current_page)
            .get_layer(self.current_layer)
    }

    fn ensure_space(&mut self, needed_mm: f32) {
        if self.cursor_y_mm - needed_mm < MARGIN_BOTTOM_MM {
            self.new_page();
        }
    }

    fn new_page(&mut self) {
        let (page, layer) = self.doc.add_page(Mm(PAGE_W_MM), Mm(PAGE_H_MM), "body");
        self.body_pages.push(page);
        self.current_page = page;
        self.current_layer = layer;
        self.cursor_y_mm = PAGE_H_MM - MARGIN_TOP_MM;
    }

    fn walk(&mut self, parser: Parser<'_>) {
        for event in parser {
            self.handle_event(event);
        }
    }

    #[allow(clippy::too_many_lines)]
    fn handle_event(&mut self, event: Event<'_>) {
        match event {
            Event::Start(Tag::Heading { level, .. }) => {
                self.mode = Some(TextMode::Heading(HeadingKind::from(level)));
                self.buf.clear();
            }
            Event::Start(Tag::Paragraph) => {
                self.mode = Some(TextMode::Paragraph);
                self.buf.clear();
            }
            Event::Start(Tag::Item) => {
                self.mode = Some(TextMode::ListItem);
                self.buf.clear();
                self.buf.push_str("- ");
            }
            Event::Start(Tag::CodeBlock(_)) => {
                self.mode = Some(TextMode::CodeBlock);
                self.buf.clear();
            }
            Event::End(
                TagEnd::Heading(_) | TagEnd::Paragraph | TagEnd::Item | TagEnd::CodeBlock,
            ) => {
                self.flush_text_block();
            }
            Event::Start(Tag::List(_)) | Event::End(TagEnd::List(_)) => {
                // Visual breathing room around lists.
                self.cursor_y_mm -= 1.0;
            }
            Event::Start(Tag::Table(_)) => {
                self.in_table = true;
                self.table_rows.clear();
                self.current_row.clear();
            }
            Event::End(TagEnd::Table) => {
                self.in_table = false;
                self.flush_table();
            }
            Event::Start(Tag::TableHead | Tag::TableRow) => {
                self.current_row.clear();
            }
            Event::End(TagEnd::TableHead | TagEnd::TableRow) => {
                if !self.current_row.is_empty() {
                    self.table_rows.push(std::mem::take(&mut self.current_row));
                }
            }
            Event::Start(Tag::TableCell) => {
                self.in_table_cell = true;
                self.buf.clear();
            }
            Event::End(TagEnd::TableCell) => {
                self.in_table_cell = false;
                self.current_row.push(std::mem::take(&mut self.buf));
            }
            Event::Text(t) | Event::Code(t) => {
                self.buf.push_str(&t);
            }
            Event::SoftBreak | Event::HardBreak => {
                if !self.buf.is_empty() && !self.buf.ends_with(' ') {
                    self.buf.push(' ');
                }
            }
            Event::Rule => {
                self.ensure_space(4.0);
                let layer = self.layer();
                draw_hline(
                    &layer,
                    MARGIN_X_MM,
                    PAGE_W_MM - MARGIN_X_MM,
                    self.cursor_y_mm,
                    0.5,
                );
                self.cursor_y_mm -= 3.0;
            }
            // Inline emphasis and other events are not styled separately
            // — their inner text events still fire and get captured by
            // the buffer above.
            _ => {}
        }
    }

    fn flush_text_block(&mut self) {
        if self.in_table || self.in_table_cell {
            // Inside table: text is accumulated into cells, not flushed
            // as a free-standing block.
            return;
        }
        let Some(mode) = self.mode.take() else {
            return;
        };
        let text = std::mem::take(&mut self.buf);
        let text = text.trim();
        if text.is_empty() {
            return;
        }
        match mode {
            TextMode::Heading(kind) => self.render_heading(kind, text),
            TextMode::Paragraph | TextMode::ListItem => self.render_body(text),
            TextMode::CodeBlock => self.render_code_block(text),
        }
    }

    fn render_heading(&mut self, kind: HeadingKind, text: &str) {
        let size_pt = kind.font_size();
        let line_h = line_height_mm(size_pt);
        // Top margin before headings.
        let top_pad = match kind {
            HeadingKind::H1 => 6.0,
            HeadingKind::H2 => 4.0,
            HeadingKind::H3 | HeadingKind::H4OrLower => 2.5,
        };
        self.ensure_space(line_h + top_pad);
        self.cursor_y_mm -= top_pad;
        let layer = self.layer();
        draw_text(
            &layer,
            text,
            size_pt,
            MARGIN_X_MM,
            self.cursor_y_mm,
            &self.fonts.bold,
        );
        self.cursor_y_mm -= line_h;
    }

    fn render_body(&mut self, text: &str) {
        let max_chars = body_max_chars();
        let lines = wrap_text(text, max_chars);
        let line_h = line_height_mm(BODY_PT);
        for line in lines {
            self.ensure_space(line_h);
            let layer = self.layer();
            draw_text(
                &layer,
                &line,
                BODY_PT,
                MARGIN_X_MM,
                self.cursor_y_mm,
                &self.fonts.regular,
            );
            self.cursor_y_mm -= line_h;
        }
        // Paragraph spacing.
        self.cursor_y_mm -= 1.5;
    }

    fn render_code_block(&mut self, text: &str) {
        let line_h = line_height_mm(BODY_PT);
        for raw_line in text.lines() {
            self.ensure_space(line_h);
            let layer = self.layer();
            // Indent code blocks slightly.
            draw_text(
                &layer,
                raw_line,
                BODY_PT,
                MARGIN_X_MM + 3.0,
                self.cursor_y_mm,
                &self.fonts.regular,
            );
            self.cursor_y_mm -= line_h;
        }
        self.cursor_y_mm -= 1.5;
    }

    fn flush_table(&mut self) {
        let rows = std::mem::take(&mut self.table_rows);
        if rows.is_empty() {
            return;
        }
        let col_count = rows.iter().map(Vec::len).max().unwrap_or(0);
        if col_count == 0 {
            return;
        }
        let usable_w = 2.0_f32.mul_add(-MARGIN_X_MM, PAGE_W_MM);
        // Floats produced by simple arithmetic on small ints; safe to cast.
        #[allow(clippy::cast_precision_loss)]
        let col_w = usable_w / col_count as f32;

        for (row_idx, row) in rows.iter().enumerate() {
            self.ensure_space(TABLE_ROW_HEIGHT_MM);
            let layer = self.layer();
            let y_top = self.cursor_y_mm;
            let y_bot = y_top - TABLE_ROW_HEIGHT_MM;
            // Cell borders + text.
            for c in 0..col_count {
                #[allow(clippy::cast_precision_loss)]
                let x0 = (c as f32).mul_add(col_w, MARGIN_X_MM);
                draw_rect_outline(
                    &layer,
                    x0,
                    y_bot,
                    col_w,
                    TABLE_ROW_HEIGHT_MM,
                    TABLE_BORDER_THICKNESS_PT,
                );
                let cell_text = row.get(c).map_or("", String::as_str);
                let truncated = truncate_for_cell(cell_text, col_w);
                let font = if row_idx == 0 {
                    &self.fonts.bold
                } else {
                    &self.fonts.regular
                };
                draw_text(
                    &layer,
                    &truncated,
                    BODY_PT - 1.0,
                    x0 + TABLE_CELL_PADDING_MM,
                    y_bot + TABLE_CELL_PADDING_MM,
                    font,
                );
            }
            self.cursor_y_mm = y_bot;
        }
        // Padding after table.
        self.cursor_y_mm -= 2.0;
    }

    fn finalise(&mut self) {
        if self.mode.is_some() && !self.buf.is_empty() {
            self.flush_text_block();
        }
        if !self.table_rows.is_empty() {
            self.flush_table();
        }
    }
}

// ---------------------------------------------------------------------------
// Drawing primitives
// ---------------------------------------------------------------------------

fn draw_text(
    layer: &PdfLayerReference,
    text: &str,
    size_pt: f32,
    x_mm: f32,
    y_mm: f32,
    font: &IndirectFontRef,
) {
    layer.use_text(sanitise_text(text), size_pt, Mm(x_mm), Mm(y_mm), font);
}

fn draw_centered(
    layer: &PdfLayerReference,
    text: &str,
    size_pt: f32,
    y_mm: f32,
    font: &IndirectFontRef,
) {
    // Approximate character width — built-in Helvetica is variable
    // width; for cover-page centring this is "close enough".
    let char_w_mm = size_pt * 0.25;
    #[allow(clippy::cast_precision_loss)]
    let text_w_mm = (text.chars().count() as f32) * char_w_mm;
    let x = (PAGE_W_MM - text_w_mm) * 0.5;
    layer.use_text(sanitise_text(text), size_pt, Mm(x.max(0.0)), Mm(y_mm), font);
}

fn draw_hline(layer: &PdfLayerReference, x0: f32, x1: f32, y_mm: f32, thickness_pt: f32) {
    let line = Line {
        points: vec![
            (Point::new(Mm(x0), Mm(y_mm)), false),
            (Point::new(Mm(x1), Mm(y_mm)), false),
        ],
        is_closed: false,
    };
    layer.set_outline_thickness(thickness_pt);
    layer.set_outline_color(Color::Rgb(Rgb::new(0.2, 0.2, 0.2, None)));
    layer.add_line(line);
}

fn draw_rect_outline(
    layer: &PdfLayerReference,
    x_mm: f32,
    y_mm: f32,
    w_mm: f32,
    h_mm: f32,
    thickness_pt: f32,
) {
    let line = Line {
        points: vec![
            (Point::new(Mm(x_mm), Mm(y_mm)), false),
            (Point::new(Mm(x_mm + w_mm), Mm(y_mm)), false),
            (Point::new(Mm(x_mm + w_mm), Mm(y_mm + h_mm)), false),
            (Point::new(Mm(x_mm), Mm(y_mm + h_mm)), false),
        ],
        is_closed: true,
    };
    layer.set_outline_thickness(thickness_pt);
    layer.set_outline_color(Color::Rgb(Rgb::new(0.3, 0.3, 0.3, None)));
    layer.add_line(line);
}

fn draw_footer(layer: &PdfLayerReference, fonts: &Fonts, page_no: usize, total: usize) {
    let label = format!("Page {page_no} of {total}");
    // Right-align: approximate text width.
    let char_w_mm = FOOTER_PT * 0.22;
    #[allow(clippy::cast_precision_loss)]
    let text_w_mm = (label.chars().count() as f32) * char_w_mm;
    let x = PAGE_W_MM - MARGIN_X_MM - text_w_mm;
    let y = MARGIN_BOTTOM_MM * 0.5;
    draw_text(
        layer,
        &label,
        FOOTER_PT,
        x.max(MARGIN_X_MM),
        y,
        &fonts.regular,
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Drop characters outside the Windows-1252 range; built-in Helvetica
/// cannot encode them and printpdf will silently corrupt strings.
fn sanitise_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        let code = ch as u32;
        if code < 0x20 && ch != '\n' && ch != '\t' {
            out.push(' ');
        } else if code > 0x00FF {
            out.push('?');
        } else {
            out.push(ch);
        }
    }
    out
}

fn line_height_mm(size_pt: f32) -> f32 {
    size_pt * LINE_HEIGHT_FACTOR
}

fn wrap_text(text: &str, max_chars: usize) -> Vec<String> {
    if max_chars == 0 {
        return vec![text.to_owned()];
    }
    let mut lines = Vec::new();
    for paragraph in text.split('\n') {
        let mut current = String::new();
        for word in paragraph.split_whitespace() {
            if current.is_empty() {
                if word.len() > max_chars {
                    let mut start = 0;
                    while start < word.len() {
                        let end = (start + max_chars).min(word.len());
                        if let Some(seg) = word.get(start..end) {
                            lines.push(seg.to_owned());
                        }
                        start = end;
                    }
                } else {
                    current.push_str(word);
                }
            } else if current.len() + 1 + word.len() <= max_chars {
                current.push(' ');
                current.push_str(word);
            } else {
                lines.push(std::mem::take(&mut current));
                current.push_str(word);
            }
        }
        if !current.is_empty() {
            lines.push(current);
        }
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// Truncate `text` with an ellipsis if it would not fit into a cell of
/// width `col_w_mm` at the table body font size.
fn truncate_for_cell(text: &str, col_w_mm: f32) -> String {
    let char_w = (BODY_PT - 1.0) * 0.22;
    if char_w <= 0.0 {
        return text.to_owned();
    }
    let avail = 2.0_f32.mul_add(-TABLE_CELL_PADDING_MM, col_w_mm) / char_w;
    let max_chars_f = avail.floor();
    if !max_chars_f.is_finite() || max_chars_f <= 0.0 {
        return String::new();
    }
    let bounded = max_chars_f.clamp(0.0, 4096.0);
    // Clamped to [0, 4096]; the float→usize cast cannot lose precision.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let max_chars_us = bounded as usize;
    if text.chars().count() <= max_chars_us {
        return text.to_owned();
    }
    let cut = max_chars_us.saturating_sub(1);
    let mut out: String = text.chars().take(cut).collect();
    if !out.is_empty() {
        out.push('.');
    }
    out
}

fn fmt_timestamp(dt: OffsetDateTime) -> String {
    let utc = dt.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second(),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn fixed_now() -> OffsetDateTime {
        datetime!(2026-05-30 12:00:00 UTC)
    }

    #[test]
    fn renders_non_empty_pdf_bytes() {
        let md = "# Title\n\nA paragraph.\n";
        let bytes = render_to_bytes_at(md, "PCI DSS v4.0", "Compliance Office", fixed_now())
            .expect("render");
        assert!(!bytes.is_empty(), "PDF byte buffer must not be empty");
        assert!(
            bytes.len() > 200,
            "PDF must contain at least the header + xref"
        );
    }

    #[test]
    fn pdf_starts_with_pdf_1_4_signature() {
        let md = "# H1\n";
        let bytes =
            render_to_bytes_at(md, "PCI DSS v4.0", "Compliance Office", fixed_now()).unwrap();
        let header = bytes.get(..8).unwrap_or(&[]);
        assert_eq!(
            header,
            b"%PDF-1.4",
            "PDF must start with %PDF-1.4 signature; got {:?}",
            std::str::from_utf8(header).unwrap_or("<non-utf8>")
        );
    }

    #[test]
    fn empty_markdown_still_produces_valid_pdf() {
        let bytes =
            render_to_bytes_at("", "PCI DSS v4.0", "Compliance Office", fixed_now()).unwrap();
        assert!(!bytes.is_empty());
        let header = bytes.get(..8).unwrap_or(&[]);
        assert_eq!(header, b"%PDF-1.4");
        // EOF marker should be present.
        let tail = bytes.get(bytes.len().saturating_sub(32)..).unwrap_or(&[]);
        let tail_str = String::from_utf8_lossy(tail);
        assert!(
            tail_str.contains("%%EOF"),
            "expected %%EOF trailer marker, got: {tail_str:?}"
        );
    }

    #[test]
    fn table_rendering_does_not_panic_on_empty_cells() {
        let md = "\
| A | B | C |
|---|---|---|
|   |   |   |
| x |   | z |
";
        let bytes =
            render_to_bytes_at(md, "PCI DSS v4.0", "Compliance Office", fixed_now()).unwrap();
        assert!(!bytes.is_empty());
        assert_eq!(bytes.get(..8).unwrap_or(&[]), b"%PDF-1.4");
    }

    #[test]
    fn heading_font_size_mapping_is_correct() {
        // Probe the const mapping directly — the renderer relies on these
        // values for body layout. Asserting them here guards against
        // accidental changes to the spec.
        assert!((HeadingKind::H1.font_size() - 24.0).abs() < f32::EPSILON);
        assert!((HeadingKind::H2.font_size() - 18.0).abs() < f32::EPSILON);
        assert!((HeadingKind::H3.font_size() - 14.0).abs() < f32::EPSILON);
        // Body and footer fall outside the heading enum but are still
        // load-bearing constants.
        assert!((BODY_PT - 11.0).abs() < f32::EPSILON);

        // And the document still renders.
        let md = "# H1\n## H2\n### H3\n\nbody\n";
        let bytes =
            render_to_bytes_at(md, "PCI DSS v4.0", "Compliance Office", fixed_now()).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn render_pci_dss_writes_file_to_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src.md");
        let out = tmp.path().join("out.pdf");
        std::fs::write(
            &src,
            "# PCI DSS Report\n\nIntro paragraph.\n\n| col |\n|---|\n| v |\n",
        )
        .unwrap();
        render_pci_dss(&src, &out, "Compliance Office").unwrap();
        let bytes = std::fs::read(&out).unwrap();
        assert!(!bytes.is_empty());
        assert_eq!(bytes.get(..8).unwrap_or(&[]), b"%PDF-1.4");
    }

    #[test]
    fn read_source_error_when_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does_not_exist.md");
        let out = tmp.path().join("out.pdf");
        let err = render_pci_dss(&missing, &out, "x").unwrap_err();
        match err {
            ReportError::ReadSource { path, .. } => assert_eq!(path, missing),
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn sanitise_text_replaces_high_codepoints() {
        let s = sanitise_text("hello \u{1F600}");
        assert!(!s.contains('\u{1F600}'));
        assert!(s.contains('?'));
    }

    #[test]
    fn wrap_text_breaks_on_word_boundaries() {
        let lines = wrap_text("alpha beta gamma delta", 11);
        for l in &lines {
            assert!(l.len() <= 11, "{l:?} too long");
        }
        assert!(lines.len() >= 2);
    }

    #[test]
    fn fmt_timestamp_is_iso_like() {
        let s = fmt_timestamp(fixed_now());
        assert_eq!(s, "2026-05-30 12:00:00 UTC");
    }
}
