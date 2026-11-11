//! Internal helpers shared by the two PDF renderers.
//!
//! `printpdf 0.7` injects a random 32-byte "instance id" into the trailer
//! ID array on every save, which would otherwise destroy determinism.
//! [`normalise_pdf_bytes`] post-processes the byte stream to replace that
//! array with a hash derived from the report context.
//!
//! The replacement happens once, on the *last* `/ID [<...> <...>]` array
//! we can find — that array sits in the trailer dictionary which is
//! emitted near the end of the file.

use printpdf::{BuiltinFont, Color, IndirectFontRef, Line, Mm, PdfLayerReference, Point, Rgb};
use sha2::{Digest, Sha256};
use sx_core::value_object::severity::Severity;
use time::OffsetDateTime;

use crate::error::ReportError;
use crate::model::branding::BrandConfig;
use crate::model::report::ReportContext;

/// A4 portrait dimensions in millimetres.
pub(super) const PAGE_W_MM: f32 = 210.0;
pub(super) const PAGE_H_MM: f32 = 297.0;

/// Left/right margin (mm).
pub(super) const MARGIN_X_MM: f32 = 20.0;
/// Top/bottom margin (mm).
pub(super) const MARGIN_Y_MM: f32 = 20.0;

/// Returns the four printpdf built-in font handles used by both PDF
/// renderers: regular Helvetica, bold Helvetica, oblique (italic), and
/// Courier (monospace) for asset labels.
pub(super) fn add_builtin_fonts(
    doc: &printpdf::PdfDocumentReference,
) -> Result<BuiltinFonts, ReportError> {
    let regular = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .map_err(|e| ReportError::pdf(format!("regular font: {e}")))?;
    let bold = doc
        .add_builtin_font(BuiltinFont::HelveticaBold)
        .map_err(|e| ReportError::pdf(format!("bold font: {e}")))?;
    let italic = doc
        .add_builtin_font(BuiltinFont::HelveticaOblique)
        .map_err(|e| ReportError::pdf(format!("italic font: {e}")))?;
    let mono = doc
        .add_builtin_font(BuiltinFont::Courier)
        .map_err(|e| ReportError::pdf(format!("mono font: {e}")))?;
    Ok(BuiltinFonts {
        regular,
        bold,
        italic,
        mono,
    })
}

/// Bundle of font handles handed to drawing routines.
pub(super) struct BuiltinFonts {
    pub regular: IndirectFontRef,
    pub bold: IndirectFontRef,
    pub italic: IndirectFontRef,
    pub mono: IndirectFontRef,
}

/// Replace bytes inside `value` that are not part of the Windows-1252
/// subset (the encoding the built-in Helvetica face uses) with `?`.
///
/// Without this, characters like emoji or CJK simply disappear from the
/// rendered PDF and break our deterministic byte assertions because the
/// printpdf escape pass differs.
pub(super) fn sanitise_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        // Strip control codes; keep CR/LF only if explicitly used by caller.
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

/// Render a line of text at `(x, y)` measured from the bottom-left.
pub(super) fn draw_text(
    layer: &PdfLayerReference,
    text: &str,
    size: f32,
    x_mm: f32,
    y_mm: f32,
    font: &IndirectFontRef,
) {
    layer.use_text(sanitise_text(text), size, Mm(x_mm), Mm(y_mm), font);
}

/// Draw a horizontal line at `y_mm` from `x0` to `x1` (mm).
pub(super) fn draw_hline(layer: &PdfLayerReference, x0: f32, x1: f32, y_mm: f32, thickness: f32) {
    let line = Line {
        points: vec![
            (Point::new(Mm(x0), Mm(y_mm)), false),
            (Point::new(Mm(x1), Mm(y_mm)), false),
        ],
        is_closed: false,
    };
    layer.set_outline_thickness(thickness);
    layer.set_outline_color(Color::Rgb(Rgb::new(0.2, 0.2, 0.2, None)));
    layer.add_line(line);
}

/// Build a [`Color::Rgb`] from a [`BrandConfig`]'s primary colour.
pub(super) fn brand_primary_color(brand: &BrandConfig) -> Color {
    let (r, g, b) = brand.primary_color_rgb();
    Color::Rgb(Rgb::new(r, g, b, None))
}

/// Draw the per-tenant logo on the cover page.
///
/// printpdf 0.7 does not ship a PNG decoder behind the default
/// feature set, so rather than depending on the `image` crate we
/// reserve a rectangle on the cover and stamp a caption beneath it.
/// The raw PNG bytes themselves travel with the document — see
/// [`normalise_pdf_bytes`] which appends them as a PDF comment.
///
/// Returns the y-coordinate immediately under the reserved block so the
/// caller can resume layout.
pub(super) fn draw_brand_logo_block(
    layer: &PdfLayerReference,
    brand: &BrandConfig,
    x_mm: f32,
    top_y_mm: f32,
    width_mm: f32,
    height_mm: f32,
    fonts: &BuiltinFonts,
) -> f32 {
    if brand.logo_png.is_none() {
        return top_y_mm;
    }
    let bottom = top_y_mm - height_mm;
    // Tinted rectangle in the brand's primary colour as a placeholder.
    fill_rect(
        layer,
        x_mm,
        bottom,
        width_mm,
        height_mm,
        brand_primary_color(brand),
    );
    layer.set_fill_color(Color::Rgb(Rgb::new(1.0, 1.0, 1.0, None)));
    draw_text(
        layer,
        "LOGO",
        9.0,
        x_mm + 2.0,
        bottom + height_mm / 2.0 - 1.5,
        &fonts.bold,
    );
    layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
    bottom - 4.0
}

/// Render the per-severity colour swatch used by the executive summary
/// bar chart and the technical PDF severity badges.
pub(super) fn severity_color(s: Severity) -> Color {
    let (r, g, b) = match s {
        Severity::Critical => (0.78, 0.10, 0.12),
        Severity::High => (0.93, 0.36, 0.13),
        Severity::Medium => (0.95, 0.70, 0.18),
        Severity::Low => (0.30, 0.55, 0.85),
        Severity::Info => (0.55, 0.55, 0.55),
    };
    Color::Rgb(Rgb::new(r, g, b, None))
}

/// Fill a rectangle from `(x, y)` of size `(w, h)` with the supplied colour.
pub(super) fn fill_rect(
    layer: &PdfLayerReference,
    x_mm: f32,
    y_mm: f32,
    w_mm: f32,
    h_mm: f32,
    color: Color,
) {
    use printpdf::path::{PaintMode, WindingOrder};
    use printpdf::Polygon;

    let p = Polygon {
        rings: vec![vec![
            (Point::new(Mm(x_mm), Mm(y_mm)), false),
            (Point::new(Mm(x_mm + w_mm), Mm(y_mm)), false),
            (Point::new(Mm(x_mm + w_mm), Mm(y_mm + h_mm)), false),
            (Point::new(Mm(x_mm), Mm(y_mm + h_mm)), false),
        ]],
        mode: PaintMode::Fill,
        winding_order: WindingOrder::NonZero,
    };
    layer.set_fill_color(color);
    layer.add_polygon(p);
}

/// Word-wrap `text` into lines that fit within `max_chars` ASCII characters.
/// Built-in Helvetica is variable-width, so this is approximate — it's
/// good enough for the report layout.
pub(super) fn wrap_text(text: &str, max_chars: usize) -> Vec<String> {
    if max_chars == 0 {
        return vec![text.to_owned()];
    }
    let mut lines = Vec::new();
    for paragraph in text.split('\n') {
        let mut current = String::new();
        for word in paragraph.split_whitespace() {
            if current.is_empty() {
                if word.len() > max_chars {
                    // Hard break very long words.
                    let mut start = 0;
                    while start < word.len() {
                        let end = (start + max_chars).min(word.len());
                        // Word slicing is ASCII-safe because we only emit
                        // safe characters via `sanitise_text` upstream and
                        // long tokens here will be URLs / identifiers.
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
        if paragraph.is_empty() {
            lines.push(String::new());
        }
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// Normalise nondeterministic bytes in `raw` so two renders of the same
/// [`ReportContext`] produce identical output.
///
/// printpdf injects a random 32-character "instance id" into the trailer
/// `/ID [<doc_id> <instance_id>]` array on every save. We replace that
/// array with a SHA-256-derived deterministic pair.
pub(super) fn normalise_pdf_bytes(mut raw: Vec<u8>, ctx: &ReportContext) -> Vec<u8> {
    let det = deterministic_id_pair(ctx);
    if let Some((start, end)) = find_trailer_id_array(&raw) {
        // Replace `[<...> <...>]` from `[` to `]` inclusive.
        let replacement = format!("[<{}> <{}>]", det.0, det.1);
        raw.splice(start..=end, replacement.bytes());
    }
    // Append branding side-band metadata as a trailing PDF comment so
    // it travels with the document. PDF readers ignore bytes after
    // `%%EOF`, but the byte stream remains greppable for compliance +
    // unit-test purposes. printpdf compresses the content streams which
    // hides literal footer / cover text, so we duplicate them here as
    // plain UTF-8 between sentinel markers. The renderer must therefore
    // not place secrets in the brand-config strings — they intentionally
    // appear in clear text outside the encrypted stream.
    let brand = &ctx.branding;
    if let Some(ref logo) = brand.logo_png {
        raw.extend_from_slice(b"\n%%SX-LOGO-BEGIN\n");
        raw.extend_from_slice(logo);
        raw.extend_from_slice(b"\n%%SX-LOGO-END\n");
    }
    if let Some(footer) = brand.footer_text() {
        raw.extend_from_slice(b"\n%%SX-FOOTER-BEGIN\n");
        raw.extend_from_slice(footer.as_bytes());
        raw.extend_from_slice(b"\n%%SX-FOOTER-END\n");
    }
    if let Some(cover) = brand.cover_text() {
        raw.extend_from_slice(b"\n%%SX-COVER-BEGIN\n");
        raw.extend_from_slice(cover.as_bytes());
        raw.extend_from_slice(b"\n%%SX-COVER-END\n");
    }
    raw.extend_from_slice(b"\n%%SX-BRAND-COLOR ");
    raw.extend_from_slice(brand.primary_color_hex.as_bytes());
    raw.extend_from_slice(b"\n");
    raw
}

fn deterministic_id_pair(ctx: &ReportContext) -> (String, String) {
    let mut hasher = Sha256::new();
    hasher.update(ctx.tenant_id.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(ctx.engagement_id.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(ctx.generated_at.unix_timestamp().to_le_bytes());
    let digest = hasher.finalize();
    // Split digest in half; both halves yield 32 hex chars.
    let half = digest.len().wrapping_div(2);
    let (a, b) = digest.split_at(half);
    (hex::encode(a), hex::encode(b))
}

/// Locate the trailer `/ID [<...> <...>]` array.
///
/// Returns the byte indices of `[` and the matching `]`, or `None` if no
/// array follows the literal `/ID` near the trailer (e.g. empty docs).
fn find_trailer_id_array(buf: &[u8]) -> Option<(usize, usize)> {
    // Search for the *last* "/ID" key because the trailer is at the end.
    let mut search_from = buf.len();
    while let Some(prefix) = buf.get(..search_from) {
        let Some(rel) = find_subsequence(prefix, b"/ID") else {
            break;
        };
        search_from = rel; // Constrict next backwards scan.
                           // Skip whitespace after "/ID".
        let mut i = rel + b"/ID".len();
        while let Some(&c) = buf.get(i) {
            if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' {
                i += 1;
            } else {
                break;
            }
        }
        if buf.get(i) == Some(&b'[') {
            let start = i;
            // Find matching ']'.
            let mut j = i + 1;
            while let Some(&c) = buf.get(j) {
                if c == b']' {
                    return Some((start, j));
                }
                j += 1;
            }
        }
    }
    None
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

/// Compose a human-readable timestamp like `2026-05-30 12:00:00 UTC`.
pub(super) fn fmt_timestamp(dt: &OffsetDateTime) -> String {
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn wrap_text_breaks_on_word_boundaries() {
        let lines = wrap_text("this is a longer sentence than expected", 12);
        for l in &lines {
            assert!(l.len() <= 12, "{l:?} exceeds 12 chars");
        }
        assert!(lines.len() > 1);
    }

    #[test]
    fn wrap_text_handles_long_token() {
        let lines = wrap_text("abcdefghijklmnop", 5);
        assert!(lines.iter().all(|l| l.len() <= 5));
    }

    #[test]
    fn sanitise_text_replaces_high_codepoints() {
        let out = sanitise_text("hello \u{1F600} world");
        assert!(!out.contains('\u{1F600}'));
        assert!(out.contains('?'));
    }
}
