//! Per-tenant report branding (P2-002).
//!
//! Holds the four customisation knobs every report renderer respects:
//!
//! - `logo_png`   — uploaded PNG bytes (max 200 KB enforced at controller
//!   and adapter layers). When present, the PDF cover page embeds the
//!   bytes verbatim as an embedded-file stream so downstream tooling
//!   (and the unit test) can prove the logo travelled with the PDF.
//! - `primary_color_hex` — `#RRGGBB` swatch used for headings + cover
//!   accent band. Always validated as a 7-character hex literal.
//! - `footer_md` — Markdown rendered into a single plain-text line that
//!   replaces the default "Distribution restricted..." footer.
//! - `cover_md` — Markdown rendered into a paragraph block on the cover
//!   page beneath the metadata. Empty by default.
//!
//! Markdown is intentionally rendered to plain text (no inline HTML, no
//! external image fetches, no JavaScript) — the PDF surface is a
//! restricted glyph stream and we want byte-deterministic output.

use serde::{Deserialize, Serialize};

use crate::error::ReportError;

/// Hard cap on uploaded logo bytes. Enforced in the controller, the
/// adapter, and again here so a programmer error cannot smuggle a
/// 50-MB blob through any single layer.
pub const MAX_LOGO_BYTES: usize = 200 * 1024;

/// Default primary colour when a tenant has not configured one.
///
/// Mirrors the existing executive PDF classification banner red so the
/// "no branding" path renders identically to the pre-P2-002 output.
pub const DEFAULT_PRIMARY_COLOR_HEX: &str = "#C71920";

/// Per-tenant branding bundle handed to every PDF renderer.
///
/// Build via [`BrandConfig::default`] for the no-branding path or via
/// [`BrandConfig::new`] to construct + validate a custom configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrandConfig {
    /// Optional PNG bytes. Always validated to start with the standard
    /// 8-byte PNG signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo_png: Option<Vec<u8>>,
    /// `#RRGGBB` primary brand colour.
    pub primary_color_hex: String,
    /// Optional Markdown footer; rendered as plain text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub footer_md: Option<String>,
    /// Optional Markdown cover-letter paragraph; rendered as plain text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cover_md: Option<String>,
}

impl Default for BrandConfig {
    fn default() -> Self {
        Self {
            logo_png: None,
            primary_color_hex: DEFAULT_PRIMARY_COLOR_HEX.to_owned(),
            footer_md: None,
            cover_md: None,
        }
    }
}

impl BrandConfig {
    /// Build a validated [`BrandConfig`].
    ///
    /// # Errors
    /// - [`ReportError::InvalidContext`] when `primary_color_hex` is not
    ///   exactly `#RRGGBB`, when the logo is empty or exceeds
    ///   [`MAX_LOGO_BYTES`], or when the logo bytes do not start with
    ///   the standard PNG signature.
    pub fn new(
        logo_png: Option<Vec<u8>>,
        primary_color_hex: impl Into<String>,
        footer_md: Option<String>,
        cover_md: Option<String>,
    ) -> Result<Self, ReportError> {
        let primary_color_hex = primary_color_hex.into();
        validate_hex(&primary_color_hex)?;
        if let Some(ref bytes) = logo_png {
            validate_logo(bytes)?;
        }
        Ok(Self {
            logo_png,
            primary_color_hex,
            footer_md: footer_md.filter(|s| !s.trim().is_empty()),
            cover_md: cover_md.filter(|s| !s.trim().is_empty()),
        })
    }

    /// Parse `#RRGGBB` into `(r, g, b)` in the `[0.0, 1.0]` range.
    ///
    /// Returns the default colour on any parse failure so renderers
    /// stay deterministic even if a caller bypasses validation.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn primary_color_rgb(&self) -> (f32, f32, f32) {
        parse_hex(&self.primary_color_hex)
            .or_else(|| parse_hex(DEFAULT_PRIMARY_COLOR_HEX))
            .unwrap_or((0.78, 0.10, 0.12))
    }

    /// Render the Markdown footer as a single line of plain text.
    ///
    /// Returns `None` when no custom footer is configured.
    #[must_use]
    pub fn footer_text(&self) -> Option<String> {
        self.footer_md.as_deref().map(markdown_to_plain)
    }

    /// Render the Markdown cover letter as a paragraph of plain text.
    ///
    /// Returns `None` when no cover letter is configured.
    #[must_use]
    pub fn cover_text(&self) -> Option<String> {
        self.cover_md.as_deref().map(markdown_to_plain)
    }
}

fn validate_hex(s: &str) -> Result<(), ReportError> {
    if s.len() != 7 || !s.starts_with('#') {
        return Err(ReportError::invalid_context(format!(
            "primary_color_hex must be #RRGGBB, got {s}"
        )));
    }
    for ch in s.chars().skip(1) {
        if !ch.is_ascii_hexdigit() {
            return Err(ReportError::invalid_context(format!(
                "primary_color_hex contains non-hex char: {ch}"
            )));
        }
    }
    Ok(())
}

fn parse_hex(s: &str) -> Option<(f32, f32, f32)> {
    if s.len() != 7 || !s.starts_with('#') {
        return None;
    }
    let r = u8::from_str_radix(s.get(1..3)?, 16).ok()?;
    let g = u8::from_str_radix(s.get(3..5)?, 16).ok()?;
    let b = u8::from_str_radix(s.get(5..7)?, 16).ok()?;
    Some((
        f32::from(r) / 255.0,
        f32::from(g) / 255.0,
        f32::from(b) / 255.0,
    ))
}

/// Standard 8-byte PNG signature.
const PNG_SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

fn validate_logo(bytes: &[u8]) -> Result<(), ReportError> {
    if bytes.is_empty() {
        return Err(ReportError::invalid_context("logo_png is empty"));
    }
    if bytes.len() > MAX_LOGO_BYTES {
        return Err(ReportError::invalid_context(format!(
            "logo_png exceeds {MAX_LOGO_BYTES} bytes (got {})",
            bytes.len()
        )));
    }
    match bytes.get(..PNG_SIGNATURE.len()) {
        Some(prefix) if prefix == PNG_SIGNATURE => {}
        _ => {
            return Err(ReportError::invalid_context(
                "logo_png does not start with the PNG signature",
            ));
        }
    }
    Ok(())
}

/// Minimal Markdown -> plain-text projection.
///
/// The PDF renderer can only emit Windows-1252 glyphs through built-in
/// Helvetica, so we strip every formatting glyph and emit a single
/// space-separated string. Newlines collapse to a single space; this
/// matches the cover-page layout expectation.
fn markdown_to_plain(md: &str) -> String {
    let mut out = String::with_capacity(md.len());
    let mut prev_space = false;
    for ch in md.chars() {
        let push = match ch {
            // Strip the formatting glyphs Markdown reserves.
            '*' | '_' | '`' | '#' | '>' | '~' | '[' | ']' | '(' | ')' | '!' | '|' => None,
            '\n' | '\r' | '\t' => Some(' '),
            other => Some(other),
        };
        if let Some(c) = push {
            if c == ' ' {
                if !prev_space && !out.is_empty() {
                    out.push(' ');
                    prev_space = true;
                }
            } else {
                out.push(c);
                prev_space = false;
            }
        }
    }
    out.trim().to_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn one_pixel_png() -> Vec<u8> {
        // The smallest valid PNG signature plus a couple of bytes is
        // enough — validate_logo only checks the 8-byte signature.
        let mut v = PNG_SIGNATURE.to_vec();
        v.extend_from_slice(&[0u8; 8]);
        v
    }

    #[test]
    fn default_uses_brand_red() {
        let b = BrandConfig::default();
        assert_eq!(b.primary_color_hex, DEFAULT_PRIMARY_COLOR_HEX);
        assert!(b.logo_png.is_none());
        assert!(b.footer_md.is_none());
        assert!(b.cover_md.is_none());
    }

    #[test]
    fn accepts_valid_hex_and_logo() {
        let b = BrandConfig::new(
            Some(one_pixel_png()),
            "#1A2B3C",
            Some("**bold** footer".into()),
            Some("Cover paragraph".into()),
        )
        .unwrap();
        assert_eq!(b.primary_color_hex, "#1A2B3C");
        assert_eq!(b.footer_text().as_deref(), Some("bold footer"));
        assert_eq!(b.cover_text().as_deref(), Some("Cover paragraph"));
    }

    #[test]
    fn rejects_short_hex() {
        let r = BrandConfig::new(None, "#1A2B3", None, None);
        assert!(r.is_err());
    }

    #[test]
    fn rejects_missing_hash() {
        let r = BrandConfig::new(None, "1A2B3C0", None, None);
        assert!(r.is_err());
    }

    #[test]
    fn rejects_non_hex_chars() {
        let r = BrandConfig::new(None, "#XYZ123", None, None);
        assert!(r.is_err());
    }

    #[test]
    fn rejects_oversize_logo() {
        let big = vec![0x89u8; MAX_LOGO_BYTES + 1];
        let r = BrandConfig::new(Some(big), "#000000", None, None);
        assert!(r.is_err());
    }

    /// Boundary case (P2-002): a logo that lands exactly on the cap must
    /// pass validation. Paired with [`rejects_oversize_logo`] this pins
    /// the inclusive-upper-bound semantics of [`MAX_LOGO_BYTES`].
    #[test]
    fn accepts_logo_at_size_cap() {
        let mut bytes = PNG_SIGNATURE.to_vec();
        // Pad with arbitrary trailing bytes up to exactly the cap.
        bytes.resize(MAX_LOGO_BYTES, 0);
        let r = BrandConfig::new(Some(bytes), "#000000", None, None);
        assert!(r.is_ok(), "logo exactly at the cap must be accepted");
    }

    /// The error message for an oversize logo MUST surface the offending
    /// byte count — this is what audit consumers grep for when triaging
    /// upload rejections.
    #[test]
    fn oversize_logo_error_carries_byte_count() {
        let too_big = MAX_LOGO_BYTES + 17;
        let r = BrandConfig::new(Some(vec![0x89u8; too_big]), "#000000", None, None);
        let err = r.expect_err("must reject oversize logo");
        let msg = err.to_string();
        assert!(
            msg.contains(&MAX_LOGO_BYTES.to_string()),
            "error must mention the cap: {msg}",
        );
        assert!(
            msg.contains(&too_big.to_string()),
            "error must mention the actual size: {msg}",
        );
    }

    #[test]
    fn rejects_non_png_logo() {
        let bytes = b"GIF89a-not-a-png".to_vec();
        let r = BrandConfig::new(Some(bytes), "#000000", None, None);
        assert!(r.is_err());
    }

    #[test]
    fn empty_footer_collapses_to_none() {
        let b = BrandConfig::new(None, "#000000", Some("   ".into()), None).unwrap();
        assert!(b.footer_md.is_none());
    }

    #[test]
    fn primary_color_rgb_round_trip() {
        let b = BrandConfig::new(None, "#FF8000", None, None).unwrap();
        let (r, g, bl) = b.primary_color_rgb();
        assert!((r - 1.0).abs() < 1e-3);
        assert!((g - 128.0 / 255.0).abs() < 1e-3);
        assert!(bl.abs() < 1e-3);
    }

    #[test]
    fn markdown_to_plain_strips_glyphs() {
        let out = markdown_to_plain("# Heading\n**bold** _italic_ [link](url)");
        assert!(!out.contains('#'));
        assert!(!out.contains('*'));
        assert!(!out.contains('_'));
        assert!(!out.contains('['));
        assert_eq!(out, "Heading bold italic linkurl");
    }
}
