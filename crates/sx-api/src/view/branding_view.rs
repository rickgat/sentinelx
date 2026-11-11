//! Per-tenant report branding DTOs (P2-002 MSSP white-label).
//!
//! Operators configure a tenant's white-label branding — logo, primary
//! colour, and optional cover / footer Markdown — which the report
//! renderers apply to executive and technical PDFs. The logo travels as a
//! base64-encoded PNG on the wire; the adapter decodes and size-checks it.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Current branding for a tenant (response DTO).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrandingView {
    /// Base64-encoded PNG logo, or `null` when none is configured.
    pub logo_png_base64: Option<String>,
    /// Primary brand colour as a `#RRGGBB` hex string.
    pub primary_color_hex: String,
    /// Optional cover-page Markdown.
    pub cover_md: Option<String>,
    /// Optional footer Markdown.
    pub footer_md: Option<String>,
}

/// Request body for `PUT /v1/reports/branding`.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct SetBrandingRequest {
    /// Base64-encoded PNG logo. Omit or `null` to clear the logo. The
    /// decoded payload must not exceed 200 KiB (enforced in the adapter).
    #[validate(length(max = 400_000))] // ~200 KiB once base64-decoded
    pub logo_png_base64: Option<String>,
    /// Primary brand colour; must be a `#RRGGBB` hex string.
    #[validate(custom(function = "validate_hex_color"))]
    pub primary_color_hex: String,
    /// Optional cover-page Markdown (bounded to keep PDFs sane).
    #[validate(length(max = 20_000))]
    pub cover_md: Option<String>,
    /// Optional footer Markdown.
    #[validate(length(max = 4_000))]
    pub footer_md: Option<String>,
}

/// Validate a `#RRGGBB` hex colour string.
///
/// # Errors
///
/// Returns a `validator::ValidationError` when `value` is not exactly a
/// leading `#` followed by six hexadecimal digits.
pub fn validate_hex_color(value: &str) -> Result<(), validator::ValidationError> {
    let ok = value.len() == 7
        && value.starts_with('#')
        && value[1..].bytes().all(|b| b.is_ascii_hexdigit());
    if ok {
        Ok(())
    } else {
        Err(validator::ValidationError::new("primary_color_hex"))
    }
}
