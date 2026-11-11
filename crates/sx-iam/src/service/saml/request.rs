//! SAML 2.0 `AuthnRequest` builder for the HTTP-Redirect binding.
//!
//! `build_authn_request` produces a base64-encoded, DEFLATE-compressed
//! `<samlp:AuthnRequest>` document ready to be appended to the IdP's SSO
//! URL as a `SAMLRequest=` query parameter (SAML 2.0 Bindings §3.4).
//!
//! The MVP does **not** sign the redirect-binding request — most
//! production deployments rely on the IdP authenticating the SP via the
//! `Issuer` value and the back-channel cert exchange. Adding signed
//! `AuthnRequest` is a follow-up.

use std::io::Write as _;

use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::Engine as _;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use rand::RngCore;
use time::OffsetDateTime;

use super::{SamlError, SamlSpConfig};

/// Build a SAML 2.0 `AuthnRequest` and return the
/// **base64-encoded, DEFLATE-compressed** form suitable for the
/// HTTP-Redirect binding (`SAMLRequest=` query parameter).
///
/// * `sp_config` — the SP configuration (entity id + IdP SSO URL).
/// * `relay_state` — optional opaque token the SP wants the IdP to echo
///   back on the response leg. The caller is responsible for binding
///   `relay_state` to a session and validating it on return; this
///   function only embeds it in tracing context (never the XML).
///
/// Returns the base64-encoded `SAMLRequest` parameter value, or
/// [`SamlError::XmlMalformed`] if DEFLATE compression / base64 encoding
/// fails (e.g. environment OOM during compression buffer allocation).
pub fn build_authn_request(
    sp_config: &SamlSpConfig,
    relay_state: Option<&str>,
) -> Result<String, SamlError> {
    let _ = relay_state; // Reserved for future signed-redirect binding.

    let id = generate_request_id();
    let issue_instant = format_xs_datetime(OffsetDateTime::now_utc());

    let xml = format!(
        "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" \
ID=\"{id}\" Version=\"2.0\" IssueInstant=\"{issue_instant}\" \
Destination=\"{sso_url}\" \
ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\">\
<saml:Issuer>{issuer}</saml:Issuer>\
<samlp:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\" \
AllowCreate=\"true\"/>\
</samlp:AuthnRequest>",
        id = id,
        issue_instant = issue_instant,
        sso_url = xml_escape(&sp_config.sso_url),
        issuer = xml_escape(&sp_config.entity_id),
    );

    let deflated = deflate_raw(xml.as_bytes())?;
    Ok(B64_STANDARD.encode(deflated))
}

/// RFC 4122-style XML ID: `_` prefix + 32 lowercase hex chars (128 bits
/// of randomness). The `_` prefix ensures the value is a valid xsd:ID
/// (which must start with a letter or underscore).
fn generate_request_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut s = String::with_capacity(33);
    s.push('_');
    for b in bytes {
        // Two lowercase hex digits per byte.
        s.push(hex_digit(b >> 4));
        s.push(hex_digit(b & 0x0f));
    }
    s
}

const fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'a' + (nibble - 10)) as char,
    }
}

/// Format an `OffsetDateTime` as an xs:dateTime in UTC with no fractional
/// seconds (`YYYY-MM-DDTHH:MM:SSZ`). Falls back to the Unix epoch if the
/// formatter rejects the input — keeps the function infallible at the
/// call-site so the caller does not have to thread another error case.
fn format_xs_datetime(dt: OffsetDateTime) -> String {
    let utc = dt.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second(),
    )
}

/// Escape the five XML predefined entities (`&`, `<`, `>`, `"`, `'`).
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

/// DEFLATE-compress (raw, no zlib header — per SAML 2.0 Bindings §3.4.4.1).
fn deflate_raw(data: &[u8]) -> Result<Vec<u8>, SamlError> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(data)
        .map_err(|e| SamlError::XmlMalformed(format!("deflate write: {e}")))?;
    encoder
        .finish()
        .map_err(|e| SamlError::XmlMalformed(format!("deflate finish: {e}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::service::saml::SamlSigningAlgo;
    use std::io::Read as _;

    fn cfg() -> SamlSpConfig {
        SamlSpConfig {
            entity_id: "https://sp.example.com/saml/metadata".to_string(),
            sso_url: "https://idp.example.com/sso".to_string(),
            slo_url: Some("https://idp.example.com/slo".to_string()),
            x509_cert_pem: "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----"
                .to_string(),
            signing_algo: SamlSigningAlgo::Sha256,
        }
    }

    fn b64_decode_inflate(s: &str) -> String {
        let raw = B64_STANDARD.decode(s).unwrap();
        let mut dec = flate2::read::DeflateDecoder::new(&raw[..]);
        let mut out = String::new();
        dec.read_to_string(&mut out).unwrap();
        out
    }

    #[test]
    fn build_authn_request_returns_base64() {
        let s = build_authn_request(&cfg(), None).unwrap();
        // Base64 standard alphabet only.
        assert!(s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='));
        assert!(!s.is_empty());
    }

    #[test]
    fn build_authn_request_round_trips_to_xml() {
        let s = build_authn_request(&cfg(), Some("opaque-state")).unwrap();
        let xml = b64_decode_inflate(&s);
        assert!(xml.contains("<samlp:AuthnRequest"));
        assert!(xml.contains("Version=\"2.0\""));
        assert!(xml.contains("Destination=\"https://idp.example.com/sso\""));
        assert!(xml.contains("<saml:Issuer>https://sp.example.com/saml/metadata</saml:Issuer>"));
        assert!(xml.contains("ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\""));
    }

    #[test]
    fn build_authn_request_id_is_random_and_well_formed() {
        let a = build_authn_request(&cfg(), None).unwrap();
        let b = build_authn_request(&cfg(), None).unwrap();
        // Two consecutive calls must produce different IDs (128 bits
        // of entropy makes a collision astronomically unlikely).
        let xa = b64_decode_inflate(&a);
        let xb = b64_decode_inflate(&b);
        let id_a = xa
            .split("ID=\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap();
        let id_b = xb
            .split("ID=\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap();
        assert_ne!(id_a, id_b);
        assert!(id_a.starts_with('_'));
        assert_eq!(id_a.len(), 33);
        assert!(id_a[1..]
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn xml_escape_handles_predefined_entities() {
        assert_eq!(xml_escape("&<>\"'"), "&amp;&lt;&gt;&quot;&apos;");
        assert_eq!(xml_escape("plain"), "plain");
    }

    #[test]
    fn build_authn_request_escapes_issuer_with_ampersand() {
        let mut c = cfg();
        c.entity_id = "https://sp.example.com/saml?x=1&y=2".to_string();
        let s = build_authn_request(&c, None).unwrap();
        let xml = b64_decode_inflate(&s);
        assert!(xml.contains("x=1&amp;y=2"));
        assert!(!xml.contains("x=1&y=2"));
    }
}
