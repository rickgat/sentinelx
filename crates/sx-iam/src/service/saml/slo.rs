//! SAML 2.0 Single Logout (SLO) request builder.
//!
//! [`build_logout_request`] produces a base64-encoded, DEFLATE-compressed
//! `<samlp:LogoutRequest>` document suitable for the HTTP-Redirect
//! binding (SAML 2.0 Bindings §3.4). The caller appends the result to
//! the IdP's `SingleLogoutService` URL as the `SAMLRequest=` query
//! parameter.
//!
//! The MVP only supports SP-initiated SLO. IdP-initiated SLO (where the
//! SP receives a `LogoutRequest` and must reply with a
//! `LogoutResponse`) is intentionally out of scope — most enterprise
//! deployments only require SP-initiated SLO.

use std::io::Write as _;

use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::Engine as _;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use rand::RngCore;
use time::OffsetDateTime;

use super::{SamlError, SamlSpConfig};

/// Build a SAML 2.0 `LogoutRequest` for SP-initiated SLO.
///
/// * `sp_config` — the SP configuration. `slo_url` MUST be `Some` —
///   otherwise this returns [`SamlError::XmlMalformed`] noting the
///   missing endpoint so the caller can map to a 422.
/// * `name_id` — the `NameID` of the user being signed out. Typically
///   the email address that was carried on the original assertion.
/// * `session_index` — the `SessionIndex` from the original
///   `AuthnStatement`. Optional — when absent the IdP terminates every
///   session it has for the principal.
///
/// Returns the base64-encoded `SAMLRequest` parameter value.
pub fn build_logout_request(
    sp_config: &SamlSpConfig,
    name_id: &str,
    session_index: Option<&str>,
) -> Result<String, SamlError> {
    let slo_url = sp_config
        .slo_url
        .as_deref()
        .ok_or_else(|| SamlError::XmlMalformed("slo_url not configured for this tenant".into()))?;

    let id = generate_request_id();
    let issue_instant = format_xs_datetime(OffsetDateTime::now_utc());

    let session_index_xml = session_index.map_or_else(String::new, |s| {
        format!(
            "<samlp:SessionIndex>{si}</samlp:SessionIndex>",
            si = xml_escape(s)
        )
    });

    let xml = format!(
        "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" \
ID=\"{id}\" Version=\"2.0\" IssueInstant=\"{issue_instant}\" \
Destination=\"{dest}\">\
<saml:Issuer>{issuer}</saml:Issuer>\
<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">{name_id}</saml:NameID>\
{sess}\
</samlp:LogoutRequest>",
        id = id,
        issue_instant = issue_instant,
        dest = xml_escape(slo_url),
        issuer = xml_escape(&sp_config.entity_id),
        name_id = xml_escape(name_id),
        sess = session_index_xml,
    );

    let deflated = deflate_raw(xml.as_bytes())?;
    Ok(B64_STANDARD.encode(deflated))
}

fn generate_request_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut s = String::with_capacity(33);
    s.push('_');
    for b in bytes {
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
    use std::io::Read as _;

    use super::*;
    use crate::service::saml::SamlSigningAlgo;

    fn cfg_with_slo() -> SamlSpConfig {
        SamlSpConfig {
            entity_id: "https://sp.example.com/saml".into(),
            sso_url: "https://idp.example.com/sso".into(),
            slo_url: Some("https://idp.example.com/slo".into()),
            x509_cert_pem: String::new(),
            signing_algo: SamlSigningAlgo::Sha256,
        }
    }

    fn cfg_without_slo() -> SamlSpConfig {
        SamlSpConfig {
            slo_url: None,
            ..cfg_with_slo()
        }
    }

    fn inflate(s: &str) -> String {
        let raw = B64_STANDARD.decode(s).unwrap();
        let mut dec = flate2::read::DeflateDecoder::new(&raw[..]);
        let mut out = String::new();
        dec.read_to_string(&mut out).unwrap();
        out
    }

    #[test]
    fn build_logout_request_returns_base64() {
        let s = build_logout_request(&cfg_with_slo(), "alice@example.com", None).unwrap();
        assert!(s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='));
    }

    #[test]
    fn build_logout_request_round_trips_to_xml() {
        let s =
            build_logout_request(&cfg_with_slo(), "alice@example.com", Some("session-1")).unwrap();
        let xml = inflate(&s);
        assert!(xml.contains("<samlp:LogoutRequest"));
        assert!(xml.contains("Destination=\"https://idp.example.com/slo\""));
        assert!(xml.contains("alice@example.com"));
        assert!(xml.contains("<samlp:SessionIndex>session-1</samlp:SessionIndex>"));
    }

    #[test]
    fn build_logout_request_omits_session_index_when_none() {
        let s = build_logout_request(&cfg_with_slo(), "alice@example.com", None).unwrap();
        let xml = inflate(&s);
        assert!(!xml.contains("SessionIndex"));
    }

    #[test]
    fn fails_when_slo_url_missing() {
        let err = build_logout_request(&cfg_without_slo(), "alice@example.com", None)
            .expect_err("no slo url");
        assert!(matches!(err, SamlError::XmlMalformed(ref m) if m.contains("slo_url")));
    }

    #[test]
    fn escapes_name_id_and_session_index() {
        let s = build_logout_request(&cfg_with_slo(), "a&b@example.com", Some("s<1>")).unwrap();
        let xml = inflate(&s);
        assert!(xml.contains("a&amp;b@example.com"));
        assert!(xml.contains("s&lt;1&gt;"));
        assert!(!xml.contains("a&b@example.com"));
    }
}
