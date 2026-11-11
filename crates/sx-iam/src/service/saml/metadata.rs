//! SAML 2.0 SP Metadata document builder.
//!
//! `parse_metadata_xml` returns the SP's `<EntityDescriptor>` XML
//! document. The output is suitable for hosting at the SP's metadata
//! URL (e.g. `/saml/metadata`) or for direct upload into the IdP's
//! Trust configuration.
//!
//! The MVP slice produces an `SPSSODescriptor` that:
//! * advertises the SAML 2.0 protocol,
//! * declares HTTP-POST as the `AssertionConsumerService` binding,
//! * advertises HTTP-Redirect as the `SingleLogoutService` binding when a
//!   `slo_url` is configured,
//! * publishes no `KeyDescriptor` (the SP does not yet sign its own
//!   AuthnRequests in the MVP).

use super::SamlSpConfig;

/// Produce the SAML 2.0 `<EntityDescriptor>` XML document for `sp_config`.
///
/// The `AssertionConsumerService` Location is derived from the SP
/// `entity_id` by appending `/acs` — this mirrors the convention used
/// throughout the SentinelX deployment manifests. Tenants that need a
/// different ACS URL should override this with their own metadata
/// publishing layer; the MVP is opinionated.
#[must_use]
pub fn parse_metadata_xml(sp_config: &SamlSpConfig) -> String {
    let acs_location = derive_acs_location(&sp_config.entity_id);
    let slo_xml = sp_config
        .slo_url
        .as_deref()
        .map_or_else(String::new, |url| {
            format!(
                "<md:SingleLogoutService \
Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" \
Location=\"{loc}\"/>",
                loc = xml_escape(url),
            )
        });

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" \
entityID=\"{entity_id}\">\
<md:SPSSODescriptor AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"true\" \
protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\
{slo}\
<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>\
<md:AssertionConsumerService \
Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" \
Location=\"{acs}\" index=\"0\" isDefault=\"true\"/>\
</md:SPSSODescriptor>\
</md:EntityDescriptor>",
        entity_id = xml_escape(&sp_config.entity_id),
        slo = slo_xml,
        acs = xml_escape(&acs_location),
    )
}

/// Derive the ACS URL from the SP entity id by appending `/acs`. If the
/// entity id already ends with `/acs` it is returned unchanged.
fn derive_acs_location(entity_id: &str) -> String {
    if entity_id.ends_with("/acs") {
        entity_id.to_string()
    } else if entity_id.ends_with('/') {
        format!("{entity_id}acs")
    } else {
        format!("{entity_id}/acs")
    }
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::service::saml::SamlSigningAlgo;

    fn cfg() -> SamlSpConfig {
        SamlSpConfig {
            entity_id: "https://sp.example.com/saml".to_string(),
            sso_url: "https://idp.example.com/sso".to_string(),
            slo_url: Some("https://idp.example.com/slo".to_string()),
            x509_cert_pem: String::new(),
            signing_algo: SamlSigningAlgo::Sha256,
        }
    }

    #[test]
    fn metadata_contains_entity_id_and_acs() {
        let xml = parse_metadata_xml(&cfg());
        assert!(xml.contains("entityID=\"https://sp.example.com/saml\""));
        assert!(xml.contains("Location=\"https://sp.example.com/saml/acs\""));
        assert!(xml.contains("Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\""));
    }

    #[test]
    fn metadata_omits_slo_when_not_configured() {
        let mut c = cfg();
        c.slo_url = None;
        let xml = parse_metadata_xml(&c);
        assert!(!xml.contains("SingleLogoutService"));
    }

    #[test]
    fn metadata_includes_slo_when_configured() {
        let xml = parse_metadata_xml(&cfg());
        assert!(xml.contains("SingleLogoutService"));
        assert!(xml.contains("Location=\"https://idp.example.com/slo\""));
    }

    #[test]
    fn derive_acs_handles_trailing_slash_and_acs() {
        assert_eq!(
            derive_acs_location("https://sp.example.com/saml"),
            "https://sp.example.com/saml/acs"
        );
        assert_eq!(
            derive_acs_location("https://sp.example.com/saml/"),
            "https://sp.example.com/saml/acs"
        );
        assert_eq!(
            derive_acs_location("https://sp.example.com/saml/acs"),
            "https://sp.example.com/saml/acs"
        );
    }

    #[test]
    fn metadata_wants_assertions_signed() {
        let xml = parse_metadata_xml(&cfg());
        assert!(xml.contains("WantAssertionsSigned=\"true\""));
        assert!(xml.contains("AuthnRequestsSigned=\"false\""));
    }
}
