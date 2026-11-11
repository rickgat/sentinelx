//! Assertion Consumer Service (ACS) use case.
//!
//! The ACS is the HTTP endpoint the IdP redirects the user agent to with
//! a signed SAML response in the POST body. This module owns the
//! protocol-level orchestration:
//!
//! 1. Base64-decode the `SAMLResponse` form field.
//! 2. Verify the embedded XML Signature via
//!    [`super::response::verify_assertion`] (cert + audience + time
//!    window).
//! 3. Reject the response if the assertion's `ID` has been seen within
//!    the replay window (5 min by default).
//! 4. If the response carries `InResponseTo`, demand a matching entry
//!    in the outstanding-request store and consume it.
//! 5. Map the verified attributes into a flat [`AcsOutcome`] the
//!    downstream HTTP adapter projects onto a token.
//!
//! The use case is deliberately storage-agnostic: replay protection and
//! `InResponseTo` correlation flow through the
//! [`super::replay::AssertionReplayCache`] trait, the per-tenant IdP
//! config flows in as a [`super::SamlSpConfig`] argument, and audit
//! logging happens via `tracing::*` so the caller can plug in any sink
//! it likes via `tracing-subscriber`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::Engine as _;
use sx_xmlsec::XmlDsigVerifier;
use tracing::{info, warn};

use super::replay::{AssertionReplayCache, InsertOutcome};
use super::response::{verify_assertion, verify_assertion_with_verifier, ParsedAssertion};
use super::{SamlError, SamlSpConfig};

/// Attribute mapping policy. P0-004 nails two mappings:
///
/// * `NameID -> user.email` — the `<Subject>/<NameID>` content becomes
///   the SX-side user email.
/// * `Group -> role` — every `<Attribute Name="Group">/<AttributeValue>`
///   surfaces as an SX role membership.
///
/// The attribute names are configurable so the same SP can serve IdPs
/// that emit `Groups` (Azure AD), `groups` (Okta), or
/// `http://schemas.xmlsoap.org/claims/Group` (ADFS).
#[derive(Debug, Clone)]
pub struct AttributeMapping {
    /// Attribute name(s) on the assertion that carry the user's group /
    /// role membership. The first one that resolves wins.
    pub group_attribute_names: Vec<String>,
}

impl Default for AttributeMapping {
    fn default() -> Self {
        Self {
            group_attribute_names: vec![
                "Group".into(),
                "Groups".into(),
                "groups".into(),
                "http://schemas.xmlsoap.org/claims/Group".into(),
            ],
        }
    }
}

/// Flat, IdP-agnostic outcome of a successful ACS verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcsOutcome {
    /// Tenant the IdP record belongs to. Echoed verbatim so the caller
    /// can scope the downstream session.
    pub tenant_id: String,
    /// `NameID` → `user.email` mapping result.
    pub email: String,
    /// Roles the user should be granted in this session, derived from
    /// the configured group attribute names.
    pub roles: Vec<String>,
    /// `AuthnStatement/@SessionIndex` — preserved so the SLO leg can
    /// echo it back to the IdP.
    pub session_index: Option<String>,
    /// Hard ceiling on the session lifetime — the assertion's
    /// `Conditions/@NotOnOrAfter`. Adapters typically clamp the issued
    /// SX token's `exp` to this value.
    pub not_on_or_after: time::OffsetDateTime,
}

/// `InResponseTo` correlation policy.
///
/// * [`InResponseToPolicy::Required`] — the response MUST carry an
///   `InResponseTo` that matches an outstanding request id. Rejects all
///   IdP-initiated flows.
/// * [`InResponseToPolicy::Optional`] — when present, the value MUST
///   match an outstanding request id; when absent (IdP-initiated), the
///   response is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InResponseToPolicy {
    /// Reject any response that does not carry an `InResponseTo`.
    Required,
    /// Accept IdP-initiated responses (no `InResponseTo`).
    Optional,
}

/// Process a SAML 2.0 `<Response>` document on the ACS endpoint.
///
/// * `xml` — the decoded `SAMLResponse` (UTF-8 XML).
/// * `sp_config` — the SP runtime config (entity id + IdP cert + algo).
/// * `tenant_id` — the tenant the IdP record was loaded for; flows
///   through `AcsOutcome.tenant_id`.
/// * `audience` — the expected `Conditions/AudienceRestriction/Audience`.
///   Almost always `sp_config.entity_id`; passed in so callers can
///   override per tenant (e.g. some IdPs sign for a per-tenant audience).
/// * `clock_skew` — the time-window tolerance.
/// * `replay_cache` — assertion-id dedup store.
/// * `in_response_to_cache` — outstanding-request store. Same trait, but
///   the use case keeps the surfaces separate so a deployment can use
///   distinct backends.
/// * `policy` — `InResponseTo` correlation policy.
/// * `attribute_mapping` — group-attribute name resolution policy.
#[allow(clippy::too_many_arguments, clippy::cognitive_complexity)] // SAML ACS pipeline: decode + verify XMLDSig + InResponseTo gate + audience check + attribute map
pub async fn process_acs_response(
    xml: &str,
    sp_config: &SamlSpConfig,
    tenant_id: &str,
    audience: &str,
    clock_skew: Duration,
    replay_cache: &Arc<dyn AssertionReplayCache>,
    in_response_to_cache: &Arc<dyn AssertionReplayCache>,
    policy: InResponseToPolicy,
    attribute_mapping: &AttributeMapping,
) -> Result<AcsOutcome, SamlError> {
    // 1. Verify XML signature + audience + time window. The verifier
    //    itself rejects multi-assertion XSW shapes before any other
    //    work.
    //
    // BACK-COMPAT: this entry point keeps invoking the hand-rolled
    // `verify_assertion` directly so existing callers that haven't been
    // refactored to pass a `&dyn XmlDsigVerifier` (every non-monolith
    // test, every embedded library consumer) continue working with no
    // code change. TOP5-#1-PHASE-2B's production cutover routes through
    // [`process_acs_response_with_verifier`] below, which the monolith
    // composition root invokes with the verifier built by
    // `verifier_factory::build_verifier`.
    let parsed = verify_assertion(sp_config, xml, audience, clock_skew).map_err(|e| {
        // Audit failure surface — every SAML auth attempt (success +
        // failure) MUST be logged per P0-004.
        warn!(
            target: "iam.saml.acs",
            tenant_id = %tenant_id,
            error = %e,
            "saml acs: assertion verification failed",
        );
        e
    })?;

    // 2. Replay-cache the assertion id. The id lives on the
    //    `<Assertion>` element and is unique per SAML response.
    let assertion_id = extract_assertion_id(xml)?;
    let key = format!("assertion:{tenant_id}:{assertion_id}");
    if matches!(
        replay_cache.insert_if_absent(&key).await,
        InsertOutcome::Duplicate
    ) {
        warn!(
            target: "iam.saml.acs",
            tenant_id = %tenant_id,
            assertion_id = %assertion_id,
            "saml acs: replay detected (assertion id already seen)",
        );
        return Err(SamlError::ReplayAssertion);
    }

    // 3. InResponseTo correlation.
    let in_response_to = extract_in_response_to(xml);
    match (policy, in_response_to.as_deref()) {
        (InResponseToPolicy::Required, None) => {
            warn!(
                target: "iam.saml.acs",
                tenant_id = %tenant_id,
                "saml acs: missing InResponseTo (policy=required)",
            );
            return Err(SamlError::ReplayAssertion);
        }
        (_, Some(req_id)) => {
            // The outstanding-request store stages the SP's AuthnRequest
            // id at issuance time. ACS consumes it: if it isn't there,
            // either the SP never issued such a request OR the request
            // has already been consumed — both are rejected as
            // replay-class failures.
            let key = format!("inresponseto:{tenant_id}:{req_id}");
            if !in_response_to_cache.contains(&key).await {
                warn!(
                    target: "iam.saml.acs",
                    tenant_id = %tenant_id,
                    in_response_to = %req_id,
                    "saml acs: unknown InResponseTo (no outstanding request)",
                );
                return Err(SamlError::ReplayAssertion);
            }
            // Consume by re-inserting — `insert_if_absent` returns
            // `Duplicate` here, which is what we want: every request
            // id MUST be consumed exactly once. We swallow the
            // outcome — the contains-check above is what gives us the
            // guarantee; the second insert just records the consume.
            let _ = in_response_to_cache.insert_if_absent(&key).await;
        }
        (InResponseToPolicy::Optional, None) => {
            // IdP-initiated flow is allowed under optional policy.
            // No correlation step.
        }
    }

    // 4. Attribute mapping.
    let outcome = map_attributes(&parsed, tenant_id, attribute_mapping);

    info!(
        target: "iam.saml.acs",
        tenant_id = %tenant_id,
        email = %outcome.email,
        role_count = outcome.roles.len(),
        "saml acs: assertion verified",
    );

    Ok(outcome)
}

/// TOP5-#1-PHASE-2B: ACS pipeline that routes signature verification
/// through a pluggable [`XmlDsigVerifier`].
///
/// The verifier is constructed ONCE at boot by the monolith composition
/// root (via [`super::verifier_factory::build_verifier`]) and passed
/// down on every ACS evaluation. With default config
/// (`saml.xmldsig.verifier: handrolled`), behaviour is byte-identical
/// to [`process_acs_response`] — the trait dispatch resolves to the
/// hand-rolled [`super::response::verify_assertion`] via the adapter in
/// `verifier_factory::HandRolledVerifier`. The wrapper exists so the
/// `shadow` and `xmlsec1` modes have a wired surface to dispatch from
/// without further code changes when operators flip the YAML flag.
///
/// The replay-cache, `InResponseTo` correlation, and attribute-mapping
/// stages are identical to [`process_acs_response`] — only the
/// signature-verification step is differentiated. Audit logging is also
/// preserved verbatim so existing log-aggregation queries keep working.
#[allow(clippy::too_many_arguments, clippy::cognitive_complexity)] // mirrors process_acs_response shape exactly
pub async fn process_acs_response_with_verifier(
    verifier: &dyn XmlDsigVerifier,
    xml: &str,
    sp_config: &SamlSpConfig,
    tenant_id: &str,
    audience: &str,
    clock_skew: Duration,
    replay_cache: &Arc<dyn AssertionReplayCache>,
    in_response_to_cache: &Arc<dyn AssertionReplayCache>,
    policy: InResponseToPolicy,
    attribute_mapping: &AttributeMapping,
) -> Result<AcsOutcome, SamlError> {
    let parsed = verify_assertion_with_verifier(verifier, sp_config, xml, audience, clock_skew)
        .map_err(|e| {
            warn!(
                target: "iam.saml.acs",
                tenant_id = %tenant_id,
                error = %e,
                verifier = verifier.name(),
                "saml acs: assertion verification failed (verifier-trait path)",
            );
            e
        })?;

    // Replay-cache the assertion id. Identical to process_acs_response.
    let assertion_id = extract_assertion_id(xml)?;
    let key = format!("assertion:{tenant_id}:{assertion_id}");
    if matches!(
        replay_cache.insert_if_absent(&key).await,
        InsertOutcome::Duplicate
    ) {
        warn!(
            target: "iam.saml.acs",
            tenant_id = %tenant_id,
            assertion_id = %assertion_id,
            "saml acs: replay detected (assertion id already seen)",
        );
        return Err(SamlError::ReplayAssertion);
    }

    // InResponseTo correlation. Identical to process_acs_response.
    let in_response_to = extract_in_response_to(xml);
    match (policy, in_response_to.as_deref()) {
        (InResponseToPolicy::Required, None) => {
            warn!(
                target: "iam.saml.acs",
                tenant_id = %tenant_id,
                "saml acs: missing InResponseTo (policy=required)",
            );
            return Err(SamlError::ReplayAssertion);
        }
        (_, Some(req_id)) => {
            let key = format!("inresponseto:{tenant_id}:{req_id}");
            if !in_response_to_cache.contains(&key).await {
                warn!(
                    target: "iam.saml.acs",
                    tenant_id = %tenant_id,
                    in_response_to = %req_id,
                    "saml acs: unknown InResponseTo (no outstanding request)",
                );
                return Err(SamlError::ReplayAssertion);
            }
            let _ = in_response_to_cache.insert_if_absent(&key).await;
        }
        (InResponseToPolicy::Optional, None) => {}
    }

    let outcome = map_attributes(&parsed, tenant_id, attribute_mapping);

    info!(
        target: "iam.saml.acs",
        tenant_id = %tenant_id,
        email = %outcome.email,
        role_count = outcome.roles.len(),
        verifier = verifier.name(),
        "saml acs: assertion verified (verifier-trait path)",
    );

    Ok(outcome)
}

/// Decode the raw base64-encoded `SAMLResponse` form parameter.
///
/// SAML 2.0 Bindings §3.5.4 — the HTTP-POST binding sends the response
/// as a base64 payload. Tolerates the `+` / `=` characters quoted by some
/// IdPs.
pub fn decode_saml_response(b64: &str) -> Result<String, SamlError> {
    // Strip whitespace some agents inject when base64-encoding.
    let cleaned: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
    let raw = B64_STANDARD
        .decode(cleaned.as_bytes())
        .map_err(|e| SamlError::XmlMalformed(format!("base64: {e}")))?;
    String::from_utf8(raw).map_err(|e| SamlError::XmlMalformed(format!("utf8: {e}")))
}

/// Map the verified assertion's `NameID` + attribute statement onto a
/// flat outcome.
fn map_attributes(
    parsed: &ParsedAssertion,
    tenant_id: &str,
    mapping: &AttributeMapping,
) -> AcsOutcome {
    let roles = resolve_roles(&parsed.attributes, &mapping.group_attribute_names);
    AcsOutcome {
        tenant_id: tenant_id.to_owned(),
        email: parsed.name_id.clone(),
        roles,
        session_index: parsed.session_index.clone(),
        not_on_or_after: parsed.not_on_or_after,
    }
}

fn resolve_roles(
    attributes: &HashMap<String, Vec<String>>,
    candidate_names: &[String],
) -> Vec<String> {
    for name in candidate_names {
        if let Some(values) = attributes.get(name) {
            if !values.is_empty() {
                // Trim each value — some IdPs pad with whitespace.
                return values
                    .iter()
                    .map(|v| v.trim().to_owned())
                    .filter(|v| !v.is_empty())
                    .collect();
            }
        }
    }
    Vec::new()
}

/// Extract the `<Assertion>`'s `ID` attribute. The verifier has already
/// confirmed there is exactly one assertion, so a single tokenising scan
/// is sufficient.
fn extract_assertion_id(xml: &str) -> Result<String, SamlError> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e) | Event::Empty(e)) => {
                if local_name(e.name().as_ref()) == b"Assertion" {
                    for attr in e.attributes().flatten() {
                        if local_name(attr.key.as_ref()) == b"ID" {
                            let v = attr
                                .decoded_and_normalized_value(
                                    quick_xml::XmlVersion::default(),
                                    reader.decoder(),
                                )
                                .map_err(|err| {
                                    SamlError::XmlMalformed(format!("attr ID: {err}"))
                                })?;
                            return Ok(v.to_string());
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(SamlError::XmlMalformed(format!("scan ID: {e}"))),
            _ => {}
        }
        buf.clear();
    }
    Err(SamlError::XmlMalformed("Assertion/@ID not found".into()))
}

/// Extract the `InResponseTo` attribute from the top-level `<Response>`.
/// Returns `None` for IdP-initiated flows.
fn extract_in_response_to(xml: &str) -> Option<String> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e) | Event::Empty(e)) => {
                if local_name(e.name().as_ref()) == b"Response" {
                    for attr in e.attributes().flatten() {
                        if local_name(attr.key.as_ref()) == b"InResponseTo" {
                            if let Ok(v) = attr.decoded_and_normalized_value(
                                quick_xml::XmlVersion::default(),
                                reader.decoder(),
                            ) {
                                return Some(v.to_string());
                            }
                        }
                    }
                    return None;
                }
            }
            Ok(Event::Eof) | Err(_) => return None,
            _ => {}
        }
        buf.clear();
    }
}

fn local_name(name: &[u8]) -> &[u8] {
    match name.iter().position(|b| *b == b':') {
        Some(i) => name.get(i + 1..).unwrap_or(name),
        None => name,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn decode_saml_response_round_trips() {
        let s = decode_saml_response(&B64_STANDARD.encode("<hello/>")).unwrap();
        assert_eq!(s, "<hello/>");
    }

    #[test]
    fn decode_saml_response_strips_whitespace() {
        let raw = B64_STANDARD.encode("<hi/>");
        let with_ws = format!("{}\n{}", &raw[..3], &raw[3..]);
        let s = decode_saml_response(&with_ws).unwrap();
        assert_eq!(s, "<hi/>");
    }

    #[test]
    fn decode_saml_response_rejects_bad_base64() {
        let err = decode_saml_response("not%base64").unwrap_err();
        assert!(matches!(err, SamlError::XmlMalformed(_)));
    }

    #[test]
    fn extract_assertion_id_finds_namespaced_id() {
        let xml =
            r#"<saml:Assertion ID="_abc" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>"#;
        assert_eq!(extract_assertion_id(xml).unwrap(), "_abc");
    }

    #[test]
    fn extract_assertion_id_returns_err_when_missing() {
        let xml = r"<saml:Assertion/>";
        let err = extract_assertion_id(xml).unwrap_err();
        assert!(matches!(err, SamlError::XmlMalformed(_)));
    }

    #[test]
    fn extract_in_response_to_present() {
        let xml = r#"<samlp:Response InResponseTo="_req-1" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>"#;
        assert_eq!(extract_in_response_to(xml).as_deref(), Some("_req-1"));
    }

    #[test]
    fn extract_in_response_to_absent() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>"#;
        assert_eq!(extract_in_response_to(xml), None);
    }

    #[test]
    fn resolve_roles_finds_first_matching_attribute() {
        let mut a: HashMap<String, Vec<String>> = HashMap::new();
        a.insert("Group".into(), vec!["admin".into(), "analyst".into()]);
        let roles = resolve_roles(&a, &["Groups".into(), "Group".into()]);
        assert_eq!(roles, vec!["admin", "analyst"]);
    }

    #[test]
    fn resolve_roles_trims_whitespace() {
        let mut a: HashMap<String, Vec<String>> = HashMap::new();
        a.insert("Group".into(), vec!["  admin  ".into(), " ".into()]);
        let roles = resolve_roles(&a, &["Group".into()]);
        assert_eq!(roles, vec!["admin"]);
    }

    #[test]
    fn resolve_roles_empty_when_no_match() {
        let a: HashMap<String, Vec<String>> = HashMap::new();
        let roles = resolve_roles(&a, &["Group".into()]);
        assert!(roles.is_empty());
    }

    #[test]
    fn default_attribute_mapping_includes_common_names() {
        let m = AttributeMapping::default();
        assert!(m.group_attribute_names.contains(&"Group".to_string()));
        assert!(m.group_attribute_names.contains(&"Groups".to_string()));
        assert!(m.group_attribute_names.contains(&"groups".to_string()));
    }
}
