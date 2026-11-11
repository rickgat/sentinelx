//! Microsoft Security Response Center (MSRC) advisory source.
//!
//! MSRC publishes monthly bulletin batches in [CVRF] XML at
//! `https://api.msrc.microsoft.com/cvrf/v2.0/document/{updateID}`, where
//! `updateID` is the form `YYYY-MMM` (e.g. `2024-Jan`). Each document
//! contains a `<DocumentTitle>` plus one `<Vulnerability>` block per CVE,
//! and a `<ProductTree>` that names the affected products.
//!
//! This module provides:
//! - [`parse_cvrf`] — a pure, streaming CVRF parser that maps the subset of
//!   the schema we care about onto [`VendorAdvisory`].
//! - [`MsrcSource::fetch_bulletin`] — async HTTP fetch + parse of a single
//!   `updateID` document.
//! - [`MsrcSource::fetch_by_cve`] — trait wiring; probes the publication
//!   year of the CVE month-by-month and returns the advisories whose CVE
//!   id matches.
//!
//! The XML body of an MSRC document never reaches the tracing logs;
//! diagnostics are limited to the `updateID`, bulletin count, and parse
//! error kind.
//!
//! [CVRF]: https://www.icasi.org/cvrf/

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::QName;
use quick_xml::Reader;
use sx_core::prelude::CveId;
use time::OffsetDateTime;
use url::Url;

use crate::error::RemediationError;
use crate::model::advisory::{Patch, VendorAdvisory};
use crate::service::source::VendorAdvisorySource;
use crate::service::{DEFAULT_TIMEOUT_SECS, USER_AGENT};

/// Slug used by [`VendorAdvisorySource::vendor`] and
/// [`crate::model::advisory::VendorAdvisory::vendor`].
pub const VENDOR: &str = "msrc";

/// Base CVRF endpoint.
const BASE_URL: &str = "https://api.msrc.microsoft.com/cvrf/v2.0/document/";

/// Errors produced while parsing an MSRC CVRF document.
#[derive(Debug)]
pub enum MsrcParseError {
    /// The underlying [`quick_xml`] reader rejected the byte stream — usually
    /// malformed or unclosed XML.
    Xml(quick_xml::Error),
    /// The document parsed structurally but lacked a required CVRF shape —
    /// for example zero `<Vulnerability>` blocks in a non-empty document.
    UnexpectedShape(String),
    /// A CDATA section or attribute could not be decoded as UTF-8.
    Encoding(String),
}

impl fmt::Display for MsrcParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Xml(e) => write!(f, "msrc cvrf xml error: {e}"),
            Self::UnexpectedShape(m) => write!(f, "msrc cvrf unexpected shape: {m}"),
            Self::Encoding(m) => write!(f, "msrc cvrf encoding error: {m}"),
        }
    }
}

impl std::error::Error for MsrcParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Xml(e) => Some(e),
            Self::UnexpectedShape(_) | Self::Encoding(_) => None,
        }
    }
}

impl From<quick_xml::Error> for MsrcParseError {
    fn from(e: quick_xml::Error) -> Self {
        Self::Xml(e)
    }
}

impl From<MsrcParseError> for RemediationError {
    fn from(e: MsrcParseError) -> Self {
        Self::malformed(VENDOR, e.to_string())
    }
}

/// MSRC advisory source.
#[derive(Debug, Clone)]
pub struct MsrcSource {
    http: reqwest::Client,
    base_url: String,
}

impl MsrcSource {
    /// Build a source backed by a fresh [`reqwest::Client`] with the crate's
    /// standard timeout and User-Agent.
    pub fn new() -> Result<Self, RemediationError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .user_agent(USER_AGENT)
            .build()
            .map_err(|e| RemediationError::transport(VENDOR, e.to_string()))?;
        Ok(Self {
            http,
            base_url: BASE_URL.to_string(),
        })
    }

    /// Build a source with a caller-supplied client. Used by tests.
    #[must_use]
    pub fn with_client(http: reqwest::Client) -> Self {
        Self {
            http,
            base_url: BASE_URL.to_string(),
        }
    }

    /// Override the base URL. Used by tests pointing at `wiremock`.
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Compose the CVRF document URL for a given `YYYY-MMM` `updateID`.
    fn build_update_url(&self, update_id: &str) -> Result<Url, RemediationError> {
        let raw = format!("{base}{id}", base = self.base_url, id = update_id);
        Url::parse(&raw).map_err(|e| RemediationError::UrlBuild(e.to_string()))
    }

    /// Compose the CVRF document URL for a `(year, month)` pair.
    pub fn build_year_month_url(
        &self,
        year: i32,
        month_index: u32,
    ) -> Result<Url, RemediationError> {
        let month = month_abbrev(month_index)
            .ok_or_else(|| RemediationError::config(format!("invalid month {month_index}")))?;
        let raw = format!("{base}{year:04}-{month}", base = self.base_url);
        Url::parse(&raw).map_err(|e| RemediationError::UrlBuild(e.to_string()))
    }

    /// Build the canonical URL for a CVE's publication year + January —
    /// a deterministic reference URL the registry can emit.
    pub fn build_url_for_cve(&self, cve: &CveId) -> Result<Url, RemediationError> {
        let year = parse_cve_year(cve)?;
        self.build_year_month_url(year, 1)
    }

    /// Fetch and parse a single `YYYY-MMM` CVRF bulletin batch.
    ///
    /// Returns every [`VendorAdvisory`] published in the batch. The caller is
    /// responsible for filtering by CVE if it only wants a subset.
    pub async fn fetch_bulletin(
        &self,
        update_id: &str,
    ) -> Result<Vec<VendorAdvisory>, RemediationError> {
        let url = self.build_update_url(update_id)?;
        let resp = self
            .http
            .get(url)
            .header("accept", "application/xml")
            .send()
            .await
            .map_err(|e| RemediationError::transport(VENDOR, e.to_string()))?;

        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(RemediationError::NotFound(VENDOR));
        }
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(RemediationError::Unauthorized(VENDOR));
        }
        if !status.is_success() {
            return Err(RemediationError::transport(
                VENDOR,
                format!("status {status}"),
            ));
        }

        let body = resp
            .text()
            .await
            .map_err(|e| RemediationError::transport(VENDOR, e.to_string()))?;

        let advisories = parse_cvrf(&body).map_err(RemediationError::from)?;
        tracing::debug!(
            target: "sx_remediation::msrc",
            update_id,
            bulletin_count = advisories.len(),
            "msrc cvrf parsed"
        );
        Ok(advisories)
    }
}

#[async_trait]
impl VendorAdvisorySource for MsrcSource {
    fn vendor(&self) -> &'static str {
        VENDOR
    }

    async fn fetch_by_cve(&self, cve: &CveId) -> Result<Vec<VendorAdvisory>, RemediationError> {
        let year = parse_cve_year(cve)?;
        // Probe every month of the CVE's publication year. A real production
        // deployment should cache this; the registry-level cache is out of
        // scope for the parser PR.
        let mut hits = Vec::new();
        for month in 1u32..=12 {
            let Some(abbrev) = month_abbrev(month) else {
                continue;
            };
            let update_id = format!("{year:04}-{abbrev}");
            match self.fetch_bulletin(&update_id).await {
                Ok(batch) => {
                    for adv in batch {
                        if adv.cves.iter().any(|c| c == cve) {
                            hits.push(adv);
                        }
                    }
                }
                Err(RemediationError::NotFound(_)) => {
                    // Some months publish nothing — treat as "no record".
                }
                Err(err) => {
                    tracing::warn!(
                        target: "sx_remediation::msrc",
                        update_id,
                        error = %err,
                        "msrc month fetch failed"
                    );
                }
            }
        }
        Ok(hits)
    }
}

/// Parse an MSRC CVRF XML document into a list of advisories in document
/// order.
///
/// The parser is streaming (no DOM) and tolerates the subset of CVRF MSRC
/// actually emits: `<DocumentTitle>`, `<ProductTree>` with `<FullProductName>`
/// children, and any number of `<Vulnerability>` blocks each containing
/// `<CVE>`, `<Title>`, `<Notes>`, `<ProductStatuses>`, `<Remediations>`,
/// and `<References>`.
pub fn parse_cvrf(xml: &str) -> Result<Vec<VendorAdvisory>, MsrcParseError> {
    let trimmed = xml.trim();
    if trimmed.is_empty() {
        return Err(MsrcParseError::UnexpectedShape(
            "empty document body".into(),
        ));
    }

    let mut reader = Reader::from_str(xml);
    let cfg = reader.config_mut();
    cfg.trim_text(true);
    cfg.expand_empty_elements = false;

    let mut state = ParserState::default();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Eof => break,
            Event::Start(ref e) => state.on_start(e)?,
            Event::End(ref e) => state.on_end(e)?,
            Event::Empty(ref e) => {
                // Self-closing tags carry attributes only — used by
                // <ProductID> and <FullProductName> in malformed feeds.
                state.on_start(e)?;
                state.on_end_name(e.name())?;
            }
            Event::Text(ref t) => {
                let s = t
                    .xml_content(quick_xml::XmlVersion::default())
                    .map_err(|e| MsrcParseError::Encoding(e.to_string()))?;
                state.on_text(&s);
            }
            Event::CData(ref c) => {
                let raw = std::str::from_utf8(c.as_ref())
                    .map_err(|e| MsrcParseError::Encoding(e.to_string()))?;
                state.on_text(raw);
            }
            _ => {}
        }
        buf.clear();
    }

    if !state.saw_document_root {
        return Err(MsrcParseError::UnexpectedShape(
            "no <cvrfdoc> root element found".into(),
        ));
    }
    Ok(state.into_advisories())
}

#[derive(Debug, Default)]
struct ParserState {
    saw_document_root: bool,
    document_title: String,
    // Stack of element names so we can disambiguate nested context
    // (e.g. <Title> appears under both DocumentTitle and Vulnerability).
    path: Vec<String>,
    // Most recent attribute payload, keyed by attribute name; cleared on
    // each Start.
    current_attrs: HashMap<String, String>,
    // Product tree: ProductID -> human name.
    product_tree: HashMap<String, String>,
    // Most recent product id seen on a <FullProductName>.
    pending_product_id: Option<String>,
    pending_product_name: String,
    // Accumulated text buffer for the deepest open element.
    text_buf: String,
    // In-progress vulnerability.
    current: Option<VulnBuilder>,
    advisories: Vec<VendorAdvisory>,
}

#[derive(Debug, Default)]
struct VulnBuilder {
    cve: String,
    title: String,
    description: Option<String>,
    note_type: Option<String>,
    references: Vec<String>,
    affected_product_ids: Vec<String>,
    fixed_version: Option<String>,
    fixed_url: Option<String>,
    remediation_type: Option<String>,
    product_status_type: Option<String>,
}

impl ParserState {
    fn on_start(&mut self, e: &BytesStart<'_>) -> Result<(), MsrcParseError> {
        let name = local_name(e.name())?;
        self.current_attrs.clear();
        for attr in e.attributes() {
            let attr = attr.map_err(|err| MsrcParseError::Xml(err.into()))?;
            let key = std::str::from_utf8(attr.key.as_ref())
                .map_err(|err| MsrcParseError::Encoding(err.to_string()))?
                .to_string();
            // No `reader` in scope here — use `normalized_value` (which
            // does XML entity unescape without needing charset decoding
            // since attribute values are always UTF-8 in XML 1.0).
            let val = attr
                .normalized_value(quick_xml::XmlVersion::default())
                .map_err(|err| MsrcParseError::Encoding(err.to_string()))?
                .into_owned();
            // Strip namespace prefix on attribute keys.
            let key = key.rsplit(':').next().unwrap_or(&key).to_string();
            self.current_attrs.insert(key, val);
        }
        self.text_buf.clear();

        match name.as_str() {
            "cvrfdoc" => self.saw_document_root = true,
            "Vulnerability" => {
                self.current = Some(VulnBuilder::default());
            }
            "Note" => {
                if let Some(ref mut v) = self.current {
                    v.note_type = self.current_attrs.get("Type").cloned();
                }
            }
            "Remediation" => {
                if let Some(ref mut v) = self.current {
                    v.remediation_type = self.current_attrs.get("Type").cloned();
                }
            }
            "ProductStatuses" => {
                if let Some(ref mut v) = self.current {
                    v.product_status_type = self.current_attrs.get("Type").cloned();
                }
            }
            "Status" => {
                // Per CVRF v1.1 the status is encoded as `<Status Type="...">`
                // wrapping `<ProductID>` children; older docs put it on
                // `<ProductStatuses>`. Honour whichever appears closest.
                if let Some(ref mut v) = self.current {
                    if let Some(t) = self.current_attrs.get("Type") {
                        v.product_status_type = Some(t.clone());
                    }
                }
            }
            "FullProductName" => {
                self.pending_product_id = self.current_attrs.get("ProductID").cloned();
                self.pending_product_name.clear();
            }
            _ => {}
        }
        self.path.push(name);
        Ok(())
    }

    fn on_end(&mut self, e: &quick_xml::events::BytesEnd<'_>) -> Result<(), MsrcParseError> {
        self.on_end_name(e.name())
    }

    fn on_end_name(&mut self, qname: QName<'_>) -> Result<(), MsrcParseError> {
        let name = local_name(qname)?;
        let popped = self.path.pop();
        if popped.as_deref() != Some(name.as_str()) {
            // Unbalanced tag — quick-xml usually catches this first, but
            // belt-and-braces.
            return Err(MsrcParseError::UnexpectedShape(format!(
                "unbalanced close: expected </{}>, saw </{name}>",
                popped.as_deref().unwrap_or("<root>"),
            )));
        }

        let text = std::mem::take(&mut self.text_buf);
        let trimmed_text = text.trim().to_string();
        self.dispatch_close(name.as_str(), trimmed_text);
        Ok(())
    }

    fn dispatch_close(&mut self, name: &str, trimmed_text: String) {
        match name {
            "DocumentTitle" => self.close_document_title(trimmed_text),
            "FullProductName" => self.close_full_product_name(trimmed_text),
            "CVE" => {
                if let Some(v) = self.current.as_mut() {
                    v.cve = trimmed_text;
                }
            }
            "Title" => self.close_vuln_title(trimmed_text),
            "Note" => self.close_note(trimmed_text),
            "URL" => self.close_url(trimmed_text),
            "Description" => self.close_remediation_description(trimmed_text),
            "ProductID" => self.close_product_id(trimmed_text),
            "Remediation" => {
                if let Some(v) = self.current.as_mut() {
                    v.remediation_type = None;
                }
            }
            "ProductStatuses" | "Status" => {
                if let Some(v) = self.current.as_mut() {
                    v.product_status_type = None;
                }
            }
            "Vulnerability" => self.close_vulnerability(),
            _ => {}
        }
    }

    fn close_document_title(&mut self, trimmed_text: String) {
        let nested = self.path.last().map(String::as_str) == Some("DocumentTracking")
            || self.in_vulnerability();
        if !nested {
            self.document_title = trimmed_text;
        }
    }

    fn close_full_product_name(&mut self, trimmed_text: String) {
        if let Some(id) = self.pending_product_id.take() {
            let resolved = if trimmed_text.is_empty() {
                self.pending_product_name.trim().to_string()
            } else {
                trimmed_text
            };
            self.product_tree.insert(id, resolved);
        }
        self.pending_product_name.clear();
    }

    fn close_vuln_title(&mut self, trimmed_text: String) {
        if let Some(v) = self.current.as_mut() {
            if v.title.is_empty() {
                v.title = trimmed_text;
            }
        }
    }

    fn close_note(&mut self, trimmed_text: String) {
        if let Some(v) = self.current.as_mut() {
            let is_description = v
                .note_type
                .as_deref()
                .is_some_and(|t| t.eq_ignore_ascii_case("Description"));
            if is_description && v.description.is_none() && !trimmed_text.is_empty() {
                v.description = Some(trimmed_text);
            }
            v.note_type = None;
        }
    }

    fn close_url(&mut self, trimmed_text: String) {
        // Per CVRF the <URL> child can appear under <Reference> or
        // under <Remediation>. Disambiguate by walking back up the path
        // stack.
        let Some(v) = self.current.as_mut() else {
            return;
        };
        if path_contains(&self.path, "Remediation") {
            if v.fixed_url.is_none() && !trimmed_text.is_empty() {
                v.fixed_url = Some(trimmed_text);
            }
        } else if (path_contains(&self.path, "Reference")
            || path_contains(&self.path, "References"))
            && !trimmed_text.is_empty()
        {
            v.references.push(trimmed_text);
        }
    }

    fn close_remediation_description(&mut self, trimmed_text: String) {
        if let Some(v) = self.current.as_mut() {
            // Used inside <Remediation> as a fix summary.
            if path_contains(&self.path, "Remediation")
                && v.fixed_version.is_none()
                && !trimmed_text.is_empty()
            {
                v.fixed_version = Some(trimmed_text);
            }
        }
    }

    fn close_product_id(&mut self, trimmed_text: String) {
        if let Some(v) = self.current.as_mut() {
            let is_affected = v
                .product_status_type
                .as_deref()
                .is_some_and(|t| t.eq_ignore_ascii_case("Known Affected"));
            if is_affected && !trimmed_text.is_empty() {
                v.affected_product_ids.push(trimmed_text);
            }
        }
    }

    fn close_vulnerability(&mut self) {
        if let Some(builder) = self.current.take() {
            if let Some(adv) = builder.build(&self.product_tree, &self.document_title) {
                self.advisories.push(adv);
            }
        }
    }

    fn on_text(&mut self, s: &str) {
        if self.path.last().map(String::as_str) == Some("FullProductName") {
            self.pending_product_name.push_str(s);
        }
        self.text_buf.push_str(s);
    }

    fn in_vulnerability(&self) -> bool {
        self.path.iter().any(|n| n == "Vulnerability")
    }

    fn into_advisories(self) -> Vec<VendorAdvisory> {
        self.advisories
    }
}

impl VulnBuilder {
    fn build(
        self,
        product_tree: &HashMap<String, String>,
        document_title: &str,
    ) -> Option<VendorAdvisory> {
        if self.cve.is_empty() {
            return None;
        }
        let cve = CveId::new(&self.cve).ok()?;
        // The CVE id itself is the advisory id — MSRC does not mint a
        // separate ADV-NNN identifier in CVRF.
        let advisory_id = self.cve.clone();

        let summary_base = if self.title.is_empty() {
            document_title.to_string()
        } else {
            self.title.clone()
        };
        let summary = match (&self.description, &self.fixed_version) {
            (Some(desc), Some(fv)) => format!("{summary_base} — {desc} (fix: {fv})"),
            (Some(desc), None) => format!("{summary_base} — {desc}"),
            (None, Some(fv)) => format!("{summary_base} (fix: {fv})"),
            (None, None) => summary_base,
        };

        let patch_url = self.fixed_url.as_deref().and_then(|u| Url::parse(u).ok());
        let patches = vec![Patch::new(self.cve.clone(), summary, patch_url)];

        let references: Vec<Url> = self
            .references
            .iter()
            .filter_map(|r| Url::parse(r).ok())
            .collect();

        // Stash affected product names into the advisory description by
        // appending to the first patch's summary — the canonical
        // VendorAdvisory model has no dedicated affected-product field, so
        // we surface them through the existing summary contract.
        let mut patches = patches;
        if !self.affected_product_ids.is_empty() {
            let names: Vec<String> = self
                .affected_product_ids
                .iter()
                .map(|id| product_tree.get(id).cloned().unwrap_or_else(|| id.clone()))
                .collect();
            if let Some(p) = patches.first_mut() {
                p.summary = format!("{} [affects: {}]", p.summary, names.join(", "));
            }
        }

        Some(VendorAdvisory::new(
            VENDOR,
            advisory_id,
            vec![cve],
            patches,
            references,
            OffsetDateTime::UNIX_EPOCH,
        ))
    }
}

fn local_name(qname: QName<'_>) -> Result<String, MsrcParseError> {
    let raw =
        std::str::from_utf8(qname.as_ref()).map_err(|e| MsrcParseError::Encoding(e.to_string()))?;
    Ok(raw.rsplit(':').next().unwrap_or(raw).to_string())
}

fn path_contains(path: &[String], name: &str) -> bool {
    path.iter().any(|n| n == name)
}

fn parse_cve_year(cve: &CveId) -> Result<i32, RemediationError> {
    let s = cve.as_str();
    let mut parts = s.split('-');
    let (_prefix, year) = (
        parts
            .next()
            .ok_or_else(|| RemediationError::malformed(VENDOR, "cve missing prefix"))?,
        parts
            .next()
            .ok_or_else(|| RemediationError::malformed(VENDOR, "cve missing year"))?,
    );
    year.parse::<i32>()
        .map_err(|e| RemediationError::malformed(VENDOR, e.to_string()))
}

const fn month_abbrev(month: u32) -> Option<&'static str> {
    match month {
        1 => Some("Jan"),
        2 => Some("Feb"),
        3 => Some("Mar"),
        4 => Some("Apr"),
        5 => Some("May"),
        6 => Some("Jun"),
        7 => Some("Jul"),
        8 => Some("Aug"),
        9 => Some("Sep"),
        10 => Some("Oct"),
        11 => Some("Nov"),
        12 => Some("Dec"),
        _ => None,
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::single_char_pattern,
    clippy::single_char_add_str,
    clippy::float_cmp,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;

    const MINIMAL_CVRF: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<cvrfdoc xmlns="http://www.icasi.org/CVRF/schema/cvrf/1.1">
  <DocumentTitle>January 2024 Security Updates</DocumentTitle>
  <DocumentTracking>
    <Identification>
      <ID>2024-Jan</ID>
    </Identification>
  </DocumentTracking>
  <ProductTree>
    <FullProductName ProductID="10001">Windows 10</FullProductName>
  </ProductTree>
  <Vulnerability>
    <Title>Windows Remote Desktop Information Disclosure</Title>
    <Notes>
      <Note Type="Description" Ordinal="1">Allows remote disclosure of memory.</Note>
    </Notes>
    <CVE>CVE-2024-12345</CVE>
    <ProductStatuses>
      <Status Type="Known Affected">
        <ProductID>10001</ProductID>
      </Status>
    </ProductStatuses>
    <Remediations>
      <Remediation Type="Vendor Fix">
        <Description>Apply KB5031356</Description>
        <URL>https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-12345</URL>
      </Remediation>
    </Remediations>
    <References>
      <Reference Type="Self">
        <URL>https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-12345</URL>
        <Description>MSRC advisory</Description>
      </Reference>
    </References>
  </Vulnerability>
</cvrfdoc>
"#;

    #[test]
    fn parse_cvrf_parses_minimal_document() {
        let out = parse_cvrf(MINIMAL_CVRF).unwrap();
        assert_eq!(out.len(), 1);
        let adv = &out[0];
        assert_eq!(adv.vendor, "msrc");
        assert_eq!(adv.advisory_id, "CVE-2024-12345");
        assert_eq!(adv.cves.len(), 1);
        assert_eq!(adv.cves[0].as_str(), "CVE-2024-12345");
        assert_eq!(adv.references.len(), 1);
        assert_eq!(adv.patches.len(), 1);
        let patch = &adv.patches[0];
        assert!(patch.summary.contains("Remote Desktop"));
        assert!(patch.summary.contains("Allows remote disclosure"));
        assert!(patch.summary.contains("KB5031356"));
        assert!(patch.summary.contains("Windows 10"));
        assert!(patch.url.is_some());
    }

    #[test]
    fn parse_cvrf_handles_multiple_vulnerabilities() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<cvrfdoc>
  <DocumentTitle>Batch</DocumentTitle>
  <Vulnerability>
    <Title>A</Title>
    <CVE>CVE-2024-1111</CVE>
  </Vulnerability>
  <Vulnerability>
    <Title>B</Title>
    <CVE>CVE-2024-2222</CVE>
  </Vulnerability>
  <Vulnerability>
    <Title>C</Title>
    <CVE>CVE-2024-3333</CVE>
  </Vulnerability>
</cvrfdoc>
"#;
        let out = parse_cvrf(xml).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].cves[0].as_str(), "CVE-2024-1111");
        assert_eq!(out[1].cves[0].as_str(), "CVE-2024-2222");
        assert_eq!(out[2].cves[0].as_str(), "CVE-2024-3333");
    }

    #[test]
    fn parse_cvrf_returns_unexpected_shape_on_empty_body() {
        let err = parse_cvrf("").unwrap_err();
        match err {
            MsrcParseError::UnexpectedShape(_) => {}
            other => panic!("expected UnexpectedShape, got {other}"),
        }
    }

    #[test]
    fn parse_cvrf_returns_unexpected_shape_on_missing_root() {
        let xml = r#"<?xml version="1.0"?>
<somethingelse><inner/></somethingelse>"#;
        let err = parse_cvrf(xml).unwrap_err();
        match err {
            MsrcParseError::UnexpectedShape(msg) => assert!(msg.contains("cvrfdoc")),
            other => panic!("expected UnexpectedShape, got {other}"),
        }
    }

    #[test]
    fn parse_cvrf_handles_cdata_in_notes() {
        let xml = r#"<?xml version="1.0"?>
<cvrfdoc>
  <DocumentTitle>X</DocumentTitle>
  <Vulnerability>
    <Title>CDATA Test</Title>
    <Notes>
      <Note Type="Description"><![CDATA[Body with <html> & "quotes" inside.]]></Note>
    </Notes>
    <CVE>CVE-2024-4444</CVE>
  </Vulnerability>
</cvrfdoc>
"#;
        let out = parse_cvrf(xml).unwrap();
        assert_eq!(out.len(), 1);
        let summary = &out[0].patches[0].summary;
        assert!(summary.contains("Body with <html>"));
        assert!(summary.contains("\"quotes\""));
    }

    #[test]
    fn parse_cvrf_resolves_product_id_to_name() {
        let xml = r#"<?xml version="1.0"?>
<cvrfdoc>
  <DocumentTitle>X</DocumentTitle>
  <ProductTree>
    <FullProductName ProductID="42">Windows Server 2022</FullProductName>
    <FullProductName ProductID="99">Azure Stack HCI</FullProductName>
  </ProductTree>
  <Vulnerability>
    <Title>RCE</Title>
    <CVE>CVE-2024-5555</CVE>
    <ProductStatuses>
      <Status Type="Known Affected">
        <ProductID>42</ProductID>
        <ProductID>99</ProductID>
      </Status>
    </ProductStatuses>
  </Vulnerability>
</cvrfdoc>
"#;
        let out = parse_cvrf(xml).unwrap();
        assert_eq!(out.len(), 1);
        let summary = &out[0].patches[0].summary;
        assert!(
            summary.contains("Windows Server 2022"),
            "missing product name: {summary}"
        );
        assert!(
            summary.contains("Azure Stack HCI"),
            "missing product name: {summary}"
        );
    }

    #[test]
    fn parse_cvrf_rejects_unclosed_tags() {
        let xml = r#"<?xml version="1.0"?>
<cvrfdoc>
  <DocumentTitle>Broken
</cvrfdoc>
"#;
        let err = parse_cvrf(xml).unwrap_err();
        match err {
            MsrcParseError::Xml(_) | MsrcParseError::UnexpectedShape(_) => {}
            MsrcParseError::Encoding(msg) => {
                panic!("expected Xml/UnexpectedShape, got Encoding({msg})")
            }
        }
    }

    #[test]
    fn msrc_source_constructs_correct_url_for_cve() {
        let s = MsrcSource::with_client(reqwest::Client::new());
        let cve = CveId::new("CVE-2024-12345").unwrap();
        let url = s.build_url_for_cve(&cve).unwrap();
        assert_eq!(
            url.as_str(),
            "https://api.msrc.microsoft.com/cvrf/v2.0/document/2024-Jan",
        );
    }

    #[test]
    fn msrc_year_month_builder() {
        let s = MsrcSource::with_client(reqwest::Client::new());
        let url = s.build_year_month_url(2024, 7).unwrap();
        assert!(url.as_str().ends_with("2024-Jul"));
    }

    #[test]
    fn msrc_rejects_invalid_month() {
        let s = MsrcSource::with_client(reqwest::Client::new());
        assert!(s.build_year_month_url(2024, 0).is_err());
        assert!(s.build_year_month_url(2024, 13).is_err());
    }

    #[test]
    fn vendor_slug_is_lowercase() {
        let s = MsrcSource::with_client(reqwest::Client::new());
        assert_eq!(s.vendor(), "msrc");
    }

    #[test]
    fn parse_error_display_includes_kind() {
        let e = MsrcParseError::UnexpectedShape("nope".into());
        assert!(e.to_string().contains("unexpected shape"));
    }

    #[tokio::test]
    #[ignore = "Requires live MSRC API access"]
    async fn fetch_bulletin_live_smoke() {
        let s = MsrcSource::new().unwrap();
        let out = s.fetch_bulletin("2024-Jan").await.unwrap();
        assert!(!out.is_empty(), "live bulletin should yield at least 1 row");
    }
}
