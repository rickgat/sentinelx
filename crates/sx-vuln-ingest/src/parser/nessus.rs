//! Nessus `.nessus` (NessusClientData_v2) XML parser.
//!
//! Document shape (simplified):
//!
//! ```xml
//! <NessusClientData_v2>
//!   <Report name="...">
//!     <ReportHost name="10.0.0.1">
//!       <HostProperties>
//!         <tag name="host-ip">10.0.0.1</tag>
//!         <tag name="host-fqdn">host.example.com</tag>
//!       </HostProperties>
//!       <ReportItem pluginID="12345" pluginName="..." severity="3">
//!         <description>...</description>
//!         <solution>...</solution>
//!         <cve>CVE-2024-12345</cve>
//!         <cvss3_base_score>7.5</cvss3_base_score>
//!       </ReportItem>
//!     </ReportHost>
//!   </Report>
//! </NessusClientData_v2>
//! ```

use quick_xml::events::{BytesStart, Event};
use quick_xml::name::QName;
use quick_xml::Reader;

use crate::model::{NormalizedFinding, Severity, SourceFormat, VulnIngestError};
use crate::registry::CheckIdRegistry;

/// Parse a Nessus `.nessus` body into a flat list of normalized findings.
///
/// The list is **not** deduplicated — pass through [`crate::dedup::deduplicate`]
/// before persistence. Findings missing `pluginID` or with an empty host
/// name are dropped (counted as `parse_errors` by the service layer).
pub fn parse(
    xml: &str,
    registry: &CheckIdRegistry,
) -> Result<Vec<NormalizedFinding>, VulnIngestError> {
    let trimmed = xml.trim();
    if trimmed.is_empty() {
        return Err(VulnIngestError::UnrecognisedShape("empty body".into()));
    }
    if !trimmed.contains("NessusClientData_v2") && !trimmed.contains("<Report") {
        return Err(VulnIngestError::UnrecognisedShape(
            "missing NessusClientData_v2 / Report root".into(),
        ));
    }

    let mut reader = Reader::from_str(xml);
    let cfg = reader.config_mut();
    cfg.trim_text(true);
    cfg.expand_empty_elements = false;

    let mut state = ParseState::default();
    let mut buf = Vec::new();
    let mut findings: Vec<NormalizedFinding> = Vec::new();
    let mut saw_root = false;

    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| VulnIngestError::Xml(e.to_string()))?
        {
            Event::Eof => break,
            Event::Start(ref e) => {
                let local = local_name(e.name());
                match local.as_str() {
                    "NessusClientData_v2" | "Report" => {
                        saw_root = true;
                    }
                    "ReportHost" => {
                        state.current_host = read_attr(e, "name").unwrap_or_default();
                    }
                    "ReportItem" => {
                        state.in_item = true;
                        state.item_plugin_id = read_attr(e, "pluginID").unwrap_or_default();
                        state.item_plugin_name = read_attr(e, "pluginName").unwrap_or_default();
                        state.item_severity = read_attr(e, "severity")
                            .as_deref()
                            .and_then(|s| s.parse::<u8>().ok())
                            .unwrap_or(0);
                        state.item_desc.clear();
                        state.item_solution.clear();
                        state.item_cve.clear();
                        state.item_cvss3.clear();
                        state.field = None;
                    }
                    "description" | "solution" | "cve" | "cvss3_base_score" if state.in_item => {
                        state.field = Some(local);
                    }
                    _ => {}
                }
            }
            Event::Empty(ref e) => {
                // Self-closing `<tag name=".." />` or empty `<cve/>`.
                let local = local_name(e.name());
                if local == "ReportItem" {
                    // Self-closing item: emit immediately if pluginID present.
                    let id = read_attr(e, "pluginID").unwrap_or_default();
                    let name = read_attr(e, "pluginName").unwrap_or_default();
                    let sev = read_attr(e, "severity")
                        .as_deref()
                        .and_then(|s| s.parse::<u8>().ok())
                        .unwrap_or(0);
                    if !id.is_empty() && !state.current_host.is_empty() {
                        findings.push(NormalizedFinding {
                            check_id: registry.resolve(SourceFormat::Nessus, &id),
                            external_id: id,
                            asset_id: state.current_host.clone(),
                            severity: Severity::from_nessus_rank(sev),
                            title: name,
                            description: String::new(),
                            cve: None,
                            cvss_v3: None,
                            remediation: None,
                            source: SourceFormat::Nessus,
                        });
                    }
                }
            }
            Event::End(ref e) => {
                let local = local_name(e.name());
                match local.as_str() {
                    "ReportHost" => {
                        state.current_host.clear();
                    }
                    "ReportItem" if state.in_item => {
                        if !state.item_plugin_id.is_empty() && !state.current_host.is_empty() {
                            let cvss = state
                                .item_cvss3
                                .trim()
                                .parse::<f64>()
                                .ok()
                                .filter(|v| (0.0..=10.0).contains(v));
                            let cve = state
                                .item_cve
                                .split(['\n', ' ', ',', ';'])
                                .map(str::trim)
                                .find(|s| s.starts_with("CVE-") || s.starts_with("cve-"))
                                .map(str::to_ascii_uppercase);
                            findings.push(NormalizedFinding {
                                check_id: registry
                                    .resolve(SourceFormat::Nessus, &state.item_plugin_id),
                                external_id: std::mem::take(&mut state.item_plugin_id),
                                asset_id: state.current_host.clone(),
                                severity: Severity::from_nessus_rank(state.item_severity),
                                title: std::mem::take(&mut state.item_plugin_name),
                                description: std::mem::take(&mut state.item_desc).trim().to_owned(),
                                cve,
                                cvss_v3: cvss,
                                remediation: Some(
                                    std::mem::take(&mut state.item_solution).trim().to_owned(),
                                )
                                .filter(|s| !s.is_empty()),
                                source: SourceFormat::Nessus,
                            });
                        }
                        state.in_item = false;
                        state.field = None;
                    }
                    "description" | "solution" | "cve" | "cvss3_base_score" if state.in_item => {
                        state.field = None;
                    }
                    _ => {}
                }
            }
            Event::Text(ref t) => {
                if let Some(field) = state.field.as_deref() {
                    let raw = t
                        .xml_content(quick_xml::XmlVersion::default())
                        .map_err(|e| VulnIngestError::Xml(e.to_string()))?;
                    match field {
                        "description" => state.item_desc.push_str(&raw),
                        "solution" => state.item_solution.push_str(&raw),
                        "cve" => {
                            if !state.item_cve.is_empty() {
                                state.item_cve.push('\n');
                            }
                            state.item_cve.push_str(&raw);
                        }
                        "cvss3_base_score" => state.item_cvss3.push_str(&raw),
                        _ => {}
                    }
                }
            }
            Event::CData(ref c) => {
                if let Some(field) = state.field.as_deref() {
                    let raw = std::str::from_utf8(c.as_ref())
                        .map_err(|e| VulnIngestError::Xml(e.to_string()))?;
                    match field {
                        "description" => state.item_desc.push_str(raw),
                        "solution" => state.item_solution.push_str(raw),
                        "cve" => state.item_cve.push_str(raw),
                        "cvss3_base_score" => state.item_cvss3.push_str(raw),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        buf.clear();
    }

    if !saw_root {
        return Err(VulnIngestError::UnrecognisedShape(
            "no NessusClientData_v2 / Report root element".into(),
        ));
    }

    Ok(findings)
}

#[derive(Debug, Default)]
struct ParseState {
    current_host: String,
    in_item: bool,
    item_plugin_id: String,
    item_plugin_name: String,
    item_severity: u8,
    item_desc: String,
    item_solution: String,
    item_cve: String,
    item_cvss3: String,
    field: Option<String>,
}

fn local_name(name: QName<'_>) -> String {
    let bytes = name.as_ref();
    let local = bytes.rsplit(|b| *b == b':').next().unwrap_or(bytes);
    String::from_utf8_lossy(local).into_owned()
}

fn read_attr(start: &BytesStart<'_>, key: &str) -> Option<String> {
    for attr in start.attributes().flatten() {
        let key_bytes: &[u8] = attr.key.as_ref();
        if key_bytes == key.as_bytes() {
            return Some(String::from_utf8_lossy(attr.value.as_ref()).into_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_BASIC: &str = r#"<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Test Scan">
    <ReportHost name="10.0.0.1">
      <HostProperties>
        <tag name="host-ip">10.0.0.1</tag>
      </HostProperties>
      <ReportItem pluginID="11936" pluginName="OS Identification" severity="0">
        <description>The remote OS is Linux 4.x.</description>
        <solution>n/a</solution>
      </ReportItem>
      <ReportItem pluginID="51192" pluginName="SSL Cert Expired" severity="3">
        <description>The SSL certificate has expired.</description>
        <solution>Renew the certificate.</solution>
        <cve>CVE-2024-1234</cve>
        <cvss3_base_score>7.5</cvss3_base_score>
      </ReportItem>
    </ReportHost>
    <ReportHost name="10.0.0.2">
      <ReportItem pluginID="51192" pluginName="SSL Cert Expired" severity="3">
        <description>Another host with the same plugin.</description>
        <solution>Renew the certificate.</solution>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"#;

    #[test]
    fn parses_basic_fixture_into_three_findings() {
        let reg = CheckIdRegistry::new();
        let out = parse(FIXTURE_BASIC, &reg).unwrap();
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn assigns_host_correctly_across_blocks() {
        let reg = CheckIdRegistry::new();
        let out = parse(FIXTURE_BASIC, &reg).unwrap();
        let hosts: Vec<&str> = out.iter().map(|f| f.asset_id.as_str()).collect();
        assert!(hosts.contains(&"10.0.0.1"));
        assert!(hosts.contains(&"10.0.0.2"));
    }

    #[test]
    fn maps_severity_from_nessus_rank() {
        let reg = CheckIdRegistry::new();
        let out = parse(FIXTURE_BASIC, &reg).unwrap();
        let info = out
            .iter()
            .find(|f| f.external_id == "11936")
            .expect("plugin 11936");
        assert_eq!(info.severity, Severity::Info);
        let high = out
            .iter()
            .find(|f| f.external_id == "51192" && f.asset_id == "10.0.0.1")
            .expect("plugin 51192 on .1");
        assert_eq!(high.severity, Severity::High);
    }

    #[test]
    fn extracts_cve_and_cvss() {
        let reg = CheckIdRegistry::new();
        let out = parse(FIXTURE_BASIC, &reg).unwrap();
        let f = out
            .iter()
            .find(|f| f.asset_id == "10.0.0.1" && f.external_id == "51192")
            .unwrap();
        assert_eq!(f.cve.as_deref(), Some("CVE-2024-1234"));
        assert!((f.cvss_v3.unwrap() - 7.5).abs() < f64::EPSILON);
    }

    #[test]
    fn applies_registry_override() {
        let mut reg = CheckIdRegistry::new();
        reg.insert(SourceFormat::Nessus, "51192", "SX.CHK.TLS.CERT_EXPIRED");
        let out = parse(FIXTURE_BASIC, &reg).unwrap();
        let f = out
            .iter()
            .find(|f| f.external_id == "51192" && f.asset_id == "10.0.0.1")
            .unwrap();
        assert_eq!(f.check_id, "SX.CHK.TLS.CERT_EXPIRED");
    }

    #[test]
    fn rejects_empty_body() {
        let reg = CheckIdRegistry::new();
        let err = parse("", &reg).unwrap_err();
        assert!(matches!(err, VulnIngestError::UnrecognisedShape(_)));
    }

    #[test]
    fn rejects_unrelated_xml() {
        let reg = CheckIdRegistry::new();
        let err = parse("<random/>", &reg).unwrap_err();
        assert!(matches!(err, VulnIngestError::UnrecognisedShape(_)));
    }

    #[test]
    fn skips_item_without_plugin_id() {
        let xml = r#"<NessusClientData_v2><Report><ReportHost name="h">
            <ReportItem pluginName="No ID"></ReportItem>
        </ReportHost></Report></NessusClientData_v2>"#;
        let reg = CheckIdRegistry::new();
        let out = parse(xml, &reg).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn handles_critical_severity() {
        let xml = r#"<NessusClientData_v2><Report><ReportHost name="h">
            <ReportItem pluginID="9" pluginName="x" severity="4">
                <description>d</description><solution>s</solution>
            </ReportItem>
        </ReportHost></Report></NessusClientData_v2>"#;
        let reg = CheckIdRegistry::new();
        let out = parse(xml, &reg).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::Critical);
    }

    #[test]
    fn ignores_findings_with_no_host() {
        let xml = r#"<NessusClientData_v2><Report>
            <ReportItem pluginID="1" pluginName="orphan" severity="0"></ReportItem>
        </Report></NessusClientData_v2>"#;
        let reg = CheckIdRegistry::new();
        let out = parse(xml, &reg).unwrap();
        assert!(out.is_empty());
    }
}
