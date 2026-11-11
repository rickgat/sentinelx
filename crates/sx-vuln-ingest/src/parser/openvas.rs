//! OpenVAS / Greenbone GMP XML report parser.
//!
//! Document shape (simplified):
//!
//! ```xml
//! <report>
//!   <results>
//!     <result id="...">
//!       <host>10.0.0.1<hostname>host.example.com</hostname></host>
//!       <nvt oid="1.3.6.1.4.1.25623.1.0.103674">
//!         <name>OpenSSL ...</name>
//!         <cvss_base>7.5</cvss_base>
//!         <refs><ref type="cve" id="CVE-2024-12345"/></refs>
//!       </nvt>
//!       <threat>High</threat>
//!       <severity>7.5</severity>
//!       <description>...</description>
//!     </result>
//!   </results>
//! </report>
//! ```

use quick_xml::events::{BytesStart, Event};
use quick_xml::name::QName;
use quick_xml::Reader;

use crate::model::{NormalizedFinding, Severity, SourceFormat, VulnIngestError};
use crate::registry::CheckIdRegistry;

/// Parse an OpenVAS XML report body into a flat list of normalized
/// findings. Not deduplicated — pass through [`crate::dedup::deduplicate`].
pub fn parse(
    xml: &str,
    registry: &CheckIdRegistry,
) -> Result<Vec<NormalizedFinding>, VulnIngestError> {
    let trimmed = xml.trim();
    if trimmed.is_empty() {
        return Err(VulnIngestError::UnrecognisedShape("empty body".into()));
    }
    if !trimmed.contains("<report") && !trimmed.contains("<get_reports_response") {
        return Err(VulnIngestError::UnrecognisedShape(
            "missing <report> root element".into(),
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
                    "report" | "get_reports_response" => {
                        saw_root = true;
                    }
                    "result" => {
                        state.reset_result();
                        state.in_result = true;
                    }
                    "nvt" if state.in_result => {
                        state.in_nvt = true;
                        state.oid = read_attr(e, "oid").unwrap_or_default();
                    }
                    "host" if state.in_result => {
                        state.field = Some(FieldKind::Host);
                    }
                    "hostname" if state.in_result => {
                        state.field = Some(FieldKind::Hostname);
                    }
                    "threat" if state.in_result => {
                        state.field = Some(FieldKind::Threat);
                    }
                    "severity" if state.in_result && !state.in_nvt => {
                        state.field = Some(FieldKind::Severity);
                    }
                    "description" if state.in_result => {
                        state.field = Some(FieldKind::Description);
                    }
                    "name" if state.in_nvt => {
                        state.field = Some(FieldKind::Name);
                    }
                    "cvss_base" if state.in_nvt => {
                        state.field = Some(FieldKind::CvssBase);
                    }
                    "solution" if state.in_nvt => {
                        state.field = Some(FieldKind::Solution);
                    }
                    _ => {}
                }
            }
            Event::Empty(ref e) => {
                let local = local_name(e.name());
                if local == "ref" && state.in_nvt {
                    let kind = read_attr(e, "type").unwrap_or_default();
                    if kind.eq_ignore_ascii_case("cve") {
                        let id = read_attr(e, "id").unwrap_or_default();
                        if !id.is_empty() && state.cve.is_none() {
                            state.cve = Some(id.to_ascii_uppercase());
                        }
                    }
                }
            }
            Event::End(ref e) => {
                let local = local_name(e.name());
                match local.as_str() {
                    "result" if state.in_result => {
                        emit_result(&mut state, registry, &mut findings);
                        state.in_result = false;
                    }
                    "nvt" => {
                        state.in_nvt = false;
                        state.field = None;
                    }
                    "host" | "hostname" | "threat" | "severity" | "description" | "name"
                    | "cvss_base" | "solution" => {
                        state.field = None;
                    }
                    _ => {}
                }
            }
            Event::Text(ref t) => {
                if let Some(field) = state.field {
                    let raw = t
                        .xml_content(quick_xml::XmlVersion::default())
                        .map_err(|e| VulnIngestError::Xml(e.to_string()))?;
                    push_field(&mut state, field, &raw);
                }
            }
            Event::CData(ref c) => {
                if let Some(field) = state.field {
                    let raw = std::str::from_utf8(c.as_ref())
                        .map_err(|e| VulnIngestError::Xml(e.to_string()))?;
                    push_field(&mut state, field, raw);
                }
            }
            _ => {}
        }
        buf.clear();
    }

    if !saw_root {
        return Err(VulnIngestError::UnrecognisedShape(
            "no <report> root element".into(),
        ));
    }

    Ok(findings)
}

fn push_field(state: &mut ParseState, field: FieldKind, raw: &str) {
    match field {
        FieldKind::Host => state.host.push_str(raw),
        FieldKind::Hostname => state.hostname.push_str(raw),
        FieldKind::Threat => state.threat.push_str(raw),
        FieldKind::Severity => state.severity_text.push_str(raw),
        FieldKind::Description => state.description.push_str(raw),
        FieldKind::Name => state.name.push_str(raw),
        FieldKind::CvssBase => state.cvss_base.push_str(raw),
        FieldKind::Solution => state.solution.push_str(raw),
    }
}

fn emit_result(
    state: &mut ParseState,
    registry: &CheckIdRegistry,
    out: &mut Vec<NormalizedFinding>,
) {
    let asset_id_raw = if state.hostname.trim().is_empty() {
        state.host.trim().to_owned()
    } else {
        state.hostname.trim().to_owned()
    };
    if asset_id_raw.is_empty() || state.oid.trim().is_empty() {
        return;
    }
    let cvss_v3 = state
        .cvss_base
        .trim()
        .parse::<f64>()
        .ok()
        .or_else(|| state.severity_text.trim().parse::<f64>().ok())
        .filter(|v| (0.0..=10.0).contains(v));
    let severity = if !state.threat.trim().is_empty() {
        Severity::from_openvas_threat(state.threat.trim())
    } else if let Some(score) = cvss_v3 {
        Severity::from_cvss(score)
    } else {
        Severity::Info
    };
    let remediation = if state.solution.trim().is_empty() {
        None
    } else {
        Some(state.solution.trim().to_owned())
    };
    let title = if state.name.trim().is_empty() {
        state.oid.clone()
    } else {
        state.name.trim().to_owned()
    };
    let oid = std::mem::take(&mut state.oid);
    out.push(NormalizedFinding {
        check_id: registry.resolve(SourceFormat::Openvas, &oid),
        external_id: oid,
        asset_id: asset_id_raw,
        severity,
        title,
        description: state.description.trim().to_owned(),
        cve: state.cve.take(),
        cvss_v3,
        remediation,
        source: SourceFormat::Openvas,
    });
}

#[derive(Debug, Default)]
struct ParseState {
    in_result: bool,
    in_nvt: bool,
    host: String,
    hostname: String,
    threat: String,
    severity_text: String,
    description: String,
    name: String,
    cvss_base: String,
    solution: String,
    oid: String,
    cve: Option<String>,
    field: Option<FieldKind>,
}

impl ParseState {
    fn reset_result(&mut self) {
        self.host.clear();
        self.hostname.clear();
        self.threat.clear();
        self.severity_text.clear();
        self.description.clear();
        self.name.clear();
        self.cvss_base.clear();
        self.solution.clear();
        self.oid.clear();
        self.cve = None;
        self.field = None;
    }
}

#[derive(Debug, Clone, Copy)]
enum FieldKind {
    Host,
    Hostname,
    Threat,
    Severity,
    Description,
    Name,
    CvssBase,
    Solution,
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
<report id="r1">
  <results>
    <result id="x1">
      <host>10.0.0.1</host>
      <nvt oid="1.3.6.1.4.1.25623.1.0.103674">
        <name>OpenSSL Outdated</name>
        <cvss_base>7.5</cvss_base>
        <solution>Upgrade OpenSSL.</solution>
        <refs><ref type="cve" id="CVE-2024-12345"/></refs>
      </nvt>
      <threat>High</threat>
      <severity>7.5</severity>
      <description>OpenSSL is outdated.</description>
    </result>
    <result id="x2">
      <host>10.0.0.2<hostname>host2.example.com</hostname></host>
      <nvt oid="1.3.6.1.4.1.25623.1.0.999999">
        <name>SSH weak ciphers</name>
        <cvss_base>5.0</cvss_base>
      </nvt>
      <threat>Medium</threat>
      <description>SSH allows weak ciphers.</description>
    </result>
    <result id="x3">
      <host>10.0.0.1</host>
      <nvt oid="1.3.6.1.4.1.25623.1.0.103674">
        <name>OpenSSL Outdated</name>
      </nvt>
      <threat>Log</threat>
      <description>repeat finding</description>
    </result>
  </results>
</report>
"#;

    #[test]
    fn parses_basic_fixture_into_three_findings() {
        let reg = CheckIdRegistry::new();
        let out = parse(FIXTURE_BASIC, &reg).unwrap();
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn prefers_hostname_over_ip_when_present() {
        let reg = CheckIdRegistry::new();
        let out = parse(FIXTURE_BASIC, &reg).unwrap();
        let f = out.iter().find(|f| f.title == "SSH weak ciphers").unwrap();
        assert_eq!(f.asset_id, "host2.example.com");
    }

    #[test]
    fn maps_threat_to_severity() {
        let reg = CheckIdRegistry::new();
        let out = parse(FIXTURE_BASIC, &reg).unwrap();
        let high = out
            .iter()
            .find(|f| f.title == "OpenSSL Outdated" && f.severity == Severity::High);
        assert!(high.is_some());
        let info = out
            .iter()
            .find(|f| f.description.contains("repeat finding"))
            .unwrap();
        assert_eq!(info.severity, Severity::Info);
    }

    #[test]
    fn extracts_cve_from_refs() {
        let reg = CheckIdRegistry::new();
        let out = parse(FIXTURE_BASIC, &reg).unwrap();
        let f = out
            .iter()
            .find(|f| f.title == "OpenSSL Outdated" && f.severity == Severity::High)
            .unwrap();
        assert_eq!(f.cve.as_deref(), Some("CVE-2024-12345"));
    }

    #[test]
    fn check_id_uses_last_oid_segment() {
        let reg = CheckIdRegistry::new();
        let out = parse(FIXTURE_BASIC, &reg).unwrap();
        for f in &out {
            assert!(f.check_id.starts_with("OPENVAS."));
        }
    }

    #[test]
    fn applies_registry_override() {
        let mut reg = CheckIdRegistry::new();
        reg.insert(
            SourceFormat::Openvas,
            "1.3.6.1.4.1.25623.1.0.103674",
            "SX.CHK.TLS.OPENSSL_OUTDATED",
        );
        let out = parse(FIXTURE_BASIC, &reg).unwrap();
        let any_override = out
            .iter()
            .any(|f| f.check_id == "SX.CHK.TLS.OPENSSL_OUTDATED");
        assert!(any_override);
    }

    #[test]
    fn rejects_empty_body() {
        let reg = CheckIdRegistry::new();
        assert!(matches!(
            parse("", &reg).unwrap_err(),
            VulnIngestError::UnrecognisedShape(_)
        ));
    }

    #[test]
    fn rejects_unrelated_xml() {
        let reg = CheckIdRegistry::new();
        assert!(matches!(
            parse("<random/>", &reg).unwrap_err(),
            VulnIngestError::UnrecognisedShape(_)
        ));
    }

    #[test]
    fn skips_result_with_missing_oid() {
        let xml = r"<report><results>
            <result><host>10.0.0.1</host><nvt><name>x</name></nvt><threat>Low</threat></result>
        </results></report>";
        let reg = CheckIdRegistry::new();
        let out = parse(xml, &reg).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn falls_back_to_severity_when_threat_absent() {
        let xml = r#"<report><results>
            <result>
                <host>10.0.0.1</host>
                <nvt oid="1.3.6.1.4.1.25623.1.0.123"><name>x</name></nvt>
                <severity>9.2</severity>
                <description>d</description>
            </result>
        </results></report>"#;
        let reg = CheckIdRegistry::new();
        let out = parse(xml, &reg).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::Critical);
    }
}
