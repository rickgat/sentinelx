//! SARIF 2.1.0 renderer.
//!
//! Spec: <https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html>
//!
//! The renderer constructs the object directly via [`serde_json::Value`]
//! to avoid pulling a heavy SARIF crate. The mapping is intentionally
//! conservative — only fields the spec marks required (or that downstream
//! ingestors care about in practice) are populated.

use async_trait::async_trait;
use serde_json::{json, Map, Value};
use sx_core::value_object::severity::Severity;
use url::Url;

use crate::error::ReportError;
use crate::model::report::ReportContext;
use crate::port::{Renderer, ReportArtifact, ReportFormat};

/// SARIF 2.1.0 renderer.
#[derive(Debug, Default, Clone, Copy)]
pub struct SarifRenderer;

impl SarifRenderer {
    /// Construct a [`SarifRenderer`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";

#[async_trait]
impl Renderer for SarifRenderer {
    fn format(&self) -> ReportFormat {
        ReportFormat::Sarif
    }

    async fn render(&self, ctx: &ReportContext) -> Result<ReportArtifact, ReportError> {
        let mut rules: Vec<Value> = Vec::with_capacity(ctx.findings.len());
        let mut results: Vec<Value> = Vec::with_capacity(ctx.findings.len());

        for f in &ctx.findings {
            let rule_id = format!("sx.{}", f.id);
            let level = severity_to_sarif_level(f.severity);

            let mut rule = Map::new();
            rule.insert("id".to_owned(), Value::String(rule_id.clone()));
            rule.insert(
                "name".to_owned(),
                Value::String(f.title.replace([' ', '\t'], "_")),
            );
            rule.insert("shortDescription".to_owned(), json!({ "text": f.title }));
            if !f.description.is_empty() {
                rule.insert(
                    "fullDescription".to_owned(),
                    json!({ "text": f.description }),
                );
            }
            rule.insert("defaultConfiguration".to_owned(), json!({ "level": level }));
            if let Some(first_ref) = f.references.first() {
                rule.insert("helpUri".to_owned(), Value::String(first_ref.clone()));
            }
            rules.push(Value::Object(rule));

            let mut result = Map::new();
            result.insert("ruleId".to_owned(), Value::String(rule_id));
            result.insert("level".to_owned(), Value::String(level.to_owned()));
            result.insert("message".to_owned(), json!({ "text": f.title }));
            if let Some(loc) = build_location(&f.asset_label) {
                result.insert("locations".to_owned(), Value::Array(vec![loc]));
            }
            if let Some(score) = f.cvss_primary() {
                result.insert(
                    "properties".to_owned(),
                    json!({
                        "security-severity": format!("{score:.1}"),
                        "severity": f.severity.to_string(),
                        "status": f.status,
                    }),
                );
            } else {
                result.insert(
                    "properties".to_owned(),
                    json!({
                        "severity": f.severity.to_string(),
                        "status": f.status,
                    }),
                );
            }
            results.push(Value::Object(result));
        }

        let driver = json!({
            "name": "SentinelX",
            "version": env!("CARGO_PKG_VERSION"),
            "informationUri": "https://example.invalid/sentinelx",
            "rules": rules,
        });
        let run = json!({
            "tool": { "driver": driver },
            "invocations": [{
                "executionSuccessful": true,
                "endTimeUtc": format_utc(&ctx.generated_at),
            }],
            "results": results,
            "properties": {
                "tenantId": ctx.tenant_id.to_string(),
                "engagementId": ctx.engagement_id.to_string(),
                "engagementName": ctx.engagement_name,
            },
        });
        let doc = json!({
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [run],
        });

        let bytes =
            serde_json::to_vec_pretty(&doc).map_err(|e| ReportError::json(e.to_string()))?;
        let filename = format!("findings-{}.sarif.json", ctx.date_slug());
        ReportArtifact::new(ReportFormat::Sarif, filename, bytes)
    }
}

const fn severity_to_sarif_level(s: Severity) -> &'static str {
    // SARIF level enum: none, note, warning, error.
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
        Severity::Info => "none",
    }
}

fn build_location(asset_label: &str) -> Option<Value> {
    // SARIF locations only make sense if the asset is addressable.
    if Url::parse(asset_label).is_err() {
        return None;
    }
    Some(json!({
        "physicalLocation": {
            "artifactLocation": { "uri": asset_label }
        }
    }))
}

fn format_utc(dt: &time::OffsetDateTime) -> String {
    // RFC 3339, second precision, Z suffix.
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::model::posture::PostureSummary;
    use crate::model::report_finding::ReportFinding;
    use sx_core::value_object::ids::{EngagementId, FindingId, TenantId};
    use time::macros::datetime;

    fn ctx(findings: Vec<ReportFinding>) -> ReportContext {
        ReportContext::new(
            TenantId::new(),
            EngagementId::new(),
            "Acme",
            "Q2 Engagement",
            "ops",
            datetime!(2026-05-30 12:00:00 UTC),
            PostureSummary::empty(),
            findings,
        )
        .unwrap()
    }

    fn finding(sev: Severity, asset: &str) -> ReportFinding {
        ReportFinding::new(
            FindingId::new(),
            asset,
            sev,
            "Demo issue",
            "Detailed description.",
            None,
            "discovered",
            vec!["https://example.com/advisory".to_owned()],
        )
        .unwrap()
    }

    #[tokio::test]
    async fn sarif_run_includes_tool_driver_and_results() {
        let c = ctx(vec![
            finding(Severity::High, "https://api.example.com/login"),
            finding(Severity::Medium, "not-a-url"),
        ]);
        let art = SarifRenderer::new().render(&c).await.unwrap();
        let v: Value = serde_json::from_slice(&art.bytes).unwrap();
        assert_eq!(v["version"], json!("2.1.0"));
        let driver = &v["runs"][0]["tool"]["driver"];
        assert_eq!(driver["name"], json!("SentinelX"));
        assert!(driver["version"].is_string());
        let results = &v["runs"][0]["results"];
        assert_eq!(results.as_array().unwrap().len(), 2);
        // First finding has a URL asset => location is set.
        assert!(results[0]["locations"].is_array());
        // Second finding asset is not a URL => no locations.
        assert!(results[1].get("locations").is_none());
    }

    #[tokio::test]
    async fn sarif_severity_maps_critical_to_error() {
        let c = ctx(vec![finding(Severity::Critical, "x.example.com")]);
        let art = SarifRenderer::new().render(&c).await.unwrap();
        let v: Value = serde_json::from_slice(&art.bytes).unwrap();
        let level = &v["runs"][0]["results"][0]["level"];
        assert_eq!(level, &json!("error"));
    }
}
