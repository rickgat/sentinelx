//! Comprehensive cross-module report aggregator (#3).
//!
//! Server-side counterpart to the dashboard's `/dashboard/reporting` page:
//! aggregates the platform's live state into a single executive report and
//! renders it as a durable Markdown artifact (plus structured fields). The
//! dashboard composes client-side for interactivity; this port produces an
//! API-accessible, shareable document.
//!
//! Sources: the shared finding repository (severity / status posture) and
//! the process-wide compliance control catalog (framework coverage,
//! including the full PCI DSS v4.0.1 set). Additional module summaries can
//! be folded in behind the same port without changing callers.

use std::sync::Arc;

use async_trait::async_trait;
use sx_api::port::{ComprehensiveReportPort, ComprehensiveReportPortError, FindingRepositoryPort};
use sx_api::view::comprehensive_report_view::{
    ComprehensiveReportView, FrameworkCoverageView, SeverityCountView,
};
use sx_compliance::model::framework::Framework;
use sx_compliance::service::catalog::ControlCatalog;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Severity buckets in report order (highest first).
const SEVERITIES: [&str; 5] = ["critical", "high", "medium", "low", "info"];

/// Bundle handed to the composition root.
pub(crate) struct ComprehensiveReportBundle {
    /// HTTP-facing port bound onto `AppState`.
    pub port: Arc<dyn ComprehensiveReportPort>,
}

impl std::fmt::Debug for ComprehensiveReportBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComprehensiveReportBundle")
            .finish_non_exhaustive()
    }
}

/// Build the bundle over the shared finding repository.
pub(crate) fn build(findings: Arc<dyn FindingRepositoryPort>) -> ComprehensiveReportBundle {
    ComprehensiveReportBundle {
        port: Arc::new(ComprehensiveReportAdapter {
            findings,
            catalog: ControlCatalog::shared(),
        }),
    }
}

struct ComprehensiveReportAdapter {
    findings: Arc<dyn FindingRepositoryPort>,
    catalog: Arc<ControlCatalog>,
}

impl std::fmt::Debug for ComprehensiveReportAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComprehensiveReportAdapter")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl ComprehensiveReportPort for ComprehensiveReportAdapter {
    async fn generate(
        &self,
        tenant_id: &str,
    ) -> Result<ComprehensiveReportView, ComprehensiveReportPortError> {
        // Pull a bounded page of findings for the posture summary.
        let findings = self
            .findings
            .list(tenant_id, 0, 1000)
            .await
            .map_err(|e| ComprehensiveReportPortError::Internal(e.to_string()))?;

        let mut counts = [0u64; 5];
        for f in &findings {
            let sev = f.severity.to_ascii_lowercase();
            if let Some(slot) = SEVERITIES
                .iter()
                .position(|s| *s == sev)
                .and_then(|idx| counts.get_mut(idx))
            {
                *slot = slot.saturating_add(1);
            }
        }
        let total: u64 = counts.iter().sum();
        let at = |i: usize| counts.get(i).copied().unwrap_or(0);
        // Weighted posture: critical -15, high -7, medium -2, low -1.
        let penalty = at(0)
            .saturating_mul(15)
            .saturating_add(at(1).saturating_mul(7))
            .saturating_add(at(2).saturating_mul(2))
            .saturating_add(at(3));
        let posture_score = 100u64.saturating_sub(penalty.min(100));

        let by_severity: Vec<SeverityCountView> = SEVERITIES
            .iter()
            .enumerate()
            .map(|(i, s)| SeverityCountView {
                severity: (*s).to_owned(),
                count: at(i),
            })
            .collect();

        let compliance: Vec<FrameworkCoverageView> = Framework::all()
            .iter()
            .map(|fw| FrameworkCoverageView {
                framework: fw.code().to_owned(),
                controls: self.catalog.by_framework(*fw).len() as u64,
            })
            .collect();

        let generated_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());

        let markdown = render_markdown(
            tenant_id,
            &generated_at,
            total,
            posture_score,
            &by_severity,
            &compliance,
        );

        Ok(ComprehensiveReportView {
            generated_at,
            tenant_id: tenant_id.to_owned(),
            total_findings: total,
            posture_score,
            by_severity,
            compliance,
            markdown,
        })
    }
}

/// Render the report as a self-contained Markdown document.
fn render_markdown(
    tenant_id: &str,
    generated_at: &str,
    total: u64,
    posture: u64,
    by_severity: &[SeverityCountView],
    compliance: &[FrameworkCoverageView],
) -> String {
    use std::fmt::Write as _;
    let mut m = String::with_capacity(1024);
    m.push_str("# SentinelX Comprehensive Security Report\n\n");
    let _ = writeln!(m, "- **Tenant:** {tenant_id}");
    let _ = writeln!(m, "- **Generated:** {generated_at}\n");
    m.push_str("## Executive Summary\n\n");
    m.push_str("| Metric | Value |\n|---|---|\n");
    let _ = writeln!(m, "| Security posture score | {posture} / 100 |");
    let _ = writeln!(m, "| Total findings | {total} |\n");
    m.push_str("## Findings by Severity\n\n| Severity | Count |\n|---|---|\n");
    for s in by_severity {
        let _ = writeln!(m, "| {} | {} |", s.severity, s.count);
    }
    m.push_str("\n## Compliance Control Coverage\n\n| Framework | Controls |\n|---|---|\n");
    for c in compliance {
        let _ = writeln!(m, "| {} | {} |", c.framework, c.controls);
    }
    m.push_str(
        "\n_Generated server-side from live platform state. Findings posture reflects the \
         current finding repository; compliance coverage reflects the shipped control catalogs \
         (PCI DSS v4.0.1 is complete across all 12 requirements)._\n",
    );
    m
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use sx_api::port::EngagementPortError;
    use sx_api::view::finding_view::FindingView;

    #[derive(Default)]
    struct StubFindings {
        rows: Mutex<Vec<FindingView>>,
    }
    #[async_trait]
    impl FindingRepositoryPort for StubFindings {
        async fn list(
            &self,
            _t: &str,
            _o: u64,
            _l: u32,
        ) -> Result<Vec<FindingView>, EngagementPortError> {
            Ok(self.rows.lock().unwrap().clone())
        }
        async fn get(&self, _t: &str, _id: &str) -> Result<FindingView, EngagementPortError> {
            Err(EngagementPortError::NotFound)
        }
        async fn update_status(
            &self,
            _t: &str,
            _id: &str,
            _s: &str,
            _c: Option<&str>,
        ) -> Result<FindingView, EngagementPortError> {
            Err(EngagementPortError::NotFound)
        }
        async fn insert(&self, v: FindingView) -> Result<FindingView, EngagementPortError> {
            self.rows.lock().unwrap().push(v.clone());
            Ok(v)
        }
    }

    fn fv(sev: &str) -> FindingView {
        FindingView {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: "t".into(),
            asset_id: "a".into(),
            severity: sev.into(),
            status: "open".into(),
            title: "x".into(),
            description: "d".into(),
            cvss: None,
            cve_id: None,
            first_seen: "1970-01-01T00:00:00Z".into(),
            last_seen: "1970-01-01T00:00:00Z".into(),
            metadata: None,
        }
    }

    #[tokio::test]
    async fn aggregates_severity_posture_and_compliance() {
        let repo = Arc::new(StubFindings::default());
        repo.rows
            .lock()
            .unwrap()
            .extend([fv("critical"), fv("high"), fv("low")]);
        let bundle = build(repo);
        let r = bundle.port.generate("t").await.unwrap();
        assert_eq!(r.total_findings, 3);
        // critical(-15) + high(-7) + low(-1) = 23 penalty → 77.
        assert_eq!(r.posture_score, 77);
        // PCI DSS coverage is the full catalog.
        let pci = r
            .compliance
            .iter()
            .find(|c| c.framework == "pcidss")
            .unwrap();
        assert!(pci.controls >= 250);
        assert!(r.markdown.contains("Comprehensive Security Report"));
        assert!(r.markdown.contains("Compliance Control Coverage"));
    }

    #[tokio::test]
    async fn empty_tenant_scores_full_posture() {
        let bundle = build(Arc::new(StubFindings::default()));
        let r = bundle.port.generate("t").await.unwrap();
        assert_eq!(r.total_findings, 0);
        assert_eq!(r.posture_score, 100);
    }
}
