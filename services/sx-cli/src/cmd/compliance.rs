//! `sx compliance ...` — list controls, map findings, and render PDF reports.

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use clap::{Args, Subcommand, ValueEnum};
use tracing::instrument;

use sx_compliance::prelude::{
    ControlCatalog, FindingCategory, Framework, MapFindingInput, MapFindingToControlsUseCase,
};
use sx_compliance::report::render_pci_dss;

use crate::output::{
    print_controls, print_framework_header, print_line, print_mapping, OutputFormat,
};

/// The `compliance` family of sub-commands.
#[derive(Debug, Subcommand)]
pub enum ComplianceCommand {
    /// List all controls for a given framework as a Markdown table.
    List(ListArgs),
    /// Map a finding category to its affected controls.
    Map(MapArgs),
    /// Render a compliance framework markdown mapping to a PDF.
    Report(ReportArgs),
}

/// Arguments for `sx compliance list`.
#[derive(Debug, Args)]
pub struct ListArgs {
    /// Framework discriminator: one of
    /// `iso27001`, `soc2`, `pcidss`, `hipaa`, `nist80053`, `cisaws`.
    #[arg(long)]
    pub framework: String,
}

/// Arguments for `sx compliance map`.
#[derive(Debug, Args)]
pub struct MapArgs {
    /// Finding category — see `FindingCategory` for the full list.
    #[arg(long)]
    pub category: String,
    /// Free-form finding identifier (typically a UUID).
    #[arg(long = "finding-id")]
    pub finding_id: String,
}

/// Frameworks for which `sx compliance report` ships a renderer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ComplianceFramework {
    /// PCI DSS v4.0 mapping (`docs/compliance/pci-dss-v4-mapping.md`).
    #[value(name = "pci-dss")]
    PciDss,
}

impl ComplianceFramework {
    /// Default markdown source path on disk for this framework.
    #[must_use]
    pub fn default_source(self) -> PathBuf {
        match self {
            Self::PciDss => PathBuf::from("docs/compliance/pci-dss-v4-mapping.md"),
        }
    }

    /// Human-readable label used in the PDF cover page.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::PciDss => "PCI DSS v4.0",
        }
    }

    /// Default maintainer to embed on the cover page.
    #[must_use]
    pub const fn default_maintainer(self) -> &'static str {
        match self {
            Self::PciDss => "Compliance Office / CISO",
        }
    }
}

/// Arguments for `sx compliance report`.
#[derive(Debug, Args)]
pub struct ReportArgs {
    /// Framework to render. Currently: `pci-dss`.
    #[arg(long, value_enum)]
    pub framework: ComplianceFramework,

    /// Destination PDF path.
    #[arg(long)]
    pub out: PathBuf,

    /// Override the source markdown path. Defaults to
    /// `docs/compliance/<framework>-mapping.md`.
    #[arg(long)]
    pub source: Option<PathBuf>,

    /// Override the cover-page maintainer string.
    #[arg(long)]
    pub maintainer: Option<String>,
}

/// Entry point for `sx compliance`.
#[instrument(skip_all)]
pub fn run(cmd: &ComplianceCommand, fmt: OutputFormat) -> anyhow::Result<()> {
    let catalog = ControlCatalog::shared();
    match cmd {
        ComplianceCommand::List(args) => run_list(args, &catalog, fmt),
        ComplianceCommand::Map(args) => run_map(args, catalog, fmt),
        ComplianceCommand::Report(args) => run_report(args, fmt),
    }
}

fn run_list(
    args: &ListArgs,
    catalog: &Arc<ControlCatalog>,
    fmt: OutputFormat,
) -> anyhow::Result<()> {
    let framework = Framework::from_str(&args.framework)
        .with_context(|| format!("unknown framework: {}", args.framework))?;
    if fmt == OutputFormat::Human {
        print_framework_header(framework);
    }
    let controls: Vec<_> = catalog
        .by_framework(framework)
        .into_iter()
        .cloned()
        .collect();
    print_controls(&controls, fmt)?;
    Ok(())
}

fn run_map(args: &MapArgs, catalog: Arc<ControlCatalog>, fmt: OutputFormat) -> anyhow::Result<()> {
    let category = FindingCategory::from_str(&args.category)
        .with_context(|| format!("unknown category: {}", args.category))?;
    let uc = MapFindingToControlsUseCase::new(catalog);
    let out = uc.execute(&MapFindingInput {
        finding_id: args.finding_id.clone(),
        category,
        severity_str: "unspecified".to_owned(),
    })?;
    print_mapping(&out.finding_id, category, &out.controls, fmt)?;
    Ok(())
}

fn run_report(args: &ReportArgs, fmt: OutputFormat) -> anyhow::Result<()> {
    let source = args
        .source
        .clone()
        .unwrap_or_else(|| args.framework.default_source());
    let maintainer = args
        .maintainer
        .as_deref()
        .unwrap_or_else(|| args.framework.default_maintainer());

    match args.framework {
        ComplianceFramework::PciDss => {
            render_pci_dss(&source, &args.out, maintainer).with_context(|| {
                format!(
                    "rendering {} report from {} to {}",
                    args.framework.label(),
                    source.display(),
                    args.out.display(),
                )
            })?;
        }
    }

    if fmt == OutputFormat::Human {
        print_line(&format!(
            "Wrote {} report to {}",
            args.framework.label(),
            args.out.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn compliance_list_iso_includes_a_8_2() {
        let catalog = ControlCatalog::shared();
        let iso = catalog.by_framework(Framework::Iso27001);
        assert!(iso.iter().any(|c| c.id == "A.8.2"));
    }

    #[test]
    fn compliance_list_runs_for_every_framework() {
        for fw in Framework::all() {
            let args = ListArgs {
                framework: fw.code().to_owned(),
            };
            let catalog = ControlCatalog::shared();
            // run_list prints; assert it doesn't error.
            run_list(&args, &catalog, OutputFormat::Json).unwrap();
        }
    }

    #[test]
    fn compliance_list_rejects_unknown_framework() {
        let args = ListArgs {
            framework: "fedramp".into(),
        };
        let catalog = ControlCatalog::shared();
        let r = run_list(&args, &catalog, OutputFormat::Json);
        assert!(r.is_err());
    }

    #[test]
    fn compliance_map_authentication_prints_known_control() {
        let catalog = ControlCatalog::shared();
        let uc = MapFindingToControlsUseCase::new(catalog);
        let out = uc
            .execute(&MapFindingInput {
                finding_id: "F-7".into(),
                category: FindingCategory::Authentication,
                severity_str: "high".into(),
            })
            .unwrap();
        assert!(out
            .controls
            .iter()
            .any(|c| c.framework == Framework::Nist80053 && c.id == "IA-2"));
    }
}
