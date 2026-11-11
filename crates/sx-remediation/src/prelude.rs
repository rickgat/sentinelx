//! Crate-wide convenience re-exports.
//!
//! ```rust,ignore
//! use sx_remediation::prelude::*;
//! ```

pub use crate::controller::fetch_advisories::FetchAdvisoriesUseCase;
pub use crate::controller::remediation_copilot::RemediationCopilotUseCase;
pub use crate::error::RemediationError;
pub use crate::model::advisory::{Patch, VendorAdvisory};
pub use crate::model::ai_remediation::{AiRemediation, AiRemediationInput};
pub use crate::service::cisco::CiscoSource;
pub use crate::service::claude_client::RealClaudeClient;
pub use crate::service::explain::{ExplainRequest, ExplainResponse, ExplainService};
pub use crate::service::llm_client::{ClaudeClient, ClaudeConfig, DisabledLlmClient, LlmClient};
pub use crate::service::msrc::MsrcSource;
pub use crate::service::redhat::RedHatSource;
pub use crate::service::registry::MultiSourceAdvisoryRegistry;
pub use crate::service::sanitiser::Sanitiser;
pub use crate::service::source::VendorAdvisorySource;
pub use crate::service::ubuntu::UbuntuSource;
