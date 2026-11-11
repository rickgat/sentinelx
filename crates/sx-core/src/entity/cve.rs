//! CVE entity — public vulnerability record.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use url::Url;

use crate::error::DomainError;
use crate::value_object::cvss::CvssScore;
use crate::value_object::epss::EpssScore;
use crate::value_object::ids::CveId;

/// A public CVE record, enriched with EPSS and KEV signals.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cve {
    /// Canonical identifier (e.g. `CVE-2024-12345`).
    pub id: CveId,
    /// Publication timestamp.
    pub published: OffsetDateTime,
    /// CVSS base score.
    pub cvss: CvssScore,
    /// EPSS score, when published.
    pub epss: Option<EpssScore>,
    /// Whether the CVE is on CISA's Known Exploited Vulnerabilities list.
    pub kev: bool,
    /// Free-form description.
    pub description: String,
    /// External reference URLs.
    pub references: Vec<Url>,
}

impl Cve {
    /// Build a new CVE record.
    pub fn new(
        id: CveId,
        published: OffsetDateTime,
        cvss: CvssScore,
        epss: Option<EpssScore>,
        kev: bool,
        description: impl Into<String>,
        references: Vec<Url>,
    ) -> Result<Self, DomainError> {
        let description = description.into();
        if description.trim().is_empty() {
            return Err(DomainError::invalid("cve description cannot be empty"));
        }
        Ok(Self {
            id,
            published,
            cvss,
            epss,
            kev,
            description,
            references,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn build_ok() {
        let cve = Cve::new(
            CveId::new("CVE-2024-12345").unwrap(),
            OffsetDateTime::UNIX_EPOCH,
            CvssScore::v3_only(9.1).unwrap(),
            Some(EpssScore::new(0.5, 0.9).unwrap()),
            true,
            "Critical RCE",
            vec![Url::parse("https://example.com/advisory").unwrap()],
        )
        .unwrap();
        assert!(cve.kev);
    }

    #[test]
    fn rejects_empty_description() {
        let r = Cve::new(
            CveId::new("CVE-2024-12345").unwrap(),
            OffsetDateTime::UNIX_EPOCH,
            CvssScore::v3_only(9.1).unwrap(),
            None,
            false,
            "  ",
            vec![],
        );
        assert!(r.is_err());
    }
}
