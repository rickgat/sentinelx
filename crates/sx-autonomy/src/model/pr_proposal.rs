//! PR proposal types fed into
//! [`crate::service::pr_generator::AutoRemediationPrGenerator`].

use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::AutonomyError;

/// GitHub repository coordinates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoTarget {
    /// Repository owner (org or user).
    pub owner: String,
    /// Repository name.
    pub name: String,
}

impl RepoTarget {
    /// Build a new repo target. Rejects empty owner or name.
    pub fn new(owner: impl Into<String>, name: impl Into<String>) -> Result<Self, AutonomyError> {
        let owner = owner.into();
        let name = name.into();
        if owner.is_empty() || name.is_empty() {
            return Err(AutonomyError::invalid_input(
                "repo owner and name must be non-empty",
            ));
        }
        Ok(Self { owner, name })
    }
}

/// A single file change in a [`PrProposal`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileChange {
    /// Path inside the repo (no leading slash).
    pub path: String,
    /// New content (full file).
    pub new_content: String,
}

impl FileChange {
    /// Build a new file change. Rejects empty path.
    pub fn new(
        path: impl Into<String>,
        new_content: impl Into<String>,
    ) -> Result<Self, AutonomyError> {
        let path = path.into();
        if path.is_empty() || path.starts_with('/') {
            return Err(AutonomyError::invalid_input(
                "file change path must be non-empty and relative",
            ));
        }
        Ok(Self {
            path,
            new_content: new_content.into(),
        })
    }

    /// Number of lines in `new_content`.
    #[must_use]
    pub fn line_count(&self) -> u32 {
        if self.new_content.is_empty() {
            0
        } else {
            // Count newlines; treat content without trailing newline as one
            // line on its own.
            let nl = u32::try_from(self.new_content.matches('\n').count()).unwrap_or(u32::MAX);
            if self.new_content.ends_with('\n') {
                nl
            } else {
                nl.saturating_add(1)
            }
        }
    }
}

/// Everything the PR generator needs to open a remediation pull request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrProposal {
    /// Repository to push to.
    pub repo: RepoTarget,
    /// Source branch — must be named `sentinelx/auto-fix/<finding_id>`.
    pub source_branch: String,
    /// Target branch the PR will be opened against.
    pub target_branch: String,
    /// PR title.
    pub title: String,
    /// PR body. The generator appends a `Signed-off-by` footer before opening.
    pub body: String,
    /// File changes that make up the diff.
    pub changes: Vec<FileChange>,
    /// Finding id (stable string form of `sx_core::value_object::ids::FindingId`).
    pub finding_id: String,
    /// References cited by the upstream remediation. Surfaced in the body.
    pub references: Vec<Url>,
}

impl PrProposal {
    /// Build a proposal, deriving the source branch name from the finding id.
    pub fn new(
        repo: RepoTarget,
        target_branch: impl Into<String>,
        title: impl Into<String>,
        body: impl Into<String>,
        changes: Vec<FileChange>,
        finding_id: impl Into<String>,
        references: Vec<Url>,
    ) -> Result<Self, AutonomyError> {
        let finding_id = finding_id.into();
        if finding_id.is_empty() {
            return Err(AutonomyError::invalid_input("finding_id must be non-empty"));
        }
        let source_branch = format!("sentinelx/auto-fix/{finding_id}");
        let target_branch = target_branch.into();
        if target_branch.is_empty() {
            return Err(AutonomyError::invalid_input(
                "target_branch must be non-empty",
            ));
        }
        let title = title.into();
        if title.is_empty() {
            return Err(AutonomyError::invalid_input("title must be non-empty"));
        }
        Ok(Self {
            repo,
            source_branch,
            target_branch,
            title,
            body: body.into(),
            changes,
            finding_id,
            references,
        })
    }

    /// Total proposed-content line count across every file change.
    #[must_use]
    pub fn total_line_count(&self) -> u32 {
        self.changes
            .iter()
            .map(FileChange::line_count)
            .fold(0u32, u32::saturating_add)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn repo_target_rejects_empty() {
        assert!(RepoTarget::new("", "x").is_err());
        assert!(RepoTarget::new("x", "").is_err());
        assert!(RepoTarget::new("a", "b").is_ok());
    }

    #[test]
    fn file_change_line_count_counts_lines() {
        let f = FileChange::new("a", "").unwrap();
        assert_eq!(f.line_count(), 0);
        let f = FileChange::new("a", "one").unwrap();
        assert_eq!(f.line_count(), 1);
        let f = FileChange::new("a", "one\ntwo").unwrap();
        assert_eq!(f.line_count(), 2);
        let f = FileChange::new("a", "one\ntwo\n").unwrap();
        assert_eq!(f.line_count(), 2);
    }

    #[test]
    fn file_change_rejects_absolute_path() {
        assert!(FileChange::new("/abs", "x").is_err());
    }

    #[test]
    fn proposal_derives_source_branch() {
        let repo = RepoTarget::new("acme", "site").unwrap();
        let p = PrProposal::new(
            repo,
            "main",
            "fix",
            "body",
            vec![FileChange::new("a", "x").unwrap()],
            "FIND-1",
            vec![],
        )
        .unwrap();
        assert_eq!(p.source_branch, "sentinelx/auto-fix/FIND-1");
    }

    #[test]
    fn proposal_rejects_empty_finding_id() {
        let repo = RepoTarget::new("a", "b").unwrap();
        assert!(PrProposal::new(repo, "main", "fix", "body", vec![], "", vec![]).is_err());
    }
}
