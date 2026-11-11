//! Hard safety rails for the auto-PR generator.
//!
//! Two independent guards collaborate to prevent destructive or
//! oversized remediation PRs from ever leaving the platform:
//!
//! - [`BranchProtectionGuard`] refuses pull requests targeting branches
//!   that operations has classified as protected (e.g. `main`, `master`,
//!   `release/*`, `prod/*`). It accepts both literal branch names and
//!   regex patterns; patterns are anchored to the full branch name.
//! - [`DiffSizeGuard`] refuses pull requests whose total proposed
//!   content line count exceeds a configured ceiling.
//!
//! Both guards are pure functions over their input; they perform no I/O
//! and never panic.

use regex::Regex;

use crate::error::AutonomyError;
use crate::model::pr_proposal::FileChange;

/// Refuses pushes to operator-classified protected branches.
///
/// A branch is rejected when either:
/// 1. its name appears verbatim in `protected`, or
/// 2. it matches any one of `protected_regexes` (anchored end-to-end).
///
/// Regex patterns supplied at construction are compiled once and reused
/// per check. Malformed patterns surface as [`AutonomyError::Config`].
#[derive(Debug, Clone)]
pub struct BranchProtectionGuard {
    /// Literal branch names that are always refused.
    protected: Vec<String>,
    /// Compiled regex patterns; a match against the full branch name
    /// causes refusal.
    protected_regexes: Vec<Regex>,
}

impl BranchProtectionGuard {
    /// Build a new guard from a list of literal branch names and a list
    /// of regex patterns. Patterns are anchored with `\A` / `\z` to
    /// avoid accidental substring matches.
    ///
    /// # Errors
    /// Returns [`AutonomyError::Config`] when any pattern fails to compile.
    pub fn new(protected: Vec<String>, regexes: Vec<String>) -> Result<Self, AutonomyError> {
        let mut compiled = Vec::with_capacity(regexes.len());
        for raw in regexes {
            let anchored = format!("\\A(?:{raw})\\z");
            let re = Regex::new(&anchored)
                .map_err(|e| AutonomyError::config(format!("invalid branch regex `{raw}`: {e}")))?;
            compiled.push(re);
        }
        Ok(Self {
            protected,
            protected_regexes: compiled,
        })
    }

    /// Return `Ok(())` if `target_branch` is not protected. Otherwise
    /// returns [`AutonomyError::ProtectedBranch`].
    pub fn check(&self, target_branch: &str) -> Result<(), AutonomyError> {
        if self.protected.iter().any(|p| p == target_branch) {
            return Err(AutonomyError::ProtectedBranch(target_branch.to_owned()));
        }
        if self
            .protected_regexes
            .iter()
            .any(|re| re.is_match(target_branch))
        {
            return Err(AutonomyError::ProtectedBranch(target_branch.to_owned()));
        }
        Ok(())
    }
}

/// Refuses pull requests whose total proposed line count exceeds
/// `max_diff_loc`.
#[derive(Debug, Clone, Copy)]
pub struct DiffSizeGuard {
    /// Configured maximum across all file changes.
    max_diff_loc: u32,
}

impl DiffSizeGuard {
    /// Build a new diff-size guard with the configured maximum.
    #[must_use]
    pub const fn new(max_diff_loc: u32) -> Self {
        Self { max_diff_loc }
    }

    /// Return `Ok(())` if the combined line count of `changes` is at or
    /// below the configured maximum. Otherwise returns
    /// [`AutonomyError::DiffTooLarge`].
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn check(&self, changes: &[FileChange]) -> Result<(), AutonomyError> {
        let total = changes
            .iter()
            .map(FileChange::line_count)
            .fold(0u32, u32::saturating_add);
        if total > self.max_diff_loc {
            return Err(AutonomyError::DiffTooLarge {
                actual: total,
                max: self.max_diff_loc,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn pr_safety_branch_guard_rejects_main() {
        let g = BranchProtectionGuard::new(vec!["main".into(), "master".into()], vec![]).unwrap();
        let err = g.check("main").unwrap_err();
        assert!(matches!(err, AutonomyError::ProtectedBranch(b) if b == "main"));
        assert!(g.check("feature/x").is_ok());
    }

    #[test]
    fn pr_safety_branch_guard_rejects_release_glob() {
        let g = BranchProtectionGuard::new(vec![], vec!["release/.*".into(), "prod/.*".into()])
            .unwrap();
        assert!(matches!(
            g.check("release/2026.06").unwrap_err(),
            AutonomyError::ProtectedBranch(_)
        ));
        assert!(matches!(
            g.check("prod/eu").unwrap_err(),
            AutonomyError::ProtectedBranch(_)
        ));
        // Anchored — substring should NOT match.
        assert!(g.check("feat/release/foo").is_ok());
        assert!(g.check("hotfix").is_ok());
    }

    #[test]
    fn pr_safety_branch_guard_rejects_invalid_regex() {
        // Unbalanced bracket = invalid pattern.
        let err = BranchProtectionGuard::new(vec![], vec!["release/[".into()]).unwrap_err();
        assert!(matches!(err, AutonomyError::Config(_)));
    }

    #[test]
    fn pr_safety_diff_guard_rejects_over_max() {
        let g = DiffSizeGuard::new(5);
        let big = FileChange::new("a.rs", "1\n2\n3\n4\n5\n6\n").unwrap();
        let err = g.check(&[big]).unwrap_err();
        assert!(matches!(
            err,
            AutonomyError::DiffTooLarge { actual: 6, max: 5 }
        ));
    }

    #[test]
    fn pr_safety_diff_guard_accepts_under_max() {
        let g = DiffSizeGuard::new(10);
        let f1 = FileChange::new("a.rs", "one\ntwo\n").unwrap();
        let f2 = FileChange::new("b.rs", "three\n").unwrap();
        assert!(g.check(&[f1, f2]).is_ok());
    }
}
