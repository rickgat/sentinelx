//! Pagination value objects used by repository ports.

use serde::{Deserialize, Serialize};

use crate::error::DomainError;

/// A page request, expressed as `(offset, limit)`.
///
/// Both fields are validated at construction time. `limit` must be in
/// the inclusive range `1..=10_000` to bound memory use at the adapter
/// layer; callers may pick a tighter cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page {
    /// Number of items to skip before the first returned item.
    pub offset: u64,
    /// Maximum number of items to return.
    pub limit: u32,
}

impl Page {
    /// Maximum permitted `limit` for a page.
    pub const MAX_LIMIT: u32 = 10_000;

    /// Construct a validated [`Page`].
    pub fn new(offset: u64, limit: u32) -> Result<Self, DomainError> {
        if limit == 0 {
            return Err(DomainError::invalid("page limit must be >= 1"));
        }
        if limit > Self::MAX_LIMIT {
            return Err(DomainError::invalid(format!(
                "page limit must be <= {}",
                Self::MAX_LIMIT,
            )));
        }
        Ok(Self { offset, limit })
    }

    /// Default first page with `limit = 50`.
    #[must_use]
    pub const fn first() -> Self {
        Self {
            offset: 0,
            limit: 50,
        }
    }
}

/// A page of results plus the unbounded total count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PagedResult<T> {
    /// The page payload.
    pub items: Vec<T>,
    /// Total count of items matching the query, across all pages.
    pub total: u64,
    /// The originating page request.
    pub page: Page,
}

impl<T> PagedResult<T> {
    /// Build a paged result from raw parts.
    pub const fn new(items: Vec<T>, total: u64, page: Page) -> Self {
        Self { items, total, page }
    }

    /// Whether more pages exist after this one.
    pub fn has_more(&self) -> bool {
        let consumed = page_consumed(self.page);
        consumed < self.total
    }
}

fn page_consumed(p: Page) -> u64 {
    p.offset.saturating_add(u64::from(p.limit))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_limit() {
        assert!(Page::new(0, 0).is_err());
    }

    #[test]
    fn rejects_huge_limit() {
        assert!(Page::new(0, Page::MAX_LIMIT + 1).is_err());
    }

    #[test]
    fn first_page_defaults() {
        let p = Page::first();
        assert_eq!(p.offset, 0);
        assert_eq!(p.limit, 50);
    }

    #[test]
    fn paged_result_has_more() {
        let page = Page::new(0, 10).unwrap();
        let pr = PagedResult::new(vec![1_u32, 2, 3], 100, page);
        assert!(pr.has_more());
    }

    #[test]
    fn paged_result_no_more() {
        let page = Page::new(0, 10).unwrap();
        let pr = PagedResult::new(vec![1_u32, 2, 3], 3, page);
        assert!(!pr.has_more());
    }
}
