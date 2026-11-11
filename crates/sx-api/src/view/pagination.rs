//! Pagination view helpers.
//!
//! Every list endpoint returns a `PageView<T>` rather than a bare array.
//! Doing so leaves room to evolve the pagination strategy (cursor vs offset)
//! without breaking the JSON shape clients already wrote integrations
//! against.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Standard list-endpoint envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageView<T> {
    /// Items on this page.
    pub items: Vec<T>,
    /// Zero-based offset of the first item.
    pub offset: u64,
    /// Page size that was requested (and honoured).
    pub limit: u32,
    /// Total number of matching items if the backend can compute it cheaply,
    /// otherwise `None`. Cursors are preferred for large datasets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
}

impl<T> PageView<T> {
    /// Build a page from items + offset + limit.
    #[must_use]
    pub fn new(items: Vec<T>, offset: u64, limit: u32) -> Self {
        Self {
            items,
            offset,
            limit,
            total: None,
        }
    }

    /// Attach a known total count.
    #[must_use]
    pub fn with_total(mut self, total: u64) -> Self {
        self.total = Some(total);
        self
    }
}

/// Query-string parameters accepted by every list endpoint.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct PageQuery {
    /// Zero-based offset, defaults to 0.
    #[serde(default)]
    pub offset: Option<u64>,
    /// Page size, defaults to 50, max 200.
    #[serde(default)]
    #[validate(range(min = 1, max = 200))]
    pub limit: Option<u32>,
}

impl PageQuery {
    /// Effective offset (defaulting to 0).
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset.unwrap_or(0)
    }

    /// Effective limit (defaulting to 50, clamped to 200).
    #[must_use]
    pub fn limit(&self) -> u32 {
        self.limit.unwrap_or(50).min(200)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_query_defaults() {
        let q = PageQuery {
            offset: None,
            limit: None,
        };
        assert_eq!(q.offset(), 0);
        assert_eq!(q.limit(), 50);
    }

    #[test]
    fn page_query_limit_capped() {
        let q = PageQuery {
            offset: Some(10),
            limit: Some(9_999),
        };
        assert_eq!(q.offset(), 10);
        assert_eq!(q.limit(), 200);
    }

    #[test]
    fn page_view_total_optional() {
        let p: PageView<u32> = PageView::new(vec![1, 2, 3], 0, 10);
        assert!(p.total.is_none());
        let p = p.with_total(3);
        assert_eq!(p.total, Some(3));
    }
}
