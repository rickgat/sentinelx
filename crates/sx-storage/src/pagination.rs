//! Pagination helpers — translate a domain [`Page`] to SQL `LIMIT`/`OFFSET`.

use crate::domain::value_object::Page;

/// `(limit, offset)` pair sized for `sqlx::bind` against `BIGINT` /
/// `BIGINT`.
///
/// We coerce the `u32` limit to `i64` (fits trivially) and the `u64`
/// offset to `i64`, saturating at `i64::MAX` to defend against integer
/// overflow if a malicious or buggy caller sets a huge offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqlBounds {
    /// Maximum rows to return (`LIMIT $1`).
    pub limit: i64,
    /// Rows to skip (`OFFSET $2`).
    pub offset: i64,
}

impl From<Page> for SqlBounds {
    fn from(p: Page) -> Self {
        let limit = i64::from(p.limit);
        // `as` cast from u64 truncates; we explicitly saturate first.
        // u64::MAX > i64::MAX so the comparison is meaningful.
        let offset = if p.offset > i64::MAX as u64 {
            i64::MAX
        } else {
            // Lossless because we just bounded it.
            i64::try_from(p.offset).unwrap_or(i64::MAX)
        };
        Self { limit, offset }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn translates_simple_page() {
        let p = Page::new(20, 10).unwrap();
        let b: SqlBounds = p.into();
        assert_eq!(b.limit, 10);
        assert_eq!(b.offset, 20);
    }

    #[test]
    fn first_page() {
        let p = Page::first();
        let b: SqlBounds = p.into();
        assert_eq!(b.offset, 0);
        assert_eq!(b.limit, 50);
    }

    #[test]
    fn saturates_huge_offset() {
        let p = Page {
            offset: u64::MAX,
            limit: 1,
        };
        let b: SqlBounds = p.into();
        assert_eq!(b.offset, i64::MAX);
        assert_eq!(b.limit, 1);
    }

    #[test]
    fn max_limit_within_i64() {
        let p = Page::new(0, Page::MAX_LIMIT).unwrap();
        let b: SqlBounds = p.into();
        assert_eq!(b.limit, i64::from(Page::MAX_LIMIT));
    }

    #[test]
    fn offset_just_under_i64_max() {
        let p = Page {
            #[allow(clippy::cast_sign_loss)]
            offset: i64::MAX as u64,
            limit: 1,
        };
        let b: SqlBounds = p.into();
        assert_eq!(b.offset, i64::MAX);
    }
}
