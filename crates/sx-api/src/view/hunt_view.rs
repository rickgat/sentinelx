//! Threat-hunt view layer (P3-006).
//!
//! Wire shapes used by `POST /v1/hunt/query`. The analyst submits a
//! KQL/SPL-like query as a plain string in [`HuntQueryRequest`]; the
//! response carries the row set plus the compiled SQL so the UI can
//! display the actual statement that ran (audit-by-default).
//!
//! No identifier or value is ever interpolated into SQL — see
//! [`sx_hunt::compile`] for the parameterisation contract. The wire
//! types here are dumb DTOs; validation lives in the parser/compiler.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// `POST /v1/hunt/query` request body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HuntQueryRequest {
    /// Analyst-typed query text. Hard byte cap enforced by the parser
    /// (see `sx_hunt::parser::MAX_QUERY_BYTES`).
    pub query: String,
}

/// One row in the response. Keys are column names; values are the raw
/// JSON values returned by ClickHouse.
pub type HuntRowView = BTreeMap<String, serde_json::Value>;

/// `POST /v1/hunt/query` response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HuntQueryResponse {
    /// Returned rows, in the order the backend produced them.
    pub rows: Vec<HuntRowView>,
    /// Compiled SQL statement (parameterised — placeholders look like
    /// `{p0:String}`). Surfaced so the UI can show the analyst the
    /// statement that ran and so support can replay it.
    pub compiled_sql: String,
    /// Source table the query read from.
    pub table: String,
    /// Row count for convenience (matches `rows.len()`).
    pub row_count: usize,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let r = HuntQueryRequest {
            query: "events_raw | top 5 by severity_id desc".to_string(),
        };
        let raw = serde_json::to_string(&r).unwrap();
        let back: HuntQueryRequest = serde_json::from_str(&raw).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    #[allow(clippy::literal_string_with_formatting_args)] // ClickHouse parameter placeholder, not Rust format.
    fn response_round_trips_with_empty_rows() {
        let r = HuntQueryResponse {
            rows: Vec::new(),
            compiled_sql: "SELECT * FROM events_raw WHERE tenant_id = {tenant:String}".into(),
            table: "events_raw".into(),
            row_count: 0,
        };
        let raw = serde_json::to_string(&r).unwrap();
        let back: HuntQueryResponse = serde_json::from_str(&raw).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn response_round_trips_with_rows() {
        let mut row = HuntRowView::new();
        let _ = row.insert("user_name".into(), serde_json::json!("alice"));
        let _ = row.insert("count".into(), serde_json::json!(42));
        let r = HuntQueryResponse {
            rows: vec![row.clone()],
            compiled_sql: "SELECT user_name, count() FROM events_raw".into(),
            table: "events_raw".into(),
            row_count: 1,
        };
        let raw = serde_json::to_string(&r).unwrap();
        let back: HuntQueryResponse = serde_json::from_str(&raw).unwrap();
        assert_eq!(back, r);
        assert_eq!(
            back.rows[0].get("user_name").unwrap(),
            &serde_json::json!("alice")
        );
    }
}
