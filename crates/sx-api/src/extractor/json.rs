//! `ValidatedJson<T>` — `FromRequest` extractor that deserialises the body
//! as JSON and then runs `validator::Validate`.
//!
//! Bad JSON becomes [`ApiError::BadRequest`]; validation failures become
//! [`ApiError::Unprocessable`] carrying a human-readable summary.

use axum::body::Bytes;
use axum::extract::FromRequest;
use axum::http::Request;
use serde::de::DeserializeOwned;
use validator::Validate;

use crate::error::ApiError;

/// Newtype extractor.
#[derive(Debug, Clone, Copy)]
pub struct ValidatedJson<T>(pub T);

#[axum::async_trait]
impl<T, S> FromRequest<S> for ValidatedJson<T>
where
    T: DeserializeOwned + Validate,
    S: Send + Sync,
    Bytes: FromRequest<S>,
{
    type Rejection = ApiError;

    async fn from_request(
        req: Request<axum::body::Body>,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|_| ApiError::BadRequest("could not read request body".into()))?;
        let value: T = serde_json::from_slice(&bytes)
            .map_err(|e| ApiError::BadRequest(format!("invalid JSON: {e}")))?;
        value
            .validate()
            .map_err(|e| ApiError::Unprocessable(format_validation_errors(&e)))?;
        Ok(Self(value))
    }
}

fn format_validation_errors(errors: &validator::ValidationErrors) -> String {
    let mut parts = Vec::new();
    for (field, kind) in errors.field_errors() {
        let codes: Vec<&str> = kind.iter().map(|e| e.code.as_ref()).collect();
        parts.push(format!("{field}: {}", codes.join(", ")));
    }
    if parts.is_empty() {
        "validation failed".to_owned()
    } else {
        parts.join("; ")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::body::Body;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, Validate)]
    struct In {
        #[validate(length(min = 3))]
        name: String,
    }

    #[tokio::test]
    async fn bad_json_is_bad_request() {
        let req = Request::builder()
            .header("content-type", "application/json")
            .body(Body::from("{not json"))
            .unwrap();
        let err = <ValidatedJson<In> as FromRequest<()>>::from_request(req, &())
            .await
            .unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn failing_validation_is_unprocessable() {
        let req = Request::builder()
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"x"}"#))
            .unwrap();
        let err = <ValidatedJson<In> as FromRequest<()>>::from_request(req, &())
            .await
            .unwrap_err();
        let msg = match err {
            ApiError::Unprocessable(m) => m,
            other => panic!("expected unprocessable, got {other:?}"),
        };
        assert!(msg.contains("name"));
    }

    #[tokio::test]
    async fn valid_input_passes() {
        let req = Request::builder()
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"abcd"}"#))
            .unwrap();
        let ValidatedJson(v) = <ValidatedJson<In> as FromRequest<()>>::from_request(req, &())
            .await
            .unwrap();
        assert_eq!(v.name, "abcd");
    }
}
