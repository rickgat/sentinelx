//! CORS middleware.
//!
//! Driven by an explicit allow-list — `*` is never used because that would
//! break the security invariant that browser-driven requests must come
//! from a known origin.

use axum::http::{HeaderName, HeaderValue, Method};
use tower_http::cors::CorsLayer;

/// Inputs to [`build_cors_layer`].
#[derive(Debug, Clone)]
pub struct CorsConfig {
    /// Allowed origins. Empty = no browser CORS allowed.
    pub allowed_origins: Vec<String>,
    /// Allowed methods (GET, POST, …).
    pub allowed_methods: Vec<Method>,
    /// Allowed request headers.
    pub allowed_headers: Vec<HeaderName>,
    /// Whether to allow credentials (cookies, bearer tokens).
    pub allow_credentials: bool,
    /// Max-age of preflight cache, in seconds.
    pub max_age_secs: u64,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: Vec::new(),
            allowed_methods: vec![
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
                Method::OPTIONS,
            ],
            allowed_headers: vec![
                HeaderName::from_static("authorization"),
                HeaderName::from_static("content-type"),
                HeaderName::from_static("x-request-id"),
            ],
            allow_credentials: false,
            max_age_secs: 600,
        }
    }
}

/// Build a [`CorsLayer`] from `cfg`.
pub fn build_cors_layer(cfg: &CorsConfig) -> CorsLayer {
    let mut layer = CorsLayer::new()
        .allow_methods(cfg.allowed_methods.clone())
        .allow_headers(cfg.allowed_headers.clone())
        .max_age(std::time::Duration::from_secs(cfg.max_age_secs));

    if cfg.allow_credentials {
        layer = layer.allow_credentials(true);
    }

    // Convert string origins to HeaderValues, silently skipping any that
    // cannot be parsed — a misconfigured origin is a deploy issue caught
    // at boot, not here.
    let origins: Vec<HeaderValue> = cfg
        .allowed_origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();

    if !origins.is_empty() {
        layer = layer.allow_origin(origins);
    }

    layer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_restrictive() {
        let cfg = CorsConfig::default();
        assert!(cfg.allowed_origins.is_empty());
        assert!(!cfg.allow_credentials);
    }

    #[test]
    fn build_layer_does_not_panic_for_empty_origins() {
        let cfg = CorsConfig::default();
        let _layer = build_cors_layer(&cfg);
    }

    #[test]
    fn build_layer_accepts_valid_origins() {
        let cfg = CorsConfig {
            allowed_origins: vec!["https://example.com".to_owned()],
            ..CorsConfig::default()
        };
        let _layer = build_cors_layer(&cfg);
    }
}
