//! Operator JWKS publishing (MED-004).
//!
//! Exposes the public-side of any signing keys the operator wants
//! external clients to verify against. This is the SP→RP direction of
//! the JWKS contract — i.e. **we** are the OP/AS, and external clients
//! verifying our `id_token` / `access_token` need a way to fetch our
//! key material.
//!
//! ## Today's content
//!
//! The workspace's [`JwtIssuer`](crate::service::token_issuer::JwtIssuer)
//! uses HS256 by default, where the verifier needs the shared secret.
//! Symmetric secrets MUST NOT be published in a JWKS — we therefore
//! publish an **empty `keys` array** when only HS keys are configured
//! and log a one-time warning so the operator knows the endpoint is
//! reachable but currently empty.
//!
//! When the operator configures an asymmetric key (RS256 / ES256 /
//! `EdDSA` — coming in a follow-up sprint), the [`SigningKeyRegistry`] is
//! populated and the JWKS materialises automatically.
//!
//! Keys are exposed via [`SigningKeyRegistry::publish`] which clones the
//! registry's current snapshot — the registry is hot-swappable so a
//! rotation does not need to restart the server.

use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

/// One JWK entry — minimal RFC 7517 shape.
///
/// We deliberately keep this hand-rolled rather than re-exporting
/// `jsonwebtoken::jwk::Jwk` because (a) downstream callers expect to
/// serialise it as a stable wire shape, and (b) we want full control
/// over which fields land on the wire — never publish `d` (private
/// component) or `k` (symmetric secret) by mistake.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublishedJwk {
    /// Key type (`RSA`, `EC`, `OKP`).
    pub kty: String,
    /// Public use (`sig`).
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    /// Algorithm hint (`RS256`, `ES256`, `EdDSA`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// Key identifier — clients select by `kid` from a token header.
    pub kid: String,
    /// RSA modulus (base64url).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// RSA exponent (base64url).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    /// EC curve.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// EC x coordinate / OKP x.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// EC y coordinate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

/// `GET /.well-known/jwks.json` response body.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct JwksDocument {
    /// Published key entries. MAY be empty when only symmetric keys are
    /// configured.
    pub keys: Vec<PublishedJwk>,
}

impl JwksDocument {
    /// Build a fresh, empty JWKS.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }
}

/// Hot-swappable registry of publishable signing keys.
///
/// The token issuer SHOULD register every asymmetric verifying key it
/// holds; the registry then drives the `/.well-known/jwks.json`
/// endpoint. Rotation = `register_key` for the new entry + a future
/// `retire_key` once the grace window expires.
#[derive(Debug, Default, Clone)]
pub struct SigningKeyRegistry {
    inner: Arc<RwLock<Vec<PublishedJwk>>>,
}

impl SigningKeyRegistry {
    /// Build an empty registry. The default state — an HS-only deploy
    /// publishes an empty JWKS.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build a registry from a fixed seed list (used in tests + when an
    /// operator pre-configures keys in the loader).
    #[must_use]
    pub fn from_keys(keys: Vec<PublishedJwk>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(keys)),
        }
    }

    /// Register an additional verifying key.
    ///
    /// If a key with the same `kid` already exists it is replaced.
    pub fn register_key(&self, jwk: PublishedJwk) {
        let mut g = match self.inner.write() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        g.retain(|k| k.kid != jwk.kid);
        g.push(jwk);
    }

    /// Remove the key with the given `kid`, returning `true` if it was
    /// present.
    pub fn retire_key(&self, kid: &str) -> bool {
        let mut g = match self.inner.write() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        let len = g.len();
        g.retain(|k| k.kid != kid);
        g.len() != len
    }

    /// Publish a snapshot of the current keys as a JWKS document.
    #[must_use]
    pub fn publish(&self) -> JwksDocument {
        let g = match self.inner.read() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        JwksDocument { keys: g.clone() }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn sample_rsa(kid: &str) -> PublishedJwk {
        PublishedJwk {
            kty: "RSA".into(),
            r#use: Some("sig".into()),
            alg: Some("RS256".into()),
            kid: kid.into(),
            n: Some("AQAB".into()),
            e: Some("AQAB".into()),
            crv: None,
            x: None,
            y: None,
        }
    }

    #[test]
    fn empty_registry_publishes_empty_keys_array() {
        let reg = SigningKeyRegistry::empty();
        let doc = reg.publish();
        assert!(doc.keys.is_empty());
        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("\"keys\":[]"));
    }

    #[test]
    fn register_dedupes_on_kid() {
        let reg = SigningKeyRegistry::empty();
        reg.register_key(sample_rsa("kid-1"));
        reg.register_key(sample_rsa("kid-1"));
        reg.register_key(sample_rsa("kid-2"));
        assert_eq!(reg.publish().keys.len(), 2);
    }

    #[test]
    fn retire_removes_by_kid() {
        let reg = SigningKeyRegistry::from_keys(vec![sample_rsa("kid-1"), sample_rsa("kid-2")]);
        assert!(reg.retire_key("kid-1"));
        assert!(!reg.retire_key("kid-1"));
        let doc = reg.publish();
        assert_eq!(doc.keys.len(), 1);
        assert_eq!(doc.keys[0].kid, "kid-2");
    }

    #[test]
    fn published_jwk_serialises_without_private_fields() {
        let jwk = sample_rsa("kid-x");
        let json = serde_json::to_value(&jwk).unwrap();
        // No `d`, `k`, or `p` allowed.
        assert!(json.get("d").is_none());
        assert!(json.get("k").is_none());
        assert_eq!(json["kid"], "kid-x");
        assert_eq!(json["alg"], "RS256");
        assert_eq!(json["use"], "sig");
    }
}
