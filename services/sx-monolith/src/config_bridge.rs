//! Translates configuration types between `sx-config` (the loader) and the
//! per-crate config DTOs each sibling crate consumes.
//!
//! Each sibling defines its own config struct so the crate can be tested in
//! isolation; the bridge is the single place a workspace-wide schema change
//! has to land.

use std::time::Duration;

use sx_config::schema::iam::IamConfig as LoaderIamConfig;
use sx_config::schema::jwt::{JwtAlgorithm as LoaderJwtAlgorithm, JwtConfig as LoaderJwtConfig};
use sx_iam::config::{
    IamConfig as IamRuntimeConfig, JwtAlgorithm as IamJwtAlgorithm, JwtConfig as IamJwtConfig,
    LockoutPolicy as IamLockout, PasswordConfig as IamPassword,
    WebauthnConfig as IamWebauthnConfig,
};

/// Translate the JWT loader config into the form `sx-iam` consumes.
///
/// Key selection:
///
/// * `HS256` — symmetric. The `signing_key` doubles as the verifying key, so
///   the bridge clones it into both slots.
/// * `RS256` / `EdDSA` — asymmetric. The verifying key is the PEM public key
///   loaded from the dedicated `jwt.verifying_key` field. The loader's
///   `check_invariants` (in `sx_config::schema::jwt`) already rejects an
///   asymmetric config with a missing / empty `verifying_key`, so the only
///   path that reaches the fallback branch below is an operator who bypassed
///   the loader's validation (e.g. constructed `Settings` by hand). In that
///   case we emit a warn-level structured log and fall back to
///   `signing_key.clone()` so the binary still boots — degraded but
///   debuggable. The trade-off (warn-fallback vs. fail-fast) is intentional:
///   the composition root must remain infallible at this seam to avoid
///   smearing a `Result<...>` across every caller of `iam_runtime`.
pub(crate) fn jwt_for_iam(jwt: &LoaderJwtConfig) -> IamJwtConfig {
    let verifying_key = match jwt.algorithm {
        LoaderJwtAlgorithm::Hs256 => jwt.signing_key.clone(),
        LoaderJwtAlgorithm::Rs256 | LoaderJwtAlgorithm::EdDsa => {
            jwt.verifying_key.clone().unwrap_or_else(|| {
                tracing::warn!(
                    target: "sx_monolith::config_bridge",
                    algorithm = ?jwt.algorithm,
                    key_id = %jwt.key_id,
                    "jwt.verifying_key missing for asymmetric algorithm; \
                     falling back to signing_key (validation gate was bypassed)",
                );
                jwt.signing_key.clone()
            })
        }
    };

    IamJwtConfig {
        issuer: jwt.issuer.clone(),
        audience: jwt.audience.clone(),
        signing_key: jwt.signing_key.clone(),
        verifying_key,
        key_id: jwt.key_id.clone(),
        access_ttl: jwt.access_ttl,
        refresh_ttl: jwt.refresh_ttl,
        algorithm: jwt_alg(jwt.algorithm),
        leeway_seconds: jwt.leeway_seconds,
    }
}

/// Translate the IAM loader config into the form `sx-iam` consumes.
pub(crate) fn iam_runtime(iam: &LoaderIamConfig, jwt: &LoaderJwtConfig) -> IamRuntimeConfig {
    IamRuntimeConfig {
        password: IamPassword {
            m_cost_kib: iam.password.m_cost,
            t_cost: iam.password.t_cost,
            p_cost: iam.password.p_cost,
            output_len: iam.password.output_len as usize,
        },
        lockout: IamLockout {
            max_failures: iam.lockout.threshold,
            lock_duration: iam.lockout.duration,
        },
        attempt_email_pepper: iam.attempt_email_pepper.clone(),
        jwt: jwt_for_iam(jwt),
        webauthn: IamWebauthnConfig::default(),
    }
}

const fn jwt_alg(a: LoaderJwtAlgorithm) -> IamJwtAlgorithm {
    match a {
        LoaderJwtAlgorithm::Hs256 => IamJwtAlgorithm::Hs256,
        LoaderJwtAlgorithm::Rs256 => IamJwtAlgorithm::Rs256,
        LoaderJwtAlgorithm::EdDsa => IamJwtAlgorithm::EdDsa,
    }
}

/// Session TTL — for now we adopt the IAM access TTL as the session window.
/// In production this should be a dedicated config field.
pub(crate) const fn session_ttl(jwt: &LoaderJwtConfig) -> Duration {
    jwt.access_ttl
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{jwt_for_iam, IamJwtAlgorithm, LoaderJwtAlgorithm, LoaderJwtConfig};
    use secrecy::{ExposeSecret, SecretString};
    use std::time::Duration;

    fn loader_jwt(
        algorithm: LoaderJwtAlgorithm,
        signing: &str,
        verifying: Option<&str>,
    ) -> LoaderJwtConfig {
        LoaderJwtConfig {
            issuer: "sentinelx".to_owned(),
            audience: "sentinelx-api".to_owned(),
            signing_key: SecretString::from(signing.to_owned()),
            key_id: "kid-1".to_owned(),
            access_ttl: Duration::from_secs(900),
            refresh_ttl: Duration::from_secs(3_600),
            algorithm,
            verifying_key: verifying.map(|v| SecretString::from(v.to_owned())),
            leeway_seconds: 30,
        }
    }

    #[test]
    fn hs256_reuses_signing_key_as_verifying_key() {
        let jwt = loader_jwt(LoaderJwtAlgorithm::Hs256, "shared-symmetric-secret", None);
        let out = jwt_for_iam(&jwt);
        assert!(matches!(out.algorithm, IamJwtAlgorithm::Hs256));
        assert_eq!(out.signing_key.expose_secret(), "shared-symmetric-secret");
        assert_eq!(out.verifying_key.expose_secret(), "shared-symmetric-secret");
    }

    #[test]
    fn rs256_consumes_dedicated_verifying_key() {
        let jwt = loader_jwt(
            LoaderJwtAlgorithm::Rs256,
            "PEM-PRIVATE-KEY",
            Some("PEM-PUBLIC-KEY"),
        );
        let out = jwt_for_iam(&jwt);
        assert!(matches!(out.algorithm, IamJwtAlgorithm::Rs256));
        assert_eq!(out.signing_key.expose_secret(), "PEM-PRIVATE-KEY");
        assert_eq!(out.verifying_key.expose_secret(), "PEM-PUBLIC-KEY");
        assert_ne!(
            out.signing_key.expose_secret(),
            out.verifying_key.expose_secret(),
            "asymmetric algorithms must not fall back to signing_key when verifying_key is present",
        );
    }

    #[test]
    fn eddsa_consumes_dedicated_verifying_key() {
        let jwt = loader_jwt(
            LoaderJwtAlgorithm::EdDsa,
            "PEM-ED25519-PRIVATE",
            Some("PEM-ED25519-PUBLIC"),
        );
        let out = jwt_for_iam(&jwt);
        assert!(matches!(out.algorithm, IamJwtAlgorithm::EdDsa));
        assert_eq!(out.verifying_key.expose_secret(), "PEM-ED25519-PUBLIC");
    }

    /// Degraded boot path: `check_invariants` was bypassed so the asymmetric
    /// config reached the bridge without a verifying key. The bridge logs a
    /// warn and falls back to `signing_key` rather than panicking.
    #[test]
    fn rs256_falls_back_to_signing_key_when_verifying_key_missing() {
        let jwt = loader_jwt(LoaderJwtAlgorithm::Rs256, "PEM-PRIVATE-KEY", None);
        let out = jwt_for_iam(&jwt);
        assert_eq!(out.signing_key.expose_secret(), "PEM-PRIVATE-KEY");
        assert_eq!(out.verifying_key.expose_secret(), "PEM-PRIVATE-KEY");
    }
}
