//! TOTP MFA adapter — in-memory implementation of [`sx_api::port::MfaPort`].
//!
//! Backs the four `/v1/mfa/*` endpoints. Each user's enrollment is keyed
//! by the bearer-claim `sub` (i.e. the user id). Recovery codes are
//! generated in cleartext at enrollment time, returned to the caller
//! exactly once, then hashed with SHA-256 before storage so a database
//! breach does not yield the cleartext fallback factor.
//!
//! ## Storage shape
//!
//! ```text
//! Mutex<HashMap<UserId, MfaEnrollment>>
//!
//! struct MfaEnrollment {
//!     secret: [u8; 20],                // RFC 6238 baseline
//!     verified: bool,                  // false until first verify()
//!     last_verified_at: Option<OffsetDateTime>,
//!     recovery_hashes: Vec<RecoveryCodeHash>,
//! }
//!
//! struct RecoveryCodeHash {
//!     hash: [u8; 32],                  // sha2::Sha256 of the plaintext code
//!     used: bool,                      // single-use enforcement
//! }
//! ```
//!
//! ## Verify semantics
//!
//! `verify(user_id, code)` accepts either:
//!
//! - a 6-digit TOTP code that passes [`TotpVerifier::verify`] within the
//!   default ±1 step window, OR
//! - a single recovery code whose SHA-256 hash matches one of the
//!   user's stored hashes AND has not been previously consumed.
//!
//! TOTP success leaves recovery codes untouched. Recovery success marks
//! the matching entry as used so it cannot be replayed.
//!
//! ## Security hygiene
//!
//! - The 20-byte secret is held in a `Mutex` and never logged. The
//!   adapter's `Debug` impl is opt-out for the secret + recovery slots.
//! - Recovery cleartexts only ever exist on the heap of the calling
//!   `enroll` invocation. They are dropped as soon as the response is
//!   serialised.
//! - Failed verifies surface as [`IamError::InvalidCredentials`] so
//!   the HTTP layer maps to 401 without revealing whether the user is
//!   enrolled.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base32::Alphabet;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::types::Json;
use sqlx::{PgPool, Row as _};
use sx_api::port::MfaPort;
use sx_api::view::mfa_view::{EnrollResponse, MfaStatusView};
use sx_iam::service::totp::TotpVerifier;
use sx_iam::IamError;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Length of the TOTP shared secret in bytes — matches RFC 6238 baseline
/// (160 bits) when used with HMAC-SHA1.
const SECRET_LEN: usize = 20;

/// Number of recovery codes generated at enrollment time.
const RECOVERY_CODE_COUNT: usize = 6;

/// Length (chars) of each recovery code.
const RECOVERY_CODE_LEN: usize = 8;

/// Alphanumeric alphabet (upper-case letters + digits) used to mint
/// recovery codes. Omits ambiguous chars (0/O, 1/I/l) so codes are
/// easy to transcribe from paper.
const RECOVERY_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Issuer label embedded in the otpauth URI.
const OTPAUTH_ISSUER: &str = "SentinelX";

/// Trait abstraction over the wall clock so tests can pin time.
pub(crate) trait MfaClock: Send + Sync + std::fmt::Debug {
    /// Current Unix-seconds timestamp.
    fn now_unix(&self) -> u64;
    /// Current UTC instant — used for `last_verified_at`.
    fn now_utc(&self) -> OffsetDateTime;
}

/// Production wall clock.
#[derive(Debug, Default)]
pub(crate) struct SystemClock;

impl MfaClock for SystemClock {
    fn now_unix(&self) -> u64 {
        let now = OffsetDateTime::now_utc();
        let secs = now.unix_timestamp();
        if secs < 0 {
            0
        } else {
            u64::try_from(secs).unwrap_or(u64::MAX)
        }
    }
    fn now_utc(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// Bundle returned to the composition root.
pub(crate) struct MfaBundle {
    /// HTTP-facing TOTP MFA port.
    pub mfa: Arc<dyn MfaPort>,
}

/// Build the in-memory MFA adapter.
pub(crate) fn build(pool: Option<PgPool>) -> MfaBundle {
    // Durable Postgres store when the database is enabled (TOTP secrets +
    // recovery codes survive restart), in-memory single-process otherwise.
    let store: Arc<dyn MfaStore> = match pool {
        Some(p) => Arc::new(PgMfaStore::new(p)),
        None => Arc::new(InMemoryMfaStore::default()),
    };
    MfaBundle {
        mfa: Arc::new(MfaService::new(store)),
    }
}

/// One stored recovery code — SHA-256 of the cleartext + single-use flag.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct RecoveryCodeHash {
    hash: [u8; 32],
    used: bool,
}

/// One stored enrollment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MfaEnrollment {
    /// RFC 6238 shared secret (20 random bytes for SHA-1 baseline).
    secret: [u8; SECRET_LEN],
    /// `true` once the user has completed `verify` at least once.
    verified: bool,
    /// Timestamp of the most recent successful `verify`.
    last_verified_at: Option<OffsetDateTime>,
    /// SHA-256 hashes of the user's recovery codes.
    recovery_hashes: Vec<RecoveryCodeHash>,
}

impl MfaEnrollment {
    fn to_status(&self) -> MfaStatusView {
        MfaStatusView {
            enrolled: self.verified,
            last_verified_at: self.last_verified_at.and_then(|t| t.format(&Rfc3339).ok()),
        }
    }
}

/// Persistence seam for MFA enrollments. In-memory for dev / tests;
/// Postgres for durable deployments, so a user's TOTP secret + recovery
/// codes survive a monolith restart (an in-memory store loses every user's
/// 2FA enrolment on restart).
#[async_trait]
pub(crate) trait MfaStore: Send + Sync + std::fmt::Debug {
    async fn get(&self, user_id: &str) -> Result<Option<MfaEnrollment>, IamError>;
    async fn put(&self, user_id: &str, enrollment: &MfaEnrollment) -> Result<(), IamError>;
    async fn remove(&self, user_id: &str) -> Result<(), IamError>;
}

/// In-memory MFA store (dev / tests). Loses all enrolments on restart.
#[derive(Debug, Default)]
pub(crate) struct InMemoryMfaStore {
    rows: Mutex<HashMap<String, MfaEnrollment>>,
}

#[async_trait]
impl MfaStore for InMemoryMfaStore {
    async fn get(&self, user_id: &str) -> Result<Option<MfaEnrollment>, IamError> {
        Ok(self
            .rows
            .lock()
            .map_err(|_| IamError::internal("mfa store poisoned"))?
            .get(user_id)
            .cloned())
    }
    async fn put(&self, user_id: &str, enrollment: &MfaEnrollment) -> Result<(), IamError> {
        self.rows
            .lock()
            .map_err(|_| IamError::internal("mfa store poisoned"))?
            .insert(user_id.to_owned(), enrollment.clone());
        Ok(())
    }
    async fn remove(&self, user_id: &str) -> Result<(), IamError> {
        self.rows
            .lock()
            .map_err(|_| IamError::internal("mfa store poisoned"))?
            .remove(user_id);
        Ok(())
    }
}

/// Postgres-backed MFA store (durable across restart). Keyed by `user_id`
/// (the `MfaPort` is tenant-less); see the migration for why there is no
/// tenant RLS here. A malformed (non-UUID) user id is a repository error.
pub(crate) struct PgMfaStore {
    pool: PgPool,
}

impl std::fmt::Debug for PgMfaStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgMfaStore").finish_non_exhaustive()
    }
}

impl PgMfaStore {
    pub(crate) const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn parse_uid(user_id: &str) -> Result<uuid::Uuid, IamError> {
        uuid::Uuid::parse_str(user_id.trim())
            .map_err(|e| IamError::internal(format!("mfa: user id not a uuid: {e}")))
    }
}

#[async_trait]
impl MfaStore for PgMfaStore {
    async fn get(&self, user_id: &str) -> Result<Option<MfaEnrollment>, IamError> {
        let uid = Self::parse_uid(user_id)?;
        let row = sqlx::query("SELECT enrollment FROM mfa_enrollments WHERE user_id = $1")
            .bind(uid)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| IamError::internal(format!("mfa get: {e}")))?;
        match row {
            Some(r) => Ok(Some(
                r.try_get::<Json<MfaEnrollment>, _>("enrollment")
                    .map_err(|e| IamError::internal(format!("mfa decode: {e}")))?
                    .0,
            )),
            None => Ok(None),
        }
    }

    async fn put(&self, user_id: &str, enrollment: &MfaEnrollment) -> Result<(), IamError> {
        let uid = Self::parse_uid(user_id)?;
        sqlx::query(
            "INSERT INTO mfa_enrollments (user_id, enrollment, updated_at) \
             VALUES ($1, $2, now()) \
             ON CONFLICT (user_id) DO UPDATE SET enrollment = EXCLUDED.enrollment, updated_at = now()",
        )
        .bind(uid)
        .bind(Json(enrollment))
        .execute(&self.pool)
        .await
        .map_err(|e| IamError::internal(format!("mfa put: {e}")))?;
        Ok(())
    }

    async fn remove(&self, user_id: &str) -> Result<(), IamError> {
        let uid = Self::parse_uid(user_id)?;
        sqlx::query("DELETE FROM mfa_enrollments WHERE user_id = $1")
            .bind(uid)
            .execute(&self.pool)
            .await
            .map_err(|e| IamError::internal(format!("mfa remove: {e}")))?;
        Ok(())
    }
}

/// TOTP MFA service over a pluggable [`MfaStore`].
pub(crate) struct MfaService {
    store: Arc<dyn MfaStore>,
    verifier: TotpVerifier,
    clock: Arc<dyn MfaClock>,
}

impl std::fmt::Debug for MfaService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MfaService")
            .field("verifier", &self.verifier)
            .finish_non_exhaustive()
    }
}

impl MfaService {
    /// Build over `store` with the default RFC 6238 verifier + prod clock.
    pub(crate) fn new(store: Arc<dyn MfaStore>) -> Self {
        Self::with_store_and_clock(store, Arc::new(SystemClock))
    }

    /// Test constructor — injectable store + clock.
    pub(crate) fn with_store_and_clock(store: Arc<dyn MfaStore>, clock: Arc<dyn MfaClock>) -> Self {
        Self {
            store,
            verifier: TotpVerifier::default(),
            clock,
        }
    }

    /// Generate a fresh 20-byte secret using `OsRng`.
    fn mint_secret() -> [u8; SECRET_LEN] {
        let mut bytes = [0_u8; SECRET_LEN];
        OsRng.fill_bytes(&mut bytes);
        bytes
    }

    /// Generate a single 8-char recovery code over the
    /// [`RECOVERY_ALPHABET`].
    fn mint_recovery_code() -> String {
        let mut out = String::with_capacity(RECOVERY_CODE_LEN);
        for _ in 0..RECOVERY_CODE_LEN {
            // Reject-sample a uniform byte from the alphabet to avoid
            // modulo bias. Alphabet length is 32, which divides 256
            // evenly, so a single byte mod 32 is unbiased — but we
            // still go through `get` for safety.
            let mut buf = [0_u8; 1];
            OsRng.fill_bytes(&mut buf);
            let idx = usize::from(buf[0] % 32);
            if let Some(&c) = RECOVERY_ALPHABET.get(idx) {
                out.push(char::from(c));
            }
        }
        out
    }

    /// SHA-256 a recovery code into the 32-byte storage representation.
    fn hash_recovery(code: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(code.as_bytes());
        let digest = hasher.finalize();
        let mut out = [0_u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Build the otpauth provisioning URI per the de-facto Google
    /// Authenticator format.
    fn build_otpauth_uri(user_id: &str, secret_b32: &str) -> String {
        // URL-encode the user id minimally — `:` is the only spec
        // separator we need to dodge for the account label.
        let safe_user = user_id.replace(':', "_");
        let issuer = OTPAUTH_ISSUER;
        format!(
            "otpauth://totp/{issuer}:{safe_user}?secret={secret_b32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
        )
    }
}

#[async_trait]
impl MfaPort for MfaService {
    async fn enroll(&self, user_id: &str) -> Result<EnrollResponse, IamError> {
        let secret = Self::mint_secret();
        let secret_b32 = base32::encode(Alphabet::Rfc4648 { padding: false }, &secret);

        // Mint 6 recovery codes; persist their hashes; surface cleartext
        // once to the caller.
        let mut recovery_clear: Vec<String> = Vec::with_capacity(RECOVERY_CODE_COUNT);
        let mut recovery_hashes: Vec<RecoveryCodeHash> = Vec::with_capacity(RECOVERY_CODE_COUNT);
        for _ in 0..RECOVERY_CODE_COUNT {
            let code = Self::mint_recovery_code();
            recovery_hashes.push(RecoveryCodeHash {
                hash: Self::hash_recovery(&code),
                used: false,
            });
            recovery_clear.push(code);
        }

        let enrollment = MfaEnrollment {
            secret,
            verified: false,
            last_verified_at: None,
            recovery_hashes,
        };

        self.store.put(user_id, &enrollment).await?;

        // Tracing — never the secret or the recovery codes.
        tracing::info!(
            target: "adapters.mfa.enroll",
            user_id = %user_id,
            recovery_count = recovery_clear.len(),
            "mfa enrollment minted"
        );

        let uri = Self::build_otpauth_uri(user_id, &secret_b32);
        Ok(EnrollResponse {
            secret_base32: secret_b32,
            otpauth_uri: uri,
            recovery_codes: recovery_clear,
        })
    }

    async fn verify(&self, user_id: &str, code: &str) -> Result<(), IamError> {
        let now_unix = self.clock.now_unix();
        let now_utc = self.clock.now_utc();

        // Avoid revealing enrollment state. Missing rows + bad codes both
        // collapse to `InvalidCredentials`.
        let Some(mut enrollment) = self.store.get(user_id).await? else {
            return Err(IamError::InvalidCredentials);
        };

        // 1. TOTP path.
        if self.verifier.verify(&enrollment.secret, code, now_unix) {
            enrollment.verified = true;
            enrollment.last_verified_at = Some(now_utc);
            self.store.put(user_id, &enrollment).await?;
            tracing::info!(
                target: "adapters.mfa.verify",
                user_id = %user_id,
                kind = "totp",
                "mfa verify succeeded"
            );
            return Ok(());
        }

        // 2. Recovery-code fallback. Hash the candidate once, then
        //    linear-scan the unused entries. Constant-time comparison
        //    is unnecessary because we're comparing a 32-byte hash, not
        //    a secret.
        let candidate = Self::hash_recovery(code);
        let mut matched: Option<usize> = None;
        for (idx, slot) in enrollment.recovery_hashes.iter().enumerate() {
            if !slot.used && slot.hash == candidate {
                matched = Some(idx);
                break;
            }
        }
        if let Some(idx) = matched {
            if let Some(slot) = enrollment.recovery_hashes.get_mut(idx) {
                slot.used = true;
            }
            enrollment.verified = true;
            enrollment.last_verified_at = Some(now_utc);
            self.store.put(user_id, &enrollment).await?;
            tracing::info!(
                target: "adapters.mfa.verify",
                user_id = %user_id,
                kind = "recovery",
                "mfa verify succeeded via recovery code"
            );
            return Ok(());
        }

        tracing::debug!(
            target: "adapters.mfa.verify",
            user_id = %user_id,
            "mfa verify rejected"
        );
        Err(IamError::InvalidCredentials)
    }

    async fn disable(&self, user_id: &str, code: &str) -> Result<(), IamError> {
        // Verify possession first so we never drop a row on an
        // unauthenticated request. `verify` updates the timestamp /
        // verified flag, but a follow-up `remove` here erases the
        // entire enrollment row.
        self.verify(user_id, code).await?;
        self.store.remove(user_id).await?;
        tracing::info!(
            target: "adapters.mfa.disable",
            user_id = %user_id,
            "mfa enrollment removed"
        );
        Ok(())
    }

    async fn status(&self, user_id: &str) -> Result<MfaStatusView, IamError> {
        Ok(self.store.get(user_id).await?.map_or_else(
            || MfaStatusView {
                enrolled: false,
                last_verified_at: None,
            },
            |e| e.to_status(),
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// Test clock — pinned to a fixed `unix_secs` + matching `OffsetDateTime`.
    #[derive(Debug)]
    struct FakeClock {
        unix: StdMutex<u64>,
    }

    impl FakeClock {
        fn new(unix: u64) -> Self {
            Self {
                unix: StdMutex::new(unix),
            }
        }
    }

    impl MfaClock for FakeClock {
        fn now_unix(&self) -> u64 {
            *self.unix.lock().unwrap()
        }
        fn now_utc(&self) -> OffsetDateTime {
            let s = *self.unix.lock().unwrap();
            OffsetDateTime::from_unix_timestamp(i64::try_from(s).unwrap_or(0)).unwrap()
        }
    }

    /// Builds a `MfaService` over a concrete in-memory store, returning
    /// the store handle alongside so tests can peek the persisted
    /// enrollment rows (`store.rows.lock()`) the way they used to read
    /// the adapter's old inline map.
    fn make_adapter(now: u64) -> (MfaService, Arc<InMemoryMfaStore>) {
        let store = Arc::new(InMemoryMfaStore::default());
        let svc = MfaService::with_store_and_clock(
            Arc::clone(&store) as Arc<dyn MfaStore>,
            Arc::new(FakeClock::new(now)),
        );
        (svc, store)
    }

    /// RFC 6238 reference test vector — verifies the *integration*
    /// of the adapter's verifier with the RFC 6238 sample secret.
    #[tokio::test]
    async fn rfc6238_test_vector_verifies_in_adapter() {
        let secret = b"12345678901234567890";
        // Inject the known secret directly by going through enroll +
        // overwriting; enrollment in production generates a random
        // secret, but we test the verifier wiring here.
        let (adapter, store) = make_adapter(59);
        adapter
            .enroll("user-rfc")
            .await
            .expect("enroll should succeed");
        {
            let mut g = store.rows.lock().unwrap();
            let row = g.get_mut("user-rfc").unwrap();
            row.secret.copy_from_slice(secret);
        }
        // T=59, TOTP6 = 287082 (RFC 6238 Appendix B).
        adapter
            .verify("user-rfc", "287082")
            .await
            .expect("RFC 6238 sample code must verify");
    }

    /// window=-1 / +1 acceptance: codes minted for the previous /
    /// following 30s step still pass the default ±1 window.
    #[tokio::test]
    async fn verify_accepts_minus_one_and_plus_one_window() {
        let now = 1_700_000_000_u64;
        let (adapter, store) = make_adapter(now);
        adapter.enroll("u1").await.unwrap();
        let secret = {
            let g = store.rows.lock().unwrap();
            g.get("u1").unwrap().secret
        };
        let v = TotpVerifier::default();
        let prev = v.generate_code(&secret, now - 30);
        let next = v.generate_code(&secret, now + 30);
        adapter.verify("u1", &prev).await.expect("prev step ok");
        adapter.verify("u1", &next).await.expect("next step ok");
    }

    /// window=-2 rejection: codes from two steps in the past fall
    /// outside the default ±1 window.
    #[tokio::test]
    async fn verify_rejects_minus_two_window() {
        let now = 1_700_000_000_u64;
        let (adapter, store) = make_adapter(now);
        adapter.enroll("u2").await.unwrap();
        let secret = {
            let g = store.rows.lock().unwrap();
            g.get("u2").unwrap().secret
        };
        let v = TotpVerifier::default();
        let stale = v.generate_code(&secret, now - 60);
        let err = adapter
            .verify("u2", &stale)
            .await
            .expect_err("stale code must be rejected");
        assert_eq!(err, IamError::InvalidCredentials);
    }

    /// Enroll must hand back 6 recovery codes — each 8 chars long.
    #[tokio::test]
    async fn enroll_produces_six_recovery_codes() {
        let (adapter, _store) = make_adapter(0);
        let resp = adapter.enroll("alice").await.unwrap();
        assert_eq!(resp.recovery_codes.len(), 6);
        for c in &resp.recovery_codes {
            assert_eq!(c.len(), 8, "each recovery code must be 8 chars");
            assert!(c.bytes().all(|b| b.is_ascii_alphanumeric()));
        }
    }

    /// Verify with the current step activates the enrollment (status
    /// flips to enrolled=true).
    #[tokio::test]
    async fn verify_activates_enrollment() {
        let now = 1_700_000_000_u64;
        let (adapter, store) = make_adapter(now);
        adapter.enroll("bob").await.unwrap();
        // Pre-verify, status is enrolled=false.
        let s0 = adapter.status("bob").await.unwrap();
        assert!(!s0.enrolled);

        let secret = {
            let g = store.rows.lock().unwrap();
            g.get("bob").unwrap().secret
        };
        let code = TotpVerifier::default().generate_code(&secret, now);
        adapter.verify("bob", &code).await.unwrap();
        let s1 = adapter.status("bob").await.unwrap();
        assert!(s1.enrolled);
        assert!(s1.last_verified_at.is_some());
    }

    /// Wrong code → `InvalidCredentials`.
    #[tokio::test]
    async fn verify_wrong_code_yields_invalid_credentials() {
        let (adapter, _store) = make_adapter(1_700_000_000);
        adapter.enroll("carol").await.unwrap();
        let err = adapter
            .verify("carol", "000000")
            .await
            .expect_err("wrong code must fail");
        assert_eq!(err, IamError::InvalidCredentials);
    }

    /// Disable requires a valid TOTP or recovery code.
    #[tokio::test]
    async fn disable_requires_valid_code() {
        let now = 1_700_000_000_u64;
        let (adapter, store) = make_adapter(now);
        adapter.enroll("dave").await.unwrap();
        // Wrong code first.
        let err = adapter
            .disable("dave", "000000")
            .await
            .expect_err("bad code must reject disable");
        assert_eq!(err, IamError::InvalidCredentials);

        // Now a valid TOTP code.
        let secret = {
            let g = store.rows.lock().unwrap();
            g.get("dave").unwrap().secret
        };
        let code = TotpVerifier::default().generate_code(&secret, now);
        adapter
            .disable("dave", &code)
            .await
            .expect("valid code must allow disable");

        // After disable the enrollment is gone.
        let s = adapter.status("dave").await.unwrap();
        assert!(!s.enrolled);
    }

    /// Status before enrollment reports `enrolled = false` and no
    /// timestamp; after verify, it flips to `true` and carries an
    /// RFC-3339 timestamp.
    #[tokio::test]
    async fn status_before_and_after_enrollment() {
        let now = 1_700_000_000_u64;
        let (adapter, store) = make_adapter(now);
        // 1. No enrollment yet.
        let s0 = adapter.status("eve").await.unwrap();
        assert!(!s0.enrolled);
        assert!(s0.last_verified_at.is_none());

        // 2. Enroll but not yet verified → still false.
        adapter.enroll("eve").await.unwrap();
        let s1 = adapter.status("eve").await.unwrap();
        assert!(!s1.enrolled);

        // 3. Verify → enrolled flips to true.
        let secret = {
            let g = store.rows.lock().unwrap();
            g.get("eve").unwrap().secret
        };
        let code = TotpVerifier::default().generate_code(&secret, now);
        adapter.verify("eve", &code).await.unwrap();
        let s2 = adapter.status("eve").await.unwrap();
        assert!(s2.enrolled);
        assert!(
            s2.last_verified_at.is_some(),
            "last_verified_at must be set after verify"
        );
    }

    /// Recovery codes are accepted exactly once (single-use) — replay
    /// of the same recovery code fails with `InvalidCredentials`.
    #[tokio::test]
    async fn recovery_code_is_single_use() {
        let now = 1_700_000_000_u64;
        let (adapter, _store) = make_adapter(now);
        let resp = adapter.enroll("frank").await.unwrap();
        let first = resp.recovery_codes.first().cloned().unwrap();
        // First use: ok.
        adapter
            .verify("frank", &first)
            .await
            .expect("first recovery use must succeed");
        // Second use: rejected.
        let err = adapter
            .verify("frank", &first)
            .await
            .expect_err("replayed recovery code must be rejected");
        assert_eq!(err, IamError::InvalidCredentials);
    }

    /// Base32 of a 20-byte secret is 32 chars (RFC 4648 unpadded).
    #[tokio::test]
    async fn enroll_emits_32_char_base32_secret() {
        let (adapter, _store) = make_adapter(0);
        let resp = adapter.enroll("g").await.unwrap();
        assert_eq!(resp.secret_base32.len(), 32);
        assert!(resp.otpauth_uri.starts_with("otpauth://totp/SentinelX:"));
        assert!(resp.otpauth_uri.contains(&resp.secret_base32));
    }
}
