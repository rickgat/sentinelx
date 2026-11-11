//! libFuzzer harness for [`sx_iam::service::JwtValidator::decode_unverified`].
//!
//! The contract under test: arbitrary byte input must never panic. Any
//! malformed token is returned as `Err(IamError::InvalidToken)`; the
//! fuzzer is responsible for discovering inputs that would crash the
//! parser were the contract broken.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run --fuzz-dir crates/sx-iam/fuzz jwt_decode
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sx_iam::service::JwtValidator::<sx_iam::service::StaticKeyResolver>::decode_unverified(data);
});
