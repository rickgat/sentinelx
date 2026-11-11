//! libFuzzer harness for [`sx_collab::model::Token::parse`].
//!
//! The contract under test: parsing arbitrary UTF-8-lossy strings must
//! never panic. Malformed input is returned as
//! `Err(CollabError::InvalidToken { .. })`.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run --fuzz-dir crates/sx-collab/fuzz token_parse
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sx_collab::model::Token::parse(&String::from_utf8_lossy(data));
});
