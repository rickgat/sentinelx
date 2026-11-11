//! Reporter sub-module.
//!
//! Phase-3 landed [`signer::HmacSigner`]. Phase-3.5 adds the HTTPS collector
//! client in [`http_client`] that uses the signer to authenticate every POST.

pub mod http_client;
pub mod signer;
