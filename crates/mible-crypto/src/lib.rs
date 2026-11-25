//! Cryptography for the Xiaomi Mi BLE login and session.
//!
//! - [`Token`]: the device's long-lived 12-byte secret.
//! - [`LoginKeys`]: per-session keys derived from the token and both sides'
//!   randoms, plus the HMAC proofs each side sends.
//! - [`SessionCipher`]: AES-128-CCM for messages after login.
//! - [`BeaconKey`] and [`BeaconCipher`]: the device's advertisement key, and
//!   AES-128-CCM for the payloads of its MiBeacon v4/v5 advertisements.
//!
//! Secrets are zeroised on drop and redacted from `Debug` output. No I/O, no
//! clock, no randomness (callers pass the randoms in), no allocator.
#![no_std]

pub mod beacon;
#[expect(
    clippy::redundant_pub_crate,
    reason = "rustc's `unreachable_pub` asks for `pub(crate)` in a private module"
)]
mod hex;
pub mod login;
pub mod session;
pub mod token;

pub use beacon::{BeaconCipher, BeaconKey, BeaconKeyParseError};
pub use login::{LoginKeys, ProofMismatch};
pub use session::{CipherError, Role, SessionCipher};
pub use token::{Token, TokenParseError};
