//! Cryptography for the Xiaomi Mi BLE login.
//!
//! - [`Token`]: the device's long-lived 12-byte secret.
//! - [`LoginKeys`]: per-session keys derived from the token and both sides'
//!   randoms, plus the HMAC proofs each side sends.
//!
//! Secrets are zeroised on drop and redacted from `Debug` output. No I/O, no
//! clock, no randomness (callers pass the randoms in), no allocator.
#![no_std]

pub mod login;
pub mod token;

pub use login::{LoginKeys, ProofMismatch};
pub use token::{Token, TokenParseError};
