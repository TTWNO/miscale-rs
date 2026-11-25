//! Sans-io weigh-in with a Xiaomi Smart Scale S200 (MJTZC02YM).
//!
//! - [`weight`]: weights, and reading them out of decrypted spec frames.
//! - [`profile`]: the user-profile message that starts the scale reporting.
#![no_std]

pub mod profile;
pub mod weight;

pub use profile::Mid;
pub use weight::{Reading, Weight};
