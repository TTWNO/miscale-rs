//! Sans-io weigh-in with a Xiaomi Smart Scale S200 (MJTZC02YM).
//!
//! - [`weight`]: weights, and reading them out of decrypted spec frames.
#![no_std]

pub mod weight;

pub use weight::{Reading, Weight};
