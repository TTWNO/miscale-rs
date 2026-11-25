//! Sans-io login for Xiaomi Mi BLE "standard auth" devices.
//!
//! ```text
//! app → control   24 00 00 00                      start login
//! app → auth      parcel 0x0B: app random (16)
//! dev → auth      parcel 0x0D: device random (16)
//! dev → auth      parcel 0x0C: device proof (32)   checked against the token
//! app → auth      parcel 0x0A: app proof (32)
//! dev → control   21 00 00 00                      logged in (23 00 00 00: refused)
//! ```
//!
//! [`Login`] performs no I/O: feed it notifications with
//! [`Login::handle_notify`] and write whatever [`Login::poll_transmit`]
//! returns. It keeps no clock either; the caller decides how long to wait.
#![no_std]

pub mod login;

pub use login::{Login, LoginError, LoginStatus};
