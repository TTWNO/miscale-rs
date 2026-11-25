//! MiBeacon: the service data Xiaomi devices advertise under the 16-bit
//! UUID `0xFE95`.
//!
//! ```text
//! frame control  u16 LE      flags; the version in the top four bits
//! product id     u16 LE      the device model
//! frame counter  u8          changes with each new advertisement
//! MAC            6 bytes     reversed; if the MAC flag is set
//! capability     u8 [u8]     if the capability flag is set; a second
//!                            (I/O) byte if capability bit 5 is set
//! objects        …           if the objects flag is set; encrypted (v4/v5):
//!                            ciphertext ‖ extended counter (3) ‖ tag (4)
//! ```
//!
//! An object is `id (u16 LE) ‖ length (u8) ‖ data`. A bound device encrypts
//! its objects under its beacon key; see [`Advertisement::decrypt`].
//!
//! The layout follows what the open-source parsers (xiaomi-ble, ESPHome)
//! accept from real devices. Mesh frames, frames older than version 2, and
//! the legacy (v2/v3) encryption are not supported.
#![no_std]

pub mod frame;
pub mod object;

pub use frame::{
    Advertisement, Body, DecryptError, EncodeError, Encrypted, FrameControl, Header, ParseError,
};
pub use object::{Object, Objects, objects};

/// The 16-bit service UUID MiBeacon service data is advertised under.
pub const SERVICE_UUID16: u16 = 0xFE95;
