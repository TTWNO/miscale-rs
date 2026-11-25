//! The MIoT "spec" channel of Xiaomi Mi BLE devices, used after login.
//!
//! - [`codec`]: the plaintext frame (`<len> 20 <seq> <body>`) and string
//!   TLVs.
//! - [`SpecChannel`]: seals frames with the session cipher and carries them
//!   as parcels on `0x001A` (app → device) and `0x001B` (device → app).
//!
//! No I/O, no clock, no allocator.
#![no_std]

pub mod channel;
pub mod codec;

pub use channel::{SpecChannel, SpecError, SpecProgress};
pub use codec::{CodecError, SpecFrame};
