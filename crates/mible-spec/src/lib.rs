//! The MIoT "spec" channel of Xiaomi Mi BLE devices, used after login.
//!
//! - [`codec`]: the plaintext frame (`<len> 20 <seq> <body>`) and string
//!   TLVs.
//!
//! No I/O, no clock, no allocator.
#![no_std]

pub mod codec;

pub use codec::{CodecError, SpecFrame};
