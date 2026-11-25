//! Sans-io framing for the Xiaomi Mi BLE control and parcel channels.
//!
//! Mi BLE devices move every multi-byte message over a GATT characteristic as
//! a *parcel*: an announcement naming the parcel kind and frame count, an
//! acknowledgement from the receiver, then numbered data fragments. This
//! crate knows the byte layouts and nothing else: it performs no I/O, keeps
//! no clock and never allocates.
#![no_std]

pub mod frame;
pub mod rx;
pub mod tx;

/// Largest GATT value this crate writes: one ATT write at the default MTU.
pub const MAX_PACKET_LEN: usize = 20;

/// One outgoing GATT value (a control frame or a fragment).
pub type Packet = heapless::Vec<u8, MAX_PACKET_LEN>;

/// Payload bytes carried by one data fragment.
///
/// A fragment is `<index: u16 LE> <payload>`; at the default ATT MTU of 23 a
/// GATT write carries 20 bytes, leaving 18 for the payload. The S200 uses this
/// size whatever MTU is negotiated, because the official app never runs the
/// optional MTU handshake.
pub const FRAGMENT_PAYLOAD_LEN: usize = 18;

#[cfg(test)]
mod tests {
    use super::FRAGMENT_PAYLOAD_LEN;

    /// A fragment (2-byte index + payload) must fit one default-MTU ATT write.
    #[test]
    fn fragment_fits_default_att_payload() {
        const DEFAULT_ATT_WRITE_LEN: usize = 23 - 3;
        assert_eq!(
            FRAGMENT_PAYLOAD_LEN + 2,
            DEFAULT_ATT_WRITE_LEN,
            "fragment must fill one write"
        );
    }
}
