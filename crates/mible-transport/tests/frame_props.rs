//! Property tests for the frame codec.
#![cfg(test)]

use core::num::NonZeroU16;

use mible_transport::frame::{AckStatus, Frame};
use proptest::prelude::*;

/// Strategy for frames that `encode` accepts and `parse` reproduces exactly.
fn canonical_frame() -> impl Strategy<Value = (u8, u8, u16, Vec<u8>)> {
    // (variant selector, byte a, u16, payload); payload kept short enough to fit.
    (
        0_u8..6,
        any::<u8>(),
        any::<u16>(),
        proptest::collection::vec(any::<u8>(), 0..=16),
    )
}

/// Builds a frame from the generated parts.
fn build(variant: u8, byte: u8, word: u16, payload: &[u8]) -> Option<Frame<'_>> {
    Some(match variant {
        0 => Frame::Announce {
            kind: byte,
            count: word,
        },
        1 => Frame::Ack {
            status: AckStatus::from_byte(byte),
            detail: payload,
        },
        2 => Frame::Single {
            code: byte,
            payload,
        },
        3 => Frame::SingleAck { code: byte },
        4 => Frame::Unknown {
            subtype: byte.max(4),
            code: byte,
            payload,
        },
        _ => {
            if payload.is_empty() {
                return None;
            }
            Frame::Fragment {
                index: NonZeroU16::new(word.max(1))?,
                payload,
            }
        }
    })
}

proptest! {
    /// `parse(encode(frame)) == frame` for every encodable frame.
    #[test]
    fn encode_then_parse_is_identity((variant, byte, word, payload) in canonical_frame()) {
        if let Some(frame) = build(variant, byte, word, &payload) {
            let wire = frame.encode().unwrap();
            prop_assert_eq!(Frame::parse(&wire), Some(frame));
        }
    }

    /// `encode(parse(bytes)) == bytes` whenever `bytes` parses and fits a write.
    #[test]
    fn parse_then_encode_is_identity(bytes in proptest::collection::vec(any::<u8>(), 0..=20)) {
        if let Some(frame) = Frame::parse(&bytes) {
            let encoded = frame.encode().unwrap();
            prop_assert_eq!(encoded.as_slice(), bytes.as_slice());
        }
    }

    /// Parsing arbitrary input never panics, whatever its length.
    #[test]
    fn parse_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..=512)) {
        let _parsed = Frame::parse(&bytes);
    }
}
