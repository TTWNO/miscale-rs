//! Spec frames and string TLVs (plaintext, before sealing).
//!
//! ```text
//! frame   <len: u8, whole frame> 20 <seq: u16 LE> <body>
//! string  <len: u8> a0 <bytes>
//! ```

use core::fmt;

/// Second byte of every spec frame.
pub const FRAME_MARKER: u8 = 0x20;

/// Type byte of a string TLV.
pub const STRING_TYPE: u8 = 0xA0;

/// Bytes before the body: length, marker, sequence number.
pub const HEADER_LEN: usize = 4;

/// Longest frame the one-byte length can describe.
pub const MAX_FRAME_LEN: usize = 255;

/// A spec frame, borrowing its body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SpecFrame<'a> {
    /// Sequence number.
    pub seq: u16,
    /// Everything after the header.
    pub body: &'a [u8],
}

impl<'a> SpecFrame<'a> {
    /// Pairs a sequence number with a body.
    #[must_use]
    pub const fn new(seq: u16, body: &'a [u8]) -> Self {
        Self { seq, body }
    }

    /// Parses a frame whose length byte matches its size and whose marker
    /// is `0x20`.
    #[must_use]
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        let (&[len, marker, lo, hi], body) = bytes.split_first_chunk::<HEADER_LEN>()?;
        (usize::from(len) == bytes.len() && marker == FRAME_MARKER).then_some(Self {
            seq: u16::from_le_bytes([lo, hi]),
            body,
        })
    }

    /// Writes the frame into `out` (cleared first).
    ///
    /// # Errors
    ///
    /// [`CodecError::TooLong`] if the frame would exceed 255 bytes or `out`.
    pub fn encode<const N: usize>(&self, out: &mut heapless::Vec<u8, N>) -> Result<(), CodecError> {
        out.clear();
        let len = HEADER_LEN
            .checked_add(self.body.len())
            .ok_or(CodecError::TooLong)?;
        let len = u8::try_from(len).map_err(|_overflow| CodecError::TooLong)?;
        let [lo, hi] = self.seq.to_le_bytes();
        out.extend_from_slice(&[len, FRAME_MARKER, lo, hi])
            .map_err(too_long)?;
        out.extend_from_slice(self.body).map_err(too_long)
    }
}

/// Appends a string TLV (`<len> a0 <bytes>`) to `out`.
///
/// # Errors
///
/// [`CodecError::TooLong`] if `value` exceeds 255 bytes or `out` is full.
pub fn push_string<const N: usize>(
    out: &mut heapless::Vec<u8, N>,
    value: &[u8],
) -> Result<(), CodecError> {
    let len = u8::try_from(value.len()).map_err(|_overflow| CodecError::TooLong)?;
    out.extend_from_slice(&[len, STRING_TYPE])
        .map_err(too_long)?;
    out.extend_from_slice(value).map_err(too_long)
}

/// Maps a buffer-capacity failure to [`CodecError::TooLong`].
const fn too_long(_: heapless::CapacityError) -> CodecError {
    CodecError::TooLong
}

/// Why a frame or TLV could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CodecError {
    /// Longer than the length byte or the output buffer allows.
    TooLong,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLong => "spec frame or TLV too long",
        })
    }
}

impl core::error::Error for CodecError {}

#[cfg(test)]
mod tests {
    use super::{CodecError, SpecFrame, push_string};

    /// The prototype's hello frame: `05 20 02 00 f0`.
    #[test]
    fn hello_frame() {
        let mut out = heapless::Vec::<u8, 16>::new();
        SpecFrame::new(2, &[0xf0]).encode(&mut out).unwrap();
        assert_eq!(out.as_slice(), &[0x05, 0x20, 0x02, 0x00, 0xf0], "encode");
        assert_eq!(
            SpecFrame::parse(&out),
            Some(SpecFrame::new(2, &[0xf0])),
            "parse"
        );
    }

    /// A mismatched length byte or marker is not a frame.
    #[test]
    fn parse_rejects() {
        assert_eq!(
            SpecFrame::parse(&[0x06, 0x20, 0x02, 0x00, 0xf0]),
            None,
            "length"
        );
        assert_eq!(
            SpecFrame::parse(&[0x05, 0x21, 0x02, 0x00, 0xf0]),
            None,
            "marker"
        );
        assert_eq!(SpecFrame::parse(&[0x03, 0x20, 0x02]), None, "short");
        assert_eq!(
            SpecFrame::parse(&[0x04, 0x20, 0x34, 0x12]),
            Some(SpecFrame::new(0x1234, &[])),
            "empty body"
        );
    }

    /// Frames longer than 255 bytes are refused.
    #[test]
    fn too_long() {
        let mut out = heapless::Vec::<u8, 300>::new();
        assert!(
            SpecFrame::new(0, &[0; 251]).encode(&mut out).is_ok(),
            "255 fits"
        );
        assert_eq!(
            SpecFrame::new(0, &[0; 252]).encode(&mut out),
            Err(CodecError::TooLong),
            "256"
        );
    }

    /// String TLVs are `<len> a0 <bytes>`.
    #[test]
    fn string_tlv() {
        let mut out = heapless::Vec::<u8, 16>::new();
        push_string(&mut out, b"abc").unwrap();
        assert_eq!(out.as_slice(), &[3, 0xa0, b'a', b'b', b'c'], "tlv");
        assert_eq!(
            push_string(&mut out, &[0; 256]),
            Err(CodecError::TooLong),
            "256"
        );
    }
}
