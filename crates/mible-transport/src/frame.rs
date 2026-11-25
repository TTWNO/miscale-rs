//! Control frames and data fragments, as they appear in one GATT write or
//! notification.
//!
//! ```text
//! control   00 00 <subtype> <code> [payload]
//! fragment  <index: u16 LE, starting at 1> <payload>
//! ```
//!
//! A fragment index is never zero, so two leading zero bytes always mean a
//! control frame.

use core::fmt;
use core::num::NonZeroU16;

use crate::Packet;

/// Control-frame subtype: announce a parcel (`00 00 00 <kind> <count: u16 LE>`).
const ANNOUNCE: u8 = 0;
/// Control-frame subtype: acknowledge a parcel (`00 00 01 <status> [detail]`).
const ACK: u8 = 1;
/// Control-frame subtype: a one-shot message (`00 00 02 <code> <payload>`).
const SINGLE: u8 = 2;
/// Control-frame subtype: acknowledge a one-shot message (`00 00 03 <code>`).
const SINGLE_ACK: u8 = 3;

/// Status byte of an acknowledgement (`00 00 01 <status> …`).
///
/// The values are the Mi BLE SDK's reliable-transfer acknowledgement codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AckStatus {
    /// `0`: every announced fragment arrived.
    Success,
    /// `1`: ready for the announced fragments.
    Ready,
    /// `2`: the receiver is busy.
    Busy,
    /// `3`: the receiver gave up waiting for fragments.
    Timeout,
    /// `4`: the transfer was cancelled.
    Cancel,
    /// `5`: fragments were lost; the detail lists their indices
    /// (see [`lost_indices`]).
    Lost,
    /// Any other status byte.
    Unknown(u8),
}

impl AckStatus {
    /// Decodes a status byte.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Self {
        match byte {
            0 => Self::Success,
            1 => Self::Ready,
            2 => Self::Busy,
            3 => Self::Timeout,
            4 => Self::Cancel,
            5 => Self::Lost,
            other => Self::Unknown(other),
        }
    }

    /// Encodes the status byte.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::Ready => 1,
            Self::Busy => 2,
            Self::Timeout => 3,
            Self::Cancel => 4,
            Self::Lost => 5,
            Self::Unknown(other) => other,
        }
    }
}

/// One control frame or data fragment, borrowing its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Frame<'a> {
    /// A parcel of `count` fragments of the given `kind` follows.
    Announce {
        /// Parcel kind, e.g. `0x0B` for the login random.
        kind: u8,
        /// Number of fragments that follow.
        count: u16,
    },
    /// Acknowledgement of a parcel.
    Ack {
        /// What is being acknowledged.
        status: AckStatus,
        /// Extra bytes; for [`AckStatus::Lost`], the lost indices.
        detail: &'a [u8],
    },
    /// A one-shot message that is not fragmented.
    Single {
        /// Message code (a sequence number on the spec channel).
        code: u8,
        /// Message body.
        payload: &'a [u8],
    },
    /// Acknowledgement of a [`Frame::Single`].
    SingleAck {
        /// The code being acknowledged.
        code: u8,
    },
    /// A control frame with a subtype this crate does not interpret
    /// (for example the optional MTU-negotiation frames).
    Unknown {
        /// Subtype byte.
        subtype: u8,
        /// Code byte.
        code: u8,
        /// Remaining bytes.
        payload: &'a [u8],
    },
    /// One numbered piece of a parcel.
    Fragment {
        /// Position in the parcel, starting at 1.
        index: NonZeroU16,
        /// Fragment bytes; never empty.
        payload: &'a [u8],
    },
}

impl<'a> Frame<'a> {
    /// Parses one GATT value.
    ///
    /// Returns `None` for anything that is not a well-formed frame: values
    /// shorter than four bytes, an announcement that is not exactly six
    /// bytes, a single-ack with trailing bytes, or an empty fragment.
    #[must_use]
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        let (head, rest) = bytes.split_first_chunk::<2>()?;
        let index = u16::from_le_bytes(*head);
        if let Some(index) = NonZeroU16::new(index) {
            return (!rest.is_empty()).then_some(Self::Fragment {
                index,
                payload: rest,
            });
        }
        let (&subtype, rest) = rest.split_first()?;
        let (&code, rest) = rest.split_first()?;
        match subtype {
            ANNOUNCE => {
                let count = u16::from_le_bytes(<[u8; 2]>::try_from(rest).ok()?);
                Some(Self::Announce { kind: code, count })
            }
            ACK => Some(Self::Ack {
                status: AckStatus::from_byte(code),
                detail: rest,
            }),
            SINGLE => Some(Self::Single {
                code,
                payload: rest,
            }),
            SINGLE_ACK => rest.is_empty().then_some(Self::SingleAck { code }),
            _ => Some(Self::Unknown {
                subtype,
                code,
                payload: rest,
            }),
        }
    }

    /// Encodes the frame into one GATT write.
    ///
    /// # Errors
    ///
    /// [`EncodeError::TooLong`] if the frame does not fit one
    /// [`Packet`], and [`EncodeError::EmptyFragment`] for a fragment
    /// without payload (which [`Frame::parse`] would reject).
    pub fn encode(&self) -> Result<Packet, EncodeError> {
        let (head, tail): ([u8; 4], &[u8]) = match *self {
            Self::Announce { kind, count } => {
                let [lo, hi] = count.to_le_bytes();
                ([0, 0, ANNOUNCE, kind], &[lo, hi])
            }
            Self::Ack { status, detail } => ([0, 0, ACK, status.to_byte()], detail),
            Self::Single { code, payload } => ([0, 0, SINGLE, code], payload),
            Self::SingleAck { code } => ([0, 0, SINGLE_ACK, code], &[]),
            Self::Unknown {
                subtype,
                code,
                payload,
            } => ([0, 0, subtype, code], payload),
            Self::Fragment { index, payload } => {
                if payload.is_empty() {
                    return Err(EncodeError::EmptyFragment);
                }
                let mut out = Packet::new();
                out.extend_from_slice(&index.get().to_le_bytes())
                    .map_err(too_long)?;
                out.extend_from_slice(payload).map_err(too_long)?;
                return Ok(out);
            }
        };
        let mut out = Packet::new();
        out.extend_from_slice(&head).map_err(too_long)?;
        out.extend_from_slice(tail).map_err(too_long)?;
        Ok(out)
    }
}

/// Maps a buffer-capacity failure to [`EncodeError::TooLong`].
const fn too_long(_: heapless::CapacityError) -> EncodeError {
    EncodeError::TooLong
}

/// Iterates the fragment indices listed in an [`AckStatus::Lost`] detail
/// (consecutive `u16` LE values; a trailing odd byte is ignored).
#[must_use]
pub fn lost_indices(detail: &[u8]) -> LostIndices<'_> {
    LostIndices {
        pairs: detail.as_chunks::<2>().0.iter(),
    }
}

/// Iterator returned by [`lost_indices`].
#[derive(Debug, Clone)]
pub struct LostIndices<'a> {
    /// Remaining two-byte pairs of the detail.
    pairs: core::slice::Iter<'a, [u8; 2]>,
}

impl Iterator for LostIndices<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<u16> {
        self.pairs.next().copied().map(u16::from_le_bytes)
    }
}

/// Why a [`Frame`] could not be encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EncodeError {
    /// The frame is longer than one [`Packet`].
    TooLong,
    /// A fragment had no payload.
    EmptyFragment,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLong => "frame does not fit one GATT write",
            Self::EmptyFragment => "fragment has no payload",
        })
    }
}

impl core::error::Error for EncodeError {}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU16;

    use super::{AckStatus, EncodeError, Frame, lost_indices};

    /// Decodes a hex string (test helper).
    fn hex(text: &str) -> heapless::Vec<u8, 64> {
        let bytes = text.as_bytes();
        bytes
            .chunks(2)
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    /// Fragment index 1, for brevity.
    const ONE: NonZeroU16 = NonZeroU16::MIN;

    /// Announcements captured from the prototype and miauth's command table.
    #[test]
    fn announce_vectors() {
        for (wire, kind, count) in [
            ("000000030400", 3, 4),
            ("0000000b0100", 0x0b, 1),
            ("000000000f00", 0, 15),
        ] {
            let frame = Frame::Announce { kind, count };
            assert_eq!(Frame::parse(&hex(wire)), Some(frame), "parse {wire}");
            assert_eq!(frame.encode().unwrap(), hex(wire), "encode {wire}");
        }
    }

    /// The acknowledgements the prototype exchanges, with their SDK meaning.
    #[test]
    fn ack_vectors() {
        let cases: [(&str, AckStatus, &[u8]); 4] = [
            ("00000101", AckStatus::Ready, &[]),
            ("00000100", AckStatus::Success, &[]),
            ("000001050100", AckStatus::Lost, &[1, 0]),
            ("000001050300", AckStatus::Lost, &[3, 0]),
        ];
        for (wire, status, detail) in cases {
            let frame = Frame::Ack { status, detail };
            assert_eq!(Frame::parse(&hex(wire)), Some(frame), "parse {wire}");
            assert_eq!(frame.encode().unwrap(), hex(wire), "encode {wire}");
        }
    }

    /// Spec-channel one-shot messages and their acknowledgement.
    #[test]
    fn single_and_single_ack() {
        let wire = hex("00000207aabbcc");
        assert_eq!(
            Frame::parse(&wire),
            Some(Frame::Single {
                code: 7,
                payload: &[0xaa, 0xbb, 0xcc]
            }),
            "single"
        );
        assert_eq!(
            Frame::parse(&hex("00000307")),
            Some(Frame::SingleAck { code: 7 }),
            "ack"
        );
        assert_eq!(
            Frame::SingleAck { code: 7 }.encode().unwrap(),
            hex("00000307"),
            "encode ack"
        );
    }

    /// A fragment keeps everything after its index, whatever the length.
    #[test]
    fn fragments_of_any_length() {
        let long = [0x5a; 40];
        let mut wire = heapless::Vec::<u8, 64>::new();
        wire.extend_from_slice(&[2, 0]).unwrap();
        wire.extend_from_slice(&long).unwrap();
        let expected = Frame::Fragment {
            index: NonZeroU16::new(2).unwrap(),
            payload: &long,
        };
        assert_eq!(Frame::parse(&wire), Some(expected), "long fragment");
        assert_eq!(
            Frame::parse(&hex("0100ff")),
            Some(Frame::Fragment {
                index: ONE,
                payload: &[0xff]
            }),
            "one-byte fragment"
        );
    }

    /// Malformed values are rejected rather than misread.
    #[test]
    fn rejects_malformed() {
        for wire in [
            "",
            "00",
            "0000",
            "000000",
            "0000000301",
            "00000003040000",
            "0000030701",
            "0100",
        ] {
            assert_eq!(Frame::parse(&hex(wire)), None, "{wire:?} must not parse");
        }
    }

    /// Unknown subtypes (e.g. MTU negotiation) parse but are not interpreted.
    #[test]
    fn unknown_subtype() {
        assert_eq!(
            Frame::parse(&hex("0000040006f4")),
            Some(Frame::Unknown {
                subtype: 4,
                code: 0,
                payload: &[6, 0xf4]
            }),
            "mng frame"
        );
    }

    /// Encoding refuses frames that cannot round-trip.
    #[test]
    fn encode_errors() {
        assert_eq!(
            Frame::Fragment {
                index: ONE,
                payload: &[]
            }
            .encode(),
            Err(EncodeError::EmptyFragment),
            "empty fragment"
        );
        assert_eq!(
            Frame::Fragment {
                index: ONE,
                payload: &[0; 19]
            }
            .encode(),
            Err(EncodeError::TooLong),
            "19-byte payload overflows a 20-byte write"
        );
        assert!(
            Frame::Fragment {
                index: ONE,
                payload: &[0; 18]
            }
            .encode()
            .is_ok(),
            "18 fits"
        );
    }

    /// Lost indices are little-endian pairs; an odd trailing byte is dropped.
    #[test]
    fn lost_index_list() {
        let found: heapless::Vec<u16, 4> = lost_indices(&[1, 0, 0x10, 0x01, 9]).collect();
        assert_eq!(found.as_slice(), &[1, 0x0110], "indices");
    }

    /// Every status byte survives a round trip.
    #[test]
    fn ack_status_round_trip() {
        for byte in 0..=u8::MAX {
            assert_eq!(AckStatus::from_byte(byte).to_byte(), byte, "status {byte}");
        }
    }
}
