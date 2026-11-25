//! The advertisement frame: header, body, and v4/v5 payload encryption.
//!
//! The payload nonce is
//!
//! ```text
//! MAC (6, reversed) ‖ product id (u16 LE) ‖ frame counter ‖ extended counter (3)
//! ```
//!
//! so the tag binds the objects to the device, its model and the frame. The
//! frame control and capability bytes are not authenticated: trust only
//! what decrypts.

use core::fmt;

use mible_crypto::beacon::{BEACON_NONCE_LEN, BEACON_TAG_LEN};
use mible_crypto::{BeaconCipher, CipherError};

/// Length of the fixed part of the header.
const FIXED_LEN: usize = 5;
/// Length of the extended counter of an encrypted payload.
const EXT_COUNTER_LEN: usize = 3;
/// Bytes an encrypted payload adds to its objects.
const ENCRYPTED_OVERHEAD: usize = EXT_COUNTER_LEN + BEACON_TAG_LEN;
/// Capability bit announcing the I/O capability byte.
const CAPABILITY_IO: u8 = 1 << 5;
/// First version with the v4/v5 payload encryption.
const FIRST_ENCRYPTED_VERSION: u8 = 4;
/// First version this crate parses.
const FIRST_SUPPORTED_VERSION: u8 = 2;

/// The frame-control field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FrameControl(u16);

impl FrameControl {
    /// Bit 3: the objects are encrypted.
    pub const ENCRYPTED: u16 = 1 << 3;
    /// Bit 4: the header includes the device's MAC.
    pub const MAC: u16 = 1 << 4;
    /// Bit 5: the header includes a capability byte.
    pub const CAPABILITY: u16 = 1 << 5;
    /// Bit 6: the frame carries objects.
    pub const OBJECTS: u16 = 1 << 6;
    /// Bit 7: a mesh frame (not supported).
    pub const MESH: u16 = 1 << 7;
    /// Bit 8: the device is registered and bound.
    pub const REGISTERED: u16 = 1 << 8;
    /// Bit 9: the device asks an app to bind it.
    pub const SOLICITED: u16 = 1 << 9;

    /// The field from its raw value.
    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    /// The raw value.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Whether every bit of `flags` is set.
    #[must_use]
    pub const fn contains(self, flags: u16) -> bool {
        self.0 & flags == flags
    }

    /// The MiBeacon version (bits 12–15).
    #[must_use]
    pub const fn version(self) -> u8 {
        self.0.to_le_bytes()[1].wrapping_shr(4)
    }

    /// The authentication mode (bits 10–11): 0 legacy, 1 secure, 2 standard.
    #[must_use]
    pub const fn auth_mode(self) -> u8 {
        self.0.to_le_bytes()[1].wrapping_shr(2) & 0b11
    }

    /// The field with `flags` set when `on`, cleared otherwise.
    #[must_use]
    pub const fn with(self, flags: u16, on: bool) -> Self {
        if on {
            Self(self.0 | flags)
        } else {
            Self(self.0 & !flags)
        }
    }
}

/// Everything in a frame before its objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Header {
    /// The flags and version. When encoding, the MAC, capability, objects
    /// and encrypted flags are set from the frame's contents.
    pub frame_control: FrameControl,
    /// The device model.
    pub product_id: u16,
    /// Changes with each new advertisement.
    pub frame_counter: u8,
    /// The device's MAC in display order (`D0:7B:…` is `[0xD0, 0x7B, …]`),
    /// if the frame includes it.
    pub mac: Option<[u8; 6]>,
    /// The capability byte, if the frame includes it.
    pub capability: Option<u8>,
    /// The I/O capability byte, present exactly when the capability byte
    /// has bit 5 set.
    pub io_capability: Option<u8>,
}

impl Header {
    /// A header without MAC or capability.
    #[must_use]
    pub const fn new(frame_control: FrameControl, product_id: u16, frame_counter: u8) -> Self {
        Self {
            frame_control,
            product_id,
            frame_counter,
            mac: None,
            capability: None,
            io_capability: None,
        }
    }

    /// The payload nonce for a device at `address` (display order).
    const fn nonce(&self, address: [u8; 6], ext_counter: [u8; 3]) -> [u8; BEACON_NONCE_LEN] {
        let [m0, m1, m2, m3, m4, m5] = address;
        let [p0, p1] = self.product_id.to_le_bytes();
        let [e0, e1, e2] = ext_counter;
        [
            m5,
            m4,
            m3,
            m2,
            m1,
            m0,
            p0,
            p1,
            self.frame_counter,
            e0,
            e1,
            e2,
        ]
    }

    /// Checks that `address` may decrypt or seal this frame: v4/v5 and,
    /// if the frame includes a MAC, the same one.
    fn check_crypto(&self, address: [u8; 6]) -> Result<(), CryptoCheck> {
        if self.frame_control.version() < FIRST_ENCRYPTED_VERSION {
            return Err(CryptoCheck::Version);
        }
        if self.mac.is_some_and(|mac| mac != address) {
            return Err(CryptoCheck::Address);
        }
        Ok(())
    }

    /// Writes the header with flags matching the contents.
    fn encode<const N: usize>(
        &self,
        objects: bool,
        encrypted: bool,
        out: &mut heapless::Vec<u8, N>,
    ) -> Result<(), EncodeError> {
        if self.capability.is_some_and(|cap| cap & CAPABILITY_IO != 0)
            != self.io_capability.is_some()
        {
            return Err(EncodeError::Inconsistent);
        }
        let frame_control = self
            .frame_control
            .with(FrameControl::MAC, self.mac.is_some())
            .with(FrameControl::CAPABILITY, self.capability.is_some())
            .with(FrameControl::OBJECTS, objects)
            .with(FrameControl::ENCRYPTED, encrypted);
        out.clear();
        let [f0, f1] = frame_control.bits().to_le_bytes();
        let [p0, p1] = self.product_id.to_le_bytes();
        push(out, &[f0, f1, p0, p1, self.frame_counter])?;
        if let Some([m0, m1, m2, m3, m4, m5]) = self.mac {
            push(out, &[m5, m4, m3, m2, m1, m0])?;
        }
        if let Some(capability) = self.capability {
            push(out, &[capability])?;
        }
        if let Some(io) = self.io_capability {
            push(out, &[io])?;
        }
        Ok(())
    }
}

/// Why a frame may not be decrypted or sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CryptoCheck {
    /// Older than v4.
    Version,
    /// The frame's MAC is not the given address.
    Address,
}

/// An encrypted payload, as it appears on air.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Encrypted<'a> {
    /// The encrypted objects.
    pub ciphertext: &'a [u8],
    /// The extended counter (the top bytes of the nonce's counter).
    pub ext_counter: [u8; 3],
    /// The authentication tag.
    pub tag: [u8; BEACON_TAG_LEN],
}

/// What a frame carries after its header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Body<'a> {
    /// No objects: the device is only announcing itself.
    Empty,
    /// Objects in the clear (see [`objects`](crate::objects)).
    Plain(&'a [u8]),
    /// Objects encrypted under the beacon key.
    Encrypted(Encrypted<'a>),
}

/// A parsed advertisement, borrowing the service data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Advertisement<'a> {
    /// The header.
    pub header: Header,
    /// The objects, if any.
    pub body: Body<'a>,
}

impl<'a> Advertisement<'a> {
    /// Parses MiBeacon service data.
    ///
    /// Bytes after the header of a frame without objects are ignored, as
    /// other parsers do.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] if a field the flags announce is missing,
    /// [`ParseError::Unsupported`] for mesh frames, versions before 2, and
    /// the legacy (pre-v4) encryption.
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        let (&[f0, f1, p0, p1, frame_counter], mut rest) = data
            .split_first_chunk::<FIXED_LEN>()
            .ok_or(ParseError::TooShort)?;
        let frame_control = FrameControl::from_bits(u16::from_le_bytes([f0, f1]));
        if frame_control.contains(FrameControl::MESH)
            || frame_control.version() < FIRST_SUPPORTED_VERSION
        {
            return Err(ParseError::Unsupported);
        }
        let mut header = Header::new(frame_control, u16::from_le_bytes([p0, p1]), frame_counter);
        if frame_control.contains(FrameControl::MAC) {
            let (&[m0, m1, m2, m3, m4, m5], after) =
                rest.split_first_chunk::<6>().ok_or(ParseError::TooShort)?;
            header.mac = Some([m5, m4, m3, m2, m1, m0]);
            rest = after;
        }
        if frame_control.contains(FrameControl::CAPABILITY) {
            let (&capability, after) = rest.split_first().ok_or(ParseError::TooShort)?;
            header.capability = Some(capability);
            rest = after;
            if capability & CAPABILITY_IO != 0 {
                let (&io, after_io) = rest.split_first().ok_or(ParseError::TooShort)?;
                header.io_capability = Some(io);
                rest = after_io;
            }
        }
        let body = if !frame_control.contains(FrameControl::OBJECTS) {
            Body::Empty
        } else if !frame_control.contains(FrameControl::ENCRYPTED) {
            Body::Plain(rest)
        } else if frame_control.version() < FIRST_ENCRYPTED_VERSION {
            return Err(ParseError::Unsupported);
        } else {
            let (rest, tag) = rest
                .split_last_chunk::<BEACON_TAG_LEN>()
                .ok_or(ParseError::TooShort)?;
            let (ciphertext, ext_counter) = rest
                .split_last_chunk::<EXT_COUNTER_LEN>()
                .ok_or(ParseError::TooShort)?;
            Body::Encrypted(Encrypted {
                ciphertext,
                ext_counter: *ext_counter,
                tag: *tag,
            })
        };
        Ok(Self { header, body })
    }

    /// Decrypts the objects of a device at `address` (its public address in
    /// display order) into `out`, which is cleared first.
    ///
    /// # Errors
    ///
    /// [`DecryptError::NotEncrypted`] unless the body is encrypted,
    /// [`DecryptError::AddressMismatch`] if the frame includes a different
    /// MAC, [`DecryptError::BufferTooSmall`] if `out` cannot hold the
    /// objects, and [`DecryptError::Authentication`] if the tag does not
    /// match (wrong key, wrong address, or a forged or corrupted frame);
    /// `out` is left empty on any error.
    pub fn decrypt<const N: usize>(
        &self,
        cipher: &BeaconCipher,
        address: [u8; 6],
        out: &mut heapless::Vec<u8, N>,
    ) -> Result<(), DecryptError> {
        out.clear();
        let Body::Encrypted(encrypted) = self.body else {
            return Err(DecryptError::NotEncrypted);
        };
        self.header
            .check_crypto(address)
            .map_err(|check| match check {
                // `parse` never yields an encrypted body before v4.
                CryptoCheck::Version => DecryptError::NotEncrypted,
                CryptoCheck::Address => DecryptError::AddressMismatch,
            })?;
        out.extend_from_slice(encrypted.ciphertext)
            .map_err(|_full| DecryptError::BufferTooSmall)?;
        let nonce = self.header.nonce(address, encrypted.ext_counter);
        cipher.open(&nonce, out, encrypted.tag).map_err(|_failed| {
            out.clear();
            DecryptError::Authentication
        })
    }

    /// Writes a frame with `objects` in the clear (or none, for `None`)
    /// into `out`, which is cleared first.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferTooSmall`] if `out` is too small,
    /// [`EncodeError::Inconsistent`] if the header has an I/O capability
    /// byte without the capability bit announcing it, or the reverse.
    pub fn encode_plain<const N: usize>(
        header: &Header,
        objects: Option<&[u8]>,
        out: &mut heapless::Vec<u8, N>,
    ) -> Result<(), EncodeError> {
        header.encode(objects.is_some(), false, out)?;
        push(out, objects.unwrap_or_default())
    }

    /// Writes a frame with `objects` encrypted for a device at `address`
    /// (display order) into `out`, which is cleared first: what a device
    /// broadcasts, for simulators and tests.
    ///
    /// # Errors
    ///
    /// [`EncodeError::Unsupported`] before v4,
    /// [`EncodeError::AddressMismatch`] if the header includes a different
    /// MAC, [`EncodeError::Crypto`] if the cipher refuses, and the errors of
    /// [`encode_plain`](Self::encode_plain).
    pub fn encode_sealed<const N: usize>(
        header: &Header,
        objects: &[u8],
        cipher: &BeaconCipher,
        address: [u8; 6],
        ext_counter: [u8; 3],
        out: &mut heapless::Vec<u8, N>,
    ) -> Result<(), EncodeError> {
        header.check_crypto(address).map_err(|check| match check {
            CryptoCheck::Version => EncodeError::Unsupported,
            CryptoCheck::Address => EncodeError::AddressMismatch,
        })?;
        header.encode(true, true, out)?;
        let start = out.len();
        let fits = out.capacity().saturating_sub(start)
            >= objects.len().saturating_add(ENCRYPTED_OVERHEAD);
        if !fits {
            out.clear();
            return Err(EncodeError::BufferTooSmall);
        }
        push(out, objects)?;
        let nonce = header.nonce(address, ext_counter);
        let tag = out
            .get_mut(start..)
            .ok_or(EncodeError::BufferTooSmall)
            .and_then(|payload| {
                cipher
                    .seal(&nonce, payload)
                    .map_err(|_refused: CipherError| EncodeError::Crypto)
            });
        match tag {
            Ok(tag) => {
                push(out, &ext_counter)?;
                push(out, &tag)
            }
            Err(err) => {
                out.clear();
                Err(err)
            }
        }
    }
}

/// Appends `bytes`, mapping a full buffer to [`EncodeError::BufferTooSmall`].
fn push<const N: usize>(out: &mut heapless::Vec<u8, N>, bytes: &[u8]) -> Result<(), EncodeError> {
    out.extend_from_slice(bytes)
        .map_err(|_full| EncodeError::BufferTooSmall)
}

/// Why service data is not a frame this crate understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ParseError {
    /// A field the flags announce is missing.
    TooShort,
    /// A mesh frame, a version before 2, or the legacy encryption.
    Unsupported,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooShort => "MiBeacon frame too short for its flags",
            Self::Unsupported => "unsupported MiBeacon frame",
        })
    }
}

impl core::error::Error for ParseError {}

/// Why a payload could not be decrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DecryptError {
    /// The frame's objects are not encrypted (or it has none).
    NotEncrypted,
    /// The frame includes a MAC other than the given address.
    AddressMismatch,
    /// The output buffer is too small.
    BufferTooSmall,
    /// The tag does not match: wrong key, wrong address, or a forged or
    /// corrupted frame.
    Authentication,
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotEncrypted => "MiBeacon payload is not encrypted",
            Self::AddressMismatch => "MiBeacon frame is from another address",
            Self::BufferTooSmall => "output buffer too small",
            Self::Authentication => "MiBeacon payload failed authentication",
        })
    }
}

impl core::error::Error for DecryptError {}

/// Why a frame could not be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EncodeError {
    /// The output buffer is too small.
    BufferTooSmall,
    /// An object's data exceeds 255 bytes.
    ObjectTooLong,
    /// The capability byte and the I/O capability byte disagree.
    Inconsistent,
    /// Encryption needs version 4 or later.
    Unsupported,
    /// The header includes a MAC other than the given address.
    AddressMismatch,
    /// The cipher refused.
    Crypto,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BufferTooSmall => "output buffer too small",
            Self::ObjectTooLong => "object data longer than 255 bytes",
            Self::Inconsistent => "capability and I/O capability disagree",
            Self::Unsupported => "encryption needs MiBeacon v4 or later",
            Self::AddressMismatch => "header MAC differs from the address",
            Self::Crypto => "cipher refused",
        })
    }
}

impl core::error::Error for EncodeError {}
