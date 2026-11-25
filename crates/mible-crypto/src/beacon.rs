//! The key and cipher that protect MiBeacon v4/v5 advertisement payloads.
//!
//! ```text
//! cipher  AES-128-CCM, 4-byte tag, associated data 11
//! nonce   12 bytes, built from the advertisement (see the mible-beacon crate)
//! ```
//!
//! A bound device encrypts the objects it broadcasts under its beacon key
//! (the "bindkey" or "BLE key"), so only the key's holder can read them, and
//! a forged advertisement fails authentication.

use core::fmt;
use core::str::FromStr;

use aes::Aes128;
use ccm::aead::AeadInOut as _;
use ccm::aead::array::Array;
use ccm::consts::{U4, U12};
use ccm::{Ccm, KeyInit as _};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::CipherError;
use crate::hex::{HexError, decode_into};

/// AES-128-CCM with a 4-byte tag and 12-byte nonce.
type Aes128Ccm = Ccm<Aes128, U4, U12>;

/// Length of a beacon key in bytes.
pub const BEACON_KEY_LEN: usize = 16;

/// Length of a beacon nonce in bytes.
pub const BEACON_NONCE_LEN: usize = 12;

/// Length of a beacon payload's authentication tag in bytes.
pub const BEACON_TAG_LEN: usize = 4;

/// The associated data of every MiBeacon v4/v5 payload.
const ASSOCIATED_DATA: [u8; 1] = [0x11];

/// The 16-byte key a bound device encrypts its advertisements with.
///
/// Zeroised on drop, redacted from [`Debug`](fmt::Debug) output, and parse
/// errors never echo the input.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct BeaconKey([u8; BEACON_KEY_LEN]);

impl BeaconKey {
    /// Wraps raw key bytes.
    #[must_use]
    pub const fn new(bytes: [u8; BEACON_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Parses 32 hexadecimal digits (either case; no separators).
    ///
    /// # Errors
    ///
    /// [`BeaconKeyParseError::Length`] unless the input is exactly 32
    /// characters, [`BeaconKeyParseError::NotHex`] if any is not a hex
    /// digit.
    pub fn from_hex(hex: &str) -> Result<Self, BeaconKeyParseError> {
        let mut bytes = [0_u8; BEACON_KEY_LEN];
        decode_into(hex, &mut bytes).map_err(|err| match err {
            HexError::Length => BeaconKeyParseError::Length,
            HexError::NotHex => BeaconKeyParseError::NotHex,
        })?;
        let key = Self(bytes);
        bytes.zeroize();
        Ok(key)
    }

    /// The raw key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; BEACON_KEY_LEN] {
        &self.0
    }
}

impl FromStr for BeaconKey {
    type Err = BeaconKeyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl fmt::Debug for BeaconKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BeaconKey(<redacted>)")
    }
}

/// Why a beacon key string was rejected. Never contains the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BeaconKeyParseError {
    /// Not exactly 32 characters.
    Length,
    /// A character is not a hexadecimal digit.
    NotHex,
}

impl fmt::Display for BeaconKeyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Length => "beacon key must be exactly 32 hexadecimal digits",
            Self::NotHex => "beacon key may contain only hexadecimal digits",
        })
    }
}

impl core::error::Error for BeaconKeyParseError {}

/// Encrypts and decrypts advertisement payloads under one beacon key.
pub struct BeaconCipher {
    /// The keyed AES-CCM instance (zeroised on drop by `aes`).
    cipher: Aes128Ccm,
}

impl fmt::Debug for BeaconCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BeaconCipher(<redacted>)")
    }
}

impl BeaconCipher {
    /// Keys a cipher.
    #[must_use]
    pub fn new(key: &BeaconKey) -> Self {
        Self {
            cipher: Aes128Ccm::new(key.as_bytes().into()),
        }
    }

    /// Encrypts `payload` in place and returns its tag.
    ///
    /// # Errors
    ///
    /// [`CipherError::Crypto`] if the cipher refuses (it does not for
    /// payloads that fit an advertisement).
    pub fn seal(
        &self,
        nonce: &[u8; BEACON_NONCE_LEN],
        payload: &mut [u8],
    ) -> Result<[u8; BEACON_TAG_LEN], CipherError> {
        self.cipher
            .encrypt_inout_detached(&Array::from(*nonce), &ASSOCIATED_DATA, payload.into())
            .map(Into::into)
            .map_err(|ccm::Error| CipherError::Crypto)
    }

    /// Decrypts `payload` in place if `tag` authenticates it.
    ///
    /// # Errors
    ///
    /// [`CipherError::Crypto`] if authentication fails (wrong key, wrong
    /// nonce, or tampering); `payload` is then zeroed.
    pub fn open(
        &self,
        nonce: &[u8; BEACON_NONCE_LEN],
        payload: &mut [u8],
        tag: [u8; BEACON_TAG_LEN],
    ) -> Result<(), CipherError> {
        let result = self.cipher.decrypt_inout_detached(
            &Array::from(*nonce),
            &ASSOCIATED_DATA,
            (&mut *payload).into(),
            &Array::from(tag),
        );
        result.map_err(|ccm::Error| {
            payload.zeroize();
            CipherError::Crypto
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{BeaconKey, BeaconKeyParseError};

    /// Upper- and lower-case hex parse to the same bytes.
    #[test]
    fn parses_hex() {
        let key = BeaconKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(
            key.as_bytes(),
            &[
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ],
            "bytes"
        );
        assert_eq!(
            "00112233445566778899AABBCCDDEEFF".parse::<BeaconKey>(),
            Ok(key),
            "upper case"
        );
    }

    /// Wrong lengths and non-hex input are rejected.
    #[test]
    fn rejects_bad_input() {
        assert_eq!(
            BeaconKey::from_hex("00112233445566778899aabb"),
            Err(BeaconKeyParseError::Length),
            "a token is not a beacon key"
        );
        assert_eq!(
            BeaconKey::from_hex("00112233445566778899aabbccddeegg"),
            Err(BeaconKeyParseError::NotHex),
            "non-hex"
        );
    }

    /// Debug output never reveals the key.
    #[test]
    fn debug_is_redacted() {
        let key = BeaconKey::new([0xab; 16]);
        let mut out = heapless::String::<64>::new();
        core::fmt::write(&mut out, format_args!("{key:?}")).unwrap();
        assert_eq!(out.as_str(), "BeaconKey(<redacted>)", "debug");
    }
}
