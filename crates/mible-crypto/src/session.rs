//! The authenticated session cipher used after login.
//!
//! ```text
//! cipher  AES-128-CCM, 4-byte tag, no associated data
//! nonce   iv (4 bytes) ‖ 00 00 00 00 ‖ counter (u32 LE)
//! wire    counter (u16 LE) ‖ ciphertext ‖ tag
//! ```
//!
//! Each direction has its own key, nonce prefix and counter. The counter
//! travels with every message, so decryption needs no shared state.

use core::fmt;

use aes::Aes128;
use ccm::aead::AeadInOut as _;
use ccm::aead::array::Array;
use ccm::consts::{U4, U12};
use ccm::{Ccm, KeyInit as _};

use crate::LoginKeys;

/// AES-128-CCM with a 4-byte tag and 12-byte nonce.
type Aes128Ccm = Ccm<Aes128, U4, U12>;

/// Length of the authentication tag.
pub const TAG_LEN: usize = 4;

/// Length of the counter prefix on the wire.
pub const COUNTER_LEN: usize = 2;

/// Bytes a sealed message adds to its plaintext.
pub const OVERHEAD: usize = COUNTER_LEN + TAG_LEN;

/// Which end of the session this cipher serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Role {
    /// The app: seals with the app key, opens with the device key.
    App,
    /// The device: seals with the device key, opens with the app key.
    Device,
}

/// One direction of the session: a keyed cipher and its nonce prefix.
struct Direction {
    /// The keyed AES-CCM instance (zeroised on drop by `aes`).
    cipher: Aes128Ccm,
    /// Nonce prefix.
    iv: [u8; 4],
}

impl Direction {
    /// Builds the direction from a key and nonce prefix.
    fn new(key: &[u8; 16], iv: [u8; 4]) -> Self {
        Self {
            cipher: Aes128Ccm::new(key.into()),
            iv,
        }
    }

    /// The 12-byte nonce for `counter`.
    fn nonce(&self, counter: u16) -> Array<u8, U12> {
        let [lo, hi] = counter.to_le_bytes();
        let [iv0, iv1, iv2, iv3] = self.iv;
        Array::from([iv0, iv1, iv2, iv3, 0, 0, 0, 0, lo, hi, 0, 0])
    }
}

/// The session cipher for one end of a logged-in session.
pub struct SessionCipher {
    /// Direction this end seals in.
    seal: Direction,
    /// Direction this end opens.
    open: Direction,
}

impl fmt::Debug for SessionCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionCipher(<redacted>)")
    }
}

impl SessionCipher {
    /// Builds the cipher for `role` from the login keys.
    #[must_use]
    pub fn new(keys: &LoginKeys, role: Role) -> Self {
        let app = || {
            let (key, iv) = keys.app_direction();
            Direction::new(key, iv)
        };
        let dev = || {
            let (key, iv) = keys.device_direction();
            Direction::new(key, iv)
        };
        match role {
            Role::App => Self {
                seal: app(),
                open: dev(),
            },
            Role::Device => Self {
                seal: dev(),
                open: app(),
            },
        }
    }

    /// Seals `plaintext` under `counter`, writing the wire form
    /// (`counter ‖ ciphertext ‖ tag`) into `out`, which is cleared first.
    ///
    /// # Errors
    ///
    /// [`SessionError::BufferTooSmall`] if `out` cannot hold
    /// `plaintext.len() + OVERHEAD` bytes; [`SessionError::Crypto`] if the
    /// cipher refuses (it does not for messages this short).
    pub fn seal<const N: usize>(
        &self,
        counter: u16,
        plaintext: &[u8],
        out: &mut heapless::Vec<u8, N>,
    ) -> Result<(), SessionError> {
        out.clear();
        out.extend_from_slice(&counter.to_le_bytes())
            .map_err(buffer_too_small)?;
        out.extend_from_slice(plaintext).map_err(buffer_too_small)?;
        let nonce = self.seal.nonce(counter);
        let tag = {
            let (_, body) = out.split_at_mut(COUNTER_LEN);
            self.seal
                .cipher
                .encrypt_inout_detached(&nonce, &[], body.into())
                .map_err(|ccm::Error| SessionError::Crypto)?
        };
        out.extend_from_slice(&tag).map_err(buffer_too_small)
    }

    /// Opens a wire message, writing its plaintext into `out` (cleared
    /// first) and returning the counter it carried.
    ///
    /// # Errors
    ///
    /// [`SessionError::TooShort`] if `message` cannot hold a counter and a
    /// tag, [`SessionError::BufferTooSmall`] if `out` cannot hold the
    /// plaintext, and [`SessionError::Crypto`] if authentication fails.
    pub fn open<const N: usize>(
        &self,
        message: &[u8],
        out: &mut heapless::Vec<u8, N>,
    ) -> Result<u16, SessionError> {
        out.clear();
        let (counter, rest) = message
            .split_first_chunk::<COUNTER_LEN>()
            .ok_or(SessionError::TooShort)?;
        let counter = u16::from_le_bytes(*counter);
        let (ciphertext, tag) = rest
            .split_last_chunk::<TAG_LEN>()
            .ok_or(SessionError::TooShort)?;
        let tag = Array::<u8, U4>::from(*tag);
        out.extend_from_slice(ciphertext)
            .map_err(buffer_too_small)?;
        let nonce = self.open.nonce(counter);
        if self
            .open
            .cipher
            .decrypt_inout_detached(&nonce, &[], out.as_mut_slice().into(), &tag)
            .is_err()
        {
            out.clear();
            return Err(SessionError::Crypto);
        }
        Ok(counter)
    }
}

/// Maps a buffer-capacity failure to [`SessionError::BufferTooSmall`].
const fn buffer_too_small(_: heapless::CapacityError) -> SessionError {
    SessionError::BufferTooSmall
}

/// Why a message could not be sealed or opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SessionError {
    /// The output buffer is too small.
    BufferTooSmall,
    /// The message is shorter than a counter plus a tag.
    TooShort,
    /// Authentication failed (wrong key, wrong direction, or tampering).
    Crypto,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BufferTooSmall => "output buffer too small",
            Self::TooShort => "message shorter than counter and tag",
            Self::Crypto => "message failed authentication",
        })
    }
}

impl core::error::Error for SessionError {}
