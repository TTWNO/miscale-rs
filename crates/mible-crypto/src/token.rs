//! The device's long-lived login token.

use core::fmt;
use core::str::FromStr;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::hex::{HexError, decode_into};

/// Length of a login token in bytes.
pub const TOKEN_LEN: usize = 12;

/// The 12-byte login token a bound device shares with its owner.
///
/// Anyone holding the token can log in to the device, so it is zeroised on
/// drop, its [`Debug`](fmt::Debug) output is redacted, and parse errors never
/// echo the input.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Token([u8; TOKEN_LEN]);

impl Token {
    /// Wraps raw token bytes.
    #[must_use]
    pub const fn new(bytes: [u8; TOKEN_LEN]) -> Self {
        Self(bytes)
    }

    /// Parses 24 hexadecimal digits (either case; no separators).
    ///
    /// # Errors
    ///
    /// [`TokenParseError::Length`] unless the input is exactly 24
    /// characters, [`TokenParseError::NotHex`] if any is not a hex digit.
    pub fn from_hex(hex: &str) -> Result<Self, TokenParseError> {
        let mut bytes = [0_u8; TOKEN_LEN];
        decode_into(hex, &mut bytes).map_err(|err| match err {
            HexError::Length => TokenParseError::Length,
            HexError::NotHex => TokenParseError::NotHex,
        })?;
        let token = Self(bytes);
        bytes.zeroize();
        Ok(token)
    }

    /// The raw token bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; TOKEN_LEN] {
        &self.0
    }
}

impl FromStr for Token {
    type Err = TokenParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

/// Why a token string was rejected. Never contains the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TokenParseError {
    /// Not exactly 24 characters.
    Length,
    /// A character is not a hexadecimal digit.
    NotHex,
}

impl fmt::Display for TokenParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Length => "token must be exactly 24 hexadecimal digits",
            Self::NotHex => "token may contain only hexadecimal digits",
        })
    }
}

impl core::error::Error for TokenParseError {}

#[cfg(test)]
mod tests {
    use super::{Token, TokenParseError};

    /// Upper- and lower-case hex parse to the same bytes.
    #[test]
    fn parses_hex() {
        let token = Token::from_hex("0cf5615003810d89c233a12a").unwrap();
        assert_eq!(
            token.as_bytes(),
            &[
                0x0c, 0xf5, 0x61, 0x50, 0x03, 0x81, 0x0d, 0x89, 0xc2, 0x33, 0xa1, 0x2a
            ],
            "bytes"
        );
        assert_eq!(
            Token::from_hex("0CF5615003810D89C233A12A").unwrap(),
            token,
            "upper case"
        );
    }

    /// Wrong lengths and non-hex input are rejected without echoing it.
    #[test]
    fn rejects_bad_input() {
        assert_eq!(Token::from_hex(""), Err(TokenParseError::Length), "empty");
        assert_eq!(
            Token::from_hex("0cf5615003810d89c233a1"),
            Err(TokenParseError::Length),
            "short"
        );
        assert_eq!(
            Token::from_hex("0cf5615003810d89c233a12a00"),
            Err(TokenParseError::Length),
            "long"
        );
        assert_eq!(
            Token::from_hex("0cf5615003810d89c233a12g"),
            Err(TokenParseError::NotHex),
            "non-hex"
        );
        assert_eq!(
            Token::from_hex("0cf5615003810d89c233a1é"),
            Err(TokenParseError::NotHex),
            "multi-byte character of the right byte length"
        );
    }

    /// Debug output never reveals the token.
    #[test]
    fn debug_is_redacted() {
        let token = Token::new([0xab; 12]);
        let mut out = heapless::String::<64>::new();
        core::fmt::write(&mut out, format_args!("{token:?}")).unwrap();
        assert_eq!(out.as_str(), "Token(<redacted>)", "debug");
    }
}
