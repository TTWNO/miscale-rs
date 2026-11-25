//! Hexadecimal parsing for secrets: no allocation, no echo of the input,
//! and nothing left behind on failure.

use zeroize::Zeroize as _;

/// Why a hex string was rejected. Never contains the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum HexError {
    /// Not exactly two digits per output byte.
    Length,
    /// A character is not a hexadecimal digit.
    NotHex,
}

/// Decodes `hex` (either case, no separators) into `out`, which it must
/// fill exactly. On failure `out` is zeroed.
pub(crate) fn decode_into(hex: &str, out: &mut [u8]) -> Result<(), HexError> {
    let (pairs, rest) = hex.as_bytes().as_chunks::<2>();
    if !rest.is_empty() || pairs.len() != out.len() {
        return Err(HexError::Length);
    }
    for (byte, &[high, low]) in out.iter_mut().zip(pairs) {
        let (Some(high), Some(low)) = (nibble(high), nibble(low)) else {
            out.zeroize();
            return Err(HexError::NotHex);
        };
        *byte = high.wrapping_shl(4) | low;
    }
    Ok(())
}

/// Value of one ASCII hex digit.
const fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => digit.checked_sub(b'0'),
        b'a'..=b'f' => match digit.checked_sub(b'a') {
            Some(value) => value.checked_add(10),
            None => None,
        },
        b'A'..=b'F' => match digit.checked_sub(b'A') {
            Some(value) => value.checked_add(10),
            None => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{HexError, decode_into};

    /// Both cases decode; the output must be filled exactly.
    #[test]
    fn decodes_exactly() {
        let mut out = [0_u8; 2];
        assert_eq!(decode_into("aB0f", &mut out), Ok(()), "mixed case");
        assert_eq!(out, [0xab, 0x0f], "bytes");
        assert_eq!(decode_into("ab0", &mut out), Err(HexError::Length), "odd");
        assert_eq!(decode_into("ab", &mut out), Err(HexError::Length), "short");
        assert_eq!(
            decode_into("ab0f00", &mut out),
            Err(HexError::Length),
            "long"
        );
    }

    /// A bad digit anywhere zeroes what was already decoded.
    #[test]
    fn zeroes_on_bad_digit() {
        let mut out = [0_u8; 2];
        assert_eq!(
            decode_into("abzz", &mut out),
            Err(HexError::NotHex),
            "bad digit"
        );
        assert_eq!(out, [0, 0], "zeroed");
    }
}
