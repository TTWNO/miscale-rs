//! Weights, and reading them out of decrypted spec frames.
//!
//! The decoders reproduce the rules proven on captured traffic; the full
//! grammar of the frames is not known, so they look for two patterns in the
//! raw plaintext:
//!
//! - **final**: a string TLV (`<len> a0 <ascii>`) whose text is five
//!   comma-separated decimal numbers, e.g. `0,0,8360,2,1764000000`; the third
//!   is the weight in hundredths of a kilogram;
//! - **live**: a frame ending in the property `02 30 <u16 LE>`, the weight in
//!   hundredths of a kilogram.
//!
//! A final reading takes precedence when both appear.

use core::fmt;

use mible_spec::codec::STRING_TYPE;

/// A weight in hundredths of a kilogram (the scale's resolution).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[expect(
    clippy::exhaustive_structs,
    reason = "a plain unit wrapper; its meaning is fixed"
)]
pub struct Weight(pub u32);

impl Weight {
    /// The weight in hundredths of a kilogram.
    #[must_use]
    pub const fn centi_kg(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Weight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let whole = self.0.checked_div(100).unwrap_or_default();
        let hundredths = self.0.checked_rem(100).unwrap_or_default();
        write!(f, "{whole}.{hundredths:02} kg")
    }
}

/// A weight found in a frame, and which kind of reading it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Reading {
    /// The stabilised measurement.
    Final(Weight),
    /// A value streamed while the load settles.
    Live(Weight),
}

/// The live-weight property marker (`02 30`): length 2, type `0x30`.
const LIVE_MARKER: [u8; 2] = [0x02, 0x30];

/// Reads a weight out of a decrypted spec frame, final first.
#[must_use]
pub fn decode(plaintext: &[u8]) -> Option<Reading> {
    decode_final(plaintext)
        .map(Reading::Final)
        .or_else(|| decode_live(plaintext).map(Reading::Live))
}

/// Finds a final reading: the first string TLV that fits exactly and holds
/// five comma-separated decimal numbers.
#[must_use]
pub fn decode_final(plaintext: &[u8]) -> Option<Weight> {
    plaintext.windows(2).enumerate().find_map(|(at, pair)| {
        let &[len, kind] = <&[u8; 2]>::try_from(pair).ok()?;
        if kind != STRING_TYPE {
            return None;
        }
        let start = at.checked_add(2)?;
        let end = start.checked_add(usize::from(len))?;
        parse_final_text(plaintext.get(start..end)?)
    })
}

/// Parses `a,b,<centi-kg>,d,e` (decimal digits only; one trailing newline
/// allowed, as the prototype's regular expression did).
fn parse_final_text(text: &[u8]) -> Option<Weight> {
    let text = text.strip_suffix(b"\n").unwrap_or(text);
    let mut fields = text.split(|&byte| byte == b',');
    let mut weight = None;
    for position in 0_u8..5 {
        let value = parse_decimal(fields.next()?)?;
        if position == 2 {
            weight = Some(value);
        }
    }
    if fields.next().is_some() {
        return None;
    }
    weight
        .and_then(|value| u32::try_from(value).ok())
        .map(Weight)
}

/// Parses a non-empty run of ASCII digits (as `u64`, saturating to `None`).
fn parse_decimal(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0_u64, |acc, &digit| {
        let value = digit.is_ascii_digit().then(|| digit.checked_sub(b'0'))??;
        acc.checked_mul(10)?.checked_add(u64::from(value))
    })
}

/// Finds a live reading: the frame ends with `02 30 <u16 LE>`.
#[must_use]
pub fn decode_live(plaintext: &[u8]) -> Option<Weight> {
    let (_, &[marker0, marker1, lo, hi]) = plaintext.split_last_chunk::<4>()?;
    ([marker0, marker1] == LIVE_MARKER).then(|| Weight(u32::from(u16::from_le_bytes([lo, hi]))))
}

/// Estimates a weight from live readings when the scale never sends a final
/// one: when the load comes off, the last five loaded readings are averaged
/// if they agree to within 0.30 kg.
///
/// Readings of 2.00 kg or more are kept (the last six); a reading under
/// 1.00 kg means the load came off; readings in between are ignored. This is
/// the prototype's rule, done in integer hundredths: the prototype compared
/// floats, which rejected about half of the spreads of exactly 0.30 kg by
/// rounding error.
#[derive(Debug, Clone, Default)]
pub struct Stabiliser {
    /// Recent loaded readings, oldest first.
    window: heapless::Deque<u32, { Self::WINDOW }>,
}

impl Stabiliser {
    /// Loaded readings remembered.
    const WINDOW: usize = 6;
    /// Readings averaged.
    const AVERAGED: usize = 5;
    /// Lightest reading counted as a load, in hundredths of a kilogram.
    const MIN_LOAD: u32 = 200;
    /// Heaviest reading counted as "load removed".
    const OFF_BELOW: u32 = 100;
    /// Largest spread of the averaged readings.
    const MAX_SPREAD: u32 = 30;

    /// An empty stabiliser.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            window: heapless::Deque::new(),
        }
    }

    /// Feeds a live reading; returns an estimate when the load comes off
    /// after a steady stretch.
    pub fn push(&mut self, live: Weight) -> Option<Weight> {
        let centi = live.centi_kg();
        if centi >= Self::MIN_LOAD {
            if self.window.is_full() {
                let _oldest: Option<u32> = self.window.pop_front();
            }
            let _pushed: Result<(), u32> = self.window.push_back(centi);
            return None;
        }
        if centi >= Self::OFF_BELOW || self.window.len() < Self::AVERAGED {
            return None;
        }
        let skip = self.window.len().saturating_sub(Self::AVERAGED);
        let recent = || self.window.iter().skip(skip).copied();
        let low = recent().min()?;
        let high = recent().max()?;
        if high.checked_sub(low)? > Self::MAX_SPREAD {
            self.window.clear();
            return None;
        }
        let sum = recent().try_fold(0_u32, u32::checked_add)?;
        // Round half up, as the prototype's `round(mean, 2)` did in practice.
        let mean = sum.checked_add(2)?.checked_div(5)?;
        Some(Weight(mean))
    }
}

#[cfg(test)]
mod tests {
    use super::{Weight, decode_live};

    /// Weights print in kilograms with two decimals.
    #[test]
    fn display() {
        let mut out = heapless::String::<16>::new();
        core::fmt::write(&mut out, format_args!("{}", Weight(8360))).unwrap();
        assert_eq!(out.as_str(), "83.60 kg", "display");
    }

    /// A live frame ends in `02 30 <u16 LE>`.
    #[test]
    fn live_frames() {
        assert_eq!(
            decode_live(&[0x19, 0x20, 0x07, 0x00, 0x02, 0x30, 0xa8, 0x20]),
            Some(Weight(8360)),
            "83.60"
        );
        assert_eq!(
            decode_live(&[0x02, 0x30, 0x00, 0x00]),
            Some(Weight(0)),
            "empty scale"
        );
        assert_eq!(decode_live(&[0x02, 0x31, 0xa8, 0x20]), None, "wrong marker");
        assert_eq!(decode_live(&[0x30, 0xa8, 0x20]), None, "too short");
    }
}
