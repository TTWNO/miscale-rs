//! The user-profile message that starts the scale reporting.
//!
//! Body: `05 07 01 01 01 00` followed by a string TLV holding compact JSON:
//!
//! ```json
//! {"mid":"<mid>","duid":1,"uc":1,"ow":1,"unit":1,"time":<unix>,
//!  "ud":[{"duid":1,"ut":1,"age":18,"sex":1,"hi":170,"wt":6000}]}
//! ```
//!
//! The scale reports the raw load-cell weight; the user fields only matter
//! to the official app's body-composition maths, so they are fixed here.

use core::fmt::{self, Write as _};

use mible_spec::codec::push_string;

/// Bytes before the JSON string TLV, as captured from the official app.
pub const BODY_PREFIX: [u8; 6] = [0x05, 0x07, 0x01, 0x01, 0x01, 0x00];

/// Longest account id accepted.
pub const MAX_MID_LEN: usize = 20;

/// Room for the profile body: prefix, TLV header and the JSON.
pub const MAX_BODY_LEN: usize = 240;

/// The Xiaomi account id (`mid`) sent in the profile: 1 to 20 decimal
/// digits, which also keeps the hand-written JSON well formed.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Mid(heapless::String<MAX_MID_LEN>);

impl Mid {
    /// Validates an account id.
    ///
    /// # Errors
    ///
    /// [`MidError`] unless `digits` is 1 to 20 ASCII digits.
    pub fn new(digits: &str) -> Result<Self, MidError> {
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(MidError);
        }
        heapless::String::try_from(digits)
            .map(Self)
            .map_err(|_overflow| MidError)
    }

    /// The digits.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for Mid {
    /// A neutral id (`1`). The scale is not known to check it.
    fn default() -> Self {
        let mut digits = heapless::String::new();
        let _pushed: Result<(), heapless::CapacityError> = digits.push('1');
        Self(digits)
    }
}

impl fmt::Debug for Mid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // An account id identifies a person; keep it out of logs.
        f.write_str("Mid(<redacted>)")
    }
}

/// An account id was not 1 to 20 decimal digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[expect(
    clippy::exhaustive_structs,
    reason = "a unit error; there is nothing to add to it"
)]
pub struct MidError;

impl fmt::Display for MidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("account id must be 1 to 20 decimal digits")
    }
}

impl core::error::Error for MidError {}

/// Builds the profile body for `mid` at Unix time `unix_time`.
///
/// # Errors
///
/// Only if the body would not fit [`MAX_BODY_LEN`], which a valid [`Mid`]
/// cannot cause.
pub fn body(mid: &Mid, unix_time: u64) -> Result<heapless::Vec<u8, MAX_BODY_LEN>, fmt::Error> {
    let mut json = heapless::String::<{ MAX_BODY_LEN }>::new();
    write!(
        json,
        concat!(
            r#"{{"mid":"{mid}","duid":1,"uc":1,"ow":1,"unit":1,"time":{time},"#,
            r#""ud":[{{"duid":1,"ut":1,"age":18,"sex":1,"hi":170,"wt":6000}}]}}"#
        ),
        mid = mid.as_str(),
        time = unix_time,
    )?;
    let mut out = heapless::Vec::new();
    out.extend_from_slice(&BODY_PREFIX)
        .map_err(|_full| fmt::Error)?;
    push_string(&mut out, json.as_bytes()).map_err(|_too_long| fmt::Error)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{BODY_PREFIX, Mid, MidError, body};

    /// The body is the prefix, a string TLV, and the prototype's JSON.
    #[test]
    fn body_layout() {
        let mid = Mid::new("1234567890").unwrap();
        let out = body(&mid, 1_764_000_000).unwrap();
        let json: &[u8] = br#"{"mid":"1234567890","duid":1,"uc":1,"ow":1,"unit":1,"time":1764000000,"ud":[{"duid":1,"ut":1,"age":18,"sex":1,"hi":170,"wt":6000}]}"#;
        let (prefix, rest) = out.split_at(BODY_PREFIX.len());
        assert_eq!(prefix, BODY_PREFIX, "prefix");
        let (&[len, kind], text) = rest.split_first_chunk::<2>().unwrap();
        assert_eq!(usize::from(len), json.len(), "tlv length");
        assert_eq!(kind, 0xa0, "string type");
        assert_eq!(text, json, "json");
    }

    /// The longest id and timestamp still fit one spec frame.
    #[test]
    fn worst_case_fits_a_frame() {
        let mid = Mid::new("99999999999999999999").unwrap();
        let out = body(&mid, u64::MAX).unwrap();
        assert!(out.len() + 4 <= 255, "frame of {} bytes", out.len() + 4);
    }

    /// Ids must be 1 to 20 digits.
    #[test]
    fn mid_validation() {
        assert_eq!(Mid::new(""), Err(MidError), "empty");
        assert_eq!(Mid::new("12a"), Err(MidError), "letter");
        assert_eq!(Mid::new("1\"}"), Err(MidError), "json injection");
        assert_eq!(
            Mid::new("123456789012345678901"),
            Err(MidError),
            "21 digits"
        );
        assert_eq!(
            Mid::new("12345678901234567890").map(|mid| mid.as_str().len()),
            Ok(20),
            "20 digits"
        );
        assert_eq!(Mid::default().as_str(), "1", "neutral default");
    }
}
