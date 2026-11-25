//! The S200's MiBeacon advertisement, and the weigh-in it broadcasts.
//!
//! When a weight is final, the S200 broadcasts it as object `0x4E16`,
//! encrypted under its beacon key (as decoded by xiaomi-ble):
//!
//! ```text
//! profile (u8) ‖ weight (u32 LE, hundredths of a kg) ‖ scale time (u32 LE)
//! ```
//!
//! Its other advertisements carry no objects. Weigh-ins are taken only from
//! payloads that decrypt: anyone can broadcast a plain one.

use core::fmt;

use mible_beacon::{Advertisement, Body, DecryptError, Object, ParseError, objects};
use mible_crypto::BeaconCipher;

use crate::Weight;

/// The S200's MiBeacon product ids (as listed by xiaomi-ble).
pub const PRODUCT_IDS: [u16; 3] = [0x45C9, 0x4C04, 0x4DCB];

/// The object id of a weigh-in.
pub const WEIGH_IN_OBJECT: u16 = 0x4E16;

/// Length of a weigh-in object's data.
const WEIGH_IN_LEN: usize = 9;

/// Largest decrypted payload read.
const MAX_PAYLOAD: usize = 64;

/// Whether `product_id` is an S200's.
#[must_use]
pub fn is_s200(product_id: u16) -> bool {
    PRODUCT_IDS.contains(&product_id)
}

/// A weigh-in the scale broadcast.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct WeighIn {
    /// The scale's user profile the weigh-in was attributed to.
    pub profile: u8,
    /// The weight.
    pub weight: Weight,
    /// When the scale took it (see
    /// [`FinalReading::scale_time`](crate::FinalReading::scale_time)).
    pub scale_time: u32,
}

impl WeighIn {
    /// A weigh-in.
    #[must_use]
    pub const fn new(profile: u8, weight: Weight, scale_time: u32) -> Self {
        Self {
            profile,
            weight,
            scale_time,
        }
    }

    /// Decodes a weigh-in object; `None` for any other object, a wrong
    /// length, or a zero weight (which the scale never measures).
    #[must_use]
    pub fn decode(object: Object<'_>) -> Option<Self> {
        if object.id != WEIGH_IN_OBJECT {
            return None;
        }
        let &[profile, w0, w1, w2, w3, t0, t1, t2, t3] =
            <&[u8; WEIGH_IN_LEN]>::try_from(object.data).ok()?;
        let weight = u32::from_le_bytes([w0, w1, w2, w3]);
        (weight != 0).then(|| {
            Self::new(
                profile,
                Weight(weight),
                u32::from_le_bytes([t0, t1, t2, t3]),
            )
        })
    }

    /// The object's data.
    #[must_use]
    pub const fn encode(&self) -> [u8; WEIGH_IN_LEN] {
        let [w0, w1, w2, w3] = self.weight.centi_kg().to_le_bytes();
        let [t0, t1, t2, t3] = self.scale_time.to_le_bytes();
        [self.profile, w0, w1, w2, w3, t0, t1, t2, t3]
    }
}

/// What an S200 advertisement says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Beacon {
    /// The product id (one of [`PRODUCT_IDS`]).
    pub product_id: u16,
    /// Changes with each new advertisement.
    pub frame_counter: u8,
    /// Whether the payload was encrypted (and so authenticated).
    pub encrypted: bool,
    /// The weigh-in it broadcast, if any.
    pub weigh_in: Option<WeighIn>,
}

/// Reads the advertisement of an S200 at `address` (display order).
///
/// # Errors
///
/// [`BeaconError::Parse`] if the service data is not a MiBeacon frame,
/// [`BeaconError::NotS200`] if it comes from another model, and
/// [`BeaconError::Decrypt`] if its payload does not decrypt; for
/// [`DecryptError::Authentication`], the beacon key (or address) is wrong
/// or the frame was forged.
pub fn read(
    service_data: &[u8],
    cipher: &BeaconCipher,
    address: [u8; 6],
) -> Result<Beacon, BeaconError> {
    let adv = Advertisement::parse(service_data).map_err(BeaconError::Parse)?;
    if !is_s200(adv.header.product_id) {
        return Err(BeaconError::NotS200);
    }
    let mut beacon = Beacon {
        product_id: adv.header.product_id,
        frame_counter: adv.header.frame_counter,
        encrypted: false,
        weigh_in: None,
    };
    if let Body::Encrypted(_) = adv.body {
        let mut payload = heapless::Vec::<u8, MAX_PAYLOAD>::new();
        adv.decrypt(cipher, address, &mut payload)
            .map_err(BeaconError::Decrypt)?;
        beacon.encrypted = true;
        beacon.weigh_in = objects(&payload).find_map(WeighIn::decode);
    }
    Ok(beacon)
}

/// Why an advertisement could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BeaconError {
    /// Not a MiBeacon frame this library understands.
    Parse(ParseError),
    /// A MiBeacon frame from another model.
    NotS200,
    /// The payload did not decrypt.
    Decrypt(DecryptError),
}

impl fmt::Display for BeaconError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Parse(err) => write!(f, "not a MiBeacon frame: {err}"),
            Self::NotS200 => f.write_str("advertisement is not from an S200"),
            Self::Decrypt(err) => write!(f, "advertisement did not decrypt: {err}"),
        }
    }
}

impl core::error::Error for BeaconError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Parse(err) => Some(err),
            Self::Decrypt(err) => Some(err),
            Self::NotS200 => None,
        }
    }
}
