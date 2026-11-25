//! Reading S200 advertisements.
//!
//! The captured vector is a Smart Scale S200 advertisement from xiaomi-ble's
//! test suite (Apache-2.0; a test device's published key, not ours).
#![cfg(test)]

use mible_beacon::{DecryptError, Object, ParseError};
use mible_crypto::{BeaconCipher, BeaconKey};
use miscale::Weight;
use miscale::beacon::{BeaconError, WeighIn, is_s200, read};
use miscale_sim::advertisement;
use proptest::prelude::*;

/// The captured advertisement.
const CAPTURED: [u8; 24] = [
    0x48, 0x59, 0x04, 0x4c, 0x01, 0x9a, 0x80, 0xa2, 0x75, 0x93, 0x90, 0x10, 0xf0, 0xab, 0xc4, 0xfa,
    0xdc, 0x06, 0x00, 0x00, 0x3d, 0x29, 0xc0, 0x44,
];

/// The captured advertisement's address.
const CAPTURED_ADDRESS: [u8; 6] = [0xd0, 0x7b, 0x6f, 0x27, 0xd7, 0x29];

/// The captured advertisement's key.
fn captured_key() -> BeaconKey {
    BeaconKey::from_hex("653b1b10e1cb35e4ac5e60fa45f3bf29").unwrap() // gitleaks:allow
}

/// A synthetic key for simulated advertisements.
fn sim_key() -> BeaconKey {
    BeaconKey::new([0x5a; 16])
}

/// A synthetic address.
const SIM_ADDRESS: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

/// The captured weigh-in reads as xiaomi-ble reports it: profile 1,
/// 62.25 kg, with the scale's timestamp.
#[test]
fn reads_captured_weigh_in() {
    let beacon = read(
        &CAPTURED,
        &BeaconCipher::new(&captured_key()),
        CAPTURED_ADDRESS,
    )
    .unwrap();
    assert_eq!(beacon.product_id, 0x4c04, "product");
    assert_eq!(beacon.frame_counter, 1, "frame counter");
    assert!(beacon.encrypted, "encrypted");
    assert_eq!(
        beacon.weigh_in,
        Some(WeighIn::new(1, Weight(6225), 1_762_728_842)),
        "weigh-in"
    );
}

/// The wrong key is an authentication failure, not a missing weigh-in.
#[test]
fn wrong_key_fails_authentication() {
    assert_eq!(
        read(&CAPTURED, &BeaconCipher::new(&sim_key()), CAPTURED_ADDRESS),
        Err(BeaconError::Decrypt(DecryptError::Authentication))
    );
}

/// Simulated advertisements read back: idle frames carry nothing, weigh-in
/// frames their weight and timestamp.
#[test]
fn reads_simulated_advertisements() {
    let cipher = BeaconCipher::new(&sim_key());
    let idle = advertisement(&sim_key(), SIM_ADDRESS, 4, None).unwrap();
    let idle = read(&idle, &cipher, SIM_ADDRESS).unwrap();
    assert!(!idle.encrypted, "idle frames are plain");
    assert_eq!(idle.weigh_in, None, "idle");

    let weigh_in = advertisement(&sim_key(), SIM_ADDRESS, 5, Some((8360, 1_764_000_000))).unwrap();
    let weigh_in = read(&weigh_in, &cipher, SIM_ADDRESS).unwrap();
    assert!(weigh_in.encrypted, "encrypted");
    assert_eq!(weigh_in.frame_counter, 5, "frame counter");
    assert_eq!(
        weigh_in.weigh_in,
        Some(WeighIn::new(1, Weight(8360), 1_764_000_000)),
        "weigh-in"
    );
}

/// Other models and non-MiBeacon data are refused.
#[test]
fn refuses_others() {
    let cipher = BeaconCipher::new(&sim_key());
    let mut other_model = advertisement(&sim_key(), SIM_ADDRESS, 1, None).unwrap();
    other_model[2] = 0x5b;
    other_model[3] = 0x05;
    assert_eq!(
        read(&other_model, &cipher, SIM_ADDRESS),
        Err(BeaconError::NotS200),
        "other model"
    );
    assert_eq!(
        read(&[0x48], &cipher, SIM_ADDRESS),
        Err(BeaconError::Parse(ParseError::TooShort)),
        "too short"
    );
    assert!(
        is_s200(0x45c9) && is_s200(0x4c04) && is_s200(0x4dcb),
        "S200 ids"
    );
    assert!(!is_s200(0x055b), "other id");
}

/// Only a well-formed, non-zero weigh-in object decodes.
#[test]
fn weigh_in_object_rules() {
    let weigh_in = WeighIn::new(2, Weight(7000), 42);
    let data = weigh_in.encode();
    assert_eq!(
        WeighIn::decode(Object::new(0x4e16, &data)),
        Some(weigh_in),
        "round trip"
    );
    assert_eq!(
        WeighIn::decode(Object::new(0x4e17, &data)),
        None,
        "other object"
    );
    assert_eq!(
        WeighIn::decode(Object::new(0x4e16, &data[..8])),
        None,
        "short"
    );
    let zero = WeighIn::new(1, Weight(0), 42).encode();
    assert_eq!(
        WeighIn::decode(Object::new(0x4e16, &zero)),
        None,
        "zero weight"
    );
}

proptest! {
    /// Reading arbitrary service data never panics.
    #[test]
    fn read_never_panics(data in proptest::collection::vec(any::<u8>(), 0..40)) {
        let _ignored = read(&data, &BeaconCipher::new(&sim_key()), SIM_ADDRESS);
    }

    /// Any simulated weigh-in reads back, and only with its own key.
    #[test]
    fn simulated_weigh_ins_round_trip(
        key in any::<[u8; 16]>(),
        address in any::<[u8; 6]>(),
        counter in any::<u8>(),
        centi_kg in 1_u32..,
        scale_time in any::<u32>(),
    ) {
        let key = BeaconKey::new(key);
        let frame = advertisement(&key, address, counter, Some((centi_kg, scale_time))).unwrap();
        let beacon = read(&frame, &BeaconCipher::new(&key), address).unwrap();
        prop_assert_eq!(beacon.weigh_in, Some(WeighIn::new(1, Weight(centi_kg), scale_time)));
        let mut other = *key.as_bytes();
        other[0] ^= 1;
        prop_assert_eq!(
            read(&frame, &BeaconCipher::new(&BeaconKey::new(other)), address),
            Err(BeaconError::Decrypt(DecryptError::Authentication))
        );
    }
}
