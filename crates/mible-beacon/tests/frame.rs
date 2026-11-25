//! Parsing, decryption and encoding of whole frames.
//!
//! The S200 vector is a Smart Scale S200 advertisement from xiaomi-ble's
//! test suite (Apache-2.0; a test device's published key, not ours).
#![cfg(test)]

use mible_beacon::{
    Advertisement, Body, DecryptError, EncodeError, FrameControl, Header, Object, ParseError,
    objects,
};
use mible_crypto::{BeaconCipher, BeaconKey};

/// The S200 vector's service data.
const S200: [u8; 24] = [
    0x48, 0x59, 0x04, 0x4c, 0x01, 0x9a, 0x80, 0xa2, 0x75, 0x93, 0x90, 0x10, 0xf0, 0xab, 0xc4, 0xfa,
    0xdc, 0x06, 0x00, 0x00, 0x3d, 0x29, 0xc0, 0x44,
];

/// The S200 vector's address.
const S200_ADDRESS: [u8; 6] = [0xd0, 0x7b, 0x6f, 0x27, 0xd7, 0x29];

/// The S200 vector's cipher.
fn s200_cipher() -> BeaconCipher {
    BeaconCipher::new(&BeaconKey::from_hex("653b1b10e1cb35e4ac5e60fa45f3bf29").unwrap()) // gitleaks:allow
}

/// The S200 vector's header: v5, standard authentication, bound, product
/// 0x4C04, frame 1, with encrypted objects.
#[test]
fn parses_s200_header() {
    let adv = Advertisement::parse(&S200).unwrap();
    let fc = adv.header.frame_control;
    assert_eq!(fc.bits(), 0x5948, "frame control");
    assert_eq!(fc.version(), 5, "version");
    assert_eq!(fc.auth_mode(), 2, "standard authentication");
    assert!(fc.contains(FrameControl::REGISTERED), "bound");
    assert!(
        fc.contains(FrameControl::OBJECTS | FrameControl::ENCRYPTED),
        "encrypted objects"
    );
    assert_eq!(adv.header.product_id, 0x4c04, "product");
    assert_eq!(adv.header.frame_counter, 1, "frame counter");
    assert_eq!(adv.header.mac, None, "no MAC");
    let Body::Encrypted(encrypted) = adv.body else {
        panic!("not encrypted: {:?}", adv.body);
    };
    assert_eq!(encrypted.ciphertext.len(), 12, "ciphertext");
    assert_eq!(
        encrypted.ext_counter,
        [0x06, 0x00, 0x00],
        "extended counter"
    );
    assert_eq!(encrypted.tag, [0x3d, 0x29, 0xc0, 0x44], "tag");
}

/// The S200 vector decrypts to one 9-byte weigh-in object.
#[test]
fn decrypts_s200() {
    let adv = Advertisement::parse(&S200).unwrap();
    let mut plain = heapless::Vec::<u8, 32>::new();
    adv.decrypt(&s200_cipher(), S200_ADDRESS, &mut plain)
        .unwrap();
    let mut iter = objects(&plain);
    assert_eq!(
        iter.next(),
        Some(Object::new(
            0x4e16,
            &[0x01, 0x51, 0x18, 0x00, 0x00, 0x8a, 0x1b, 0x11, 0x69]
        )),
        "weigh-in object"
    );
    assert_eq!(iter.next(), None, "only object");
}

/// The wrong key or address fails authentication and leaves `out` empty.
#[test]
fn rejects_wrong_key_or_address() {
    let adv = Advertisement::parse(&S200).unwrap();
    let mut plain = heapless::Vec::<u8, 32>::new();
    let wrong_key = BeaconCipher::new(&BeaconKey::new([0; 16]));
    assert_eq!(
        adv.decrypt(&wrong_key, S200_ADDRESS, &mut plain),
        Err(DecryptError::Authentication),
        "wrong key"
    );
    assert!(plain.is_empty(), "cleared");
    let mut other = S200_ADDRESS;
    other[5] ^= 1;
    assert_eq!(
        adv.decrypt(&s200_cipher(), other, &mut plain),
        Err(DecryptError::Authentication),
        "wrong address"
    );
    let mut small = heapless::Vec::<u8, 4>::new();
    assert_eq!(
        adv.decrypt(&s200_cipher(), S200_ADDRESS, &mut small),
        Err(DecryptError::BufferTooSmall),
        "small buffer"
    );
}

/// Sealing the S200's weigh-in again reproduces the captured frame.
#[test]
fn seals_s200() {
    let adv = Advertisement::parse(&S200).unwrap();
    let mut plain = heapless::Vec::<u8, 32>::new();
    adv.decrypt(&s200_cipher(), S200_ADDRESS, &mut plain)
        .unwrap();
    let mut out = heapless::Vec::<u8, 31>::new();
    Advertisement::encode_sealed(
        &adv.header,
        &plain,
        &s200_cipher(),
        S200_ADDRESS,
        [0x06, 0x00, 0x00],
        &mut out,
    )
    .unwrap();
    assert_eq!(out.as_slice(), S200.as_slice(), "sealed");
}

/// An idle frame (no objects) parses to an empty body; trailing bytes after
/// such a header are ignored.
#[test]
fn parses_idle_frame() {
    // The S200 vector's frame control without the objects flag.
    let idle = [0x08, 0x59, 0x04, 0x4c, 0x07];
    let adv = Advertisement::parse(&idle).unwrap();
    assert_eq!(adv.body, Body::Empty, "no objects");
    let mut with_trailer = idle.to_vec();
    with_trailer.push(0xff);
    assert_eq!(
        Advertisement::parse(&with_trailer).unwrap().body,
        Body::Empty,
        "trailer ignored"
    );
    let mut plain = heapless::Vec::<u8, 8>::new();
    assert_eq!(
        adv.decrypt(&s200_cipher(), S200_ADDRESS, &mut plain),
        Err(DecryptError::NotEncrypted),
        "nothing to decrypt"
    );
}

/// The MAC and capability fields parse, and a MAC other than the address
/// is refused before any decryption.
#[test]
fn parses_optional_fields() {
    let mut header = Header::new(FrameControl::from_bits(0x5000), 0x4c04, 9);
    header.mac = Some(S200_ADDRESS);
    header.capability = Some(0x28);
    header.io_capability = Some(0x01);
    let mut out = heapless::Vec::<u8, 31>::new();
    Advertisement::encode_sealed(
        &header,
        &[0x01, 0x10, 0x00],
        &s200_cipher(),
        S200_ADDRESS,
        [0; 3],
        &mut out,
    )
    .unwrap();
    assert_eq!(
        &out[5..11],
        &[0x29, 0xd7, 0x27, 0x6f, 0x7b, 0xd0],
        "MAC reversed on air"
    );
    let adv = Advertisement::parse(&out).unwrap();
    assert_eq!(adv.header.mac, Some(S200_ADDRESS), "MAC");
    assert_eq!(adv.header.capability, Some(0x28), "capability");
    assert_eq!(adv.header.io_capability, Some(0x01), "I/O capability");
    let mut plain = heapless::Vec::<u8, 8>::new();
    adv.decrypt(&s200_cipher(), S200_ADDRESS, &mut plain)
        .unwrap();
    assert_eq!(plain.as_slice(), &[0x01, 0x10, 0x00], "objects");
    let mut other = S200_ADDRESS;
    other[0] ^= 1;
    assert_eq!(
        adv.decrypt(&s200_cipher(), other, &mut plain),
        Err(DecryptError::AddressMismatch),
        "MAC differs from address"
    );
}

/// Frames that announce missing fields, mesh frames, old versions and the
/// legacy encryption are refused.
#[test]
fn rejects_bad_frames() {
    assert_eq!(
        Advertisement::parse(&S200[..4]),
        Err(ParseError::TooShort),
        "short header"
    );
    assert_eq!(
        Advertisement::parse(&[0x10, 0x50, 0x04, 0x4c, 0x01, 0xd0]),
        Err(ParseError::TooShort),
        "truncated MAC"
    );
    assert_eq!(
        Advertisement::parse(&[0x20, 0x50, 0x04, 0x4c, 0x01]),
        Err(ParseError::TooShort),
        "missing capability"
    );
    assert_eq!(
        Advertisement::parse(&[0x20, 0x50, 0x04, 0x4c, 0x01, 0x20]),
        Err(ParseError::TooShort),
        "missing I/O capability"
    );
    assert_eq!(
        Advertisement::parse(&[0x48, 0x50, 0x04, 0x4c, 0x01, 0, 0, 0, 0, 0, 0]),
        Err(ParseError::TooShort),
        "encrypted body shorter than its trailer"
    );
    assert_eq!(
        Advertisement::parse(&[0x80, 0x50, 0x04, 0x4c, 0x01]),
        Err(ParseError::Unsupported),
        "mesh"
    );
    assert_eq!(
        Advertisement::parse(&[0x00, 0x10, 0x04, 0x4c, 0x01]),
        Err(ParseError::Unsupported),
        "version 1"
    );
    assert_eq!(
        Advertisement::parse(&[0x48, 0x30, 0x04, 0x4c, 0x01, 0, 0, 0, 0, 0, 0, 0]),
        Err(ParseError::Unsupported),
        "legacy encryption"
    );
}

/// An encrypted body may be empty: the tag still authenticates the frame.
#[test]
fn empty_ciphertext() {
    let header = Header::new(FrameControl::from_bits(0x5000), 0x4c04, 3);
    let mut out = heapless::Vec::<u8, 31>::new();
    Advertisement::encode_sealed(&header, &[], &s200_cipher(), S200_ADDRESS, [0; 3], &mut out)
        .unwrap();
    assert_eq!(out.len(), 5 + 7, "header and trailer");
    let adv = Advertisement::parse(&out).unwrap();
    let mut plain = heapless::Vec::<u8, 8>::new();
    assert_eq!(
        adv.decrypt(&s200_cipher(), S200_ADDRESS, &mut plain),
        Ok(()),
        "authentic"
    );
    assert!(plain.is_empty(), "no objects");
}

/// Encoding refuses what it cannot write, and leaves `out` empty.
#[test]
fn encode_errors() {
    let v5 = Header::new(FrameControl::from_bits(0x5000), 0x4c04, 1);
    let mut out = heapless::Vec::<u8, 31>::new();
    let v3 = Header::new(FrameControl::from_bits(0x3000), 0x4c04, 1);
    assert_eq!(
        Advertisement::encode_sealed(&v3, &[], &s200_cipher(), S200_ADDRESS, [0; 3], &mut out),
        Err(EncodeError::Unsupported),
        "legacy"
    );
    let mut with_mac = v5;
    with_mac.mac = Some([0; 6]);
    assert_eq!(
        Advertisement::encode_sealed(
            &with_mac,
            &[],
            &s200_cipher(),
            S200_ADDRESS,
            [0; 3],
            &mut out
        ),
        Err(EncodeError::AddressMismatch),
        "MAC differs from address"
    );
    let mut io_without_bit = v5;
    io_without_bit.capability = Some(0);
    io_without_bit.io_capability = Some(1);
    assert_eq!(
        Advertisement::encode_plain(&io_without_bit, None, &mut out),
        Err(EncodeError::Inconsistent),
        "I/O byte without its bit"
    );
    let mut small = heapless::Vec::<u8, 12>::new();
    assert_eq!(
        Advertisement::encode_sealed(&v5, &[0], &s200_cipher(), S200_ADDRESS, [0; 3], &mut small),
        Err(EncodeError::BufferTooSmall),
        "no room for the trailer"
    );
    assert!(small.is_empty(), "cleared");
}
