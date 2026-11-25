//! Known-answer tests.
//!
//! The login vector is miauth's published test vector (a synthetic token,
//! not a real device's). The session-cipher vectors were generated from it
//! independently with Python's `cryptography` package (`AESCCM`, tag 4),
//! using the nonce layout `iv ‖ 00000000 ‖ counter (u32 LE)`.
#![cfg(test)]

use mible_crypto::{LoginKeys, ProofMismatch, Role, SessionCipher, SessionError, Token};

/// Decodes a hex string.
fn hex(text: &str) -> Vec<u8> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    assert!(rest.is_empty(), "odd-length hex");
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

/// Decodes a 16-byte hex random.
fn random(text: &str) -> [u8; 16] {
    hex(text).try_into().unwrap()
}

/// The vector's token.
fn token() -> Token {
    Token::from_hex("0cf5615003810d89c233a12a").unwrap()
}

/// The vector's app random.
fn app_rand() -> [u8; 16] {
    random("a8699783c1f03c7b73a046cdb613a9bf")
}

/// The vector's device random.
fn dev_rand() -> [u8; 16] {
    random("90fdec0ece05016d7f116b50fca4b4bf")
}

/// Both proofs match miauth's published values.
#[test]
fn login_proofs() {
    let keys = LoginKeys::derive(&token(), &app_rand(), &dev_rand());
    assert_eq!(
        keys.device_proof(&app_rand(), &dev_rand()).to_vec(),
        hex("471467ea7ed6064f8dd72f416c079dcb3bb78e3c94a51e97b98ef7623a7798e5"),
        "device proof"
    );
    assert_eq!(
        keys.app_proof(&app_rand(), &dev_rand()).to_vec(),
        hex("bbb99b6a6f1ae419e3b13db93514f3e12a1843033f276392eea99068affca753"),
        "app proof"
    );
}

/// Proof verification accepts the right proof and rejects any other.
#[test]
fn proof_verification() {
    let keys = LoginKeys::derive(&token(), &app_rand(), &dev_rand());
    let good = keys.device_proof(&app_rand(), &dev_rand());
    assert_eq!(
        keys.verify_device_proof(&app_rand(), &dev_rand(), &good),
        Ok(()),
        "good"
    );
    let mut bad = good;
    bad[31] ^= 1;
    assert_eq!(
        keys.verify_device_proof(&app_rand(), &dev_rand(), &bad),
        Err(ProofMismatch),
        "flip"
    );
    assert_eq!(
        keys.verify_device_proof(&app_rand(), &dev_rand(), &good[..31]),
        Err(ProofMismatch),
        "short"
    );
    let app = keys.app_proof(&app_rand(), &dev_rand());
    assert_eq!(
        keys.verify_app_proof(&app_rand(), &dev_rand(), &app),
        Ok(()),
        "app proof"
    );
    assert_eq!(
        keys.verify_device_proof(&app_rand(), &dev_rand(), &app),
        Err(ProofMismatch),
        "swapped"
    );

    let wrong = LoginKeys::derive(&Token::new([0; 12]), &app_rand(), &dev_rand());
    assert_eq!(
        wrong.verify_device_proof(&app_rand(), &dev_rand(), &good),
        Err(ProofMismatch),
        "token"
    );
}

/// Sealing the hello frame and its echo gives the independently computed bytes.
#[test]
fn session_vectors() {
    let keys = LoginKeys::derive(&token(), &app_rand(), &dev_rand());
    let app = SessionCipher::new(&keys, Role::App);
    let device = SessionCipher::new(&keys, Role::Device);
    let hello = hex("05200200f0");
    let mut out = heapless::Vec::<u8, 64>::new();

    app.seal(0, &hello, &mut out).unwrap();
    assert_eq!(
        out.to_vec(),
        hex("00000e5e875c5e89a88170"),
        "app hello, counter 0"
    );
    device.seal(1, &hello, &mut out).unwrap();
    assert_eq!(
        out.to_vec(),
        hex("01006d240755b0d36977d5"),
        "device echo, counter 1"
    );
    let twenty: Vec<u8> = (0..20).collect();
    app.seal(0x1234, &twenty, &mut out).unwrap();
    assert_eq!(
        out.to_vec(),
        hex("3412a5187731a4d1975a5490a866bb82673d719b531f5e705c18"),
        "counter in both nonce bytes"
    );
}

/// Each end opens what the other sealed; the counter comes back.
#[test]
fn session_round_trip() {
    let keys = LoginKeys::derive(&token(), &app_rand(), &dev_rand());
    let app = SessionCipher::new(&keys, Role::App);
    let device = SessionCipher::new(&keys, Role::Device);
    let mut wire = heapless::Vec::<u8, 64>::new();
    let mut plain = heapless::Vec::<u8, 64>::new();
    device.seal(7, b"weight", &mut wire).unwrap();
    assert_eq!(app.open(&wire, &mut plain), Ok(7), "counter");
    assert_eq!(plain.as_slice(), b"weight", "plaintext");
    app.seal(8, b"", &mut wire).unwrap();
    assert_eq!(device.open(&wire, &mut plain), Ok(8), "empty plaintext");
    assert!(plain.is_empty(), "empty");
}

/// Tampering, the wrong direction, and truncation are all rejected, and the
/// output buffer is left empty.
#[test]
fn session_rejects() {
    let keys = LoginKeys::derive(&token(), &app_rand(), &dev_rand());
    let app = SessionCipher::new(&keys, Role::App);
    let device = SessionCipher::new(&keys, Role::Device);
    let mut wire = heapless::Vec::<u8, 64>::new();
    let mut plain = heapless::Vec::<u8, 64>::new();
    device.seal(1, b"hello", &mut wire).unwrap();

    let mut tampered = wire.clone();
    tampered[3] ^= 0x80;
    assert_eq!(
        app.open(&tampered, &mut plain),
        Err(SessionError::Crypto),
        "ciphertext"
    );
    assert!(plain.is_empty(), "cleared on failure");
    let mut recounted = wire.clone();
    recounted[0] = 2;
    assert_eq!(
        app.open(&recounted, &mut plain),
        Err(SessionError::Crypto),
        "counter"
    );
    assert_eq!(
        device.open(&wire, &mut plain),
        Err(SessionError::Crypto),
        "own direction"
    );
    assert_eq!(
        app.open(&wire[..5], &mut plain),
        Err(SessionError::TooShort),
        "truncated"
    );
    assert_eq!(
        app.open(&[], &mut plain),
        Err(SessionError::TooShort),
        "empty"
    );

    let mut tiny = heapless::Vec::<u8, 4>::new();
    assert_eq!(
        app.open(&wire, &mut tiny),
        Err(SessionError::BufferTooSmall),
        "small out"
    );
    assert_eq!(
        device.seal(1, b"hello", &mut tiny),
        Err(SessionError::BufferTooSmall),
        "small seal"
    );
}

/// Debug output never shows key material.
#[test]
fn debug_is_redacted() {
    let keys = LoginKeys::derive(&token(), &app_rand(), &dev_rand());
    assert_eq!(format!("{keys:?}"), "LoginKeys(<redacted>)", "keys");
    assert_eq!(
        format!("{:?}", SessionCipher::new(&keys, Role::App)),
        "SessionCipher(<redacted>)",
        "cipher"
    );
    assert_eq!(format!("{:?}", token()), "Token(<redacted>)", "token");
}
