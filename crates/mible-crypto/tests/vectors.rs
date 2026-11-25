//! Known-answer tests.
//!
//! The login vector is miauth's published test vector (a synthetic token,
//! not a real device's).
#![cfg(test)]

use mible_crypto::{LoginKeys, ProofMismatch, Token};

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

/// Debug output never shows key material.
#[test]
fn debug_is_redacted() {
    let keys = LoginKeys::derive(&token(), &app_rand(), &dev_rand());
    assert_eq!(format!("{keys:?}"), "LoginKeys(<redacted>)", "keys");
    assert_eq!(format!("{:?}", token()), "Token(<redacted>)", "token");
}
