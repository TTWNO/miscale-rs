//! Login against a scripted device, byte for byte.
//!
//! The values are miauth's published login vector (a synthetic token).
#![cfg(test)]

use mible_auth::login::{command, kind};
use mible_auth::{Login, LoginError, LoginStatus};
use mible_crypto::{LoginKeys, Role, SessionCipher, Token};
use mible_transport::frame::AckStatus;
use mible_transport::rx::ReceiveError;
use mible_transport::tx::SendError;
use mible_transport::{Channel, Transmit};
use proptest::prelude::*;

/// Decodes a hex string.
fn hex(text: &str) -> Vec<u8> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    assert!(rest.is_empty(), "odd-length hex");
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

/// The vector's token.
fn token() -> Token {
    Token::from_hex("0cf5615003810d89c233a12a").unwrap()
}

/// The vector's app random.
fn app_rand() -> [u8; 16] {
    hex("a8699783c1f03c7b73a046cdb613a9bf").try_into().unwrap()
}

/// The vector's device random.
fn dev_rand() -> [u8; 16] {
    hex("90fdec0ece05016d7f116b50fca4b4bf").try_into().unwrap()
}

/// The device proof for the vector.
fn dev_proof() -> Vec<u8> {
    hex("471467ea7ed6064f8dd72f416c079dcb3bb78e3c94a51e97b98ef7623a7798e5")
}

/// The app proof for the vector.
fn app_proof() -> Vec<u8> {
    hex("bbb99b6a6f1ae419e3b13db93514f3e12a1843033f276392eea99068affca753")
}

/// Drains every pending write as (channel, bytes).
fn drain(login: &mut Login) -> Vec<(Channel, Vec<u8>)> {
    core::iter::from_fn(|| login.poll_transmit())
        .map(|Transmit { channel, data, .. }| (channel, data.to_vec()))
        .collect()
}

/// Feeds one notification and drains the writes it caused, as the driving
/// contract requires; returns the status and the writes.
fn feed(
    login: &mut Login,
    channel: Channel,
    value: &[u8],
) -> (LoginStatus, Vec<(Channel, Vec<u8>)>) {
    let status = login.handle_notify(channel, value);
    (status, drain(login))
}

/// `<index LE> <bytes>` fragment.
fn fragment(index: u16, bytes: &[u8]) -> Vec<u8> {
    let mut out = index.to_le_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

/// Ready ack.
const READY: [u8; 4] = [0, 0, 1, 1];
/// Success ack.
const SUCCESS: [u8; 4] = [0, 0, 1, 0];

/// Runs the vector's login up to the device proof; returns the machine.
fn up_to_device_proof() -> Login {
    let mut login = Login::new(&token(), app_rand());
    assert_eq!(
        drain(&mut login),
        [
            (Channel::Control, command::LOGIN.to_vec()),
            (Channel::Auth, hex("0000000b0100"))
        ],
        "login command, then the app random's announcement"
    );
    let _ready = login.handle_notify(Channel::Auth, &READY);
    assert_eq!(
        drain(&mut login),
        [(Channel::Auth, fragment(1, &app_rand()))],
        "app random"
    );
    let _done = login.handle_notify(Channel::Auth, &SUCCESS);
    assert!(
        drain(&mut login).is_empty(),
        "nothing until the device speaks"
    );

    let _announce = login.handle_notify(Channel::Auth, &hex("0000000d0100"));
    assert_eq!(
        drain(&mut login),
        [(Channel::Auth, READY.to_vec())],
        "ready for device random"
    );
    let _random = login.handle_notify(Channel::Auth, &fragment(1, &dev_rand()));
    assert_eq!(
        drain(&mut login),
        [(Channel::Auth, SUCCESS.to_vec())],
        "device random received"
    );
    login
}

/// The full exchange produces exactly the prototype's bytes and ends
/// authenticated with a working session cipher.
#[test]
fn full_login() {
    let mut login = up_to_device_proof();
    let proof = dev_proof();
    let _announce = login.handle_notify(Channel::Auth, &hex("0000000c0200"));
    assert_eq!(
        drain(&mut login),
        [(Channel::Auth, READY.to_vec())],
        "ready for device proof"
    );
    let _first = login.handle_notify(Channel::Auth, &fragment(1, &proof[..18]));
    assert!(drain(&mut login).is_empty(), "mid-parcel");
    let _second = login.handle_notify(Channel::Auth, &fragment(2, &proof[18..]));
    assert_eq!(
        drain(&mut login),
        [
            (Channel::Auth, SUCCESS.to_vec()),
            (Channel::Auth, hex("0000000a0200"))
        ],
        "ack the device proof before announcing the app proof"
    );
    let _ready = login.handle_notify(Channel::Auth, &READY);
    let app = app_proof();
    assert_eq!(
        drain(&mut login),
        [
            (Channel::Auth, fragment(1, &app[..18])),
            (Channel::Auth, fragment(2, &app[18..]))
        ],
        "app proof"
    );
    assert_eq!(
        login.handle_notify(Channel::Auth, &SUCCESS),
        LoginStatus::InProgress
    );
    assert!(
        login.take_session_cipher().is_none(),
        "no cipher before confirmation"
    );
    assert_eq!(
        login.handle_notify(Channel::Control, &command::LOGIN_OK),
        LoginStatus::Authenticated
    );
    assert!(drain(&mut login).is_empty(), "nothing after success");

    let cipher = login.take_session_cipher().expect("cipher after success");
    let device = SessionCipher::new(
        &LoginKeys::derive(&token(), &app_rand(), &dev_rand()),
        Role::Device,
    );
    let mut wire = heapless::Vec::<u8, 32>::new();
    let mut plain = heapless::Vec::<u8, 32>::new();
    device.seal(1, b"ok", &mut wire).unwrap();
    assert_eq!(
        cipher.open(&wire, &mut plain),
        Ok(1),
        "cipher talks to the device"
    );
    assert_eq!(plain.as_slice(), b"ok", "plaintext");
}

/// A device proof made with another token fails the login before the app
/// proof is sent.
#[test]
fn wrong_token() {
    let mut login = Login::new(&Token::new([0x11; 12]), app_rand());
    drop(drain(&mut login));
    let proof = dev_proof();
    let mut status = LoginStatus::InProgress;
    for value in [
        READY.to_vec(),
        SUCCESS.to_vec(),
        hex("0000000d0100"),
        fragment(1, &dev_rand()),
        hex("0000000c0200"),
        fragment(1, &proof[..18]),
        fragment(2, &proof[18..]),
    ] {
        let (now, writes) = feed(&mut login, Channel::Auth, &value);
        status = now;
        if status != LoginStatus::InProgress {
            assert!(writes.is_empty(), "no app proof leaves after a mismatch");
        }
    }
    assert_eq!(status, LoginStatus::Failed(LoginError::ProofMismatch));
    assert!(
        login.take_session_cipher().is_none(),
        "no cipher after failure"
    );
}

/// Device error codes and an explicit refusal end the login at any step.
#[test]
fn device_errors() {
    for code in 0xE0..=0xE3 {
        let mut login = up_to_device_proof();
        assert_eq!(
            login.handle_notify(Channel::Control, &[code, 0, 0, 0]),
            LoginStatus::Failed(LoginError::DeviceError(code)),
            "{code:#x}"
        );
        assert!(drain(&mut login).is_empty(), "silent after failure");
    }
    let mut login = Login::new(&token(), app_rand());
    assert_eq!(
        login.handle_notify(Channel::Control, &command::LOGIN_REFUSED),
        LoginStatus::Failed(LoginError::Refused)
    );
    assert!(
        drain(&mut login).is_empty(),
        "the queued command is dropped too"
    );
}

/// The device sending its proof where its random belongs is an error.
#[test]
fn unexpected_parcel() {
    let mut login = Login::new(&token(), app_rand());
    drop(drain(&mut login));
    let (_ready, _) = feed(&mut login, Channel::Auth, &READY);
    let (_done, _) = feed(&mut login, Channel::Auth, &SUCCESS);
    let (_announce, _) = feed(&mut login, Channel::Auth, &hex("0000000c0100"));
    let (status, _) = feed(&mut login, Channel::Auth, &fragment(1, &[0; 16]));
    assert_eq!(
        status,
        LoginStatus::Failed(LoginError::UnexpectedParcel {
            expected: kind::DEVICE_RANDOM,
            got: kind::DEVICE_PROOF
        })
    );
}

/// A device random of the wrong length is rejected.
#[test]
fn short_device_random() {
    let mut login = Login::new(&token(), app_rand());
    drop(drain(&mut login));
    let (_ready, _) = feed(&mut login, Channel::Auth, &READY);
    let (_done, _) = feed(&mut login, Channel::Auth, &SUCCESS);
    let (_announce, _) = feed(&mut login, Channel::Auth, &hex("0000000d0100"));
    let (status, _) = feed(&mut login, Channel::Auth, &fragment(1, &[0; 15]));
    assert_eq!(
        status,
        LoginStatus::Failed(LoginError::BadLength {
            kind: kind::DEVICE_RANDOM,
            len: 15
        })
    );
}

/// Transport failures surface as login errors.
#[test]
fn transport_failures() {
    let mut busy = Login::new(&token(), app_rand());
    drop(drain(&mut busy));
    assert_eq!(
        busy.handle_notify(Channel::Auth, &[0, 0, 1, 2]),
        LoginStatus::Failed(LoginError::Send(SendError::Refused(AckStatus::Busy)))
    );

    let mut gap = up_to_device_proof();
    let (_announce, _) = feed(&mut gap, Channel::Auth, &hex("0000000c0200"));
    assert_eq!(
        gap.handle_notify(Channel::Auth, &fragment(2, &[0; 14])),
        LoginStatus::Failed(LoginError::Receive(ReceiveError::Gap {
            expected: 1,
            got: 2
        }))
    );
}

/// Lost-fragment reports are answered by resending, and the login goes on.
#[test]
fn lost_fragment_is_resent() {
    let mut login = Login::new(&token(), app_rand());
    drop(drain(&mut login));
    let (_ready, first) = feed(&mut login, Channel::Auth, &READY);
    assert_eq!(first.len(), 1, "the fragment");
    let (_lost, resent) = feed(&mut login, Channel::Auth, &[0, 0, 1, 5, 1, 0]);
    assert_eq!(
        resent,
        [(Channel::Auth, fragment(1, &app_rand()))],
        "resent"
    );
    assert_eq!(
        login.handle_notify(Channel::Auth, &SUCCESS),
        LoginStatus::InProgress
    );
}

/// Noise is ignored: other channels, stray acks, single frames on the auth
/// channel (with no acknowledgement), early confirmations, garbage.
#[test]
fn noise_is_ignored() {
    let mut login = Login::new(&token(), app_rand());
    drop(drain(&mut login));
    for (channel, value) in [
        (Channel::SpecDown, hex("00000201ff")),
        (Channel::Auth, SUCCESS.to_vec()),
        (Channel::Auth, hex("00000207aabb")),
        (Channel::Control, command::LOGIN_OK.to_vec()),
        (Channel::Control, hex("21000000ff")),
        (Channel::Auth, hex("ff")),
    ] {
        assert_eq!(
            login.handle_notify(channel, &value),
            LoginStatus::InProgress,
            "{value:02x?}"
        );
        assert!(drain(&mut login).is_empty(), "no reply to {value:02x?}");
    }
}

/// Errors render without exposing secrets.
#[test]
fn error_display() {
    assert_eq!(
        LoginError::DeviceError(0xE1).to_string(),
        "device reported authentication error 0xe1"
    );
    assert_eq!(
        LoginError::ProofMismatch.to_string(),
        "device proof does not match (wrong token?)"
    );
}

proptest! {
    /// Arbitrary notifications never panic and never revive a finished login.
    #[test]
    fn arbitrary_input_never_panics(
        inputs in proptest::collection::vec((0_u8..4, proptest::collection::vec(any::<u8>(), 0..=24)), 0..=64)
    ) {
        let mut login = Login::new(&token(), app_rand());
        let mut finished = false;
        for (channel, value) in &inputs {
            let channel = Channel::ALL[usize::from(*channel)];
            let status = login.handle_notify(channel, value);
            drop(drain(&mut login));
            if finished {
                prop_assert_ne!(status, LoginStatus::InProgress);
            }
            finished = status != LoginStatus::InProgress;
        }
    }
}
