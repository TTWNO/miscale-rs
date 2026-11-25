//! App ↔ device spec channels wired back to back.
#![cfg(test)]

use mible_crypto::CipherError;
use mible_crypto::{LoginKeys, Role, SessionCipher, Token};
use mible_spec::{SpecChannel, SpecError, SpecFrame, SpecProgress};
use mible_transport::Channel;
use proptest::prelude::*;

/// Keys from miauth's published login vector.
fn keys() -> LoginKeys {
    let token = Token::from_hex("0cf5615003810d89c233a12a").unwrap();
    LoginKeys::derive(&token, &[0xa8; 16], &[0x90; 16])
}

/// A fresh app/device pair.
fn pair() -> (SpecChannel, SpecChannel) {
    let keys = keys();
    (
        SpecChannel::new(SessionCipher::new(&keys, Role::App), Role::App),
        SpecChannel::new(SessionCipher::new(&keys, Role::Device), Role::Device),
    )
}

/// Moves every pending write from `from` into `to`; returns what `to`
/// reported for each, plus the raw writes.
fn pump(
    from: &mut SpecChannel,
    to: &mut SpecChannel,
) -> (Vec<SpecProgress>, Vec<(Channel, Vec<u8>)>) {
    let mut progress = Vec::new();
    let mut writes = Vec::new();
    while let Some(tx) = from.poll_transmit() {
        writes.push((tx.channel, tx.data.to_vec()));
        progress.push(to.handle_notify(tx.channel, &tx.data));
    }
    (progress, writes)
}

/// Runs both directions until quiet; returns everything each side reported.
fn settle(
    app: &mut SpecChannel,
    device: &mut SpecChannel,
) -> (Vec<SpecProgress>, Vec<SpecProgress>) {
    let (mut at_app, mut at_device) = (Vec::new(), Vec::new());
    for _round in 0_u32..32 {
        let (to_device, sent) = pump(app, device);
        let (to_app, replies) = pump(device, app);
        at_device.extend(to_device);
        at_app.extend(to_app);
        if sent.is_empty() && replies.is_empty() {
            return (at_app, at_device);
        }
    }
    panic!("channels did not settle");
}

/// The app's hello goes out as a one-fragment parcel of kind 0 on 0x001A,
/// sealed under counter 0, and the device decrypts it.
#[test]
fn app_hello() {
    let (mut app, mut device) = pair();
    let mut hello = heapless::Vec::<u8, 16>::new();
    SpecFrame::new(2, &[0xf0]).encode(&mut hello).unwrap();
    app.send(&hello).unwrap();
    let (progress, writes) = pump(&mut app, &mut device);
    assert_eq!(
        writes,
        [(Channel::SpecUp, vec![0, 0, 0, 0, 1, 0])],
        "announce, kind 0, one fragment"
    );
    assert_eq!(progress, [SpecProgress::Idle], "device readies");
    let (at_app, at_device) = settle(&mut app, &mut device);
    assert_eq!(
        at_device,
        [SpecProgress::Received { counter: 0 }],
        "device got counter 0"
    );
    assert_eq!(
        at_app,
        [SpecProgress::Idle, SpecProgress::Sent],
        "app: ready, then sent"
    );
    assert_eq!(device.message(), hello.as_slice(), "plaintext");
}

/// Short device messages travel as single frames on 0x001B and are acked
/// with `00 00 03 <code>`; long ones as parcels. Counters start at 1.
#[test]
fn device_single_and_parcel() {
    let (mut app, mut device) = pair();
    device.send(b"echo").unwrap();
    let (progress, writes) = pump(&mut device, &mut app);
    assert_eq!(writes.len(), 1, "one single frame");
    assert_eq!(writes[0].0, Channel::SpecDown, "on 0x001B");
    assert_eq!(&writes[0].1[..4], &[0, 0, 2, 0], "single, code 0");
    assert_eq!(
        progress,
        [SpecProgress::Received { counter: 1 }],
        "counter 1"
    );
    assert_eq!(app.message(), b"echo", "plaintext");
    let (_, acks) = pump(&mut app, &mut device);
    assert_eq!(acks, [(Channel::SpecDown, vec![0, 0, 3, 0])], "single ack");

    let long = [0x5a; 100];
    device.send(&long).unwrap();
    let (at_app, _) = settle(&mut app, &mut device);
    assert_eq!(
        at_app.last(),
        Some(&SpecProgress::Received { counter: 2 }),
        "parcel, counter 2"
    );
    assert_eq!(app.message(), long, "long plaintext");
}

/// Sending again before the acknowledgement is refused; afterwards it works.
#[test]
fn busy_until_acknowledged() {
    let (mut app, mut device) = pair();
    app.send(b"one").unwrap();
    assert!(app.is_sending(), "awaiting ack");
    assert_eq!(app.send(b"two"), Err(SpecError::Busy), "busy");
    drop(settle(&mut app, &mut device));
    assert!(!app.is_sending(), "acknowledged");
    app.send(b"two").unwrap();
    let (_, at_device) = settle(&mut app, &mut device);
    assert_eq!(
        at_device.last(),
        Some(&SpecProgress::Received { counter: 1 }),
        "second message"
    );
}

/// Over-long plaintext is refused before anything is sealed.
#[test]
fn too_long() {
    let (mut app, _) = pair();
    assert_eq!(app.send(&[0; 256]), Err(SpecError::TooLong), "256 bytes");
    assert!(app.poll_transmit().is_none(), "nothing queued");
}

/// A message that fails authentication stops the channel for good.
#[test]
fn tampered_message_fails_the_channel() {
    let (mut app, mut device) = pair();
    device.send(b"echo").unwrap();
    let tx = device.poll_transmit().unwrap();
    let mut data = tx.data.to_vec();
    let last = data.len() - 1;
    data[last] ^= 1;
    let failed = SpecProgress::Failed(SpecError::Crypto(CipherError::Crypto));
    assert_eq!(
        app.handle_notify(Channel::SpecDown, &data),
        failed,
        "tag mismatch"
    );
    assert_eq!(
        app.handle_notify(Channel::SpecDown, &tx.data),
        failed,
        "stays failed"
    );
    assert!(app.poll_transmit().is_none(), "silent after failure");
    assert_eq!(
        app.send(b"x"),
        Err(SpecError::Crypto(CipherError::Crypto)),
        "send refused"
    );
}

/// Values on the wrong characteristic or that are not frames are ignored.
#[test]
fn noise_is_ignored() {
    let (mut app, _) = pair();
    for (channel, value) in [
        (Channel::Auth, vec![0, 0, 2, 0, 1, 2, 3, 4, 5, 6]),
        (Channel::Control, vec![0x21, 0, 0, 0]),
        (Channel::SpecDown, vec![0xff]),
        (Channel::SpecUp, vec![0, 0, 1, 0]),
    ] {
        assert_eq!(
            app.handle_notify(channel, &value),
            SpecProgress::Idle,
            "{channel:?}"
        );
    }
    assert!(app.poll_transmit().is_none(), "no replies to noise");
}

proptest! {
    /// Any plaintext up to 255 bytes crosses in both directions intact.
    #[test]
    fn any_plaintext_round_trips(plain in proptest::collection::vec(any::<u8>(), 0..=255)) {
        let (mut app, mut device) = pair();
        app.send(&plain).unwrap();
        drop(settle(&mut app, &mut device));
        prop_assert_eq!(device.message(), plain.as_slice());
        device.send(&plain).unwrap();
        drop(settle(&mut app, &mut device));
        prop_assert_eq!(app.message(), plain.as_slice());
    }

    /// Arbitrary notifications never panic.
    #[test]
    fn arbitrary_input_never_panics(
        inputs in proptest::collection::vec((0_u8..4, proptest::collection::vec(any::<u8>(), 0..=24)), 0..=64)
    ) {
        let (mut app, _) = pair();
        for (channel, value) in &inputs {
            let _progress = app.handle_notify(Channel::ALL[usize::from(*channel)], value);
            while app.poll_transmit().is_some() {}
        }
    }
}
