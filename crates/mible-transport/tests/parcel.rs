//! Sender ↔ receiver behaviour, wired back to back.
#![cfg(test)]

use mible_transport::frame::{AckStatus, Frame};
use mible_transport::rx::{Delivery, ReceiveError, ReceiveProgress, Receiver, SinglePolicy};
use mible_transport::tx::{MAX_RESEND_ROUNDS, SendError, SendProgress, Sender};
use mible_transport::{FRAGMENT_PAYLOAD_LEN, Packet};
use proptest::prelude::*;

/// Parcel-buffer size used by these tests.
const CAP: usize = 288;

/// Collects every pending transmit of a sender.
fn drain_sender(tx: &mut Sender<CAP>) -> Vec<Packet> {
    core::iter::from_fn(|| tx.poll_transmit()).collect()
}

/// Collects every pending transmit of a receiver.
fn drain_receiver(rx: &mut Receiver<CAP>) -> Vec<Packet> {
    core::iter::from_fn(|| rx.poll_transmit()).collect()
}

/// Runs a whole transfer between a sender and a receiver; returns the
/// delivered message and how many packets crossed in each direction.
fn transfer(kind: u8, payload: &[u8]) -> (Vec<u8>, usize, usize) {
    let mut tx = Sender::<CAP>::new();
    let mut rx = Receiver::<CAP>::new(SinglePolicy::Ignore);
    tx.start(kind, payload).unwrap();
    let (mut sent, mut acked) = (Vec::new(), Vec::new());
    let mut delivered = None;
    for _round in 0_u32..64 {
        for packet in drain_sender(&mut tx) {
            sent.push(packet.clone());
            let frame = Frame::parse(&packet).unwrap();
            if let ReceiveProgress::Complete {
                kind: got,
                delivery,
            } = rx.handle(&frame)
            {
                assert_eq!((got, delivery), (kind, Delivery::Parcel), "delivery");
                delivered = Some(rx.message().to_vec());
            }
        }
        for packet in drain_receiver(&mut rx) {
            acked.push(packet.clone());
            let _progress = tx.handle(&Frame::parse(&packet).unwrap());
        }
        if tx.is_complete() {
            return (
                delivered.expect("receiver completed"),
                sent.len(),
                acked.len(),
            );
        }
    }
    panic!("transfer did not finish");
}

/// One-, two- and many-fragment parcels arrive intact, with the expected
/// number of writes: announce + fragments one way, ready + success the other.
#[test]
fn round_trips() {
    for len in [1_usize, 16, 18, 19, 32, 64, 270] {
        let payload: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
        let (delivered, sent, acked) = transfer(0x0b, &payload);
        assert_eq!(delivered, payload, "payload of {len} bytes");
        assert_eq!(
            sent.checked_sub(1),
            Some(len.div_ceil(FRAGMENT_PAYLOAD_LEN)),
            "writes for {len} bytes"
        );
        assert_eq!(acked, 2, "acks for {len} bytes");
    }
}

/// The exact bytes of a two-fragment send match the prototype's framing.
#[test]
fn wire_bytes_of_a_two_fragment_send() {
    let mut tx = Sender::<CAP>::new();
    let payload: Vec<u8> = (1..=32).collect();
    tx.start(0x0a, &payload).unwrap();
    assert_eq!(
        drain_sender(&mut tx),
        [Packet::from_slice(&[0, 0, 0, 0x0a, 2, 0]).unwrap()]
    );
    assert_eq!(
        tx.handle(&Frame::parse(&[0, 0, 1, 1]).unwrap()),
        SendProgress::Advanced
    );
    let frames = drain_sender(&mut tx);
    assert_eq!(frames.len(), 2, "two fragments");
    assert_eq!(&frames[0][..2], &[1, 0], "first index");
    assert_eq!(&frames[0][2..], &payload[..18], "first payload");
    assert_eq!(&frames[1][..2], &[2, 0], "second index");
    assert_eq!(&frames[1][2..], &payload[18..], "second payload");
    assert_eq!(
        tx.handle(&Frame::parse(&[0, 0, 1, 0]).unwrap()),
        SendProgress::Complete
    );
}

/// Fragments reported lost are resent before anything new, then the
/// transfer completes; too many reports fail it.
#[test]
fn lost_fragments_are_resent() {
    let mut tx = Sender::<CAP>::new();
    tx.start(0, &[7; 54]).unwrap(); // three fragments
    let _announce = drain_sender(&mut tx);
    let _ready = tx.handle(&Frame::Ack {
        status: AckStatus::Ready,
        detail: &[],
    });
    assert_eq!(drain_sender(&mut tx).len(), 3, "first pass");
    let lost = Frame::Ack {
        status: AckStatus::Lost,
        detail: &[2, 0, 3, 0],
    };
    assert_eq!(tx.handle(&lost), SendProgress::Advanced, "lost report");
    let resent = drain_sender(&mut tx);
    assert_eq!(
        resent.iter().map(|packet| packet[0]).collect::<Vec<_>>(),
        [2, 3],
        "resent indices"
    );
    for round in 1..MAX_RESEND_ROUNDS {
        assert_eq!(tx.handle(&lost), SendProgress::Advanced, "round {round}");
        let _again = drain_sender(&mut tx);
    }
    assert_eq!(
        tx.handle(&lost),
        SendProgress::Failed(SendError::TooManyResends),
        "one round too many"
    );
}

/// A lost report naming a fragment outside the parcel fails the transfer.
#[test]
fn lost_index_out_of_range() {
    let mut tx = Sender::<CAP>::new();
    tx.start(0, &[1; 10]).unwrap();
    let _announce = drain_sender(&mut tx);
    let _ready = tx.handle(&Frame::Ack {
        status: AckStatus::Ready,
        detail: &[],
    });
    let _fragments = drain_sender(&mut tx);
    let lost = Frame::Ack {
        status: AckStatus::Lost,
        detail: &[9, 0],
    };
    assert_eq!(
        tx.handle(&lost),
        SendProgress::Failed(SendError::BadLostIndex(9))
    );
}

/// Busy / timeout / cancel answers end the transfer; stray acks do not.
#[test]
fn refusals_and_strays() {
    for status in [
        AckStatus::Busy,
        AckStatus::Timeout,
        AckStatus::Cancel,
        AckStatus::Unknown(9),
    ] {
        let mut tx = Sender::<CAP>::new();
        tx.start(0, &[1]).unwrap();
        let _announce = drain_sender(&mut tx);
        let ack = Frame::Ack {
            status,
            detail: &[],
        };
        assert_eq!(
            tx.handle(&ack),
            SendProgress::Failed(SendError::Refused(status)),
            "{status:?}"
        );
        assert!(!tx.is_active(), "failed sender is inactive");
    }
    let mut tx = Sender::<CAP>::new();
    tx.start(0, &[1]).unwrap();
    let _announce = drain_sender(&mut tx);
    let success = Frame::Ack {
        status: AckStatus::Success,
        detail: &[],
    };
    assert_eq!(
        tx.handle(&success),
        SendProgress::Ignored,
        "success before ready is stray"
    );
    let single = Frame::Single {
        code: 1,
        payload: &[],
    };
    assert_eq!(
        tx.handle(&single),
        SendProgress::Ignored,
        "non-ack frames are ignored"
    );
}

/// A payload larger than the buffer is refused up front.
#[test]
fn oversized_payload() {
    let mut tx = Sender::<16>::new();
    assert_eq!(tx.start(0, &[0; 17]), Err(SendError::TooLarge));
    assert_eq!(tx.poll_transmit(), None, "nothing to send after a refusal");
}

/// An empty parcel is announced with zero fragments and completes on success.
#[test]
fn empty_parcel() {
    let (delivered, sent, acked) = transfer(5, &[]);
    assert!(delivered.is_empty(), "empty payload");
    assert_eq!((sent, acked), (1, 2), "announce only; ready + success");
}

/// Receiver: a repeat of the previous fragment is ignored; a gap fails.
#[test]
fn receiver_duplicates_and_gaps() {
    let mut rx = Receiver::<CAP>::new(SinglePolicy::Ignore);
    let one = core::num::NonZeroU16::MIN;
    let three = core::num::NonZeroU16::new(3).unwrap();
    assert_eq!(
        rx.handle(&Frame::Announce {
            kind: 0x0d,
            count: 3
        }),
        ReceiveProgress::Advanced
    );
    assert_eq!(
        rx.handle(&Frame::Fragment {
            index: one,
            payload: &[1]
        }),
        ReceiveProgress::Advanced
    );
    assert_eq!(
        rx.handle(&Frame::Fragment {
            index: one,
            payload: &[1]
        }),
        ReceiveProgress::Ignored,
        "duplicate"
    );
    assert_eq!(
        rx.handle(&Frame::Fragment {
            index: three,
            payload: &[3]
        }),
        ReceiveProgress::Failed(ReceiveError::Gap {
            expected: 2,
            got: 3
        }),
        "gap"
    );
    assert_eq!(
        drain_receiver(&mut rx).len(),
        1,
        "only the ready ack was sent"
    );
}

/// Receiver: a parcel that overflows the buffer is acknowledged and dropped.
#[test]
fn receiver_discards_oversized() {
    let mut rx = Receiver::<20>::new(SinglePolicy::Ignore);
    let _announced: ReceiveProgress = rx.handle(&Frame::Announce { kind: 0, count: 2 });
    let first = core::num::NonZeroU16::MIN;
    let second = core::num::NonZeroU16::new(2).unwrap();
    assert_eq!(
        rx.handle(&Frame::Fragment {
            index: first,
            payload: &[0; 18]
        }),
        ReceiveProgress::Advanced
    );
    assert_eq!(
        rx.handle(&Frame::Fragment {
            index: second,
            payload: &[0; 18]
        }),
        ReceiveProgress::Discarded { kind: 0 }
    );
    let acks: Vec<_> = core::iter::from_fn(|| rx.poll_transmit()).collect();
    assert_eq!(
        acks,
        [
            Packet::from_slice(&[0, 0, 1, 1]).unwrap(),
            Packet::from_slice(&[0, 0, 1, 0]).unwrap()
        ]
    );
    assert!(rx.message().is_empty(), "nothing delivered");
}

/// Receiver: single frames follow the configured policy.
#[test]
fn receiver_single_policy() {
    let single = Frame::Single {
        code: 9,
        payload: &[0xaa, 0xbb],
    };
    let mut ignoring = Receiver::<CAP>::new(SinglePolicy::Ignore);
    assert_eq!(ignoring.handle(&single), ReceiveProgress::Ignored);
    assert_eq!(
        ignoring.poll_transmit(),
        None,
        "no ack on the login channel"
    );

    let mut delivering = Receiver::<CAP>::new(SinglePolicy::AckAndDeliver);
    assert_eq!(
        delivering.handle(&single),
        ReceiveProgress::Complete {
            kind: 9,
            delivery: Delivery::Single
        }
    );
    assert_eq!(delivering.message(), [0xaa, 0xbb]);
    assert_eq!(
        delivering.poll_transmit(),
        Some(Packet::from_slice(&[0, 0, 3, 9]).unwrap())
    );
}

/// Receiver: fragments longer than 18 bytes (higher MTU) are accepted.
#[test]
fn receiver_accepts_long_fragments() {
    let mut rx = Receiver::<CAP>::new(SinglePolicy::Ignore);
    let _announced: ReceiveProgress = rx.handle(&Frame::Announce {
        kind: 0x0c,
        count: 1,
    });
    let payload = [0x42; 32];
    let index = core::num::NonZeroU16::MIN;
    assert_eq!(
        rx.handle(&Frame::Fragment {
            index,
            payload: &payload
        }),
        ReceiveProgress::Complete {
            kind: 0x0c,
            delivery: Delivery::Parcel
        }
    );
    assert_eq!(rx.message(), payload);
}

/// Receiver: acknowledgements that are not drained fail the transfer
/// rather than being lost silently.
#[test]
fn receiver_backlog() {
    let mut rx = Receiver::<CAP>::new(SinglePolicy::AckAndDeliver);
    let single = Frame::Single {
        code: 1,
        payload: &[0xaa],
    };
    assert!(
        matches!(rx.handle(&single), ReceiveProgress::Complete { .. }),
        "first"
    );
    assert!(
        matches!(rx.handle(&single), ReceiveProgress::Complete { .. }),
        "second"
    );
    assert_eq!(
        rx.handle(&single),
        ReceiveProgress::Failed(ReceiveError::Backlog),
        "third"
    );
    assert_eq!(
        drain_receiver(&mut rx).len(),
        2,
        "the two queued acks are still sent"
    );
}

proptest! {
    /// Any payload up to the buffer size survives a transfer.
    #[test]
    fn any_payload_round_trips(payload in proptest::collection::vec(any::<u8>(), 0..=CAP), kind in any::<u8>()) {
        let (delivered, _, _) = transfer(kind, &payload);
        prop_assert_eq!(delivered, payload);
    }

    /// Arbitrary frame sequences never panic either state machine.
    #[test]
    fn arbitrary_input_never_panics(values in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..=24), 0..=64)) {
        let mut tx = Sender::<CAP>::new();
        tx.start(1, &[0; 40]).unwrap();
        let mut rx = Receiver::<CAP>::new(SinglePolicy::AckAndDeliver);
        for value in &values {
            if let Some(frame) = Frame::parse(value) {
                let _tx = tx.handle(&frame);
                let _rx = rx.handle(&frame);
            }
            drop(drain_sender(&mut tx));
            drop(drain_receiver(&mut rx));
        }
    }
}
