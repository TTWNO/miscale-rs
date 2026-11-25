//! Whole weigh-ins between a `WeighSession` and the simulated scale.
#![cfg(test)]

use mible_auth::LoginError;
use mible_crypto::Token;
use mible_spec::SpecFrame;
use mible_transport::{Channel, Packet, Transmit};
use miscale::session::{HELLO_BODY, HELLO_SEQ, PROFILE_SEQ};
use miscale::{
    Config, Event, Instant, Mid, Outcome, SessionError, Source, Stage, WeighSession, Weight,
};
use miscale_sim::{SimConfig, SimPhase, SimScale, Step};
use proptest::prelude::*;

/// A synthetic token (miauth's published test vector).
fn token() -> Token {
    Token::from_hex("0cf5615003810d89c233a12a").unwrap()
}

/// The app random used throughout.
const APP_RAND: [u8; 16] = [0xa8; 16];

/// The device random used throughout.
const DEV_RAND: [u8; 16] = [0x90; 16];

/// A well-behaved simulated scale playing `script`.
fn scale(script: &[Step]) -> SimScale {
    SimScale::new(SimConfig::new(token(), DEV_RAND), script)
}

/// A session at time zero with default settings.
fn session() -> WeighSession {
    WeighSession::new(
        Instant(0),
        &token(),
        APP_RAND,
        1_764_000_000,
        Config::default(),
    )
}

/// Shuttles writes and notifications at a fixed time until both sides fall
/// quiet; returns every event the session produced.
fn run(session: &mut WeighSession, scale: &mut SimScale, now: Instant) -> Vec<Event> {
    run_clocked(session, scale, now, 0)
}

/// Like [`run`], but the clock advances `step_ms` before each notification
/// and the session's deadline is checked each time.
fn run_clocked(
    session: &mut WeighSession,
    scale: &mut SimScale,
    start: Instant,
    step_ms: u64,
) -> Vec<Event> {
    run_filtered(session, scale, start, step_ms, |notes| notes, Some)
}

/// The general driver. Each round the scale's pending notifications are
/// collected and passed through `to_session` (which may reorder, replace or
/// drop them) and delivered one at a time; after every call the session's
/// writes are drained, each through `to_scale` (which may drop it), as the
/// driving contract requires.
fn run_filtered(
    session: &mut WeighSession,
    scale: &mut SimScale,
    start: Instant,
    step_ms: u64,
    mut to_session: impl FnMut(Vec<Transmit>) -> Vec<Transmit>,
    mut to_scale: impl FnMut(Transmit) -> Option<Transmit>,
) -> Vec<Event> {
    let mut events = Vec::new();
    let mut now = start;
    let mut drain = |client: &mut WeighSession, device: &mut SimScale| {
        while let Some(tx) = client.poll_transmit() {
            if let Some(tx) = to_scale(tx) {
                device.handle_write(tx.channel, &tx.data);
            }
        }
    };
    drain(session, scale);
    for _round in 0_u32..1024 {
        let notes = to_session(core::iter::from_fn(|| scale.poll_notify()).collect());
        if notes.is_empty() {
            events.extend(core::iter::from_fn(|| session.poll_event()));
            return events;
        }
        for rx in notes {
            now = now.plus_millis(step_ms);
            session.handle_timeout(now);
            session.handle_notify(now, rx.channel, &rx.data);
            drain(session, scale);
            events.extend(core::iter::from_fn(|| session.poll_event()));
        }
    }
    panic!("session and scale never fell quiet");
}

/// A notification value, for building replacements.
fn note(channel: Channel, data: &[u8]) -> Transmit {
    Transmit::new(channel, Packet::from_slice(data).unwrap())
}

/// The last event, which must be `Finished`.
fn outcome(events: &[Event]) -> Outcome {
    match events.last() {
        Some(Event::Finished(outcome)) => *outcome,
        other => panic!("last event was {other:?}"),
    }
}

/// Login, hello, profile, live readings, then the final weight.
#[test]
fn final_weight() {
    let mut scale = scale(&[
        Step::Live(4120),
        Step::Live(8100),
        Step::Live(8355),
        Step::Final(8360),
    ]);
    let mut session = session();
    let events = run(&mut session, &mut scale, Instant(0));
    assert_eq!(
        events,
        [
            Event::Authenticated,
            Event::Live(Weight(4120)),
            Event::Live(Weight(8100)),
            Event::Live(Weight(8355)),
            Event::Finished(Outcome::Measured {
                weight: Weight(8360),
                source: Source::Final
            }),
        ]
    );
    assert!(session.is_finished(), "finished");
    assert_eq!(session.poll_timeout(), None, "no deadline after the end");
    assert!(
        session.poll_transmit().is_none(),
        "nothing to send after the end"
    );
    assert_eq!(
        scale.unacknowledged(),
        0,
        "every message from the scale, the final one included, was acknowledged"
    );
}

/// The hello and profile reach the scale with the captured sequence
/// numbers, and the profile carries the configured account id and time.
#[test]
fn hello_and_profile_on_the_wire() {
    let mut scale = scale(&[]);
    let mid = Mid::new("4242").unwrap();
    let mut session = WeighSession::new(
        Instant(0),
        &token(),
        APP_RAND,
        1_700_000_123,
        Config::with_mid(mid),
    );
    let _events = run(&mut session, &mut scale, Instant(0));
    let profile = SpecFrame::parse(scale.profile()).expect("profile frame");
    assert_eq!(profile.seq, PROFILE_SEQ, "profile sequence number");
    let text = core::str::from_utf8(&profile.body[8..]).unwrap();
    assert!(text.starts_with(r#"{"mid":"4242","#), "mid in {text}");
    assert!(text.contains(r#""time":1700000123,"#), "time in {text}");
    assert_eq!((HELLO_SEQ, HELLO_BODY), (2, [0xf0]), "captured hello");
}

/// No final frame: the steady live readings are averaged when the load
/// comes off.
#[test]
fn estimated_weight() {
    let steady = [8350, 8360, 8355, 8358, 8362].map(Step::Live);
    let mut script = steady.to_vec();
    script.push(Step::Live(40));
    let mut scale = scale(&script);
    let mut session = session();
    let events = run(&mut session, &mut scale, Instant(0));
    assert_eq!(
        outcome(&events),
        Outcome::Measured {
            weight: Weight(8357),
            source: Source::Estimated
        }
    );
    assert_eq!(
        scale.unacknowledged(),
        0,
        "the reading that ended it was acknowledged"
    );
}

/// The hello's echo may arrive before the hello's acknowledgement; the
/// profile still goes out (once both are in) and the weigh-in completes.
#[test]
fn echo_before_ack() {
    let mut scale = scale(&[Step::Final(7000)]);
    let mut session = session();
    let mut swapped = false;
    let events = run_filtered(
        &mut session,
        &mut scale,
        Instant(0),
        0,
        |mut notes| {
            let ack = notes
                .iter()
                .position(|tx| tx.channel == Channel::SpecUp && tx.data.as_slice() == [0, 0, 1, 0]);
            let echo = notes.iter().position(|tx| tx.channel == Channel::SpecDown);
            if let (Some(ack), Some(echo), false) = (ack, echo, swapped) {
                notes.swap(ack, echo);
                swapped = true;
            }
            notes
        },
        Some,
    );
    assert!(swapped, "the echo was delivered first");
    assert_eq!(
        outcome(&events),
        Outcome::Measured {
            weight: Weight(7000),
            source: Source::Final
        }
    );
}

/// A scale that answers the hello's announcement with "busy" fails the
/// session with that reason.
#[test]
fn busy_on_the_spec_channel() {
    let mut scale = scale(&[]);
    let mut session = session();
    let events = run_filtered(
        &mut session,
        &mut scale,
        Instant(0),
        0,
        |notes| {
            notes
                .into_iter()
                .map(|tx| {
                    if tx.channel == Channel::SpecUp && tx.data.as_slice() == [0, 0, 1, 1] {
                        note(Channel::SpecUp, &[0, 0, 1, 2])
                    } else {
                        tx
                    }
                })
                .collect()
        },
        Some,
    );
    assert_eq!(
        outcome(&events),
        Outcome::Failed(SessionError::Spec(mible_spec::SpecError::Send(
            mible_transport::tx::SendError::Refused(mible_transport::frame::AckStatus::Busy)
        )))
    );
}

/// The hello's only fragment is lost on the way; the scale reports it lost,
/// the session resends it, and the weigh-in completes.
#[test]
fn lost_fragment_on_the_spec_channel() {
    let mut scale = scale(&[Step::Final(6400)]);
    let mut session = session();
    let mut dropped = false;
    let report_lost = core::cell::Cell::new(false);
    let events = run_filtered(
        &mut session,
        &mut scale,
        Instant(0),
        0,
        |mut notes| {
            if report_lost.take() {
                notes.push(note(Channel::SpecUp, &[0, 0, 1, 5, 1, 0]));
            }
            notes
        },
        |tx| {
            let fragment = tx.channel == Channel::SpecUp && tx.data.first() == Some(&1);
            if fragment && !dropped {
                dropped = true;
                report_lost.set(true);
                return None;
            }
            Some(tx)
        },
    );
    assert!(dropped, "a fragment was dropped");
    assert_eq!(
        outcome(&events),
        Outcome::Measured {
            weight: Weight(6400),
            source: Source::Final
        }
    );
}

/// Frames that are not weights (device info) are ignored.
#[test]
fn unrelated_frames_are_ignored() {
    let info: &'static [u8] = &[
        0x0b, 0x20, 0x09, 0x00, 0x05, 0xa0, b'2', b'.', b'1', b'.', b'2',
    ];
    let mut scale = scale(&[Step::Raw(info), Step::Final(5545)]);
    let mut session = session();
    let events = run(&mut session, &mut scale, Instant(0));
    assert_eq!(
        outcome(&events),
        Outcome::Measured {
            weight: Weight(5545),
            source: Source::Final
        }
    );
}

/// Logged in but nobody steps on: the measurement window closes after
/// 45 s measured from the profile's acknowledgement, not before.
#[test]
fn nobody_steps_on() {
    let mut scale = scale(&[]);
    let mut session = session();
    let events = run(&mut session, &mut scale, Instant(1_000));
    assert_eq!(events, [Event::Authenticated], "waiting");
    assert_eq!(
        session.poll_timeout(),
        Some(Instant(46_000)),
        "absolute window"
    );
    session.handle_timeout(Instant(45_999));
    assert_eq!(session.poll_event(), None, "not yet");
    session.handle_timeout(Instant(46_000));
    assert_eq!(
        session.poll_event(),
        Some(Event::Finished(Outcome::NoMeasurement)),
        "window closed"
    );
}

/// Live readings do not extend the measurement window: with the clock
/// advancing 2 s per notification, the window closes 45 s after the profile
/// while the scale is still streaming.
#[test]
fn live_readings_do_not_extend_the_window() {
    let script = [Step::Live(150); 30];
    let mut scale = SimScale::new(SimConfig::new(token(), DEV_RAND), &script);
    let mut session = session();
    let events = run_clocked(&mut session, &mut scale, Instant(0), 2_000);
    assert_eq!(outcome(&events), Outcome::NoMeasurement, "window closed");
    let live = events
        .iter()
        .filter(|event| matches!(event, Event::Live(_)))
        .count();
    assert!(
        live > 0 && live < script.len(),
        "closed mid-stream after {live} readings"
    );
}

/// A scale bound with another token: the device proof does not verify.
#[test]
fn wrong_token() {
    let mut scale = SimScale::new(SimConfig::new(Token::new([7; 12]), DEV_RAND), &[]);
    let mut session = session();
    let events = run(&mut session, &mut scale, Instant(0));
    assert_eq!(
        outcome(&events),
        Outcome::Failed(SessionError::Login(LoginError::ProofMismatch))
    );
    // The app stops at the mismatch: it neither acknowledges the device
    // proof nor sends its own.
    assert_eq!(scale.phase(), SimPhase::SendProof, "the app went silent");
}

/// A scale that refuses the login.
#[test]
fn login_refused() {
    let mut config = SimConfig::new(token(), DEV_RAND);
    config.refuse_login = true;
    let mut scale = SimScale::new(config, &[]);
    let mut session = session();
    let events = run(&mut session, &mut scale, Instant(0));
    assert_eq!(
        outcome(&events),
        Outcome::Failed(SessionError::Login(LoginError::Refused))
    );
}

/// A scale that never answers: the login times out after 10 s of silence.
#[test]
fn silent_scale() {
    let mut session = session();
    while session.poll_transmit().is_some() {}
    assert_eq!(
        session.poll_timeout(),
        Some(Instant(10_000)),
        "inactivity deadline"
    );
    session.handle_timeout(Instant(10_000));
    assert_eq!(
        session.poll_event(),
        Some(Event::Finished(Outcome::Failed(SessionError::Timeout(
            Stage::Login
        ))))
    );
}

/// A scale that never echoes the hello: the session times out at the hello,
/// 10 s after the last thing it heard.
#[test]
fn no_hello_echo() {
    let mut config = SimConfig::new(token(), DEV_RAND);
    config.echo_hello = false;
    let mut scale = SimScale::new(config, &[]);
    let mut session = session();
    let events = run(&mut session, &mut scale, Instant(2_000));
    assert_eq!(events, [Event::Authenticated], "logged in");
    assert_eq!(
        session.poll_timeout(),
        Some(Instant(12_000)),
        "inactivity from the last frame"
    );
    session.handle_timeout(Instant(12_000));
    assert_eq!(
        session.poll_event(),
        Some(Event::Finished(Outcome::Failed(SessionError::Timeout(
            Stage::Hello
        ))))
    );
}

/// Aborting ends the session once; nothing happens after the end.
#[test]
fn abort_and_after() {
    let mut session = session();
    session.abort();
    session.abort();
    assert_eq!(
        session.poll_event(),
        Some(Event::Finished(Outcome::Aborted)),
        "aborted"
    );
    assert_eq!(session.poll_event(), None, "exactly one terminal event");
    session.handle_notify(Instant(0), Channel::Control, &[0x21, 0, 0, 0]);
    session.handle_timeout(Instant(u64::MAX));
    assert_eq!(session.poll_event(), None, "input after the end is ignored");
    assert!(session.poll_transmit().is_none(), "no writes after the end");
}

proptest! {
    /// Arbitrary notifications and timeouts never panic; a session emits at
    /// most one terminal event, it is the last one, and nothing is sent
    /// after it but acknowledgements.
    #[test]
    fn arbitrary_input_is_safe(
        inputs in proptest::collection::vec(
            (0_u8..5, proptest::collection::vec(any::<u8>(), 0..=24), 0_u64..20_000),
            0..=96
        )
    ) {
        let mut session = session();
        let mut finished = false;
        let mut now = 0_u64;
        for (channel, value, step) in &inputs {
            now = now.saturating_add(*step);
            if let Some(channel) = Channel::ALL.get(usize::from(*channel)) {
                session.handle_notify(Instant(now), *channel, value);
            } else {
                session.handle_timeout(Instant(now));
            }
            while let Some(tx) = session.poll_transmit() {
                if finished {
                    let ack = matches!(
                        mible_transport::frame::Frame::parse(&tx.data),
                        Some(mible_transport::frame::Frame::Ack { .. } | mible_transport::frame::Frame::SingleAck { .. })
                    );
                    prop_assert!(ack, "only acknowledgements after the end");
                }
            }
            while let Some(event) = session.poll_event() {
                prop_assert!(!finished, "an event after Finished: {event:?}");
                finished = matches!(event, Event::Finished(_));
            }
        }
    }
}
