//! One weigh-in, from login to the final weight.

use core::fmt;

use mible_auth::{Login, LoginError, LoginStatus};
use mible_crypto::login::Random;
use mible_crypto::{Role, Token};
use mible_spec::{SpecChannel, SpecError, SpecFrame, SpecProgress};
use mible_transport::{Channel, Transmit};

use crate::profile::{self, Mid};
use crate::weight::{self, Reading, Stabiliser, Weight};

/// Sequence number of the hello frame, as captured from the official app.
pub const HELLO_SEQ: u16 = 2;
/// Body of the hello frame.
pub const HELLO_BODY: [u8; 1] = [0xF0];
/// Sequence number of the profile frame, as captured from the official app.
pub const PROFILE_SEQ: u16 = 3;

/// Most events held before the oldest is dropped (the final one never is).
const EVENT_CAPACITY: usize = 8;

/// A point in time on the caller's monotonic clock, in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[expect(
    clippy::exhaustive_structs,
    reason = "a plain unit wrapper; its meaning is fixed"
)]
pub struct Instant(pub u64);

impl Instant {
    /// `self` plus `millis`, saturating.
    #[must_use]
    pub const fn plus_millis(self, millis: u64) -> Self {
        Self(self.0.saturating_add(millis))
    }
}

/// Session settings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Config {
    /// Longest silence tolerated while logging in and opening the channel.
    pub inactivity_timeout_ms: u64,
    /// How long to wait for a measurement once the profile is accepted.
    pub measurement_timeout_ms: u64,
    /// Account id sent in the profile.
    pub mid: Mid,
}

impl Default for Config {
    /// The prototype's timings: 10 s of silence, a 45 s measurement window.
    fn default() -> Self {
        Self {
            inactivity_timeout_ms: 10_000,
            measurement_timeout_ms: 45_000,
            mid: Mid::default(),
        }
    }
}

impl Config {
    /// The default settings with `mid` as the account id.
    #[must_use]
    pub fn with_mid(mid: Mid) -> Self {
        Self {
            mid,
            ..Self::default()
        }
    }
}

/// How a measurement was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Source {
    /// The scale's own stabilised value.
    Final,
    /// Averaged from steady live readings (the scale sent no final value).
    Estimated,
}

/// Which step was waiting when a deadline passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Stage {
    /// Logging in.
    Login,
    /// Waiting for the hello echo.
    Hello,
    /// Waiting for the profile to be acknowledged.
    Profile,
}

/// Why a session failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SessionError {
    /// The login failed (for [`LoginError::ProofMismatch`]: wrong token).
    Login(LoginError),
    /// The spec channel failed.
    Spec(SpecError),
    /// The device went quiet.
    Timeout(Stage),
    /// The profile could not be built.
    Profile,
    /// A state the session should never reach; please report it.
    Internal,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Login(err) => write!(f, "login failed: {err}"),
            Self::Spec(err) => write!(f, "spec channel failed: {err}"),
            Self::Timeout(stage) => write!(f, "scale went quiet during {stage:?}"),
            Self::Profile => f.write_str("could not build the profile message"),
            Self::Internal => f.write_str("internal error in the weigh session"),
        }
    }
}

impl core::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Login(err) => Some(err),
            Self::Spec(err) => Some(err),
            Self::Timeout(_) | Self::Profile | Self::Internal => None,
        }
    }
}

/// How a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Outcome {
    /// A weight was measured.
    Measured {
        /// The weight.
        weight: Weight,
        /// How it was obtained.
        source: Source,
        /// For [`Source::Final`], the scale's timestamp of the measurement
        /// (see [`FinalReading::scale_time`](crate::weight::FinalReading::scale_time)).
        scale_time: Option<u32>,
    },
    /// Logged in, but nobody stood on the scale in time.
    NoMeasurement,
    /// The caller aborted (for example, the link dropped).
    Aborted,
    /// The session failed.
    Failed(SessionError),
}

/// Something the caller may want to act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Event {
    /// Logged in; the spec channel is opening.
    Authenticated,
    /// The scale is streaming a weight while the load settles.
    Live(Weight),
    /// The session is over. Always the last event.
    Finished(Outcome),
}

/// Progress of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Logging in.
    Login,
    /// Hello sent; waiting for its acknowledgement and echo.
    Hello {
        /// The hello was acknowledged.
        acked: bool,
        /// The device echoed.
        echoed: bool,
    },
    /// Profile sent; waiting for its acknowledgement.
    Profile,
    /// Waiting for a measurement until the deadline.
    Measuring,
    /// Over. Acknowledgements already queued for the scale may still go out
    /// after a measurement, so it knows its last message arrived.
    Finished {
        /// Whether queued acknowledgements are still delivered.
        flush_acks: bool,
    },
}

/// Sans-io weigh-in with an S200.
///
/// See the crate docs for the driving contract.
pub struct WeighSession {
    /// Current progress.
    phase: Phase,
    /// The login, until it completes.
    login: Login,
    /// The spec channel, once logged in.
    spec: Option<SpecChannel>,
    /// When the current wait expires.
    deadline: Instant,
    /// Unix time for the profile.
    unix_time: u64,
    /// Settings.
    config: Config,
    /// Fallback estimate from live readings.
    stabiliser: Stabiliser,
    /// Events not yet polled.
    events: heapless::Deque<Event, EVENT_CAPACITY>,
}

impl fmt::Debug for WeighSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WeighSession")
            .field("phase", &self.phase)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl WeighSession {
    /// Starts a session at `now`, with the device `token`, 16 fresh random
    /// bytes from a secure source, and the current Unix time (seconds).
    #[must_use]
    pub fn new(
        now: Instant,
        token: &Token,
        app_rand: Random,
        unix_time: u64,
        config: Config,
    ) -> Self {
        Self {
            phase: Phase::Login,
            login: Login::new(token, app_rand),
            spec: None,
            deadline: now.plus_millis(config.inactivity_timeout_ms),
            unix_time,
            config,
            stabiliser: Stabiliser::new(),
            events: heapless::Deque::new(),
        }
    }

    /// Whether the session is over (its [`Event::Finished`] may still be
    /// waiting in [`WeighSession::poll_event`]).
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        matches!(self.phase, Phase::Finished { .. })
    }

    /// Feeds a notification received at `now` on `channel`.
    pub fn handle_notify(&mut self, now: Instant, channel: Channel, data: &[u8]) {
        match self.phase {
            Phase::Finished { .. } => {}
            Phase::Login => {
                self.deadline = now.plus_millis(self.config.inactivity_timeout_ms);
                match self.login.handle_notify(channel, data) {
                    LoginStatus::Authenticated => self.on_authenticated(),
                    LoginStatus::Failed(err) => {
                        self.finish(Outcome::Failed(SessionError::Login(err)));
                    }
                    LoginStatus::InProgress | _ => {}
                }
            }
            Phase::Hello { .. } | Phase::Profile | Phase::Measuring => {
                if !matches!(self.phase, Phase::Measuring) {
                    self.deadline = now.plus_millis(self.config.inactivity_timeout_ms);
                }
                self.on_spec(now, channel, data);
            }
        }
    }

    /// Tells the session the time is `now`; acts on an expired deadline.
    pub fn handle_timeout(&mut self, now: Instant) {
        if self.is_finished() || now < self.deadline {
            return;
        }
        let outcome = match self.phase {
            Phase::Login => Outcome::Failed(SessionError::Timeout(Stage::Login)),
            Phase::Hello { .. } => Outcome::Failed(SessionError::Timeout(Stage::Hello)),
            Phase::Profile => Outcome::Failed(SessionError::Timeout(Stage::Profile)),
            Phase::Measuring | Phase::Finished { .. } => Outcome::NoMeasurement,
        };
        self.finish(outcome);
    }

    /// Ends the session now (for example because the link dropped).
    pub fn abort(&mut self) {
        if !self.is_finished() {
            self.finish(Outcome::Aborted);
        }
    }

    /// The next write to perform, if any (always write-without-response).
    ///
    /// After [`Event::Finished`] nothing new is sent, but acknowledgements
    /// of messages the scale already sent are still delivered after a
    /// measurement, as the official app does before disconnecting.
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        match (self.phase, self.spec.as_mut()) {
            (Phase::Finished { flush_acks: true }, Some(spec)) => spec.poll_acknowledgement(),
            (Phase::Finished { .. }, _) => None,
            (Phase::Login, _) => self.login.poll_transmit(),
            (_, Some(spec)) => spec.poll_transmit(),
            (_, None) => None,
        }
    }

    /// The next event, if any.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// When to call [`WeighSession::handle_timeout`] next, if ever.
    #[must_use]
    pub const fn poll_timeout(&self) -> Option<Instant> {
        if self.is_finished() {
            None
        } else {
            Some(self.deadline)
        }
    }

    /// Login succeeded: open the spec channel and say hello.
    fn on_authenticated(&mut self) {
        let Some(cipher) = self.login.take_session_cipher() else {
            return self.finish(Outcome::Failed(SessionError::Internal));
        };
        self.push_event(Event::Authenticated);
        self.phase = Phase::Hello {
            acked: false,
            echoed: false,
        };
        let mut spec = SpecChannel::new(cipher, Role::App);
        let mut frame = heapless::Vec::<u8, 8>::new();
        let sent = SpecFrame::new(HELLO_SEQ, &HELLO_BODY)
            .encode(&mut frame)
            .map_err(|_too_long| SessionError::Profile)
            .and_then(|()| spec.send(&frame).map_err(SessionError::Spec));
        self.spec = Some(spec);
        if let Err(err) = sent {
            self.finish(Outcome::Failed(err));
        }
    }

    /// Handles a notification once the spec channel is open.
    fn on_spec(&mut self, now: Instant, channel: Channel, data: &[u8]) {
        let Some(spec) = self.spec.as_mut() else {
            return;
        };
        match spec.handle_notify(channel, data) {
            SpecProgress::Sent => self.on_sent(now),
            SpecProgress::Received { .. } => self.on_message(),
            SpecProgress::Failed(err) => self.finish(Outcome::Failed(SessionError::Spec(err))),
            SpecProgress::Idle | SpecProgress::Discarded | _ => {}
        }
    }

    /// Our message was acknowledged.
    fn on_sent(&mut self, now: Instant) {
        match self.phase {
            Phase::Hello { echoed, .. } => {
                self.phase = Phase::Hello {
                    acked: true,
                    echoed,
                };
                self.maybe_send_profile();
            }
            Phase::Profile => {
                self.phase = Phase::Measuring;
                self.deadline = now.plus_millis(self.config.measurement_timeout_ms);
            }
            Phase::Login | Phase::Measuring | Phase::Finished { .. } => {}
        }
    }

    /// A message arrived on the spec channel.
    fn on_message(&mut self) {
        if let Phase::Hello { acked, .. } = self.phase {
            // The first message after the hello is its echo.
            self.phase = Phase::Hello {
                acked,
                echoed: true,
            };
            return self.maybe_send_profile();
        }
        let Some(reading) = self
            .spec
            .as_ref()
            .and_then(|spec| weight::decode(spec.message()))
        else {
            return;
        };
        match reading {
            Reading::Final(reading) => {
                self.finish(Outcome::Measured {
                    weight: reading.weight,
                    source: Source::Final,
                    scale_time: Some(reading.scale_time),
                });
            }
            Reading::Live(weight) => {
                self.push_event(Event::Live(weight));
                if let Some(weight) = self.stabiliser.push(weight) {
                    self.finish(Outcome::Measured {
                        weight,
                        source: Source::Estimated,
                        scale_time: None,
                    });
                }
            }
        }
    }

    /// Sends the profile once the hello is both acknowledged and echoed.
    fn maybe_send_profile(&mut self) {
        let Phase::Hello {
            acked: true,
            echoed: true,
        } = self.phase
        else {
            return;
        };
        let Some(spec) = self.spec.as_mut() else {
            return;
        };
        let sent = profile::body(&self.config.mid, self.unix_time)
            .map_err(|_overflow| SessionError::Profile)
            .and_then(|body| {
                let mut frame = heapless::Vec::<u8, 255>::new();
                SpecFrame::new(PROFILE_SEQ, &body)
                    .encode(&mut frame)
                    .map_err(|_too_long| SessionError::Profile)?;
                spec.send(&frame).map_err(SessionError::Spec)
            });
        match sent {
            Ok(()) => self.phase = Phase::Profile,
            Err(err) => self.finish(Outcome::Failed(err)),
        }
    }

    /// Ends the session with `outcome`.
    fn finish(&mut self, outcome: Outcome) {
        self.phase = Phase::Finished {
            flush_acks: matches!(outcome, Outcome::Measured { .. }),
        };
        self.push_event(Event::Finished(outcome));
    }

    /// Queues an event, dropping the oldest if full.
    fn push_event(&mut self, event: Event) {
        if self.events.is_full() {
            let _oldest: Option<Event> = self.events.pop_front();
        }
        let _queued: Result<(), Event> = self.events.push_back(event);
    }
}
