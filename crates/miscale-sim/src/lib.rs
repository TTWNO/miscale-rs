//! A simulated Xiaomi Smart Scale S200, device side, for tests.
//!
//! [`SimScale`] answers a login with its token, echoes the hello, accepts
//! the profile, then plays a script of [`Step`]s. It speaks the same wire
//! format as the real scale as far as it is known: parcels and single frames
//! on the same characteristics, the same counters and sequence numbers.
//!
//! Like the client, it is sans-io: feed it the client's writes with
//! [`SimScale::handle_write`] and deliver what [`SimScale::poll_notify`]
//! returns to the client as notifications.
#![no_std]

use core::fmt;

use mible_auth::login::{command, kind};
use mible_crypto::login::Random;
use mible_crypto::{LoginKeys, Role, SessionCipher, Token};
use mible_spec::codec::push_string;
use mible_spec::{SpecChannel, SpecFrame, SpecProgress};
use mible_transport::frame::Frame;
use mible_transport::rx::{ReceiveProgress, Receiver, SinglePolicy};
use mible_transport::tx::{SendProgress, Sender};
use mible_transport::{Channel, Packet, Transmit};

/// Most script steps a simulator holds.
pub const MAX_STEPS: usize = 32;

/// Largest profile frame remembered.
const MAX_PROFILE: usize = 255;

/// Sequence number of the device's first streamed frame.
const FIRST_DEVICE_SEQ: u16 = 7;

/// The scale's clock (seconds since the Unix epoch) unless a test sets it.
pub const DEFAULT_DEVICE_TIME: u32 = 1_764_000_000;

/// One thing the simulated scale sends after the profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Step {
    /// A live reading, in hundredths of a kilogram.
    Live(u16),
    /// The final reading, in hundredths of a kilogram.
    Final(u32),
    /// An arbitrary plaintext frame (e.g. device info the client ignores).
    Raw(&'static [u8]),
}

/// How the simulated scale behaves.
#[derive(Clone)]
#[non_exhaustive]
pub struct SimConfig {
    /// The token the scale was bound with.
    pub token: Token,
    /// The scale's login random.
    pub dev_rand: Random,
    /// Whether to echo the hello (a scale that does not stalls the client).
    pub echo_hello: bool,
    /// Whether to refuse every login with `23 00 00 00`.
    pub refuse_login: bool,
    /// The timestamp the scale writes into final readings.
    pub device_time: u32,
}

impl fmt::Debug for SimConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SimConfig")
            .field("echo_hello", &self.echo_hello)
            .field("refuse_login", &self.refuse_login)
            .field("device_time", &self.device_time)
            .finish_non_exhaustive()
    }
}

impl SimConfig {
    /// A well-behaved scale bound with `token`.
    #[must_use]
    pub const fn new(token: Token, dev_rand: Random) -> Self {
        Self {
            token,
            dev_rand,
            echo_hello: true,
            refuse_login: false,
            device_time: DEFAULT_DEVICE_TIME,
        }
    }
}

/// Progress of the simulated scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SimPhase {
    /// Waiting for the login command.
    AwaitLogin,
    /// Receiving the app random.
    AwaitAppRandom,
    /// Sending the device random.
    SendRandom,
    /// Sending the device proof.
    SendProof,
    /// Receiving the app proof.
    AwaitAppProof,
    /// Logged in; serving the spec channel.
    Spec,
    /// The login failed.
    Failed,
}

/// A simulated S200.
pub struct SimScale {
    /// Behaviour.
    config: SimConfig,
    /// Progress.
    phase: SimPhase,
    /// The app's random, once received.
    app_rand: Random,
    /// Session keys, once derived.
    keys: Option<LoginKeys>,
    /// Receives login parcels.
    login_rx: Receiver<64>,
    /// Sends login parcels.
    login_tx: Sender<64>,
    /// A control-channel confirmation waiting to be sent.
    control: Option<[u8; 4]>,
    /// The spec channel, once logged in.
    spec: Option<SpecChannel>,
    /// Steps still to send.
    script: heapless::Deque<Step, MAX_STEPS>,
    /// Whether the profile arrived (streaming starts then).
    streaming: bool,
    /// Sequence number of the next streamed frame.
    seq: u16,
    /// The last profile frame received.
    profile: heapless::Vec<u8, MAX_PROFILE>,
    /// Single frames sent and not yet acknowledged by the client.
    unacked_singles: usize,
}

impl fmt::Debug for SimScale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SimScale")
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl SimScale {
    /// A simulated scale with `config` that will play `script`.
    ///
    /// Steps beyond [`MAX_STEPS`] are dropped.
    #[must_use]
    pub fn new(config: SimConfig, script: &[Step]) -> Self {
        let mut steps = heapless::Deque::new();
        for &step in script {
            if steps.push_back(step).is_err() {
                break;
            }
        }
        Self {
            config,
            phase: SimPhase::AwaitLogin,
            app_rand: [0; 16],
            keys: None,
            login_rx: Receiver::new(SinglePolicy::Ignore),
            login_tx: Sender::new(),
            control: None,
            spec: None,
            script: steps,
            streaming: false,
            seq: FIRST_DEVICE_SEQ,
            profile: heapless::Vec::new(),
            unacked_singles: 0,
        }
    }

    /// Where the simulated scale stands.
    #[must_use]
    pub const fn phase(&self) -> SimPhase {
        self.phase
    }

    /// The last profile frame the client sent (plaintext), if any.
    #[must_use]
    pub fn profile(&self) -> &[u8] {
        &self.profile
    }

    /// Messages the scale sent on the spec channel that the client has not
    /// acknowledged yet (a parcel in flight counts once).
    #[must_use]
    pub fn unacknowledged(&self) -> usize {
        let parcel = self.spec.as_ref().is_some_and(SpecChannel::is_sending);
        self.unacked_singles.saturating_add(usize::from(parcel))
    }

    /// Feeds a write the client made.
    pub fn handle_write(&mut self, channel: Channel, data: &[u8]) {
        if channel == Channel::SpecDown
            && matches!(Frame::parse(data), Some(Frame::SingleAck { .. }))
        {
            self.unacked_singles = self.unacked_singles.saturating_sub(1);
        }
        match (self.phase, channel) {
            (SimPhase::AwaitLogin, Channel::Control) if data == command::LOGIN => {
                self.phase = SimPhase::AwaitAppRandom;
            }
            (SimPhase::Spec, Channel::SpecUp | Channel::SpecDown) => self.on_spec(channel, data),
            (_, Channel::Auth) => {
                if let Some(frame) = Frame::parse(data) {
                    self.on_auth(&frame);
                }
            }
            _ => {}
        }
    }

    /// The next notification to deliver to the client, if any.
    pub fn poll_notify(&mut self) -> Option<Transmit> {
        // Acknowledge the client's parcel before confirming the login: the
        // real scale's order (the prototype waits for the ack first).
        if let Some(data) = self.login_rx.poll_transmit() {
            return Some(Transmit::new(Channel::Auth, data));
        }
        if let Some(value) = self.control.take() {
            return Packet::from_slice(&value)
                .ok()
                .map(|data| Transmit::new(Channel::Control, data));
        }
        if let Some(data) = self.login_tx.poll_transmit() {
            return Some(Transmit::new(Channel::Auth, data));
        }
        let tx = self
            .spec
            .as_mut()
            .and_then(SpecChannel::poll_transmit)
            .or_else(|| {
                self.send_next_step();
                self.spec.as_mut().and_then(SpecChannel::poll_transmit)
            })?;
        if tx.channel == Channel::SpecDown
            && matches!(Frame::parse(&tx.data), Some(Frame::Single { .. }))
        {
            self.unacked_singles = self.unacked_singles.saturating_add(1);
        }
        Some(tx)
    }

    /// Handles a login frame on the auth channel.
    fn on_auth(&mut self, frame: &Frame<'_>) {
        if self.login_tx.handle(frame) == SendProgress::Complete {
            match self.phase {
                SimPhase::SendRandom => self.start_proof(),
                SimPhase::SendProof => self.phase = SimPhase::AwaitAppProof,
                SimPhase::AwaitLogin
                | SimPhase::AwaitAppRandom
                | SimPhase::AwaitAppProof
                | SimPhase::Spec
                | SimPhase::Failed => {}
            }
        }
        let ReceiveProgress::Complete { kind, .. } = self.login_rx.handle(frame) else {
            return;
        };
        match (self.phase, kind) {
            (SimPhase::AwaitAppRandom, kind::APP_RANDOM) => self.on_app_random(),
            (SimPhase::AwaitAppProof, kind::APP_PROOF) => self.on_app_proof(),
            _ => {}
        }
    }

    /// The app random arrived: derive keys, send the device random.
    fn on_app_random(&mut self) {
        let Ok(app_rand) = Random::try_from(self.login_rx.message()) else {
            self.phase = SimPhase::Failed;
            return;
        };
        self.app_rand = app_rand;
        self.keys = Some(LoginKeys::derive(
            &self.config.token,
            &self.app_rand,
            &self.config.dev_rand,
        ));
        self.phase = match self
            .login_tx
            .start(kind::DEVICE_RANDOM, &self.config.dev_rand)
        {
            Ok(()) => SimPhase::SendRandom,
            Err(_) => SimPhase::Failed,
        };
    }

    /// The device random was delivered: send the device proof.
    fn start_proof(&mut self) {
        let Some(keys) = &self.keys else {
            self.phase = SimPhase::Failed;
            return;
        };
        let proof = keys.device_proof(&self.app_rand, &self.config.dev_rand);
        self.phase = match self.login_tx.start(kind::DEVICE_PROOF, &proof) {
            Ok(()) => SimPhase::SendProof,
            Err(_) => SimPhase::Failed,
        };
    }

    /// The app proof arrived: confirm or refuse.
    fn on_app_proof(&mut self) {
        let accepted = !self.config.refuse_login
            && self.keys.as_ref().is_some_and(|keys| {
                keys.verify_app_proof(
                    &self.app_rand,
                    &self.config.dev_rand,
                    self.login_rx.message(),
                )
                .is_ok()
            });
        if let (true, Some(keys)) = (accepted, &self.keys) {
            self.control = Some(command::LOGIN_OK);
            let cipher = SessionCipher::new(keys, Role::Device);
            self.spec = Some(SpecChannel::new(cipher, Role::Device));
            self.phase = SimPhase::Spec;
        } else {
            self.control = Some(command::LOGIN_REFUSED);
            self.phase = SimPhase::Failed;
        }
    }

    /// Handles a write on a spec characteristic.
    fn on_spec(&mut self, channel: Channel, data: &[u8]) {
        let Some(spec) = self.spec.as_mut() else {
            return;
        };
        if !matches!(
            spec.handle_notify(channel, data),
            SpecProgress::Received { .. }
        ) {
            return;
        }
        let message = spec.message();
        let Some(frame) = SpecFrame::parse(message) else {
            return;
        };
        if frame.seq == HELLO_SEQ && frame.body == HELLO_BODY {
            if self.config.echo_hello {
                let mut echo = heapless::Vec::<u8, 8>::new();
                if echo.extend_from_slice(message).is_ok() {
                    let _echoed: Result<(), _> = spec.send(&echo);
                }
            }
        } else if frame.body.starts_with(&PROFILE_PREFIX) {
            self.profile.clear();
            let _stored: Result<(), _> = self.profile.extend_from_slice(message);
            self.streaming = true;
        }
    }

    /// Sends the next script step if the channel is free.
    fn send_next_step(&mut self) {
        if !self.streaming {
            return;
        }
        let Some(spec) = self.spec.as_mut() else {
            return;
        };
        if spec.is_sending() {
            return;
        }
        let Some(step) = self.script.pop_front() else {
            return;
        };
        let mut frame = heapless::Vec::<u8, 255>::new();
        if encode_step(step, self.seq, self.config.device_time, &mut frame).is_some() {
            self.seq = self.seq.wrapping_add(1);
            let _sent: Result<(), _> = spec.send(&frame);
        }
    }
}

/// Encodes a script step as a plaintext spec frame.
fn encode_step(
    step: Step,
    seq: u16,
    device_time: u32,
    out: &mut heapless::Vec<u8, 255>,
) -> Option<()> {
    let mut body = heapless::Vec::<u8, 251>::new();
    match step {
        Step::Live(centi) => {
            // 17 bytes the client ignores, then the live property: a 25-byte
            // frame (`19 20 …`), like the real scale's.
            body.extend_from_slice(&[0x07, 0x02, 0x01, 0x01, 0x05, 0x00, 0x01])
                .ok()?;
            body.extend_from_slice(&[0; 10]).ok()?;
            let [lo, hi] = centi.to_le_bytes();
            body.extend_from_slice(&[0x02, 0x30, lo, hi]).ok()?;
        }
        Step::Final(centi) => {
            let mut text = heapless::String::<48>::new();
            fmt::write(&mut text, format_args!("0,0,{centi},2,{device_time}")).ok()?;
            body.extend_from_slice(&[0x09, 0x02]).ok()?;
            push_string(&mut body, text.as_bytes()).ok()?;
        }
        Step::Raw(bytes) => return out.extend_from_slice(bytes).ok(),
    }
    SpecFrame::new(seq, &body).encode(out).ok()
}

/// Sequence number of the client's hello (mirrors `miscale`, which depends
/// on this crate only for its tests).
const HELLO_SEQ: u16 = 2;

/// Body of the client's hello.
const HELLO_BODY: [u8; 1] = [0xF0];

/// First bytes of the client's profile body.
const PROFILE_PREFIX: [u8; 6] = [0x05, 0x07, 0x01, 0x01, 0x01, 0x00];
