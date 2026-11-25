//! The login state machine.

use core::fmt;

use mible_crypto::login::{PROOF_LEN, RANDOM_LEN, Random};
use mible_crypto::{LoginKeys, Role, SessionCipher, Token};
use mible_transport::frame::Frame;
use mible_transport::rx::{ReceiveError, ReceiveProgress, Receiver, SinglePolicy};
use mible_transport::tx::{SendError, SendProgress, Sender};
use mible_transport::{Channel, Packet, Transmit};

/// Parcel kinds exchanged during login.
pub mod kind {
    /// App → device: the app's proof.
    pub const APP_PROOF: u8 = 0x0A;
    /// App → device: the app's random.
    pub const APP_RANDOM: u8 = 0x0B;
    /// Device → app: the device's proof.
    pub const DEVICE_PROOF: u8 = 0x0C;
    /// Device → app: the device's random.
    pub const DEVICE_RANDOM: u8 = 0x0D;
}

/// Four-byte values on the control channel.
pub mod command {
    /// App → device: start a login.
    pub const LOGIN: [u8; 4] = [0x24, 0, 0, 0];
    /// Device → app: login succeeded.
    pub const LOGIN_OK: [u8; 4] = [0x21, 0, 0, 0];
    /// Device → app: login refused.
    pub const LOGIN_REFUSED: [u8; 4] = [0x23, 0, 0, 0];
    /// First bytes of the device's authentication error codes (`Ex 00 00 00`).
    pub const AUTH_ERRORS: core::ops::RangeInclusive<u8> = 0xE0..=0xE3;
}

/// Largest parcel exchanged during login (the 32-byte proofs), with room.
const PARCEL_CAPACITY: usize = 64;

/// Progress of a [`Login`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Sending the app random.
    SendRandom,
    /// Waiting for the device random.
    AwaitDeviceRandom,
    /// Waiting for the device proof.
    AwaitDeviceProof,
    /// Sending the app proof.
    SendProof,
    /// Waiting for the login confirmation.
    AwaitConfirm,
    /// Logged in.
    Done,
    /// Failed; see the error.
    Failed(LoginError),
}

/// Where a [`Login`] stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LoginStatus {
    /// Still exchanging messages.
    InProgress,
    /// Logged in; take the cipher with [`Login::take_session_cipher`].
    Authenticated,
    /// The login failed and will not progress further.
    Failed(LoginError),
}

/// Why a login failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LoginError {
    /// The device sent an authentication error code (`0xE0`–`0xE3`).
    DeviceError(u8),
    /// The device refused the login (`23 00 00 00`).
    Refused,
    /// The device's proof does not match: the token is wrong.
    ProofMismatch,
    /// The device sent a parcel other than the one expected next.
    UnexpectedParcel {
        /// Kind expected.
        expected: u8,
        /// Kind received.
        got: u8,
    },
    /// A parcel had the wrong length.
    BadLength {
        /// Parcel kind.
        kind: u8,
        /// Length received (saturated at the receive buffer size).
        len: usize,
    },
    /// Sending a parcel failed.
    Send(SendError),
    /// Receiving a parcel failed.
    Receive(ReceiveError),
}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::DeviceError(code) => {
                write!(f, "device reported authentication error {code:#04x}")
            }
            Self::Refused => f.write_str("device refused the login"),
            Self::ProofMismatch => f.write_str("device proof does not match (wrong token?)"),
            Self::UnexpectedParcel { expected, got } => {
                write!(f, "expected parcel {expected:#04x}, device sent {got:#04x}")
            }
            Self::BadLength { kind, len } => write!(f, "parcel {kind:#04x} has length {len}"),
            Self::Send(err) => write!(f, "sending a parcel failed: {err}"),
            Self::Receive(err) => write!(f, "receiving a parcel failed: {err}"),
        }
    }
}

impl core::error::Error for LoginError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Send(err) => Some(err),
            Self::Receive(err) => Some(err),
            Self::DeviceError(_)
            | Self::Refused
            | Self::ProofMismatch
            | Self::UnexpectedParcel { .. }
            | Self::BadLength { .. } => None,
        }
    }
}

/// Sans-io login for the app side.
///
/// Created with the token and a fresh 16-byte random from a secure source.
/// The first transmits are the login command and the random's
/// announcement.
pub struct Login {
    /// Current progress.
    state: State,
    /// The device token until the keys are derived (zeroised on drop).
    token: Option<Token>,
    /// This side's random.
    app_rand: Random,
    /// The device's random, once received.
    dev_rand: Random,
    /// Session keys, once derived (zeroised on drop).
    keys: Option<LoginKeys>,
    /// Parcel sender on the auth channel.
    sender: Sender<PARCEL_CAPACITY>,
    /// Parcel receiver on the auth channel.
    receiver: Receiver<PARCEL_CAPACITY>,
    /// Control-channel command waiting to be written.
    command: Option<[u8; 4]>,
}

impl fmt::Debug for Login {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Login")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl Login {
    /// Starts a login with `token` and a fresh random `app_rand`.
    #[must_use]
    pub fn new(token: &Token, app_rand: Random) -> Self {
        let mut sender = Sender::new();
        // A 16-byte random always fits the 64-byte buffer.
        let state = match sender.start(kind::APP_RANDOM, &app_rand) {
            Ok(()) => State::SendRandom,
            Err(err) => State::Failed(LoginError::Send(err)),
        };
        Self {
            state,
            token: Some(token.clone()),
            app_rand,
            dev_rand: [0; RANDOM_LEN],
            keys: None,
            sender,
            receiver: Receiver::new(SinglePolicy::Ignore),
            command: Some(command::LOGIN),
        }
    }

    /// Where the login stands.
    #[must_use]
    pub const fn status(&self) -> LoginStatus {
        match self.state {
            State::Done => LoginStatus::Authenticated,
            State::Failed(err) => LoginStatus::Failed(err),
            State::SendRandom
            | State::AwaitDeviceRandom
            | State::AwaitDeviceProof
            | State::SendProof
            | State::AwaitConfirm => LoginStatus::InProgress,
        }
    }

    /// Hands out the session cipher once [`LoginStatus::Authenticated`],
    /// exactly once: the keys move into it and leave the login. (Two ciphers
    /// from one login would reuse AES-CCM nonces.)
    pub fn take_session_cipher(&mut self) -> Option<SessionCipher> {
        if !matches!(self.state, State::Done) {
            return None;
        }
        self.keys
            .take()
            .map(|keys| SessionCipher::new(&keys, Role::App))
    }

    /// Feeds a notification received on `channel`.
    ///
    /// Values on channels the login does not use, and frames that do not
    /// fit the current step (stray or duplicate acknowledgements, for
    /// example), are ignored. After the login ends, all input is ignored.
    pub fn handle_notify(&mut self, channel: Channel, data: &[u8]) -> LoginStatus {
        if self.is_finished() {
            return self.status();
        }
        match channel {
            Channel::Control => self.on_control(data),
            Channel::Auth => {
                if let Some(frame) = Frame::parse(data) {
                    self.on_auth(&frame);
                }
            }
            Channel::SpecUp | Channel::SpecDown | _ => {}
        }
        self.status()
    }

    /// The next write to perform, if any.
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        if self.is_finished() {
            return None;
        }
        if let Some(command) = self.command.take() {
            return Packet::from_slice(&command)
                .ok()
                .map(|data| Transmit::new(Channel::Control, data));
        }
        // Acknowledge what we received before sending anything new, as the
        // official app does.
        if let Some(data) = self.receiver.poll_transmit() {
            return Some(Transmit::new(Channel::Auth, data));
        }
        self.sender
            .poll_transmit()
            .map(|data| Transmit::new(Channel::Auth, data))
    }

    /// Whether the login has ended, successfully or not.
    const fn is_finished(&self) -> bool {
        matches!(self.state, State::Done | State::Failed(_))
    }

    /// Handles a value on the control channel.
    fn on_control(&mut self, data: &[u8]) {
        let Ok(value) = <[u8; 4]>::try_from(data) else {
            return;
        };
        match value {
            command::LOGIN_OK if matches!(self.state, State::SendProof | State::AwaitConfirm) => {
                self.state = State::Done;
            }
            command::LOGIN_REFUSED => self.fail(LoginError::Refused),
            [code, 0, 0, 0] if command::AUTH_ERRORS.contains(&code) => {
                self.fail(LoginError::DeviceError(code));
            }
            _ => {}
        }
    }

    /// Handles a frame on the auth channel.
    fn on_auth(&mut self, frame: &Frame<'_>) {
        match self.sender.handle(frame) {
            SendProgress::Complete => self.on_sent(),
            SendProgress::Failed(err) => return self.fail(LoginError::Send(err)),
            SendProgress::Ignored | SendProgress::Advanced | _ => {}
        }
        if !matches!(
            self.state,
            State::AwaitDeviceRandom | State::AwaitDeviceProof
        ) {
            return;
        }
        match self.receiver.handle(frame) {
            ReceiveProgress::Complete { kind, .. } => self.on_parcel(kind),
            ReceiveProgress::Discarded { kind } => {
                self.fail(LoginError::BadLength {
                    kind,
                    len: PARCEL_CAPACITY,
                });
            }
            ReceiveProgress::Failed(err) => self.fail(LoginError::Receive(err)),
            ReceiveProgress::Ignored | ReceiveProgress::Advanced | _ => {}
        }
    }

    /// The parcel being sent was confirmed.
    const fn on_sent(&mut self) {
        match self.state {
            State::SendRandom => self.state = State::AwaitDeviceRandom,
            State::SendProof => self.state = State::AwaitConfirm,
            State::AwaitDeviceRandom
            | State::AwaitDeviceProof
            | State::AwaitConfirm
            | State::Done
            | State::Failed(_) => {}
        }
    }

    /// A whole parcel arrived.
    fn on_parcel(&mut self, kind: u8) {
        let expected = if matches!(self.state, State::AwaitDeviceRandom) {
            kind::DEVICE_RANDOM
        } else {
            kind::DEVICE_PROOF
        };
        if kind != expected {
            return self.fail(LoginError::UnexpectedParcel {
                expected,
                got: kind,
            });
        }
        let message = self.receiver.message();
        let len = message.len();
        if kind == kind::DEVICE_RANDOM {
            let Ok(dev_rand) = Random::try_from(message) else {
                return self.fail(LoginError::BadLength { kind, len });
            };
            self.dev_rand = dev_rand;
            // The token is not needed again; drop (and zeroise) it now.
            let Some(token) = self.token.take() else {
                return self.fail(LoginError::ProofMismatch);
            };
            self.keys = Some(LoginKeys::derive(&token, &self.app_rand, &self.dev_rand));
            self.state = State::AwaitDeviceProof;
            return;
        }
        let verified = len == PROOF_LEN
            && self.keys.as_ref().is_some_and(|keys| {
                keys.verify_device_proof(&self.app_rand, &self.dev_rand, message)
                    .is_ok()
            });
        if len != PROOF_LEN {
            return self.fail(LoginError::BadLength { kind, len });
        }
        let Some(keys) = self.keys.as_ref().filter(|_| verified) else {
            return self.fail(LoginError::ProofMismatch);
        };
        let proof = keys.app_proof(&self.app_rand, &self.dev_rand);
        match self.sender.start(kind::APP_PROOF, &proof) {
            Ok(()) => self.state = State::SendProof,
            Err(err) => self.fail(LoginError::Send(err)),
        }
    }

    /// Ends the login with `err`, dropping anything left to send.
    fn fail(&mut self, err: LoginError) {
        self.state = State::Failed(err);
        self.command = None;
        self.keys = None;
        self.token = None;
    }
}
