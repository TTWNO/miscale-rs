//! The encrypted spec channel.
//!
//! The app writes sealed messages to `0x001A` as parcels of kind `0x00`
//! (even when one fragment would do, as the official app does) and the
//! device acknowledges there. The device sends on `0x001B`, either as a
//! one-shot single frame or as a parcel, and the app acknowledges there,
//! before decrypting.

use core::fmt;

use mible_crypto::{CipherError, Role, SessionCipher};
use mible_transport::frame::Frame;
use mible_transport::rx::{ReceiveError, ReceiveProgress, Receiver, SinglePolicy};
use mible_transport::tx::{SendError, SendProgress, Sender};
use mible_transport::{Channel, Packet, Transmit};

use crate::codec::MAX_FRAME_LEN;

/// Parcel kind of every spec message.
pub const SPEC_KIND: u8 = 0x00;

/// Largest sealed message sent: a 255-byte frame plus counter and tag.
pub const MAX_SEALED_LEN: usize = MAX_FRAME_LEN + mible_crypto::session::OVERHEAD;

/// Largest message accepted from the peer, sealed or opened. Larger ones
/// are acknowledged and dropped.
pub const MAX_RECEIVED_LEN: usize = 512;

/// Largest sealed message the device side sends as a single frame.
const MAX_SINGLE_PAYLOAD: usize = 16;

/// What a notification did to a [`SpecChannel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpecProgress {
    /// Nothing for the caller.
    Idle,
    /// The message being sent was acknowledged.
    Sent,
    /// A message arrived and decrypted; read it with
    /// [`SpecChannel::message`].
    Received {
        /// The counter it was sealed under.
        counter: u16,
    },
    /// A message too large to hold was acknowledged and dropped.
    Discarded,
    /// The channel failed and will not progress further.
    Failed(SpecError),
}

/// Why the spec channel failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SpecError {
    /// A message is still being sent.
    Busy,
    /// The plaintext is too long to send.
    TooLong,
    /// Sealing or opening failed (for opening: wrong keys or tampering).
    Crypto(CipherError),
    /// Every counter value has been used; a new session is needed.
    CounterExhausted,
    /// Sending a parcel failed.
    Send(SendError),
    /// Receiving a parcel failed.
    Receive(ReceiveError),
}

impl fmt::Display for SpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Busy => f.write_str("a spec message is still being sent"),
            Self::TooLong => f.write_str("spec message too long"),
            Self::Crypto(err) => write!(f, "spec message crypto failed: {err}"),
            Self::CounterExhausted => f.write_str("spec message counter exhausted"),
            Self::Send(err) => write!(f, "sending a spec message failed: {err}"),
            Self::Receive(err) => write!(f, "receiving a spec message failed: {err}"),
        }
    }
}

impl core::error::Error for SpecError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Crypto(err) => Some(err),
            Self::Send(err) => Some(err),
            Self::Receive(err) => Some(err),
            Self::Busy | Self::TooLong | Self::CounterExhausted => None,
        }
    }
}

/// Sans-io encrypted spec channel for one end of a session.
pub struct SpecChannel {
    /// Which end this is.
    role: Role,
    /// Session cipher for this end.
    cipher: SessionCipher,
    /// Counter for the next message sealed; `None` once all are used.
    next_counter: Option<u16>,
    /// Code for the next single frame (device side only).
    next_single: u8,
    /// Sends parcels on the outgoing characteristic.
    sender: Sender<MAX_SEALED_LEN>,
    /// Receives on the incoming characteristic.
    receiver: Receiver<MAX_RECEIVED_LEN>,
    /// A single frame waiting to be written (device side only).
    single: Option<Packet>,
    /// The last message received, opened.
    message: heapless::Vec<u8, MAX_RECEIVED_LEN>,
    /// Set once the channel has failed.
    failed: Option<SpecError>,
}

impl fmt::Debug for SpecChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpecChannel")
            .field("role", &self.role)
            .field("next_counter", &self.next_counter)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl SpecChannel {
    /// Opens the channel for `role`. The app's first message uses counter 0,
    /// the device's counter 1, matching captures of the official app.
    #[must_use]
    pub const fn new(cipher: SessionCipher, role: Role) -> Self {
        Self {
            role,
            cipher,
            next_counter: Some(if matches!(role, Role::Device) { 1 } else { 0 }),
            next_single: 0,
            sender: Sender::new(),
            receiver: Receiver::new(SinglePolicy::AckAndDeliver),
            single: None,
            message: heapless::Vec::new(),
            failed: None,
        }
    }

    /// The characteristic this end writes messages to.
    #[must_use]
    pub const fn outgoing(&self) -> Channel {
        match self.role {
            Role::Device => Channel::SpecDown,
            Role::App => Channel::SpecUp,
        }
    }

    /// The characteristic this end receives messages on.
    #[must_use]
    pub const fn incoming(&self) -> Channel {
        match self.role {
            Role::Device => Channel::SpecUp,
            Role::App => Channel::SpecDown,
        }
    }

    /// Whether a message is still being sent: a parcel awaiting its
    /// acknowledgement, or a single frame not yet polled.
    #[must_use]
    pub const fn is_sending(&self) -> bool {
        self.sender.is_active() || self.single.is_some()
    }

    /// Seals `plaintext` and starts sending it.
    ///
    /// # Errors
    ///
    /// [`SpecError::Busy`] while a previous message is still being sent,
    /// [`SpecError::TooLong`] for a plaintext over 255 bytes,
    /// [`SpecError::CounterExhausted`] after 65 536 messages, and the
    /// failure that stopped the channel, if it has failed.
    pub fn send(&mut self, plaintext: &[u8]) -> Result<(), SpecError> {
        if let Some(err) = self.failed {
            return Err(err);
        }
        if self.is_sending() {
            return Err(SpecError::Busy);
        }
        if plaintext.len() > MAX_FRAME_LEN {
            return Err(SpecError::TooLong);
        }
        let counter = self.next_counter.ok_or(SpecError::CounterExhausted)?;
        let mut sealed = heapless::Vec::<u8, MAX_SEALED_LEN>::new();
        self.cipher
            .seal(counter, plaintext, &mut sealed)
            .map_err(SpecError::Crypto)?;
        // Never reuse a counter: it is half of the AES-CCM nonce.
        self.next_counter = counter.checked_add(1);
        if matches!(self.role, Role::Device) && sealed.len() <= MAX_SINGLE_PAYLOAD {
            let code = self.next_single;
            self.next_single = self.next_single.wrapping_add(1);
            self.single = Frame::Single {
                code,
                payload: &sealed,
            }
            .encode()
            .ok();
            return Ok(());
        }
        self.sender
            .start(SPEC_KIND, &sealed)
            .map_err(SpecError::Send)
    }

    /// Feeds a notification. Values on other characteristics are ignored.
    pub fn handle_notify(&mut self, channel: Channel, data: &[u8]) -> SpecProgress {
        if let Some(err) = self.failed {
            return SpecProgress::Failed(err);
        }
        let Some(frame) = Frame::parse(data) else {
            return SpecProgress::Idle;
        };
        if channel == self.outgoing() {
            return match self.sender.handle(&frame) {
                SendProgress::Complete => SpecProgress::Sent,
                SendProgress::Failed(err) => self.fail(SpecError::Send(err)),
                SendProgress::Ignored | SendProgress::Advanced | _ => SpecProgress::Idle,
            };
        }
        if channel != self.incoming() {
            return SpecProgress::Idle;
        }
        match self.receiver.handle(&frame) {
            ReceiveProgress::Complete { .. } => {
                match self.cipher.open(self.receiver.message(), &mut self.message) {
                    Ok(counter) => SpecProgress::Received { counter },
                    Err(err) => self.fail(SpecError::Crypto(err)),
                }
            }
            ReceiveProgress::Discarded { .. } => SpecProgress::Discarded,
            ReceiveProgress::Failed(err) => self.fail(SpecError::Receive(err)),
            ReceiveProgress::Ignored | ReceiveProgress::Advanced | _ => SpecProgress::Idle,
        }
    }

    /// The next write to perform, if any. Acknowledgements of received
    /// messages go first.
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        if self.failed.is_some() {
            return None;
        }
        if let Some(data) = self.receiver.poll_transmit() {
            return Some(Transmit::new(self.incoming(), data));
        }
        if let Some(data) = self.single.take() {
            return Some(Transmit::new(self.outgoing(), data));
        }
        self.sender
            .poll_transmit()
            .map(|data| Transmit::new(self.outgoing(), data))
    }

    /// The next acknowledgement of a received message, if any, and nothing
    /// else: for flushing acknowledgements once the caller is done sending.
    pub fn poll_acknowledgement(&mut self) -> Option<Transmit> {
        if self.failed.is_some() {
            return None;
        }
        self.receiver
            .poll_transmit()
            .map(|data| Transmit::new(self.incoming(), data))
    }

    /// The plaintext of the last message received.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Stops the channel with `err`.
    const fn fail(&mut self, err: SpecError) -> SpecProgress {
        self.failed = Some(err);
        SpecProgress::Failed(err)
    }
}
