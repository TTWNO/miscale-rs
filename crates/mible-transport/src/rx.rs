//! Receiving a parcel: answer an announcement with "ready", collect the
//! fragments in order, answer "success", deliver the payload.

use core::fmt;

use crate::Packet;
use crate::frame::{AckStatus, Frame};

/// Most control frames waiting to be written at once. The receiver answers
/// at most one frame per input, so two leaves room for a restart.
const MAX_PENDING: usize = 2;

/// What to do with a [`Frame::Single`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SinglePolicy {
    /// Ignore it, sending nothing (the login channel).
    Ignore,
    /// Acknowledge it, then deliver its payload (the spec channel).
    AckAndDeliver,
}

/// How a completed message arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Delivery {
    /// As an announced, fragmented parcel.
    Parcel,
    /// As a one-shot [`Frame::Single`].
    Single,
}

/// Progress of a [`Receiver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// No message in flight.
    Idle,
    /// Collecting a parcel into the buffer.
    Collecting {
        /// Announced kind.
        kind: u8,
        /// Announced fragment count.
        count: u16,
        /// Index of the next expected fragment.
        next: u16,
    },
    /// Swallowing a parcel that does not fit the buffer.
    Discarding {
        /// Announced kind.
        kind: u8,
        /// Announced fragment count.
        count: u16,
        /// Index of the next expected fragment.
        next: u16,
    },
}

/// What a frame did to a [`Receiver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReceiveProgress {
    /// The frame was not for this receiver, or not expected now.
    Ignored,
    /// The transfer moved on; poll for transmits.
    Advanced,
    /// A whole message arrived; read it with [`Receiver::message`].
    Complete {
        /// Parcel kind, or the code of a [`Frame::Single`].
        kind: u8,
        /// How it arrived.
        delivery: Delivery,
    },
    /// A parcel larger than the buffer was acknowledged and dropped.
    Discarded {
        /// Announced kind.
        kind: u8,
    },
    /// The parcel cannot be completed; see the error.
    Failed(ReceiveError),
}

/// Why a parcel could not be received.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ReceiveError {
    /// A fragment arrived out of order (notifications are ordered, so a
    /// fragment went missing).
    Gap {
        /// Index expected next.
        expected: u16,
        /// Index received.
        got: u16,
    },
}

impl fmt::Display for ReceiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Gap { expected, got } => {
                write!(f, "expected fragment {expected}, received fragment {got}")
            }
        }
    }
}

impl core::error::Error for ReceiveError {}

/// Sans-io parcel receiver holding up to `N` payload bytes.
///
/// Fragments may be any length (devices fragment to their negotiated MTU).
/// A repeat of the previous fragment is ignored; any other out-of-order
/// fragment fails the parcel. A parcel that overflows the buffer is still
/// acknowledged, then reported as [`ReceiveProgress::Discarded`].
#[derive(Debug, Clone)]
pub struct Receiver<const N: usize> {
    /// Current progress.
    state: State,
    /// What to do with one-shot messages.
    single: SinglePolicy,
    /// The message being collected, or the last one completed.
    buffer: heapless::Vec<u8, N>,
    /// Control frames waiting to be written.
    pending: heapless::Deque<Packet, MAX_PENDING>,
}

impl<const N: usize> Receiver<N> {
    /// Creates an idle receiver.
    #[must_use]
    pub const fn new(single: SinglePolicy) -> Self {
        Self {
            state: State::Idle,
            single,
            buffer: heapless::Vec::new(),
            pending: heapless::Deque::new(),
        }
    }

    /// The message delivered by the last [`ReceiveProgress::Complete`].
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.buffer
    }

    /// Feeds a frame received on the parcel's characteristic.
    pub fn handle(&mut self, frame: &Frame<'_>) -> ReceiveProgress {
        match *frame {
            Frame::Announce { kind, count } => self.on_announce(kind, count),
            Frame::Fragment { index, payload } => self.on_fragment(index.get(), payload),
            Frame::Single { code, payload } => self.on_single(code, payload),
            Frame::Ack { .. } | Frame::SingleAck { .. } | Frame::Unknown { .. } => {
                ReceiveProgress::Ignored
            }
        }
    }

    /// The next control frame to write, if any.
    pub fn poll_transmit(&mut self) -> Option<Packet> {
        self.pending.pop_front()
    }

    /// Starts collecting a parcel (restarting if one was in flight).
    fn on_announce(&mut self, kind: u8, count: u16) -> ReceiveProgress {
        self.buffer.clear();
        self.queue(Frame::Ack {
            status: AckStatus::Ready,
            detail: &[],
        });
        if count == 0 {
            self.state = State::Idle;
            self.queue(Frame::Ack {
                status: AckStatus::Success,
                detail: &[],
            });
            return ReceiveProgress::Complete {
                kind,
                delivery: Delivery::Parcel,
            };
        }
        self.state = State::Collecting {
            kind,
            count,
            next: 1,
        };
        ReceiveProgress::Advanced
    }

    /// Takes the next fragment of the parcel in flight.
    fn on_fragment(&mut self, index: u16, payload: &[u8]) -> ReceiveProgress {
        let (kind, count, next, collecting) = match self.state {
            State::Idle => return ReceiveProgress::Ignored,
            State::Collecting { kind, count, next } => (kind, count, next, true),
            State::Discarding { kind, count, next } => (kind, count, next, false),
        };
        if index != next {
            if next.checked_sub(1) == Some(index) {
                return ReceiveProgress::Ignored; // repeat of the previous fragment
            }
            self.state = State::Idle;
            self.buffer.clear();
            return ReceiveProgress::Failed(ReceiveError::Gap {
                expected: next,
                got: index,
            });
        }
        let collecting = collecting && self.buffer.extend_from_slice(payload).is_ok();
        if index < count {
            let following = index.saturating_add(1);
            self.state = if collecting {
                State::Collecting {
                    kind,
                    count,
                    next: following,
                }
            } else {
                self.buffer.clear();
                State::Discarding {
                    kind,
                    count,
                    next: following,
                }
            };
            return ReceiveProgress::Advanced;
        }
        self.state = State::Idle;
        self.queue(Frame::Ack {
            status: AckStatus::Success,
            detail: &[],
        });
        if collecting {
            ReceiveProgress::Complete {
                kind,
                delivery: Delivery::Parcel,
            }
        } else {
            self.buffer.clear();
            ReceiveProgress::Discarded { kind }
        }
    }

    /// Handles a one-shot message according to the [`SinglePolicy`].
    fn on_single(&mut self, code: u8, payload: &[u8]) -> ReceiveProgress {
        match self.single {
            SinglePolicy::Ignore => ReceiveProgress::Ignored,
            SinglePolicy::AckAndDeliver => {
                self.queue(Frame::SingleAck { code });
                self.state = State::Idle;
                self.buffer.clear();
                if self.buffer.extend_from_slice(payload).is_err() {
                    self.buffer.clear();
                    return ReceiveProgress::Discarded { kind: code };
                }
                ReceiveProgress::Complete {
                    kind: code,
                    delivery: Delivery::Single,
                }
            }
        }
    }

    /// Queues a control frame, dropping the oldest if the queue is full.
    fn queue(&mut self, frame: Frame<'_>) {
        if let Ok(packet) = frame.encode() {
            if self.pending.is_full() {
                let _dropped: Option<Packet> = self.pending.pop_front();
            }
            let _queued: Result<(), Packet> = self.pending.push_back(packet);
        }
    }
}
