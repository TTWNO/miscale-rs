//! Sending a parcel: announce, wait for "ready", send fragments, wait for
//! "success", resending any fragments the receiver reports lost.

use core::fmt;
use core::num::NonZeroU16;

use crate::frame::{AckStatus, Frame, lost_indices};
use crate::{FRAGMENT_PAYLOAD_LEN, Packet};

/// How many times the receiver may report lost fragments before giving up.
pub const MAX_RESEND_ROUNDS: u8 = 3;

/// Most lost indices remembered from one acknowledgement.
const MAX_PENDING_RESENDS: usize = 8;

/// Progress of a [`Sender`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Nothing to send.
    Idle,
    /// The announcement is waiting in `poll_transmit`.
    Announcing,
    /// Announced; waiting for [`AckStatus::Ready`].
    AwaitReady,
    /// Sending fragments; the next new one has this index.
    Sending(u16),
    /// Every fragment sent; waiting for [`AckStatus::Success`].
    AwaitSuccess,
    /// The receiver confirmed the whole parcel.
    Done,
    /// The transfer failed.
    Failed(SendError),
}

/// What a frame did to a [`Sender`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SendProgress {
    /// The frame was not for this transfer, or not expected now.
    Ignored,
    /// The transfer moved on; poll for more to transmit.
    Advanced,
    /// The receiver confirmed the whole parcel.
    Complete,
    /// The transfer failed; see the error.
    Failed(SendError),
}

/// Why a parcel transfer failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SendError {
    /// The payload does not fit the sender's buffer.
    TooLarge,
    /// The payload needs more fragments than a `u16` index can number.
    TooManyFragments,
    /// The receiver answered busy, timeout, cancel, or an unknown status.
    Refused(AckStatus),
    /// The receiver kept reporting lost fragments.
    TooManyResends,
    /// The receiver reported a fragment index outside the parcel.
    BadLostIndex(u16),
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::TooLarge => f.write_str("parcel payload does not fit the send buffer"),
            Self::TooManyFragments => f.write_str("parcel payload needs too many fragments"),
            Self::Refused(status) => write!(f, "receiver refused the parcel ({status:?})"),
            Self::TooManyResends => f.write_str("receiver kept reporting lost fragments"),
            Self::BadLostIndex(index) => write!(f, "receiver reported lost fragment {index}"),
        }
    }
}

impl core::error::Error for SendError {}

/// Sans-io parcel sender holding up to `N` payload bytes.
///
/// Fragments are generated lazily by [`Sender::poll_transmit`], so a long
/// parcel never needs a deep transmit queue.
#[derive(Debug, Clone)]
pub struct Sender<const N: usize> {
    /// Current progress.
    state: State,
    /// Parcel kind for the announcement.
    kind: u8,
    /// Total fragments in the parcel.
    total: u16,
    /// The payload being sent.
    payload: heapless::Vec<u8, N>,
    /// Lost fragments still to resend, oldest first.
    resend: heapless::Deque<u16, MAX_PENDING_RESENDS>,
    /// Lost reports received so far.
    resend_rounds: u8,
}

impl<const N: usize> Default for Sender<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Sender<N> {
    /// Creates an idle sender.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: State::Idle,
            kind: 0,
            total: 0,
            payload: heapless::Vec::new(),
            resend: heapless::Deque::new(),
            resend_rounds: 0,
        }
    }

    /// Starts sending `payload` as a parcel of `kind`, replacing any
    /// transfer in progress. The announcement is the next transmit.
    ///
    /// # Errors
    ///
    /// [`SendError::TooLarge`] if `payload` exceeds `N` bytes, and
    /// [`SendError::TooManyFragments`] if it needs more than `u16::MAX`
    /// fragments. The sender is left in the failed state.
    pub fn start(&mut self, kind: u8, payload: &[u8]) -> Result<(), SendError> {
        self.resend.clear();
        self.resend_rounds = 0;
        self.kind = kind;
        self.payload.clear();
        let fragments = payload.len().div_ceil(FRAGMENT_PAYLOAD_LEN);
        let result = self
            .payload
            .extend_from_slice(payload)
            .map_err(too_large)
            .and_then(|()| u16::try_from(fragments).map_err(too_many));
        match result {
            Ok(total) => {
                self.total = total;
                self.state = State::Announcing;
                Ok(())
            }
            Err(err) => {
                self.state = State::Failed(err);
                Err(err)
            }
        }
    }

    /// Whether the receiver confirmed the whole parcel.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.state, State::Done)
    }

    /// Whether a transfer is under way (started, not yet done or failed).
    #[must_use]
    pub const fn is_active(&self) -> bool {
        !matches!(self.state, State::Idle | State::Done | State::Failed(_))
    }

    /// Feeds a frame received on the parcel's characteristic.
    pub fn handle(&mut self, frame: &Frame<'_>) -> SendProgress {
        let Frame::Ack { status, detail } = *frame else {
            return SendProgress::Ignored;
        };
        match (self.state, status) {
            (State::AwaitReady, AckStatus::Ready) => {
                self.state = if self.total == 0 {
                    State::AwaitSuccess
                } else {
                    State::Sending(1)
                };
                SendProgress::Advanced
            }
            (State::Sending(_) | State::AwaitSuccess, AckStatus::Success) => {
                self.state = State::Done;
                SendProgress::Complete
            }
            (State::Sending(_) | State::AwaitSuccess, AckStatus::Lost) => {
                self.queue_resends(detail)
            }
            (
                State::AwaitReady | State::Sending(_) | State::AwaitSuccess,
                AckStatus::Busy | AckStatus::Timeout | AckStatus::Cancel | AckStatus::Unknown(_),
            ) => self.fail(SendError::Refused(status)),
            // Stray or duplicate acknowledgements are harmless.
            _ => SendProgress::Ignored,
        }
    }

    /// The next frame to write, if any.
    pub fn poll_transmit(&mut self) -> Option<Packet> {
        match self.state {
            State::Announcing => {
                self.state = State::AwaitReady;
                Frame::Announce {
                    kind: self.kind,
                    count: self.total,
                }
                .encode()
                .ok()
            }
            State::Sending(_) | State::AwaitSuccess => {
                if let Some(index) = self.resend.pop_front() {
                    return self.fragment(index);
                }
                let State::Sending(next) = self.state else {
                    return None;
                };
                self.state = match next.checked_add(1) {
                    Some(after) if after <= self.total => State::Sending(after),
                    _ => State::AwaitSuccess,
                };
                self.fragment(next)
            }
            State::Idle | State::AwaitReady | State::Done | State::Failed(_) => None,
        }
    }

    /// Encodes fragment `index` (1-based) of the payload.
    fn fragment(&self, index: u16) -> Option<Packet> {
        let start = usize::from(index.checked_sub(1)?).checked_mul(FRAGMENT_PAYLOAD_LEN)?;
        let end = start
            .checked_add(FRAGMENT_PAYLOAD_LEN)?
            .min(self.payload.len());
        let payload = self.payload.get(start..end)?;
        Frame::Fragment {
            index: NonZeroU16::new(index)?,
            payload,
        }
        .encode()
        .ok()
    }

    /// Records the indices of a [`AckStatus::Lost`] report for resending.
    fn queue_resends(&mut self, detail: &[u8]) -> SendProgress {
        self.resend_rounds = self.resend_rounds.saturating_add(1);
        if self.resend_rounds > MAX_RESEND_ROUNDS {
            return self.fail(SendError::TooManyResends);
        }
        for index in lost_indices(detail) {
            if index == 0 || index > self.total {
                return self.fail(SendError::BadLostIndex(index));
            }
            if !self.resend.iter().any(|&queued| queued == index)
                && self.resend.push_back(index).is_err()
            {
                break;
            }
        }
        SendProgress::Advanced
    }

    /// Enters the failed state.
    const fn fail(&mut self, err: SendError) -> SendProgress {
        self.state = State::Failed(err);
        SendProgress::Failed(err)
    }
}

/// Maps a buffer-capacity failure to [`SendError::TooLarge`].
const fn too_large(_: heapless::CapacityError) -> SendError {
    SendError::TooLarge
}

/// Maps a fragment-count overflow to [`SendError::TooManyFragments`].
const fn too_many(_: core::num::TryFromIntError) -> SendError {
    SendError::TooManyFragments
}
