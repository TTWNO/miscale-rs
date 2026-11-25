//! Sans-io weigh-in with a Xiaomi Smart Scale S200 (MJTZC02YM).
//!
//! A [`WeighSession`] logs in with the device token, opens the encrypted
//! spec channel, says hello, sends the user profile, and then turns what the
//! scale streams into [`Event::Live`] readings and one
//! [`Event::Finished`] carrying the [`Outcome`].
//!
//! # Driving a session
//!
//! The session performs no I/O and keeps no clock. The caller:
//!
//! 1. subscribes to notifications on every [`Channel`](mible_transport::Channel),
//! 2. feeds each one, in order, to [`WeighSession::handle_notify`],
//! 3. after every call, writes everything [`WeighSession::poll_transmit`]
//!    returns (write-without-response, in order) and handles everything
//!    [`WeighSession::poll_event`] returns,
//! 4. calls [`WeighSession::handle_timeout`] when the instant from
//!    [`WeighSession::poll_timeout`] passes,
//! 5. calls [`WeighSession::abort`] if the link drops,
//!
//! until [`Event::Finished`] arrives, which is always the last event. After
//! a measurement, keep draining [`WeighSession::poll_transmit`] once more:
//! it still carries the acknowledgement of the scale's last message.
//!
//! # Advertisements
//!
//! The scale also broadcasts each final weigh-in, encrypted under its beacon
//! key; [`beacon::read`] decodes its advertisements.
#![no_std]

pub mod beacon;
pub mod profile;
pub mod session;
pub mod weight;

pub use profile::Mid;
pub use session::{Config, Event, Instant, Outcome, SessionError, Source, Stage, WeighSession};
pub use weight::{FinalReading, Reading, Weight};
