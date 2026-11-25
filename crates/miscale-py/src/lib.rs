//! Python bindings for the [`miscale`] weigh session and advertisements.
//!
//! The module performs no I/O: Python feeds notifications and advertisements
//! in and writes out what the session asks for. Secrets (the token, the
//! beacon key, session keys) never cross into Python except as the strings
//! the caller already holds; errors never echo them.

use mible_auth::LoginError;
use mible_beacon::{Advertisement, DecryptError};
use mible_crypto::{BeaconCipher, BeaconKey, Token};
use mible_transport::Channel;
use miscale::beacon::BeaconError;
use miscale::{Config, Event as CoreEvent, Instant, Mid, Outcome, SessionError, Source};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// The Xiaomi service's 16-bit UUID.
const SERVICE_UUID16: u16 = 0xFE95;

/// Parses a token, mapping errors to `ValueError` without echoing input.
fn parse_token(token_hex: &str) -> PyResult<Token> {
    Token::from_hex(token_hex).map_err(|err| PyValueError::new_err(err.to_string()))
}

/// Parses a beacon key, mapping errors to `ValueError` without echoing input.
fn parse_beacon_key(beacon_key_hex: &str) -> PyResult<BeaconKey> {
    BeaconKey::from_hex(beacon_key_hex).map_err(|err| PyValueError::new_err(err.to_string()))
}

/// Parses a Bluetooth address (`AA:BB:CC:DD:EE:FF`, either case).
fn parse_address(address: &str) -> PyResult<[u8; 6]> {
    let invalid = || PyValueError::new_err("address must be six colon-separated hex bytes");
    let mut bytes = [0_u8; 6];
    let mut parts = address.split(':');
    for byte in &mut bytes {
        let part = parts.next().ok_or_else(invalid)?;
        if part.len() != 2 || !part.bytes().all(|digit| digit.is_ascii_hexdigit()) {
            return Err(invalid());
        }
        *byte = u8::from_str_radix(part, 16).map_err(|_not_hex| invalid())?;
    }
    if parts.next().is_some() {
        return Err(invalid());
    }
    Ok(bytes)
}

/// Parses an account id, mapping errors to `ValueError` without echoing input.
fn parse_mid(mid: &str) -> PyResult<Mid> {
    Mid::new(mid).map_err(|err| PyValueError::new_err(err.to_string()))
}

/// Converts a 16-byte Python `bytes` into a random, or raises `ValueError`.
fn parse_random(random: &[u8], what: &str) -> PyResult<[u8; 16]> {
    <[u8; 16]>::try_from(random)
        .map_err(|_wrong_len| PyValueError::new_err(format!("{what} must be exactly 16 bytes")))
}

/// Maps a 16-bit characteristic UUID to a channel.
fn channel(uuid16: u16) -> PyResult<Channel> {
    Channel::from_uuid16(uuid16)
        .ok_or_else(|| PyValueError::new_err(format!("not a Mi BLE channel: {uuid16:#06x}")))
}

/// Raises `ValueError` unless `token_hex` is 24 hexadecimal digits.
#[pyfunction]
fn validate_token(token_hex: &str) -> PyResult<()> {
    parse_token(token_hex).map(drop)
}

/// Raises `ValueError` unless `beacon_key_hex` is 32 hexadecimal digits.
#[pyfunction]
fn validate_beacon_key(beacon_key_hex: &str) -> PyResult<()> {
    parse_beacon_key(beacon_key_hex).map(drop)
}

/// Raises `ValueError` unless `mid` is 1 to 20 decimal digits.
#[pyfunction]
fn validate_mid(mid: &str) -> PyResult<()> {
    parse_mid(mid).map(drop)
}

/// Something the session reports. Immutable.
#[pyclass(module = "miscale_native", frozen, eq)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct Event {
    /// `"authenticated"`, `"live"` or `"finished"`.
    #[pyo3(get)]
    kind: &'static str,
    /// Weight in hundredths of a kilogram (`live`, and `finished` with
    /// outcome `measured`).
    #[pyo3(get)]
    weight_centi_kg: Option<u32>,
    /// For `finished`: `"measured"`, `"no_measurement"`, `"aborted"` or
    /// `"failed"`.
    #[pyo3(get)]
    outcome: Option<&'static str>,
    /// For a measurement: `"final"` or `"estimated"`.
    #[pyo3(get)]
    source: Option<&'static str>,
    /// For a `"final"` measurement: the scale's timestamp of it (seconds
    /// since the Unix epoch by the scale's clock).
    #[pyo3(get)]
    scale_time: Option<u32>,
    /// For a failure: a human-readable reason (never contains secrets).
    #[pyo3(get)]
    error: Option<String>,
    /// For a failure: `"wrong_token"`, `"refused"`, `"timeout"` or
    /// `"protocol"`, for code to act on.
    #[pyo3(get)]
    reason: Option<&'static str>,
}

#[pymethods]
impl Event {
    /// Python-style representation, e.g. `Event(kind='live', weight_centi_kg=8360, …)`.
    fn __repr__(&self) -> String {
        format!(
            "Event(kind={}, weight_centi_kg={}, outcome={}, source={}, scale_time={}, error={}, \
             reason={})",
            py_repr(Some(self.kind)),
            int_repr(self.weight_centi_kg),
            py_repr(self.outcome),
            py_repr(self.source),
            int_repr(self.scale_time),
            py_repr(self.error.as_deref()),
            py_repr(self.reason),
        )
    }
}

/// Formats an optional string the way Python's `repr` would.
fn py_repr(value: Option<&str>) -> String {
    value.map_or_else(
        || "None".to_owned(),
        |text| format!("'{}'", text.escape_default()),
    )
}

/// Formats an optional integer the way Python's `repr` would.
fn int_repr(value: Option<u32>) -> String {
    value.map_or_else(|| "None".to_owned(), |number| number.to_string())
}

/// Classifies a failure for code to act on.
const fn failure_reason(err: SessionError) -> &'static str {
    match err {
        SessionError::Login(LoginError::ProofMismatch) => "wrong_token",
        SessionError::Login(LoginError::Refused) => "refused",
        SessionError::Timeout(_) => "timeout",
        SessionError::Login(_) | SessionError::Spec(_) | SessionError::Profile | _ => "protocol",
    }
}

/// An event with only a kind.
const fn bare_event(kind: &'static str) -> Event {
    Event {
        kind,
        weight_centi_kg: None,
        outcome: None,
        source: None,
        scale_time: None,
        error: None,
        reason: None,
    }
}

/// Converts a core event.
fn event_from_core(event: CoreEvent) -> Event {
    match event {
        CoreEvent::Authenticated => bare_event("authenticated"),
        CoreEvent::Live(weight) => Event {
            weight_centi_kg: Some(weight.centi_kg()),
            ..bare_event("live")
        },
        CoreEvent::Finished(outcome) => event_from_outcome(outcome),
        _ => bare_event("unknown"),
    }
}

/// Converts a terminal outcome.
fn event_from_outcome(outcome: Outcome) -> Event {
    let finished = bare_event("finished");
    match outcome {
        Outcome::Measured {
            weight,
            source,
            scale_time,
        } => Event {
            weight_centi_kg: Some(weight.centi_kg()),
            outcome: Some("measured"),
            source: Some(match source {
                Source::Final => "final",
                Source::Estimated | _ => "estimated",
            }),
            scale_time,
            ..finished
        },
        Outcome::NoMeasurement => Event {
            outcome: Some("no_measurement"),
            ..finished
        },
        Outcome::Aborted => Event {
            outcome: Some("aborted"),
            ..finished
        },
        Outcome::Failed(err) => Event {
            outcome: Some("failed"),
            error: Some(err.to_string()),
            reason: Some(failure_reason(err)),
            ..finished
        },
        _ => Event {
            outcome: Some("failed"),
            error: Some("unknown outcome".into()),
            reason: Some("protocol"),
            ..finished
        },
    }
}

/// One weigh-in with an S200. See the `miscale` crate for the driving
/// contract; times are milliseconds on a monotonic clock.
#[pyclass(module = "miscale_native")]
struct WeighSession {
    /// The core session.
    inner: miscale::WeighSession,
}

#[pymethods]
impl WeighSession {
    /// Starts a session.
    #[new]
    #[pyo3(signature = (
        token_hex, app_rand, now_ms, unix_time, *, mid = None,
        inactivity_timeout_ms = 10_000, measurement_timeout_ms = 45_000
    ))]
    fn new(
        token_hex: &str,
        app_rand: &[u8],
        now_ms: u64,
        unix_time: u64,
        mid: Option<&str>,
        inactivity_timeout_ms: u64,
        measurement_timeout_ms: u64,
    ) -> PyResult<Self> {
        let token = parse_token(token_hex)?;
        let app_rand = parse_random(app_rand, "app_rand")?;
        let mut config = mid
            .map(parse_mid)
            .transpose()?
            .map_or_else(Config::default, Config::with_mid);
        config.inactivity_timeout_ms = inactivity_timeout_ms;
        config.measurement_timeout_ms = measurement_timeout_ms;
        Ok(Self {
            inner: miscale::WeighSession::new(Instant(now_ms), &token, app_rand, unix_time, config),
        })
    }

    /// Feeds a notification from characteristic `uuid16`.
    fn handle_notify(&mut self, now_ms: u64, uuid16: u16, data: &[u8]) -> PyResult<()> {
        self.inner
            .handle_notify(Instant(now_ms), channel(uuid16)?, data);
        Ok(())
    }

    /// Acts on an expired deadline.
    fn handle_timeout(&mut self, now_ms: u64) {
        self.inner.handle_timeout(Instant(now_ms));
    }

    /// Ends the session (e.g. the link dropped).
    fn abort(&mut self) {
        self.inner.abort();
    }

    /// The next write as `(uuid16, data)`, or `None`.
    fn poll_transmit<'py>(&mut self, py: Python<'py>) -> Option<(u16, Bound<'py, PyBytes>)> {
        self.inner
            .poll_transmit()
            .map(|tx| (tx.channel.uuid16(), PyBytes::new(py, &tx.data)))
    }

    /// The next event, or `None`.
    fn poll_event(&mut self) -> Option<Event> {
        self.inner.poll_event().map(event_from_core)
    }

    /// The next deadline in milliseconds, or `None` once finished.
    fn poll_timeout(&self) -> Option<u64> {
        self.inner.poll_timeout().map(|instant| instant.0)
    }

    /// Whether the session is over.
    #[getter]
    const fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }
}

/// A weigh-in the scale broadcast. Immutable.
#[pyclass(module = "miscale_native", frozen, eq)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct WeighIn {
    /// The weight in hundredths of a kilogram.
    #[pyo3(get)]
    weight_centi_kg: u32,
    /// The scale's timestamp of the weigh-in (seconds since the Unix epoch
    /// by the scale's clock); the same weigh-in reported over a connection
    /// carries the same one.
    #[pyo3(get)]
    scale_time: u32,
    /// The scale's user profile the weigh-in was attributed to.
    #[pyo3(get)]
    profile: u8,
}

#[pymethods]
impl WeighIn {
    /// Python-style representation.
    fn __repr__(&self) -> String {
        format!(
            "WeighIn(weight_centi_kg={}, scale_time={}, profile={})",
            self.weight_centi_kg, self.scale_time, self.profile
        )
    }
}

/// What an S200 advertisement says. Immutable.
#[pyclass(module = "miscale_native", frozen, eq)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct Beacon {
    /// The MiBeacon product id.
    #[pyo3(get)]
    product_id: u16,
    /// Changes with each new advertisement.
    #[pyo3(get)]
    frame_counter: u8,
    /// Whether the payload was encrypted.
    #[pyo3(get)]
    encrypted: bool,
    /// Whether the payload decrypted under the beacon key. An encrypted
    /// payload that does not means the key (or address) is wrong, or the
    /// advertisement was forged.
    #[pyo3(get)]
    authentic: bool,
    /// The weigh-in it broadcast, if any (only from authentic payloads).
    #[pyo3(get)]
    weigh_in: Option<WeighIn>,
}

#[pymethods]
impl Beacon {
    /// Python-style representation.
    fn __repr__(&self) -> String {
        format!(
            "Beacon(product_id={:#06x}, frame_counter={}, encrypted={}, authentic={}, \
             weigh_in={})",
            self.product_id,
            self.frame_counter,
            py_bool(self.encrypted),
            py_bool(self.authentic),
            self.weigh_in
                .as_ref()
                .map_or_else(|| "None".to_owned(), WeighIn::__repr__),
        )
    }
}

/// Formats a boolean the way Python's `repr` would.
const fn py_bool(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}

/// Reads one S200's advertisements with its beacon key, which stays on the
/// Rust side.
#[pyclass(module = "miscale_native", frozen)]
struct BeaconReader {
    /// The keyed cipher.
    cipher: BeaconCipher,
    /// The scale's address, display order.
    address: [u8; 6],
}

#[pymethods]
impl BeaconReader {
    /// A reader for the scale at `address` (`AA:BB:CC:DD:EE:FF`).
    #[new]
    fn new(beacon_key_hex: &str, address: &str) -> PyResult<Self> {
        let address = parse_address(address)?;
        let key = parse_beacon_key(beacon_key_hex)?;
        Ok(Self {
            cipher: BeaconCipher::new(&key),
            address,
        })
    }

    /// Reads MiBeacon service data; `None` unless it is an S200's frame
    /// from this address.
    fn read(&self, service_data: &[u8]) -> Option<Beacon> {
        let header = Advertisement::parse(service_data).ok()?.header;
        let beacon = |encrypted, authentic, weigh_in| Beacon {
            product_id: header.product_id,
            frame_counter: header.frame_counter,
            encrypted,
            authentic,
            weigh_in,
        };
        match miscale::beacon::read(service_data, &self.cipher, self.address) {
            Ok(read) => Some(beacon(
                read.encrypted,
                read.encrypted,
                read.weigh_in.map(|weigh_in| WeighIn {
                    weight_centi_kg: weigh_in.weight.centi_kg(),
                    scale_time: weigh_in.scale_time,
                    profile: weigh_in.profile,
                }),
            )),
            Err(BeaconError::Decrypt(DecryptError::Authentication)) => {
                Some(beacon(true, false, None))
            }
            Err(_other) => None,
        }
    }
}

/// A simulated S200 for tests (only with the `sim` feature).
#[cfg(feature = "sim")]
#[pyclass(module = "miscale_native")]
struct SimulatedScale {
    /// The core simulator.
    inner: miscale_sim::SimScale,
}

#[cfg(feature = "sim")]
#[pymethods]
impl SimulatedScale {
    /// A scale bound with `token_hex` that plays `script`, a list of
    /// `("live" | "final", centi_kg)` pairs.
    #[new]
    #[pyo3(signature = (
        token_hex, dev_rand, script, *, echo_hello = true, refuse_login = false,
        device_time = miscale_sim::DEFAULT_DEVICE_TIME
    ))]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "PyO3 extracts a Python list as a Vec"
    )]
    fn new(
        token_hex: &str,
        dev_rand: &[u8],
        script: Vec<(String, u32)>,
        echo_hello: bool,
        refuse_login: bool,
        device_time: u32,
    ) -> PyResult<Self> {
        let mut config = miscale_sim::SimConfig::new(
            parse_token(token_hex)?,
            parse_random(dev_rand, "dev_rand")?,
        );
        config.echo_hello = echo_hello;
        config.refuse_login = refuse_login;
        config.device_time = device_time;
        let steps = script
            .iter()
            .map(|(kind, centi)| match kind.as_str() {
                "live" => u16::try_from(*centi)
                    .map(miscale_sim::Step::Live)
                    .map_err(|_overflow| PyValueError::new_err("live weight exceeds 655.35 kg")),
                "final" => Ok(miscale_sim::Step::Final(*centi)),
                _ => Err(PyValueError::new_err(
                    "step kind must be \"live\" or \"final\"",
                )),
            })
            .collect::<PyResult<Vec<_>>>()?;
        Ok(Self {
            inner: miscale_sim::SimScale::new(config, &steps),
        })
    }

    /// Feeds a write the client made to characteristic `uuid16`.
    fn handle_write(&mut self, uuid16: u16, data: &[u8]) -> PyResult<()> {
        self.inner.handle_write(channel(uuid16)?, data);
        Ok(())
    }

    /// The next notification as `(uuid16, data)`, or `None`.
    fn poll_notify<'py>(&mut self, py: Python<'py>) -> Option<(u16, Bound<'py, PyBytes>)> {
        self.inner
            .poll_notify()
            .map(|tx| (tx.channel.uuid16(), PyBytes::new(py, &tx.data)))
    }
}

/// The service data a simulated S200 at `address` broadcasts: idle, or a
/// `(centi_kg, scale_time)` weigh-in encrypted under the beacon key (only
/// with the `sim` feature).
#[cfg(feature = "sim")]
#[pyfunction]
#[pyo3(signature = (beacon_key_hex, address, frame_counter, weigh_in = None))]
fn simulated_advertisement<'py>(
    py: Python<'py>,
    beacon_key_hex: &str,
    address: &str,
    frame_counter: u8,
    weigh_in: Option<(u32, u32)>,
) -> PyResult<Bound<'py, PyBytes>> {
    let frame = miscale_sim::advertisement(
        &parse_beacon_key(beacon_key_hex)?,
        parse_address(address)?,
        frame_counter,
        weigh_in,
    )
    .map_err(|err| PyValueError::new_err(err.to_string()))?;
    Ok(PyBytes::new(py, &frame))
}

/// The `miscale_native` Python module.
#[pymodule]
fn miscale_native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("SERVICE_UUID16", SERVICE_UUID16)?;
    module.add("CHANNEL_UUID16S", Channel::ALL.map(Channel::uuid16))?;
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    module.add_function(wrap_pyfunction!(validate_token, module)?)?;
    module.add_function(wrap_pyfunction!(validate_mid, module)?)?;
    module.add_function(wrap_pyfunction!(validate_beacon_key, module)?)?;
    module.add_class::<Event>()?;
    module.add_class::<WeighSession>()?;
    module.add_class::<Beacon>()?;
    module.add_class::<BeaconReader>()?;
    module.add_class::<WeighIn>()?;
    #[cfg(feature = "sim")]
    module.add_class::<SimulatedScale>()?;
    #[cfg(feature = "sim")]
    module.add_function(wrap_pyfunction!(simulated_advertisement, module)?)?;
    Ok(())
}
