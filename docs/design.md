# miscale-rs design

Status: accepted (2026-11-24). This document records *why* the code is shaped
the way it is. Protocol byte layouts live in [`protocol.md`](protocol.md).

## Goal

Read the weight from a Xiaomi Smart Scale S200 (MJTZC02YM,
`yunmai.scales.ms106`) into Home Assistant, fully locally, and expose it as a
*standard* HA scale so that any other integration that consumes health data
(Bodymiscale, statistics, multi-user routers, …) can use it as a source.

The only secret needed at runtime is the device's static 12-byte login token,
extracted once by the user. No Xiaomi account, app, or server is involved at
runtime.

## Non-goals

- **Binding / registration.** On this firmware the device verifies a
  cloud-issued signature during register (it answers `0x12`), so a local bind
  is impossible. Running register against a real scale could also rotate its
  token. The crates leave room for it but do not implement it.
- **Passive MiBeacon decoding.** HA's built-in `xiaomi_ble` already does this
  with a bindkey, and the S200 does not reliably broadcast measurements anyway.
- **Body composition.** The S200 has no electrodes; it reports weight only.

## Why a HACS integration and not an MQTT daemon

The first idea was a standalone daemon talking MQTT to HA, reaching the scale
through an ESPHome Bluetooth proxy. ESPHome's `bluetooth_proxy` serves exactly
**one** API subscriber (`BluetoothProxy::api_connection_`; the newest
subscriber replaces the previous one, and GATT results are sent only to it).
HA's ESPHome integration subscribes to every adopted proxy, so a second client
would fight HA for the proxy.

HA's own Bluetooth stack already routes connections through any adopted
proxy (or a local adapter). So all I/O lives in a thin Python integration,
and everything else is Rust behind PyO3.

## Architecture

```text
            ┌──────────────────────────────────────────────┐
  HA core   │ custom_components/miscale  (Python, all I/O)  │
  bluetooth │  config flow · coordinator · runner · entities│
  stack ───▶│        ▲ bytes in            │ bytes out      │
            └────────┼──────────────────────┼───────────────┘
                     │   miscale_native (PyO3, no I/O)
            ┌────────┴──────────────────────▼───────────────┐
            │ miscale       WeighSession: login → hello →    │
            │               profile → Live/Final events      │
            │ mible-spec    spec frames + encrypted channel  │
            │ mible-auth    login state machine              │
            │ mible-crypto  HKDF/HMAC, AES-CCM session cipher│
            │ mible-transport  control frames, parcel TX/RX  │
            └────────────────────────────────────────────────┘
                 all #![no_std], no allocator, no I/O, no clock
```

| crate             | `no_std` | role |
|-------------------|----------|------|
| `mible-transport` | yes | control-frame codec; parcel sender / receiver state machines |
| `mible-crypto`    | yes | login key schedule + proofs; AES-CCM session cipher |
| `mible-auth`      | yes | login state machine |
| `mible-spec`      | yes | spec frame codec, TLVs, encrypted spec channel |
| `miscale`         | yes | S200 weigh session, weight decoding, stabiliser |
| `miscale-sim`     | yes | device-side simulator for tests (`publish = false`) |
| `miscale-py`      | no  | PyO3 bindings (`abi3-py312`); `sim` feature for tests |

### The sans-io contract

Every state machine has the same shape (in the spirit of `quinn-proto`):

```rust,ignore
let mut machine = WeighSession::new(now, token, app_rand, unix_time, &config);
machine.handle_notify(now, channel, &bytes);   // feed an inbound notification
machine.handle_timeout(now);                   // the deadline passed
machine.abort();                               // link lost / caller gives up
while let Some(tx) = machine.poll_transmit() { /* write tx.data to tx.channel */ }
while let Some(ev) = machine.poll_event() { /* react */ }
let deadline = machine.poll_timeout();         // next wake-up, if any
```

- **Termination.** Every session ends with exactly one terminal event
  (`Finished(outcome)`). After it, `poll_transmit()` and `poll_timeout()`
  return `None` and further input is ignored.
- **Single-threaded driving.** The integration's Bluetooth callbacks only
  enqueue notifications; one task feeds them in order and, after *every*
  call, drains transmits (written as write-without-response, in order) and
  events. A receiver whose acknowledgements are not drained fails with a
  backlog error instead of silently losing one.

- **No I/O, no clock, no RNG** inside the crates. The caller passes a
  monotonic `Instant` (milliseconds), the wall-clock Unix time the profile
  needs, and the 16 random bytes for `app_rand`. Tests are therefore fully
  deterministic.
- **No allocator.** Buffers are fixed-capacity (`heapless`); capacities are
  derived from protocol limits and overflow is a protocol error, never a
  panic.
- **Errors are events.** A failed machine emits a terminal `Failed(error)`
  event and stops; `handle_*` never returns errors and never panics.
  Errors implement `core::error::Error`, so no `std` feature is needed.
- Only the top-level `WeighSession` owns deadlines. Lower layers are purely
  event-driven, which keeps them reusable for other Mi devices. Login and the
  hello exchange use an inactivity timeout that restarts on every received
  frame; the measurement window is absolute, as in the prototype.
- **Lenient where hardware may differ, strict where it matters.** Inbound
  fragments may be any length (higher MTUs); stray or duplicate acks are
  ignored; oversized messages are acknowledged and discarded. Authentication
  failures, decryption failures and device error codes end the session.
- Fragments are generated lazily from a cursor, so a long message never needs
  a deep transmit queue. Fragments the receiver reports lost are resent.

### Secrets

- `Token` and the derived session keys are zeroised on drop and their
  `Debug` output is redacted. Session keys never leave `WeighSession`, so
  they never cross into Python.
- The integration stores the token in the config entry, never logs it, and
  redacts it from diagnostics.
- Tests use synthetic keys only (plus the published miauth known-answer
  vectors). Real captures are never committed: they are only meaningful with
  the real token.

## Home Assistant integration

- **Discovery.** A manifest Bluetooth matcher on service data UUID FE95. The
  config flow keeps only S200 product ids (`0x45C9`, `0x4C04`, `0x4DCB`) and
  asks for the token (24 hex digits).
- **Coordinator.** HA's `ActiveBluetoothDataUpdateCoordinator`. An
  advertisement means the scale is awake. The poll itself guards against
  overlap (a running flag plus a cooldown measured from the end of the last
  session), because the debouncer can fire a trailing call. A poll connects
  with `bleak-retry-connector`, drives a `WeighSession` to completion, then
  disconnects (holding the link drains the battery). Entities stay
  available while the scale sleeps.
- **A standard scale.** The weight entity follows HA core's scale integrations
  (`okok_scale`): `sensor` with `device_class: weight`, unit `kg`,
  `state_class: measurement`, `translation_key: weight`. `measurement` puts
  it in long-term statistics. The manifest declares
  `categories: ["health_wellbeing"]` and `connectivity: ["bluetooth"]`.
- **Other entities.** A live-weight sensor, updated during a session
  (disabled by default, so consumers never mistake a transient value for a
  measurement); a last-weigh-in
  timestamp; an `event` entity that fires on *every* weigh-in, even when the
  weight repeats, so text-to-speech automations can announce each one;
  diagnostics with secrets redacted.
- **Native module.** Bundled prebuilt `abi3` shared objects for x86_64 and
  aarch64 musl: HA OS and HA Container both run Python on Alpine, and the
  glibc-only "Core" install method is deprecated. The objects live in a
  versioned directory so an update never overwrites a mapped library. A
  small loader imports the right one once per process and falls back to an
  installed `miscale_native` (development and tests). Nothing is fetched from
  PyPI.

## Testing strategy

- Unit tests in every crate; published miauth vectors as known-answer tests.
- Property tests: framing round-trips, and "never panics on arbitrary
  input" for every parser and state machine.
- End-to-end login + weigh between `WeighSession` and `miscale-sim`.
- Python: the bundled musl object is imported inside the real HA container
  image in CI.
- Python: `pytest-homeassistant-custom-component` with a fake BLE client
  whose peer is the Rust simulator, exercising config flow → coordinator →
  runner → entities.

## Known risks

- The profile JSON carries a `mid` (Mi account id). The default here is a
  neutral value. It is not yet verified on hardware that the scale accepts
  an arbitrary `mid`, so the config flow lets the user enter theirs (digits
  only, length-bounded). This is the first thing to check on hardware.
- The scale's idle advertisement never changes, and HA's Bluetooth stack
  skips callbacks for unchanged advertisements. Whether a second wake-up
  soon after the first triggers a poll depends on HA noticing the scale went
  away in between; this needs checking on hardware.
- The stabilisation fallback compares spreads in integer centi-kilograms.
  The prototype compared floats, which rejects about half of the exact
  0.30 kg spreads by rounding error; the integer form is the intent.
- The weight decoders are heuristics proven on captured traffic (see
  `protocol.md`); the full spec TLV grammar is not known.
