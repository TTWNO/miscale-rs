"""The Python surface of the native module (built with the `sim` feature)."""

from __future__ import annotations

import miscale_native
import pytest

# miauth's published test vector: a synthetic token.
TOKEN = "0cf5615003810d89c233a12a"
# A synthetic beacon key and address.
BEACON_KEY = "5a" * 16
ADDRESS = "02:00:00:00:00:01"
# A Smart Scale S200 advertisement from xiaomi-ble's test suite (a test
# device's published key, not ours): 62.25 kg for profile 1.
CAPTURED = bytes.fromhex("4859044c019a80a275939010f0abc4fadc0600003d29c044")
CAPTURED_KEY = "653b1b10e1cb35e4ac5e60fa45f3bf29"  # gitleaks:allow
CAPTURED_ADDRESS = "D0:7B:6F:27:D7:29"


def weigh(
    session: miscale_native.WeighSession, scale: miscale_native.SimulatedScale
) -> list[miscale_native.Event]:
    """Shuttle bytes until both sides are quiet, draining after every call."""
    events: list[miscale_native.Event] = []

    def drain() -> None:
        while (tx := session.poll_transmit()) is not None:
            scale.handle_write(*tx)
        while (event := session.poll_event()) is not None:
            events.append(event)

    drain()
    while (note := scale.poll_notify()) is not None:
        session.handle_notify(0, *note)
        drain()
    return events


def test_constants() -> None:
    """The module names the service and channels it speaks."""
    assert miscale_native.SERVICE_UUID16 == 0xFE95
    assert list(miscale_native.CHANNEL_UUID16S) == [0x10, 0x19, 0x1A, 0x1B]


def test_weigh_in() -> None:
    """A whole weigh-in through the bindings."""
    session = miscale_native.WeighSession(TOKEN, bytes(16), 0, 1_764_000_000)
    scale = miscale_native.SimulatedScale(TOKEN, bytes(16), [("live", 4120), ("final", 8360)])
    events = weigh(session, scale)
    assert [event.kind for event in events] == ["authenticated", "live", "finished"]
    final = events[-1]
    assert (final.outcome, final.source, final.weight_centi_kg) == ("measured", "final", 8360)
    assert final.scale_time == 1_764_000_000
    assert session.is_finished
    assert session.poll_timeout() is None
    assert repr(events[1]) == (
        "Event(kind='live', weight_centi_kg=4120, outcome=None, source=None, scale_time=None, "
        "error=None, reason=None)"
    )


def test_scale_time() -> None:
    """A final reading carries the scale's own timestamp."""
    session = miscale_native.WeighSession(TOKEN, bytes(16), 0, 0)
    scale = miscale_native.SimulatedScale(
        TOKEN, bytes(16), [("final", 7000)], device_time=1_800_000_000
    )
    assert weigh(session, scale)[-1].scale_time == 1_800_000_000


def test_wrong_token_reason() -> None:
    """A rejected token is reported as such, without echoing it."""
    session = miscale_native.WeighSession("ff" * 12, bytes(16), 0, 0)
    scale = miscale_native.SimulatedScale(TOKEN, bytes(16), [])
    final = weigh(session, scale)[-1]
    assert (final.outcome, final.reason) == ("failed", "wrong_token")
    assert final.error is not None
    assert "ff" * 12 not in final.error


def test_timeout() -> None:
    """Deadlines are milliseconds on the caller's clock."""
    session = miscale_native.WeighSession(TOKEN, bytes(16), 1_000, 0, inactivity_timeout_ms=500)
    assert session.poll_timeout() == 1_500
    session.handle_timeout(1_500)
    final = session.poll_event()
    assert final is not None
    assert (final.kind, final.outcome, final.reason) == ("finished", "failed", "timeout")


@pytest.mark.parametrize(
    "token", ["", "0cf5615003810d89c233a1", "0cf5615003810d89c233a12g", "x" * 24]
)
def test_bad_tokens(token: str) -> None:
    """Bad tokens raise ValueError, and the message never contains them."""
    with pytest.raises(ValueError, match="token") as raised:
        miscale_native.validate_token(token)
    if token:
        assert token not in str(raised.value)
    with pytest.raises(ValueError, match="token"):
        miscale_native.WeighSession(token, bytes(16), 0, 0)


def test_bad_arguments() -> None:
    """Other arguments are checked too."""
    with pytest.raises(ValueError, match="16 bytes"):
        miscale_native.WeighSession(TOKEN, bytes(15), 0, 0)
    with pytest.raises(ValueError, match="decimal digits"):
        miscale_native.WeighSession(TOKEN, bytes(16), 0, 0, mid="12a")
    with pytest.raises(ValueError, match="not a Mi BLE channel"):
        miscale_native.WeighSession(TOKEN, bytes(16), 0, 0).handle_notify(0, 0x2A00, b"")
    miscale_native.validate_mid("4242")


def test_captured_beacon() -> None:
    """The captured S200 weigh-in reads as xiaomi-ble reports it."""
    beacon = miscale_native.BeaconReader(CAPTURED_KEY, CAPTURED_ADDRESS).read(CAPTURED)
    assert beacon is not None
    assert (beacon.product_id, beacon.frame_counter) == (0x4C04, 1)
    assert beacon.encrypted
    assert beacon.authentic
    assert beacon.weigh_in is not None
    weigh_in = beacon.weigh_in
    assert (weigh_in.weight_centi_kg, weigh_in.scale_time, weigh_in.profile) == (
        6225,
        1_762_728_842,
        1,
    )
    assert repr(beacon) == (
        "Beacon(product_id=0x4c04, frame_counter=1, encrypted=True, authentic=True, "
        "weigh_in=WeighIn(weight_centi_kg=6225, scale_time=1762728842, profile=1))"
    )


def test_simulated_beacons() -> None:
    """Simulated idle and weigh-in advertisements read back."""
    reader = miscale_native.BeaconReader(BEACON_KEY, ADDRESS)
    idle = reader.read(miscale_native.simulated_advertisement(BEACON_KEY, ADDRESS, 1))
    assert idle is not None
    assert (idle.encrypted, idle.authentic, idle.weigh_in) == (False, False, None)
    frame = miscale_native.simulated_advertisement(
        BEACON_KEY, ADDRESS, 2, weigh_in=(8360, 1_764_000_000)
    )
    beacon = reader.read(frame)
    assert beacon is not None
    assert beacon.authentic
    assert beacon.weigh_in is not None
    assert (beacon.weigh_in.weight_centi_kg, beacon.weigh_in.scale_time) == (
        8360,
        1_764_000_000,
    )


def test_wrong_beacon_key() -> None:
    """An encrypted frame that does not decrypt is reported as not authentic."""
    beacon = miscale_native.BeaconReader("00" * 16, CAPTURED_ADDRESS).read(CAPTURED)
    assert beacon is not None
    assert (beacon.encrypted, beacon.authentic, beacon.weigh_in) == (True, False, None)


def test_not_a_beacon() -> None:
    """Data that is not an S200's MiBeacon frame reads as None."""
    reader = miscale_native.BeaconReader(BEACON_KEY, ADDRESS)
    assert reader.read(b"") is None
    assert reader.read(b"\x48\x59\x5b\x05\x01") is None


@pytest.mark.parametrize("key", ["", "5a" * 12, "5a" * 15 + "zz", "5a" * 17])
def test_bad_beacon_keys(key: str) -> None:
    """Bad beacon keys raise ValueError, and the message never contains them."""
    with pytest.raises(ValueError, match="beacon key") as raised:
        miscale_native.validate_beacon_key(key)
    if key:
        assert key not in str(raised.value)
    with pytest.raises(ValueError, match="beacon key"):
        miscale_native.BeaconReader(key, ADDRESS)


@pytest.mark.parametrize(
    "address",
    ["", "02:00:00:00:00", "02:00:00:00:00:01:02", "0200000000:01", "+2:00:00:00:00:01"],
)
def test_bad_addresses(address: str) -> None:
    """Malformed addresses raise ValueError."""
    with pytest.raises(ValueError, match="address"):
        miscale_native.BeaconReader(BEACON_KEY, address)
