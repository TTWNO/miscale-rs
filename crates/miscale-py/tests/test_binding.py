"""The Python surface of the native module (built with the `sim` feature)."""

from __future__ import annotations

import miscale_native
import pytest

# miauth's published test vector: a synthetic token.
TOKEN = "0cf5615003810d89c233a12a"


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
    assert session.is_finished
    assert session.poll_timeout() is None
    assert repr(events[1]) == (
        "Event(kind='live', weight_centi_kg=4120, outcome=None, source=None, error=None, "
        "reason=None)"
    )


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
