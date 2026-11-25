"""The Bluetooth driver loop, against the simulator."""

from __future__ import annotations

import asyncio
from typing import override

from bleak.exc import BleakError
import miscale_native
import pytest

from custom_components.miscale.runner import SessionRunner, char_uuid, new_session

from .conftest import DEV_RAND, TOKEN, FakeClient


def test_char_uuid() -> None:
    """16-bit UUIDs expand into the Bluetooth base UUID."""
    assert char_uuid(0x001A) == "0000001a-0000-1000-8000-00805f9b34fb"


async def test_run_to_final() -> None:
    """The runner shuttles bytes until the final weight, in order."""
    scale = miscale_native.SimulatedScale(TOKEN, DEV_RAND, [("live", 5000), ("final", 5545)])
    events: list[miscale_native.Event] = []
    finished = await SessionRunner(FakeClient(scale), new_session(TOKEN, None), events.append).run()
    assert finished.kind == "finished"
    assert (finished.outcome, finished.source, finished.weight_centi_kg) == (
        "measured",
        "final",
        5545,
    )
    assert [event.kind for event in events] == ["authenticated", "live", "finished"]


async def test_disconnect_aborts() -> None:
    """A dropped link ends the session as aborted."""
    scale = miscale_native.SimulatedScale(TOKEN, DEV_RAND, [], echo_hello=False)
    runner = SessionRunner(FakeClient(scale), new_session(TOKEN, None), lambda _event: None)
    task = asyncio.create_task(runner.run())
    await asyncio.sleep(0)
    runner.notify_disconnected()
    finished = await asyncio.wait_for(task, 5)
    assert finished.outcome == "aborted"


class FailingClient(FakeClient):
    """A client whose writes fail, as on a dropped link."""

    @override
    async def write_gatt_char(
        self, char_specifier: str, data: bytes, *, response: bool | None = None
    ) -> None:
        """Fail every write."""
        del char_specifier, data, response
        msg = "link lost"
        raise BleakError(msg)


async def test_write_error_propagates() -> None:
    """A failed write aborts the session and reaches the coordinator."""
    scale = miscale_native.SimulatedScale(TOKEN, DEV_RAND, [])
    session = new_session(TOKEN, None)
    with pytest.raises(BleakError, match="link lost"):
        await SessionRunner(FailingClient(scale), session, lambda _event: None).run()
    assert session.is_finished


async def test_refused_login() -> None:
    """A refusal is reported with a machine-readable reason."""
    scale = miscale_native.SimulatedScale(TOKEN, DEV_RAND, [], refuse_login=True)
    finished = await SessionRunner(
        FakeClient(scale), new_session(TOKEN, None), lambda _event: None
    ).run()
    assert (finished.outcome, finished.reason) == ("failed", "refused")
    assert finished.error is not None
    assert TOKEN not in finished.error
