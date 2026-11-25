"""Drive one weigh session over a Bluetooth connection.

This is the only place that does Bluetooth I/O. The protocol lives in the
native module; this loop shuttles bytes between it and bleak:

1. subscribe to every protocol characteristic; notifications only go into a
   queue (so they are handled one at a time, in order, on this task);
2. feed each notification to the session, then write everything it wants
   written (write-without-response, in order) and hand on its events;
3. wake up at the session's deadline;
4. stop at the session's single `finished` event, or abort it if the link
   drops.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import TYPE_CHECKING, Protocol

from bleak.exc import BleakError

from .const import INACTIVITY_TIMEOUT_MS, MEASUREMENT_TIMEOUT_MS
from .native import native

if TYPE_CHECKING:
    from collections.abc import Callable

    from miscale_native import Event, WeighSession

_LOGGER = logging.getLogger(__name__)

# Put on the queue when the link drops.
_DISCONNECTED: tuple[int, bytes] = (-1, b"")


def char_uuid(uuid16: int) -> str:
    """Expand a 16-bit UUID into the Bluetooth base UUID."""
    return f"0000{uuid16:04x}-0000-1000-8000-00805f9b34fb"


class GattClient(Protocol):
    """The part of a bleak client the runner uses."""

    async def start_notify(
        self, char_specifier: str, callback: Callable[[object, bytearray], None]
    ) -> None:
        """Subscribe to notifications."""

    async def write_gatt_char(
        self, char_specifier: str, data: bytes, *, response: bool | None = None
    ) -> None:
        """Write a characteristic value."""


def _now_ms() -> int:
    """Milliseconds on a monotonic clock."""
    return time.monotonic_ns() // 1_000_000


class SessionRunner:
    """Runs one session over a connected client."""

    def __init__(
        self,
        client: GattClient,
        session: WeighSession,
        on_event: Callable[[Event], None],
        clock: Callable[[], int] = _now_ms,
    ) -> None:
        """Pair a connected client with a fresh session."""
        self._client = client
        self._session = session
        self._on_event = on_event
        self._clock = clock
        self._queue: asyncio.Queue[tuple[int, bytes]] = asyncio.Queue()

    def notify_disconnected(self) -> None:
        """Tell the runner the link dropped (from bleak's callback)."""
        self._queue.put_nowait(_DISCONNECTED)

    async def run(self) -> Event:
        """Run the session to its end and return the `finished` event."""
        await self._subscribe()
        while True:
            if (finished := await self._drain()) is not None:
                return finished
            deadline = self._session.poll_timeout()
            timeout = None if deadline is None else max(0, deadline - self._clock()) / 1000
            try:
                uuid16, data = await asyncio.wait_for(self._queue.get(), timeout)
            except TimeoutError:
                self._session.handle_timeout(self._clock())
                continue
            if (uuid16, data) == _DISCONNECTED:
                self._session.abort()
                continue
            self._session.handle_notify(self._clock(), uuid16, data)

    async def _subscribe(self) -> None:
        """Subscribe to every protocol characteristic."""
        for uuid16 in native.CHANNEL_UUID16S:

            def callback(_char: object, data: bytearray, uuid16: int = uuid16) -> None:
                self._queue.put_nowait((uuid16, bytes(data)))

            try:
                await self._client.start_notify(char_uuid(uuid16), callback)
            except BleakError as err:
                # The prototype tolerated this too; the session times out if a
                # characteristic it needs stays silent.
                _LOGGER.debug("Cannot subscribe to %s: %s", char_uuid(uuid16), err)

    async def _drain(self) -> Event | None:
        """Write pending transmits and hand on events; return `finished`."""
        while (tx := self._session.poll_transmit()) is not None:
            uuid16, data = tx
            try:
                await self._client.write_gatt_char(char_uuid(uuid16), data, response=False)
            except BleakError:
                self._session.abort()
                raise
        while (event := self._session.poll_event()) is not None:
            self._on_event(event)
            if event.kind == "finished":
                return event
        return None


def new_session(token: str, mid: str | None) -> WeighSession:
    """Start a session now, with a fresh random from the OS."""
    return native.WeighSession(
        token,
        os.urandom(16),
        _now_ms(),
        int(time.time()),
        mid=mid,
        inactivity_timeout_ms=INACTIVITY_TIMEOUT_MS,
        measurement_timeout_ms=MEASUREMENT_TIMEOUT_MS,
    )
