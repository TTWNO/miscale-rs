"""Coordinator: an advertisement means the scale is awake, so weigh."""

from __future__ import annotations

from dataclasses import dataclass, replace
import logging
import time
from typing import TYPE_CHECKING

from bleak_retry_connector import BleakClientWithServiceCache, establish_connection

from homeassistant.components.bluetooth import (
    BluetoothScanningMode,
    BluetoothServiceInfoBleak,
    async_ble_device_from_address,
)
from homeassistant.components.bluetooth.active_update_coordinator import (
    ActiveBluetoothDataUpdateCoordinator,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_ADDRESS
from homeassistant.core import CoreState, HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.util import dt as dt_util

from .const import CONF_MID, CONF_TOKEN, DOMAIN, POLL_COOLDOWN_SECONDS
from .mibeacon import is_s200
from .runner import SessionRunner, new_session

if TYPE_CHECKING:
    from datetime import datetime

    from miscale_native import Event

_LOGGER = logging.getLogger(__name__)

type MiScaleConfigEntry = ConfigEntry[MiScaleCoordinator]


@dataclass(frozen=True, slots=True)
class MiScaleData:
    """What the integration knows about the scale."""

    weight_kg: float | None = None
    """The last measured weight."""
    source: str | None = None
    """How it was obtained: `final` or `estimated`."""
    measured_at: datetime | None = None
    """When it was measured."""
    measurement_count: int = 0
    """Measurements since start-up; changes on every new one."""
    live_kg: float | None = None
    """The latest live reading of the current or last session."""
    last_outcome: str | None = None
    """How the last session ended."""
    last_error: str | None = None
    """Why the last session failed, if it did."""


def _kilograms(centi_kg: int | None) -> float | None:
    """Convert hundredths of a kilogram to kilograms."""
    return None if centi_kg is None else round(centi_kg / 100, 2)


class MiScaleCoordinator(ActiveBluetoothDataUpdateCoordinator[MiScaleData]):
    """Weighs whenever the scale wakes up and advertises."""

    def __init__(self, hass: HomeAssistant, entry: MiScaleConfigEntry) -> None:
        """Set up for the scale in `entry`."""
        self._entry = entry
        self._running = False
        self._last_end: float | None = None
        super().__init__(
            hass,
            _LOGGER,
            address=entry.data[CONF_ADDRESS],
            mode=BluetoothScanningMode.PASSIVE,
            needs_poll_method=self._needs_poll,
            poll_method=self._poll,
            connectable=True,
        )
        self.data = MiScaleData()

    @callback
    def _needs_poll(
        self, service_info: BluetoothServiceInfoBleak, _seconds_since_poll: float | None
    ) -> bool:
        """Weigh when an awake S200 is seen, unless one ran just now."""
        return (
            self.hass.state is CoreState.running
            and not self._running
            and not self._cooling_down()
            and is_s200(service_info)
        )

    def _cooling_down(self) -> bool:
        """Whether the last session ended within the cooldown."""
        return (
            self._last_end is not None and time.monotonic() - self._last_end < POLL_COOLDOWN_SECONDS
        )

    async def _poll(self, service_info: BluetoothServiceInfoBleak) -> MiScaleData:
        """Connect, run one weigh session, disconnect."""
        # The poll debouncer can call again after a session; guard here too.
        if self._running or self._cooling_down():
            return self.data
        device = async_ble_device_from_address(self.hass, service_info.address, connectable=True)
        if device is None:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="no_connectable_device",
                translation_placeholders={"address": service_info.address},
            )
        self._running = True
        self.data = replace(self.data, live_kg=None)
        try:
            session = new_session(self._entry.data[CONF_TOKEN], self._entry.options.get(CONF_MID))
            runner: SessionRunner | None = None

            def disconnected(_client: BleakClientWithServiceCache) -> None:
                if runner is not None:
                    runner.notify_disconnected()

            client = await establish_connection(
                BleakClientWithServiceCache, device, device.name or device.address, disconnected
            )
            try:
                runner = SessionRunner(client, session, self._on_event)
                finished = await runner.run()
            finally:
                await client.disconnect()
        finally:
            self._running = False
            self._last_end = time.monotonic()
        return self._apply(finished)

    @callback
    def _on_event(self, event: Event) -> None:
        """Push live readings to entities while the session runs."""
        if event.kind == "live":
            self.data = replace(self.data, live_kg=_kilograms(event.weight_centi_kg))
            self.async_update_listeners()

    def _apply(self, finished: Event) -> MiScaleData:
        """Fold a session's `finished` event into the data."""
        data = replace(self.data, last_outcome=finished.outcome, last_error=finished.error)
        if finished.outcome == "measured":
            data = replace(
                data,
                weight_kg=_kilograms(finished.weight_centi_kg),
                source=finished.source,
                measured_at=dt_util.utcnow(),
                measurement_count=data.measurement_count + 1,
            )
            _LOGGER.debug("Measured %s kg (%s)", data.weight_kg, data.source)
        elif finished.outcome == "failed":
            _LOGGER.warning("Weigh session failed: %s", finished.error)
            if finished.reason == "wrong_token":
                self._entry.async_start_reauth(self.hass)
        return data
