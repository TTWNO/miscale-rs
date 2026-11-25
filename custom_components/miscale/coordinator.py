"""Coordinator: an advertisement means the scale is awake, so weigh.

Every advertisement is also read with the beacon key: once a weight is
final, the scale broadcasts it, encrypted. A weigh-in reported both ways
carries the same scale timestamp and is recorded once.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import logging
import time
from typing import TYPE_CHECKING, override

from bleak_retry_connector import BleakClientWithServiceCache, establish_connection

from homeassistant.components.bluetooth import (
    BluetoothChange,
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

from .const import (
    CONF_BEACON_KEY,
    CONF_MID,
    CONF_TOKEN,
    DOMAIN,
    ESTIMATE_REFINE_KG,
    ESTIMATE_REFINE_SECONDS,
    MIBEACON_UUID,
    POLL_COOLDOWN_SECONDS,
    WRONG_BEACON_KEY_AFTER,
)
from .mibeacon import is_s200
from .native import native
from .runner import SessionRunner, new_session

if TYPE_CHECKING:
    from datetime import datetime

    from miscale_native import Event, WeighIn

_LOGGER = logging.getLogger(__name__)

type MiScaleConfigEntry = ConfigEntry[MiScaleCoordinator]


@dataclass(frozen=True, slots=True)
class MiScaleData:
    """What the integration knows about the scale."""

    weight_kg: float | None = None
    """The last measured weight."""
    source: str | None = None
    """How it was obtained: `final`, `estimated` or `broadcast`."""
    measured_at: datetime | None = None
    """When it was measured."""
    scale_time: int | None = None
    """The scale's own timestamp of it (`final` and `broadcast` only)."""
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
        self._beacon = native.BeaconReader(entry.data[CONF_BEACON_KEY], entry.data[CONF_ADDRESS])
        self._undecryptable = 0
        # When the last weigh-in was estimated, and its weight.
        self._estimate: tuple[float, float] | None = None
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
    @override
    def _async_handle_bluetooth_event(
        self, service_info: BluetoothServiceInfoBleak, change: BluetoothChange
    ) -> None:
        """Read the advertisement, then let the base class decide whether to weigh."""
        self._read_advertisement(service_info)
        super()._async_handle_bluetooth_event(service_info, change)

    @callback
    def _read_advertisement(self, service_info: BluetoothServiceInfoBleak) -> None:
        """Record a broadcast weigh-in; notice a wrong beacon key."""
        data = service_info.service_data.get(MIBEACON_UUID)
        beacon = None if data is None else self._beacon.read(data)
        if beacon is None or not beacon.encrypted:
            return
        if not beacon.authentic:
            self._undecryptable += 1
            if self._undecryptable == WRONG_BEACON_KEY_AFTER:
                _LOGGER.warning("The scale's advertisements do not decrypt with its beacon key")
                self._entry.async_start_reauth(self.hass)
            return
        self._undecryptable = 0
        if beacon.weigh_in is not None:
            self._on_broadcast(beacon.weigh_in)

    @callback
    def _on_broadcast(self, weigh_in: WeighIn) -> None:
        """Record a weigh-in the scale broadcast, unless it is already known."""
        weight_kg = _kilograms(weigh_in.weight_centi_kg)
        _LOGGER.debug("Broadcast weigh-in: %s kg, scale time %s", weight_kg, weigh_in.scale_time)
        # The weigh-in is over: do not connect for it.
        self._last_end = time.monotonic()
        if weigh_in.scale_time == self.data.scale_time:
            return
        if self._refines_estimate(weight_kg):
            # The scale's value of the weigh-in just estimated: no new event.
            self._estimate = None
            self.data = replace(
                self.data, weight_kg=weight_kg, source="broadcast", scale_time=weigh_in.scale_time
            )
        else:
            self.data = self._measured(self.data, weight_kg, "broadcast", weigh_in.scale_time)
        self.async_update_listeners()

    def _refines_estimate(self, weight_kg: float | None) -> bool:
        """Whether a broadcast weight is the scale's value of the last estimate."""
        if self._estimate is None or weight_kg is None:
            return False
        estimated_at, estimate_kg = self._estimate
        return (
            time.monotonic() - estimated_at < ESTIMATE_REFINE_SECONDS
            and abs(weight_kg - estimate_kg) <= ESTIMATE_REFINE_KG
        )

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
            session = new_session(self._entry.data[CONF_TOKEN], self._entry.data[CONF_MID])
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
        if finished.outcome == "measured" and (
            finished.scale_time is None or finished.scale_time != data.scale_time
        ):
            data = self._measured(
                data,
                _kilograms(finished.weight_centi_kg),
                finished.source or "final",
                finished.scale_time,
            )
            self._estimate = (
                (time.monotonic(), data.weight_kg)
                if finished.source == "estimated" and data.weight_kg is not None
                else None
            )
            _LOGGER.debug(
                "Measured %s kg (%s, scale time %s)", data.weight_kg, data.source, data.scale_time
            )
        elif finished.outcome == "failed":
            _LOGGER.warning("Weigh session failed: %s", finished.error)
            if finished.reason == "wrong_token":
                self._entry.async_start_reauth(self.hass)
        return data

    @staticmethod
    def _measured(
        data: MiScaleData, weight_kg: float | None, source: str, scale_time: int | None
    ) -> MiScaleData:
        """Return `data` with a new measurement."""
        return replace(
            data,
            weight_kg=weight_kg,
            source=source,
            measured_at=dt_util.utcnow(),
            scale_time=scale_time,
            measurement_count=data.measurement_count + 1,
        )
