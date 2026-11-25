"""Sensors: the weight (a standard HA scale), the live weight, the time."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, override

from homeassistant.components.sensor import (
    RestoreSensor,
    SensorDeviceClass,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import UnitOfMass

from .entity import MiScaleEntity

if TYPE_CHECKING:
    from collections.abc import Callable

    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

    from .coordinator import MiScaleConfigEntry, MiScaleCoordinator, MiScaleData

PARALLEL_UPDATES = 0


@dataclass(frozen=True, kw_only=True)
class MiScaleSensorDescription(SensorEntityDescription):
    """Describes a scale sensor and where its value comes from."""

    value: Callable[[MiScaleData], float | datetime | None]


SENSORS: tuple[MiScaleSensorDescription, ...] = (
    # The weight other integrations consume: the device-class conventions of
    # Home Assistant's own scale integrations, and long-term statistics.
    MiScaleSensorDescription(
        key="weight",
        device_class=SensorDeviceClass.WEIGHT,
        native_unit_of_measurement=UnitOfMass.KILOGRAMS,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=2,
        value=lambda data: data.weight_kg,
    ),
    # Changes while the load settles. Disabled by default, and without a
    # state class, so nothing mistakes it for a measurement.
    MiScaleSensorDescription(
        key="live_weight",
        translation_key="live_weight",
        device_class=SensorDeviceClass.WEIGHT,
        native_unit_of_measurement=UnitOfMass.KILOGRAMS,
        suggested_display_precision=2,
        entity_registry_enabled_default=False,
        value=lambda data: data.live_kg,
    ),
    MiScaleSensorDescription(
        key="last_weigh_in",
        translation_key="last_weigh_in",
        device_class=SensorDeviceClass.TIMESTAMP,
        value=lambda data: data.measured_at,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,  # noqa: ARG001
    entry: MiScaleConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the scale's sensors."""
    async_add_entities(MiScaleSensor(entry.runtime_data, description) for description in SENSORS)


class MiScaleSensor(MiScaleEntity, RestoreSensor):
    """A scale sensor that keeps its last value across restarts."""

    def __init__(
        self, coordinator: MiScaleCoordinator, description: MiScaleSensorDescription
    ) -> None:
        """Keep the typed description for reading the value."""
        super().__init__(coordinator, description)
        self._description = description
        self._restored: float | datetime | None = None

    @override
    async def async_added_to_hass(self) -> None:
        """Restore the last value until a new one arrives."""
        await super().async_added_to_hass()
        if self._description.key == "live_weight":
            return
        last = await self.async_get_last_sensor_data()
        if last is not None and isinstance(last.native_value, float | int | datetime):
            self._restored = last.native_value

    @property
    @override
    def native_value(self) -> float | datetime | None:
        """The current value, or the restored one before any measurement."""
        value = self._description.value(self.coordinator.data)
        return self._restored if value is None else value
