"""Base entity for the scale."""

from __future__ import annotations

from typing import TYPE_CHECKING, override

from homeassistant.components.bluetooth.passive_update_coordinator import (
    PassiveBluetoothCoordinatorEntity,
)
from homeassistant.helpers.device_registry import CONNECTION_BLUETOOTH, DeviceInfo

from .const import MANUFACTURER, MODEL, MODEL_ID
from .coordinator import MiScaleCoordinator

if TYPE_CHECKING:
    from homeassistant.helpers.entity import EntityDescription


class MiScaleEntity(PassiveBluetoothCoordinatorEntity[MiScaleCoordinator]):
    """An entity of one scale."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: MiScaleCoordinator, description: EntityDescription) -> None:
        """Attach the entity to the scale's device."""
        super().__init__(coordinator)
        self.entity_description = description
        address = coordinator.address
        self._attr_unique_id = f"{address}-{description.key}"
        self._attr_device_info = DeviceInfo(
            connections={(CONNECTION_BLUETOOTH, address)},
            manufacturer=MANUFACTURER,
            model=MODEL,
            model_id=MODEL_ID,
        )

    @property
    @override
    def available(self) -> bool:
        """Stay available while the scale sleeps between weigh-ins."""
        return True
