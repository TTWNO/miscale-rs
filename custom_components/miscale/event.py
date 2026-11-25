"""An event on every weigh-in, even when the weight repeats.

A sensor's state does not change when someone weighs the same twice, so
automations that announce each weigh-in (for example by text to speech)
listen to this event entity instead.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, override

from homeassistant.components.event import EventEntity, EventEntityDescription
from homeassistant.const import UnitOfMass
from homeassistant.core import HomeAssistant, callback

from .const import EVENT_WEIGH_IN
from .entity import MiScaleEntity

if TYPE_CHECKING:
    from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

    from .coordinator import MiScaleConfigEntry, MiScaleCoordinator

PARALLEL_UPDATES = 0

WEIGH_IN = EventEntityDescription(
    key=EVENT_WEIGH_IN,
    translation_key=EVENT_WEIGH_IN,
    event_types=[EVENT_WEIGH_IN],
)


async def async_setup_entry(
    hass: HomeAssistant,  # noqa: ARG001
    entry: MiScaleConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the weigh-in event."""
    async_add_entities([MiScaleWeighInEvent(entry.runtime_data, WEIGH_IN)])


class MiScaleWeighInEvent(MiScaleEntity, EventEntity):
    """Fires once per measurement."""

    def __init__(
        self, coordinator: MiScaleCoordinator, description: EventEntityDescription
    ) -> None:
        """Remember which measurement was last announced."""
        super().__init__(coordinator, description)
        self._seen = coordinator.data.measurement_count

    @callback
    @override
    def _handle_coordinator_update(self) -> None:
        """Fire for each new measurement, and only then."""
        data = self.coordinator.data
        if data.measurement_count == self._seen:
            return
        self._seen = data.measurement_count
        self._trigger_event(
            EVENT_WEIGH_IN,
            {
                "weight": data.weight_kg,
                "unit_of_measurement": UnitOfMass.KILOGRAMS,
                "source": data.source,
            },
        )
        self.async_write_ha_state()
