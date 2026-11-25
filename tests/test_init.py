"""Setting up, weighing, and the entities a weigh-in produces."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from unittest.mock import patch

from habluetooth import get_manager
from pytest_homeassistant_custom_component.common import (
    async_capture_events,
    mock_restore_cache_with_extra_data,
)

from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import (
    ATTR_DEVICE_CLASS,
    ATTR_UNIT_OF_MEASUREMENT,
    STATE_UNKNOWN,
    UnitOfMass,
)
from homeassistant.core import HomeAssistant, State
from homeassistant.helpers import device_registry as dr, entity_registry as er

from .conftest import ADDRESS, TOKEN, config_entry, inject, service_info, setup

if TYPE_CHECKING:
    from collections.abc import Callable

    from .conftest import FakeClient, Script

WEIGHT = "sensor.smart_scale_s200_eeff_weight"
LIVE = "sensor.smart_scale_s200_eeff_live_weight"
LAST = "sensor.smart_scale_s200_eeff_last_weigh_in"
EVENT = "event.smart_scale_s200_eeff_weigh_in"


def state_of(hass: HomeAssistant, entity_id: str) -> State:
    """Return an entity's state, which must exist."""
    state = hass.states.get(entity_id)
    assert state is not None, entity_id
    return state


async def weigh(hass: HomeAssistant) -> None:
    """Wake the scale (an advertisement) and let the session run."""
    inject(service_info())
    await hass.async_block_till_done(wait_background_tasks=True)


async def test_weigh_in(
    hass: HomeAssistant,
    connect: Callable[[Script], FakeClient],
    entity_registry: er.EntityRegistry,
    device_registry: dr.DeviceRegistry,
) -> None:
    """A wake-up connects, logs in, and publishes a standard HA weight."""
    client = connect([("live", 4120), ("live", 8355), ("final", 8360)])
    entry = config_entry()
    await setup(hass, entry)
    assert state_of(hass, WEIGHT).state == STATE_UNKNOWN
    await weigh(hass)

    weight = hass.states.get(WEIGHT)
    assert weight is not None
    assert float(weight.state) == 83.6
    assert weight.attributes[ATTR_DEVICE_CLASS] == "weight"
    assert weight.attributes[ATTR_UNIT_OF_MEASUREMENT] == UnitOfMass.KILOGRAMS
    assert weight.attributes["state_class"] == "measurement"
    last = hass.states.get(LAST)
    assert last is not None
    assert datetime.fromisoformat(last.state).tzinfo is not None
    assert client.disconnected, "the link is closed after the weigh-in"
    assert client.writes[0] == ("00000010-0000-1000-8000-00805f9b34fb", bytes([0x24, 0, 0, 0]))

    live = entity_registry.async_get(LIVE)
    assert live is not None
    assert live.disabled_by is er.RegistryEntryDisabler.INTEGRATION
    device = device_registry.async_get_device_by_connection(
        (dr.CONNECTION_BLUETOOTH, ADDRESS), entry.entry_id
    )
    assert device is not None
    assert (device.manufacturer, device.model, device.model_id) == (
        "Xiaomi",
        "Smart Scale S200",
        "MJTZC02YM",
    )


async def test_event_fires_on_every_weigh_in(
    hass: HomeAssistant,
    connect: Callable[[Script], FakeClient],
    no_cooldown: None,  # noqa: ARG001
) -> None:
    """The weigh-in event fires each time, even when the weight repeats."""
    connect([("final", 7000)])
    connect([("final", 7000)])
    events = async_capture_events(hass, "state_changed")
    await setup(hass, config_entry())
    await weigh(hass)
    # The scale sleeps, then wakes again (HA forgets it in between).
    forget_scale()
    await weigh(hass)
    fired = [e for e in events if e.data["entity_id"] == EVENT and e.data["new_state"]]
    assert len(fired) == 2
    state = hass.states.get(EVENT)
    assert state is not None
    assert state.attributes["event_type"] == "weigh_in"
    assert state.attributes["weight"] == 70.0
    assert state.attributes["unit_of_measurement"] == "kg"
    assert state.attributes["source"] == "final"


def forget_scale() -> None:
    """Make the next identical advertisement count as new (as after sleep)."""
    manager = get_manager()
    manager._all_history.pop(ADDRESS, None)
    manager._connectable_history.pop(ADDRESS, None)


async def test_cooldown(hass: HomeAssistant, connect: Callable[[Script], FakeClient]) -> None:
    """Advertisements right after a weigh-in do not reconnect."""
    connect([("final", 7000)])
    await setup(hass, config_entry())
    await weigh(hass)
    forget_scale()
    with patch("custom_components.miscale.coordinator.establish_connection") as establish:
        await weigh(hass)
    establish.assert_not_called()


async def test_nobody_steps_on(
    hass: HomeAssistant, connect: Callable[[Script], FakeClient]
) -> None:
    """Logged in, but no load before the window closes: no measurement."""
    client = connect([])
    with patch("custom_components.miscale.runner.MEASUREMENT_TIMEOUT_MS", 50):
        await setup(hass, config_entry())
        await weigh(hass)
    assert state_of(hass, WEIGHT).state == STATE_UNKNOWN
    assert client.disconnected


async def test_weight_is_restored(hass: HomeAssistant) -> None:
    """The last weight survives a restart, until the next weigh-in."""
    mock_restore_cache_with_extra_data(
        hass,
        [
            (
                State(WEIGHT, "81.0"),
                {"native_value": 81.0, "native_unit_of_measurement": "kg"},
            )
        ],
    )
    await setup(hass, config_entry())
    assert state_of(hass, WEIGHT).state == "81.0"


async def test_unload(hass: HomeAssistant) -> None:
    """The entry unloads cleanly."""
    entry = config_entry()
    await setup(hass, entry)
    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.NOT_LOADED


def test_token_fixture_is_synthetic() -> None:
    """The tests only ever use miauth's published vector."""
    assert TOKEN == "0cf5615003810d89c233a12a"
