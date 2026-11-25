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

from custom_components.miscale.const import CONF_TOKEN, DOMAIN
from custom_components.miscale.runner import new_session
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import (
    ATTR_DEVICE_CLASS,
    ATTR_UNIT_OF_MEASUREMENT,
    EVENT_STATE_CHANGED,
    STATE_UNKNOWN,
    UnitOfMass,
)
from homeassistant.core import Event, EventStateChangedData, HomeAssistant, State
from homeassistant.helpers import device_registry as dr, entity_registry as er

from .conftest import (
    ADDRESS,
    BEACON_KEY,
    MID,
    SCALE_TIME,
    TOKEN,
    broadcast,
    config_entry,
    inject,
    service_info,
    setup,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from habluetooth import BluetoothServiceInfoBleak

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


async def test_credentials_reach_the_session(
    hass: HomeAssistant, connect: Callable[[Script], FakeClient]
) -> None:
    """Each weigh-in logs in with the token and tells the scale the account id."""
    connect([("final", 7000)])
    with patch("custom_components.miscale.coordinator.new_session", wraps=new_session) as started:
        await setup(hass, config_entry())
        await weigh(hass)
    started.assert_called_once_with(TOKEN, MID)


async def test_cooldown(hass: HomeAssistant, connect: Callable[[Script], FakeClient]) -> None:
    """Advertisements right after a weigh-in do not reconnect."""
    connect([("final", 7000)])
    await setup(hass, config_entry())
    await weigh(hass)
    forget_scale()
    with patch("custom_components.miscale.coordinator.establish_connection") as establish:
        await weigh(hass)
    establish.assert_not_called()


async def test_wrong_token_starts_reauth(
    hass: HomeAssistant, connect: Callable[[Script], FakeClient]
) -> None:
    """A token the scale rejects asks the user for a new one."""
    connect([("final", 7000)])
    entry = config_entry()
    entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        entry, data={**entry.data, CONF_TOKEN: "ffffffffffffffffffffffff"}
    )
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    await weigh(hass)
    assert state_of(hass, WEIGHT).state == STATE_UNKNOWN
    flows = hass.config_entries.flow.async_progress_by_handler(DOMAIN)
    assert [flow["context"]["source"] for flow in flows] == ["reauth"]


def weigh_in_events(hass: HomeAssistant) -> list[State]:
    """Start recording the weigh-in event's new states."""
    fired: list[State] = []

    def record(event: Event[EventStateChangedData]) -> None:
        if event.data["entity_id"] == EVENT and (state := event.data["new_state"]) is not None:
            fired.append(state)

    hass.bus.async_listen(EVENT_STATE_CHANGED, record)
    return fired


async def hear(hass: HomeAssistant, info: BluetoothServiceInfoBleak) -> None:
    """Deliver an advertisement and let everything it starts finish."""
    inject(info)
    await hass.async_block_till_done(wait_background_tasks=True)


async def test_broadcast_weigh_in(hass: HomeAssistant) -> None:
    """A weigh-in the scale broadcasts is recorded without connecting."""
    await setup(hass, config_entry())
    fired = weigh_in_events(hass)
    with patch("custom_components.miscale.coordinator.establish_connection") as establish:
        await hear(hass, broadcast(7000, 1))
    establish.assert_not_called()
    assert float(state_of(hass, WEIGHT).state) == 70.0
    assert [state.attributes["source"] for state in fired] == ["broadcast"]
    assert state_of(hass, LAST).state != STATE_UNKNOWN


async def test_weigh_in_reported_twice_is_recorded_once(
    hass: HomeAssistant, connect: Callable[[Script], FakeClient]
) -> None:
    """The broadcast of a weigh-in read over the connection is not a new one."""
    connect([("final", 7000)])
    await setup(hass, config_entry())
    fired = weigh_in_events(hass)
    await weigh(hass)
    await hear(hass, broadcast(7000, 1, scale_time=SCALE_TIME))
    await hear(hass, broadcast(7000, 2, scale_time=SCALE_TIME))
    assert [state.attributes["source"] for state in fired] == ["final"]
    # The next weigh-in has a later timestamp, even at the same weight.
    await hear(hass, broadcast(7000, 3, scale_time=SCALE_TIME + 60))
    assert [state.attributes["source"] for state in fired] == ["final", "broadcast"]


async def test_broadcast_refines_an_estimate(
    hass: HomeAssistant, connect: Callable[[Script], FakeClient]
) -> None:
    """The scale's broadcast value replaces an estimate of the same weigh-in."""
    connect([*[("live", centi) for centi in (8350, 8360, 8355, 8358, 8362)], ("live", 40)])
    await setup(hass, config_entry())
    fired = weigh_in_events(hass)
    await weigh(hass)
    assert float(state_of(hass, WEIGHT).state) == 83.57
    await hear(hass, broadcast(8360, 1))
    assert float(state_of(hass, WEIGHT).state) == 83.6
    assert [state.attributes["source"] for state in fired] == ["estimated"], "one weigh-in"


async def test_someone_else_after_an_estimate(
    hass: HomeAssistant, connect: Callable[[Script], FakeClient]
) -> None:
    """A broadcast far from the estimate is another weigh-in, with its own event."""
    connect([*[("live", centi) for centi in (8350, 8360, 8355, 8358, 8362)], ("live", 40)])
    await setup(hass, config_entry())
    fired = weigh_in_events(hass)
    await weigh(hass)
    await hear(hass, broadcast(6400, 1))
    assert float(state_of(hass, WEIGHT).state) == 64.0
    assert [state.attributes["source"] for state in fired] == ["estimated", "broadcast"]


async def test_wrong_beacon_key_starts_reauth(
    hass: HomeAssistant, connect: Callable[[Script], FakeClient]
) -> None:
    """Advertisements that keep failing to decrypt ask for new credentials."""
    connect([("final", 7000)])
    await setup(hass, config_entry())
    await hear(hass, broadcast(7000, 1, beacon_key="a5" * 16))
    assert not hass.config_entries.flow.async_progress_by_handler(DOMAIN), "one could be forged"
    await hear(hass, broadcast(7000, 2, beacon_key="a5" * 16))
    flows = hass.config_entries.flow.async_progress_by_handler(DOMAIN)
    assert [flow["context"]["source"] for flow in flows] == ["reauth"]


async def test_one_undecryptable_advertisement_is_forgiven(
    hass: HomeAssistant, connect: Callable[[Script], FakeClient]
) -> None:
    """A good advertisement between bad ones resets the count."""
    connect([("final", 7000)])
    await setup(hass, config_entry())
    await hear(hass, broadcast(None, 1))
    await hear(hass, broadcast(7000, 2, beacon_key="a5" * 16))
    await hear(hass, broadcast(7100, 3))
    await hear(hass, broadcast(7000, 4, beacon_key="a5" * 16))
    assert not hass.config_entries.flow.async_progress_by_handler(DOMAIN)


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


def test_fixtures_are_synthetic() -> None:
    """The tests only ever use miauth's published token and made-up values."""
    assert TOKEN == "0cf5615003810d89c233a12a"
    assert BEACON_KEY == "5a" * 16
    assert MID == "4242"
