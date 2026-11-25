"""Shared fixtures and helpers.

The scale is the Rust simulator (`miscale_native.SimulatedScale`, built with
the `sim` feature), behind a fake bleak client: the integration runs its real
code path, from discovery to entities, against simulated hardware.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal
from unittest.mock import patch

from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from habluetooth import BluetoothServiceInfoBleak, get_manager
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.miscale.const import CONF_TOKEN, DOMAIN, MIBEACON_UUID
from homeassistant import loader
from homeassistant.const import CONF_ADDRESS

if TYPE_CHECKING:
    from collections.abc import Generator

    from homeassistant.core import HomeAssistant
    from homeassistant.loader import BluetoothMatcher

# miauth's published test vector: a synthetic token, not a real device's.
TOKEN = "0cf5615003810d89c233a12a"
ADDRESS = "AA:BB:CC:DD:EE:FF"
DEV_RAND = bytes([0x90] * 16)

# A MiBeacon v5 idle frame with the S200's product id (0x45C9), from the
# public xiaomi-ble test data shape; the address bytes are the fake above.
S200_SERVICE_DATA = bytes.fromhex("305ac94500ffeeddccbbaa08")
OTHER_SERVICE_DATA = bytes.fromhex("305a5b0500ffeeddccbbaa08")

type Script = list[tuple[Literal["live", "final"], int]]


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations: None) -> None:
    """Let Home Assistant load the integration from custom_components."""


@pytest.fixture(autouse=True)
def _mock_bluetooth(mock_bluetooth: None) -> None:
    """Replace Bluetooth hardware with Home Assistant's test doubles."""


@pytest.fixture(autouse=True)
def _only_our_bluetooth_matchers() -> Generator[None]:
    """Keep other integrations' discovery (xiaomi_ble also claims FE95) out."""
    real = loader.async_get_bluetooth

    async def ours(hass: HomeAssistant) -> list[BluetoothMatcher]:
        return [matcher for matcher in await real(hass) if matcher["domain"] == DOMAIN]

    with patch("homeassistant.components.bluetooth.async_get_bluetooth", ours):
        yield


def service_info(
    address: str = ADDRESS, service_data: bytes = S200_SERVICE_DATA
) -> BluetoothServiceInfoBleak:
    """Build an advertisement from an awake scale."""
    device = BLEDevice(address, "MI SCALE", {})
    advertisement = AdvertisementData(
        local_name="MI SCALE",
        manufacturer_data={},
        service_data={MIBEACON_UUID: service_data},
        service_uuids=[],
        tx_power=None,
        rssi=-60,
        platform_data=(),
    )
    return BluetoothServiceInfoBleak(
        name="MI SCALE",
        address=address,
        rssi=-60,
        manufacturer_data={},
        service_data={MIBEACON_UUID: service_data},
        service_uuids=[],
        source="local",
        device=device,
        advertisement=advertisement,
        connectable=True,
        time=0.0,
        tx_power=None,
    )


def inject(info: BluetoothServiceInfoBleak) -> None:
    """Deliver an advertisement as if a scanner had heard it."""
    get_manager().scanner_adv_received(info)


def config_entry(**options: str) -> MockConfigEntry:
    """Build a config entry for the fake scale."""
    return MockConfigEntry(
        domain=DOMAIN,
        unique_id=ADDRESS,
        title="Smart Scale S200 EEFF",
        data={CONF_ADDRESS: ADDRESS, CONF_TOKEN: TOKEN},
        options=options,
    )


async def setup(hass: HomeAssistant, entry: MockConfigEntry) -> None:
    """Add and set up a config entry."""
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
