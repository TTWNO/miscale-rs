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
import miscale_native
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.miscale.const import CONF_TOKEN, DOMAIN, MIBEACON_UUID
from homeassistant import loader
from homeassistant.const import CONF_ADDRESS

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Iterator

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


class FakeClient:
    """Stands in for a connected BleakClient, with the simulator behind it."""

    def __init__(self, scale: miscale_native.SimulatedScale) -> None:
        """Wrap a simulated scale."""
        self.scale = scale
        self.callbacks: dict[str, Callable[[object, bytearray], None]] = {}
        self.writes: list[tuple[str, bytes]] = []
        self.disconnected = False

    async def start_notify(
        self, char_specifier: str, callback: Callable[[object, bytearray], None]
    ) -> None:
        """Remember the notification callback."""
        self.callbacks[char_specifier] = callback

    async def write_gatt_char(
        self, char_specifier: str, data: bytes, *, response: bool | None = None
    ) -> None:
        """Hand the write to the simulator and deliver what it answers."""
        assert response is False, "every protocol write is write-without-response"
        self.writes.append((char_specifier, bytes(data)))
        self.scale.handle_write(int(char_specifier[4:8], 16), bytes(data))
        while (note := self.scale.poll_notify()) is not None:
            uuid16, value = note
            self.callbacks[f"0000{uuid16:04x}-0000-1000-8000-00805f9b34fb"](None, bytearray(value))

    async def disconnect(self) -> bool:
        """Record the disconnect."""
        self.disconnected = True
        return True


@pytest.fixture
def connect() -> Iterator[Callable[[Script], FakeClient]]:
    """Patch `establish_connection` to connect to a simulated scale.

    Returns a function that, given a script, arms the next connection and
    returns the fake client it will use.
    """
    clients: list[FakeClient] = []

    def arm(script: Script, **kwargs: bool) -> FakeClient:
        client = FakeClient(miscale_native.SimulatedScale(TOKEN, DEV_RAND, script, **kwargs))
        clients.append(client)
        return client

    async def establish(*_args: object, **_kwargs: object) -> FakeClient:
        return clients.pop(0)

    with patch("custom_components.miscale.coordinator.establish_connection", establish):
        yield arm


async def setup(hass: HomeAssistant, entry: MockConfigEntry) -> None:
    """Add and set up a config entry."""
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
