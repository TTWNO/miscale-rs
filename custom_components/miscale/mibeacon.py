"""Recognise the S200 from its MiBeacon advertisement."""

from typing import TYPE_CHECKING

from .const import MIBEACON_UUID, S200_PRODUCT_IDS
from .native import native

if TYPE_CHECKING:
    from homeassistant.components.bluetooth import BluetoothServiceInfoBleak

# Frame control (2 bytes, LE) precedes the product id (2 bytes, LE).
_PRODUCT_ID = slice(2, 4)


def product_id(service_info: BluetoothServiceInfoBleak) -> int | None:
    """Return the MiBeacon product id, or None if there is no MiBeacon."""
    data = service_info.service_data.get(MIBEACON_UUID)
    if data is None or len(data) < _PRODUCT_ID.stop:
        return None
    return int.from_bytes(data[_PRODUCT_ID], "little")


def is_s200(service_info: BluetoothServiceInfoBleak) -> bool:
    """Return whether the advertisement comes from a Smart Scale S200."""
    return product_id(service_info) in S200_PRODUCT_IDS


def beacon_key_rejected(service_info: BluetoothServiceInfoBleak, beacon_key: str) -> bool:
    """Return whether the advertisement is encrypted but `beacon_key` does not decrypt it."""
    data = service_info.service_data.get(MIBEACON_UUID)
    if data is None:
        return False
    try:
        reader = native.BeaconReader(beacon_key, service_info.address)
    except ValueError:  # an address that is not a MAC (only on some test hosts)
        return False
    beacon = reader.read(data)
    return beacon is not None and beacon.encrypted and not beacon.authentic
