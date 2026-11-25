"""Recognising the S200 from its MiBeacon advertisement, and checking its key."""

from __future__ import annotations

import miscale_native

from custom_components.miscale.mibeacon import beacon_key_rejected, is_s200, product_id

from .conftest import ADDRESS, BEACON_KEY, OTHER_SERVICE_DATA, S200_SERVICE_DATA, service_info


def test_product_id() -> None:
    """The product id follows the two frame-control bytes, little-endian."""
    assert product_id(service_info(service_data=S200_SERVICE_DATA)) == 0x45C9
    assert is_s200(service_info(service_data=S200_SERVICE_DATA))
    assert not is_s200(service_info(service_data=OTHER_SERVICE_DATA))


def test_truncated() -> None:
    """Too-short service data is not mistaken for anything."""
    assert product_id(service_info(service_data=b"\x30\x5a\xc9")) is None
    assert not is_s200(service_info(service_data=b""))


def test_beacon_key_rejected() -> None:
    """Only an encrypted advertisement that does not decrypt rejects a key."""
    encrypted = service_info(
        service_data=miscale_native.simulated_advertisement(
            BEACON_KEY, ADDRESS, 1, weigh_in=(7000, 1_764_000_000)
        )
    )
    assert not beacon_key_rejected(encrypted, BEACON_KEY)
    assert beacon_key_rejected(encrypted, "a5" * 16)
    assert not beacon_key_rejected(service_info(), "a5" * 16), "idle frames prove nothing"
    assert not beacon_key_rejected(service_info(service_data=b""), BEACON_KEY)
    assert not beacon_key_rejected(service_info(address="not-a-mac"), BEACON_KEY)
