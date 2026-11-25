"""Recognising the S200 from its MiBeacon advertisement."""

from __future__ import annotations

from custom_components.miscale.mibeacon import is_s200, product_id

from .conftest import OTHER_SERVICE_DATA, S200_SERVICE_DATA, service_info


def test_product_id() -> None:
    """The product id follows the two frame-control bytes, little-endian."""
    assert product_id(service_info(service_data=S200_SERVICE_DATA)) == 0x45C9
    assert is_s200(service_info(service_data=S200_SERVICE_DATA))
    assert not is_s200(service_info(service_data=OTHER_SERVICE_DATA))


def test_truncated() -> None:
    """Too-short service data is not mistaken for anything."""
    assert product_id(service_info(service_data=b"\x30\x5a\xc9")) is None
    assert not is_s200(service_info(service_data=b""))
