"""Diagnostics never contain the credentials or identifiers."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from pytest_homeassistant_custom_component.components.diagnostics import (
    get_diagnostics_for_config_entry,
)

from .conftest import ADDRESS, BEACON_KEY, MID, TOKEN, config_entry, setup

if TYPE_CHECKING:
    from pytest_homeassistant_custom_component.typing import ClientSessionGenerator

    from homeassistant.core import HomeAssistant


async def test_diagnostics_are_redacted(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
) -> None:
    """The token, beacon key, account id and address are redacted."""
    entry = config_entry()
    await setup(hass, entry)
    diagnostics = await get_diagnostics_for_config_entry(hass, hass_client, entry)
    text = json.dumps(diagnostics)
    for secret in (TOKEN, BEACON_KEY, MID, ADDRESS):
        assert secret not in text
    assert isinstance(diagnostics, dict)
    data = diagnostics["data"]
    assert isinstance(data, dict)
    assert data["weight_kg"] is None
