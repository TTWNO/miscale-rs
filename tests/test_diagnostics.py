"""Diagnostics never contain the token or identifiers."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from pytest_homeassistant_custom_component.components.diagnostics import (
    get_diagnostics_for_config_entry,
)

from custom_components.miscale.const import CONF_MID

from .conftest import ADDRESS, TOKEN, config_entry, setup

if TYPE_CHECKING:
    from pytest_homeassistant_custom_component.typing import ClientSessionGenerator

    from homeassistant.core import HomeAssistant


async def test_diagnostics_are_redacted(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
) -> None:
    """The token, account id and address are redacted."""
    entry = config_entry(**{CONF_MID: "4242"})
    await setup(hass, entry)
    diagnostics = await get_diagnostics_for_config_entry(hass, hass_client, entry)
    text = json.dumps(diagnostics)
    for secret in (TOKEN, "4242", ADDRESS):
        assert secret not in text
    assert isinstance(diagnostics, dict)
    data = diagnostics["data"]
    assert isinstance(data, dict)
    assert data["weight_kg"] is None
