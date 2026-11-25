"""Diagnostics, with secrets and identifiers redacted."""

from __future__ import annotations

from dataclasses import asdict
from typing import TYPE_CHECKING, Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.const import CONF_ADDRESS

from .const import CONF_BEACON_KEY, CONF_MID, CONF_TOKEN
from .native import native

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

    from .coordinator import MiScaleConfigEntry

TO_REDACT = {CONF_TOKEN, CONF_BEACON_KEY, CONF_MID, CONF_ADDRESS, "unique_id", "title"}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant,  # noqa: ARG001
    entry: MiScaleConfigEntry,
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    return {
        "entry": async_redact_data(entry.as_dict(), TO_REDACT),
        "native_version": native.__version__,
        "data": asdict(entry.runtime_data.data),
    }
