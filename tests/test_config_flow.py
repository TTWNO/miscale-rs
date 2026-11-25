"""The config flow: discovery, picking a scale, the token, reauth, options."""

from __future__ import annotations

from typing import TYPE_CHECKING

from custom_components.miscale.const import CONF_TOKEN, DOMAIN
from homeassistant.config_entries import SOURCE_BLUETOOTH, SOURCE_USER
from homeassistant.const import CONF_ADDRESS
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.setup import async_setup_component

from .conftest import ADDRESS, OTHER_SERVICE_DATA, TOKEN, config_entry, inject, service_info

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant


async def test_bluetooth_discovery(hass: HomeAssistant) -> None:
    """A discovered S200 asks for its token, rejects a bad one, then sets up."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_BLUETOOTH}, data=service_info()
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "token"

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_TOKEN: "not a token"}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {CONF_TOKEN: "invalid_token"}

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_TOKEN: " ".join([TOKEN[:12].upper(), TOKEN[12:]])}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "Smart Scale S200 EEFF"
    assert result["data"] == {CONF_ADDRESS: ADDRESS, CONF_TOKEN: TOKEN}
    assert result["result"].unique_id == ADDRESS


async def test_bluetooth_discovery_other_device(hass: HomeAssistant) -> None:
    """Other Xiaomi devices advertise FE95 too; they are turned away."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_BLUETOOTH},
        data=service_info(service_data=OTHER_SERVICE_DATA),
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "not_supported"


async def test_bluetooth_discovery_already_configured(hass: HomeAssistant) -> None:
    """A scale that is already set up is not offered again."""
    config_entry().add_to_hass(hass)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_BLUETOOTH}, data=service_info()
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


async def test_user_flow_without_scales(hass: HomeAssistant) -> None:
    """With no scale in range, the user flow says so."""
    assert await async_setup_component(hass, "bluetooth", {})
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "no_devices_found"


async def test_user_flow(hass: HomeAssistant) -> None:
    """The user picks a scale in range, then enters its token."""
    assert await async_setup_component(hass, "bluetooth", {})
    inject(service_info())
    inject(service_info("11:22:33:44:55:66", OTHER_SERVICE_DATA))
    await hass.async_block_till_done()
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"
    schema = result["data_schema"]
    assert schema is not None
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_ADDRESS: ADDRESS}
    )
    assert result["step_id"] == "token"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {CONF_TOKEN: TOKEN})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"] == {CONF_ADDRESS: ADDRESS, CONF_TOKEN: TOKEN}
