"""The config flow: discovery, picking a scale, credentials, reauth, reconfigure."""

from __future__ import annotations

from typing import TYPE_CHECKING

import miscale_native
import pytest

from custom_components.miscale.const import CONF_BEACON_KEY, CONF_MID, CONF_TOKEN, DOMAIN
from homeassistant.config_entries import SOURCE_BLUETOOTH, SOURCE_USER
from homeassistant.const import CONF_ADDRESS
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.setup import async_setup_component

from .conftest import (
    ADDRESS,
    BEACON_KEY,
    MID,
    OTHER_SERVICE_DATA,
    TOKEN,
    config_entry,
    credentials,
    inject,
    service_info,
)

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

# Synthetic replacements for reauth and reconfigure.
NEW_TOKEN = "00112233445566778899aabb"  # gitleaks:allow - a synthetic test value
NEW_BEACON_KEY = "a5" * 16


def weigh_in_service_data(beacon_key: str = BEACON_KEY) -> bytes:
    """Build an encrypted weigh-in advertisement from the fake scale."""
    return miscale_native.simulated_advertisement(
        beacon_key, ADDRESS, 1, weigh_in=(7000, 1_764_000_000)
    )


async def test_bluetooth_discovery(hass: HomeAssistant) -> None:
    """A discovered S200 asks for all three credentials, then sets up."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_BLUETOOTH}, data=service_info()
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "credentials"

    spaced_token = " ".join([TOKEN[:12].upper(), TOKEN[12:]])
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        credentials(token=spaced_token, beacon_key=BEACON_KEY.upper(), mid=f" {MID} "),
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "Smart Scale S200 EEFF"
    assert result["data"] == {CONF_ADDRESS: ADDRESS, **credentials()}
    assert result["result"].unique_id == ADDRESS


@pytest.mark.parametrize(
    ("changes", "errors"),
    [
        ({CONF_TOKEN: "not a token"}, {CONF_TOKEN: "invalid_token"}),
        ({CONF_BEACON_KEY: TOKEN}, {CONF_BEACON_KEY: "invalid_beacon_key"}),
        ({CONF_MID: "12a"}, {CONF_MID: "invalid_mid"}),
        ({CONF_MID: ""}, {CONF_MID: "invalid_mid"}),
        (
            {CONF_TOKEN: "", CONF_BEACON_KEY: "", CONF_MID: ""},
            {
                CONF_TOKEN: "invalid_token",
                CONF_BEACON_KEY: "invalid_beacon_key",
                CONF_MID: "invalid_mid",
            },
        ),
    ],
)
async def test_every_credential_is_required(
    hass: HomeAssistant, changes: dict[str, str], errors: dict[str, str]
) -> None:
    """Each credential must be present and well-formed."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_BLUETOOTH}, data=service_info()
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], credentials(**changes)
    )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == errors


async def test_beacon_key_checked_against_advertisement(hass: HomeAssistant) -> None:
    """When the scale's advertisement is encrypted, the key must decrypt it."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_BLUETOOTH},
        data=service_info(service_data=weigh_in_service_data()),
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], credentials(beacon_key=NEW_BEACON_KEY)
    )
    assert result["errors"] == {CONF_BEACON_KEY: "wrong_beacon_key"}
    result = await hass.config_entries.flow.async_configure(result["flow_id"], credentials())
    assert result["type"] is FlowResultType.CREATE_ENTRY


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
    """The user picks a scale in range, then enters its credentials."""
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
    assert result["step_id"] == "credentials"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], credentials())
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"] == {CONF_ADDRESS: ADDRESS, **credentials()}


async def test_user_flow_checks_latest_advertisement(hass: HomeAssistant) -> None:
    """The beacon key is checked against the newest advertisement heard."""
    assert await async_setup_component(hass, "bluetooth", {})
    inject(service_info())
    await hass.async_block_till_done()
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_ADDRESS: ADDRESS}
    )
    inject(service_info(service_data=weigh_in_service_data()))
    await hass.async_block_till_done()
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], credentials(beacon_key=NEW_BEACON_KEY)
    )
    assert result["errors"] == {CONF_BEACON_KEY: "wrong_beacon_key"}


async def test_reauth(hass: HomeAssistant) -> None:
    """Reauth replaces the stored credentials; the account id is filled in."""
    entry = config_entry()
    entry.add_to_hass(hass)
    result = await entry.start_reauth_flow(hass)
    assert result["step_id"] == "reauth_confirm"
    schema = result["data_schema"]
    assert schema is not None
    suggested = {
        str(key): key.description["suggested_value"]
        for key in schema.schema
        if key.description and "suggested_value" in key.description
    }
    assert suggested == {CONF_MID: MID}, "secrets are never sent back to the browser"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], credentials(token="x")
    )
    assert result["errors"] == {CONF_TOKEN: "invalid_token"}
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], credentials(token=NEW_TOKEN, beacon_key=NEW_BEACON_KEY)
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert entry.data == {
        CONF_ADDRESS: ADDRESS,
        **credentials(token=NEW_TOKEN, beacon_key=NEW_BEACON_KEY),
    }


async def test_reconfigure(hass: HomeAssistant) -> None:
    """Reconfigure replaces all three credentials."""
    assert await async_setup_component(hass, "bluetooth", {})
    entry = config_entry()
    entry.add_to_hass(hass)
    inject(service_info(service_data=weigh_in_service_data(NEW_BEACON_KEY)))
    await hass.async_block_till_done()
    result = await entry.start_reconfigure_flow(hass)
    assert result["step_id"] == "reconfigure"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], credentials())
    assert result["errors"] == {CONF_BEACON_KEY: "wrong_beacon_key"}, "old key, re-paired scale"
    new = credentials(token=NEW_TOKEN, beacon_key=NEW_BEACON_KEY, mid="77")
    result = await hass.config_entries.flow.async_configure(result["flow_id"], new)
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    assert entry.data == {CONF_ADDRESS: ADDRESS, **new}
