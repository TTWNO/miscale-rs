"""Config flow: pick a discovered S200, enter its token."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, override

import probatio

from homeassistant.components.bluetooth import (
    BluetoothServiceInfoBleak,
    async_discovered_service_info,
)
from homeassistant.config_entries import (
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
    OptionsFlowWithReload,
)
from homeassistant.const import CONF_ADDRESS
from homeassistant.core import callback
from homeassistant.helpers.selector import TextSelector, TextSelectorConfig, TextSelectorType

from .const import CONF_MID, CONF_TOKEN, DOMAIN, MODEL
from .mibeacon import is_s200
from .native import native

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .coordinator import MiScaleConfigEntry

TOKEN_SCHEMA = probatio.Schema(
    {
        probatio.Required(CONF_TOKEN): TextSelector(
            TextSelectorConfig(type=TextSelectorType.PASSWORD)
        )
    }
)


def _title(info: BluetoothServiceInfoBleak) -> str:
    """Name the scale by its model and the end of its address."""
    return f"{MODEL} {info.address.replace(':', '')[-4:]}"


def _clean_token(user_input: Mapping[str, Any]) -> tuple[str, dict[str, str]]:
    """Normalise and validate the token; return it and any form errors."""
    token = "".join(str(user_input[CONF_TOKEN]).split()).lower()
    try:
        native.validate_token(token)
    except ValueError:
        return token, {CONF_TOKEN: "invalid_token"}
    return token, {}


class MiScaleConfigFlow(ConfigFlow, domain=DOMAIN):
    """Set up a scale."""

    VERSION = 1

    def __init__(self) -> None:
        """Start with nothing discovered."""
        self._info: BluetoothServiceInfoBleak | None = None
        self._discovered: dict[str, BluetoothServiceInfoBleak] = {}

    @override
    async def async_step_bluetooth(
        self, discovery_info: BluetoothServiceInfoBleak
    ) -> ConfigFlowResult:
        """Handle a scale found by the Bluetooth integration."""
        await self.async_set_unique_id(discovery_info.address)
        self._abort_if_unique_id_configured()
        if not is_s200(discovery_info):
            return self.async_abort(reason="not_supported")
        self._info = discovery_info
        self.context["title_placeholders"] = {"name": _title(discovery_info)}
        return await self.async_step_token()

    @override
    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Let the user pick a scale in range."""
        if user_input is not None:
            address = user_input[CONF_ADDRESS]
            await self.async_set_unique_id(address, raise_on_progress=False)
            self._abort_if_unique_id_configured()
            self._info = self._discovered[address]
            return await self.async_step_token()

        configured = self._async_current_ids(include_ignore=False)
        for info in async_discovered_service_info(self.hass, connectable=True):
            if info.address not in configured and is_s200(info):
                self._discovered[info.address] = info
        if not self._discovered:
            return self.async_abort(reason="no_devices_found")
        return self.async_show_form(
            step_id="user",
            data_schema=probatio.Schema(
                {
                    probatio.Required(CONF_ADDRESS): probatio.In(
                        {address: _title(info) for address, info in self._discovered.items()}
                    )
                }
            ),
        )

    async def async_step_token(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Ask for the scale's token."""
        info = self._info
        if info is None:  # pragma: no cover - flow steps always set it first
            return self.async_abort(reason="no_devices_found")
        errors: dict[str, str] = {}
        if user_input is not None:
            token, errors = _clean_token(user_input)
            if not errors:
                return self.async_create_entry(
                    title=_title(info), data={CONF_ADDRESS: info.address, CONF_TOKEN: token}
                )
        return self.async_show_form(
            step_id="token",
            data_schema=TOKEN_SCHEMA,
            errors=errors,
            description_placeholders={"name": _title(info)},
        )

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:  # noqa: ARG002
        """Start re-authentication after the scale rejected the stored token."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for a new token."""
        errors: dict[str, str] = {}
        if user_input is not None:
            token, errors = _clean_token(user_input)
            if not errors:
                return self.async_update_reload_and_abort(
                    self._get_reauth_entry(), data_updates={CONF_TOKEN: token}
                )
        return self.async_show_form(
            step_id="reauth_confirm", data_schema=TOKEN_SCHEMA, errors=errors
        )

    @staticmethod
    @callback
    @override
    def async_get_options_flow(config_entry: MiScaleConfigEntry) -> OptionsFlow:
        """Options: the account id sent to the scale."""
        return MiScaleOptionsFlow()


class MiScaleOptionsFlow(OptionsFlowWithReload):
    """Change the account id (mid) sent in the profile.

    Reloads the entry only when the options actually change: an update
    listener would also reload on unrelated updates (Bluetooth discovery
    refreshing the entry's discovery keys), which would start a second
    weigh-in from the replayed advertisement.
    """

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Show and save the options."""
        errors: dict[str, str] = {}
        if user_input is not None:
            mid = str(user_input.get(CONF_MID, "")).strip()
            if not mid:
                return self.async_create_entry(data={})
            try:
                native.validate_mid(mid)
            except ValueError:
                errors[CONF_MID] = "invalid_mid"
            else:
                return self.async_create_entry(data={CONF_MID: mid})
        current = self.config_entry.options.get(CONF_MID, "")
        return self.async_show_form(
            step_id="init",
            data_schema=probatio.Schema({probatio.Optional(CONF_MID, default=current): str}),
            errors=errors,
        )
