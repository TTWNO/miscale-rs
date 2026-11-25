"""Config flow: pick a discovered S200, enter what it was paired with."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, override

import probatio

from homeassistant.components.bluetooth import (
    BluetoothServiceInfoBleak,
    async_discovered_service_info,
    async_last_service_info,
)
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_ADDRESS
from homeassistant.helpers.selector import TextSelector, TextSelectorConfig, TextSelectorType

from .const import CONF_BEACON_KEY, CONF_MID, CONF_TOKEN, DOMAIN, MODEL
from .mibeacon import beacon_key_rejected, is_s200
from .native import native

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

_SECRET = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))

# Everything the scale was paired with; each is needed for it to fully work.
CREDENTIALS_SCHEMA = probatio.Schema(
    {
        probatio.Required(CONF_TOKEN): _SECRET,
        probatio.Required(CONF_BEACON_KEY): _SECRET,
        probatio.Required(CONF_MID): TextSelector(),
    }
)

# How each credential is checked, and the form error when it is malformed.
_VALIDATORS: tuple[tuple[str, Callable[[str], None], str], ...] = (
    (CONF_TOKEN, native.validate_token, "invalid_token"),
    (CONF_BEACON_KEY, native.validate_beacon_key, "invalid_beacon_key"),
    (CONF_MID, native.validate_mid, "invalid_mid"),
)


def _title(info: BluetoothServiceInfoBleak) -> str:
    """Name the scale by its model and the end of its address."""
    return f"{MODEL} {info.address.replace(':', '')[-4:]}"


def _compact(value: object) -> str:
    """Drop whitespace (pasted values are often split) and lower-case."""
    return "".join(str(value).split()).lower()


def _clean_credentials(
    user_input: Mapping[str, Any], latest: BluetoothServiceInfoBleak | None
) -> tuple[dict[str, str], dict[str, str]]:
    """Normalise and validate the credentials; return them and any form errors.

    The beacon key is also checked against the scale's latest advertisement,
    when that one is encrypted.
    """
    credentials = {
        CONF_TOKEN: _compact(user_input[CONF_TOKEN]),
        CONF_BEACON_KEY: _compact(user_input[CONF_BEACON_KEY]),
        CONF_MID: str(user_input[CONF_MID]).strip(),
    }
    errors: dict[str, str] = {}
    for key, validate, error in _VALIDATORS:
        try:
            validate(credentials[key])
        except ValueError:
            errors[key] = error
    if (
        not errors
        and latest is not None
        and beacon_key_rejected(latest, credentials[CONF_BEACON_KEY])
    ):
        errors[CONF_BEACON_KEY] = "wrong_beacon_key"
    return credentials, errors


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
        return await self.async_step_credentials()

    @override
    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Let the user pick a scale in range."""
        if user_input is not None:
            address = user_input[CONF_ADDRESS]
            await self.async_set_unique_id(address, raise_on_progress=False)
            self._abort_if_unique_id_configured()
            self._info = self._discovered[address]
            return await self.async_step_credentials()

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

    async def async_step_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for the scale's token, beacon key and account id."""
        info = self._info
        if info is None:  # pragma: no cover - flow steps always set it first
            return self.async_abort(reason="no_devices_found")
        errors: dict[str, str] = {}
        if user_input is not None:
            credentials, errors = _clean_credentials(user_input, self._latest(info.address))
            if not errors:
                return self.async_create_entry(
                    title=_title(info), data={CONF_ADDRESS: info.address, **credentials}
                )
        return self.async_show_form(
            step_id="credentials",
            data_schema=CREDENTIALS_SCHEMA,
            errors=errors,
            description_placeholders={"name": _title(info)},
        )

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:  # noqa: ARG002
        """Start re-authentication after the scale rejected the stored credentials."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for the scale's current credentials."""
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            credentials, errors = _clean_credentials(
                user_input, self._latest(entry.data[CONF_ADDRESS])
            )
            if not errors:
                return self.async_update_reload_and_abort(entry, data_updates=credentials)
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=self._schema_for(entry.data[CONF_MID], user_input),
            errors=errors,
        )

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Change the credentials, e.g. after the scale was paired again."""
        entry = self._get_reconfigure_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            credentials, errors = _clean_credentials(
                user_input, self._latest(entry.data[CONF_ADDRESS])
            )
            if not errors:
                return self.async_update_reload_and_abort(entry, data_updates=credentials)
        return self.async_show_form(
            step_id="reconfigure",
            data_schema=self._schema_for(entry.data[CONF_MID], user_input),
            errors=errors,
        )

    def _schema_for(self, mid: str, user_input: Mapping[str, Any] | None) -> probatio.Schema:
        """Return the credentials form, with the account id filled in.

        The token and beacon key are never sent back to the browser.
        """
        suggested = {CONF_MID: mid if user_input is None else user_input[CONF_MID]}
        return self.add_suggested_values_to_schema(CREDENTIALS_SCHEMA, suggested)

    def _latest(self, address: str) -> BluetoothServiceInfoBleak | None:
        """Return the scale's latest advertisement, from any adapter or proxy."""
        return async_last_service_info(self.hass, address, connectable=False) or (
            self._info if self._info is not None and self._info.address == address else None
        )
