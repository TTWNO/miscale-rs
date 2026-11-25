"""Constants for the Xiaomi Smart Scale S200 (local) integration."""

from typing import Final

DOMAIN: Final = "miscale"

CONF_TOKEN: Final = "token"  # noqa: S105 - a config key, not a secret

MODEL: Final = "Smart Scale S200"

# Version of the bundled native module; must match the Rust workspace.
NATIVE_VERSION: Final = "0.1.0"

# MiBeacon service data (Xiaomi 16-bit UUID FE95 in the Bluetooth base UUID).
MIBEACON_UUID: Final = "0000fe95-0000-1000-8000-00805f9b34fb"
# MiBeacon product ids of the S200 (as listed by xiaomi-ble).
S200_PRODUCT_IDS: Final = frozenset({0x45C9, 0x4C04, 0x4DCB})
