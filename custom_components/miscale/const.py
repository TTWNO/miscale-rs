"""Constants for the Xiaomi Smart Scale S200 (local) integration."""

from typing import Final

DOMAIN: Final = "miscale"

CONF_TOKEN: Final = "token"  # noqa: S105 - a config key, not a secret
CONF_BEACON_KEY: Final = "beacon_key"
CONF_MID: Final = "mid"

MANUFACTURER: Final = "Xiaomi"
MODEL: Final = "Smart Scale S200"
MODEL_ID: Final = "MJTZC02YM"

# Version of the bundled native module; must match the Rust workspace.
NATIVE_VERSION: Final = "0.1.0"

# MiBeacon service data (Xiaomi 16-bit UUID FE95 in the Bluetooth base UUID).
MIBEACON_UUID: Final = "0000fe95-0000-1000-8000-00805f9b34fb"
# MiBeacon product ids of the S200 (as listed by xiaomi-ble).
S200_PRODUCT_IDS: Final = frozenset({0x45C9, 0x4C04, 0x4DCB})

# Seconds after a session ends (or a broadcast weigh-in arrives) before the
# scale may be polled again; the scale keeps advertising for a while after a
# weigh-in.
POLL_COOLDOWN_SECONDS: Final = 20.0

# A weigh-in the scale broadcasts within this many seconds of an estimated
# one, and within this many kilograms of it, is the same weigh-in, with the
# scale's own value. (An estimate averages readings within 0.30 kg.)
ESTIMATE_REFINE_SECONDS: Final = 120.0
ESTIMATE_REFINE_KG: Final = 1.0

# Consecutive encrypted advertisements that fail to decrypt before the
# beacon key is taken to be wrong (one could be a forgery).
WRONG_BEACON_KEY_AFTER: Final = 2

# Session timings (the proven prototype's): silence tolerated while logging
# in and opening the channel, and how long to wait for someone to stand on
# the scale once it is ready.
INACTIVITY_TIMEOUT_MS: Final = 10_000
MEASUREMENT_TIMEOUT_MS: Final = 45_000

EVENT_WEIGH_IN: Final = "weigh_in"
