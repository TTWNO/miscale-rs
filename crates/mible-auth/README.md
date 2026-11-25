# mible-auth

Sans-io, `no_std`, allocation-free login state machine for Xiaomi Mi BLE
"standard auth" devices: given the device's token and a fresh random, it
produces the writes to make and consumes the notifications received, and
ends either authenticated (with a session cipher) or failed.

Part of [miscale-rs](../../README.md). Licensed under MIT OR Apache-2.0.
