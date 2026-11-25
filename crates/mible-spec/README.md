# mible-spec

Sans-io, `no_std`, allocation-free MIoT "spec" channel for Xiaomi Mi BLE
devices, used after login: the `<len> 20 <seq> <body>` frame codec, string
TLVs, and an encrypted channel that seals, fragments, reassembles and opens
messages on characteristics `0x001A` / `0x001B`.

Part of [miscale-rs](../../README.md). Licensed under MIT OR Apache-2.0.
