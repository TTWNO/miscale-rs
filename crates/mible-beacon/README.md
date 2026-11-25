# mible-beacon

`no_std`, allocation-free codec for MiBeacon, the service data Xiaomi
devices advertise under the 16-bit UUID `0xFE95`: the frame header, the
objects it carries, and the decryption (and, for simulators, encryption) of
MiBeacon v4/v5 payloads under the device's beacon key. No I/O: pass it the
service data your Bluetooth stack reports.

Part of [miscale-rs](../../README.md). Licensed under MIT OR Apache-2.0.
