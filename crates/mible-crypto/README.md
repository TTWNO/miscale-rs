# mible-crypto

`no_std`, allocation-free cryptography for Xiaomi Mi BLE devices: the
redacted, zeroising login `Token`, the HKDF-SHA256 login key schedule, the
HMAC-SHA256 proofs, and the AES-128-CCM session cipher; and the redacted,
zeroising `BeaconKey` with the AES-128-CCM cipher for MiBeacon v4/v5
advertisement payloads.

Built on the RustCrypto crates. Part of [miscale-rs](../../README.md).
Licensed under MIT OR Apache-2.0.
