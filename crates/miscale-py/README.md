# miscale-py

Python bindings ([PyO3](https://pyo3.rs), stable ABI for CPython 3.12+) for
the `miscale` sans-io weigh session and advertisement reader, built as the
`miscale_native` module. The Home Assistant integration drives Bluetooth
from Python and feeds bytes through this module; the module itself performs
no I/O. Secrets stay on the Rust side once passed in: a `BeaconReader`
holds the beacon key, a `WeighSession` the token.

The `sim` feature adds `SimulatedScale` and `simulated_advertisement`, a
device simulator for tests. They are never part of a shipped build.

Part of [miscale-rs](../../README.md). Licensed under MIT OR Apache-2.0.
