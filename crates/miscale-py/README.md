# miscale-py

Python bindings ([PyO3](https://pyo3.rs), stable ABI for CPython 3.12+) for
the `miscale` sans-io weigh session, built as the `miscale_native` module.
The Home Assistant integration drives Bluetooth from Python and feeds bytes
through this module; the module itself performs no I/O.

The `sim` feature adds `SimulatedScale`, a device simulator for tests. It is
never part of a shipped build.

Part of [miscale-rs](../../README.md). Licensed under MIT OR Apache-2.0.
