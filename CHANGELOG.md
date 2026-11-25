# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `no_std`, allocation-free, sans-io Rust crates for the Xiaomi Mi BLE
  protocol: parcel framing (`mible-transport`), the login key schedule,
  proofs and AES-CCM session cipher (`mible-crypto`), the login state
  machine (`mible-auth`), the encrypted spec channel (`mible-spec`), and
  the Smart Scale S200 weigh session (`miscale`).
- `miscale-sim`, a simulated S200 for end-to-end tests without hardware.
- `miscale-py`, Python bindings (PyO3, stable ABI for CPython 3.12+).
- A Home Assistant integration (`custom_components/miscale`):
  - discovers the scale and asks for its token;
  - weighs whenever the scale wakes, through any local adapter or ESPHome
    proxy Home Assistant offers;
  - exposes a standard weight sensor (kg, long-term statistics), a weigh-in
    event, the last weigh-in time and a live weight (disabled by default);
  - asks for a new token if the scale rejects it;
  - offers an option for the account id sent to the scale;
  - provides diagnostics with secrets redacted.
- A release archive for HACS with native modules for x86_64 and aarch64
  (musl), smoke-tested on Alpine CPython.
- CI: formatting, clippy (pedantic, nursery, cargo, and curated restriction
  lints), tests, rustdoc, the no_std build, the MSRV, cargo-deny,
  cargo-machete, typos, taplo, actionlint, zizmor, gitleaks, Conventional
  Commits, ruff (every rule), mypy --strict, pytest, hassfest and HACS
  validation, and the release archive.
