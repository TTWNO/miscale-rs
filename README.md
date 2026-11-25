# miscale-rs

Local, account-free weight readings from the **Xiaomi Smart Scale S200**
(MJTZC02YM) in Home Assistant.

> Status: early development. Nothing is released yet.

The scale only reports a weight over an authenticated, encrypted Bluetooth
session. This project implements that session as a set of small `no_std`,
sans-io Rust crates, and drives them from a Home Assistant custom integration
that does all Bluetooth I/O through HA's own Bluetooth stack (local adapters
and ESPHome Bluetooth proxies alike).

See [`docs/design.md`](docs/design.md) for the architecture and the reasons
behind it.

## Workspace

| crate | what it does |
|-------|--------------|
| [`mible-transport`](crates/mible-transport) | control-frame and parcel framing |
| [`mible-crypto`](crates/mible-crypto) | login token, key schedule, proofs, session cipher |
| [`mible-auth`](crates/mible-auth) | login state machine |
| [`mible-spec`](crates/mible-spec) | spec frames and the encrypted spec channel |

## Developing

```sh
make check   # formatting, clippy, tests, docs, typos, taplo, cargo-deny, machete
make ci      # the full GitHub Actions workflow, locally, under act
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the lint policy and commit
conventions.

## Licence

Licensed under either of

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))
- MIT licence ([`LICENSE-MIT`](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
licence, shall be dual licensed as above, without any additional terms or
conditions.
