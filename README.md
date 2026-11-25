# miscale-rs

Local, cloud-free weight readings from the **Xiaomi Smart Scale S200**
(MJTZC02YM) in Home Assistant.

> **Status:** early. Everything is tested against a simulated scale; the
> hardware checklist in [`docs/hardware.md`](docs/hardware.md) has not been
> run yet. Nothing is released.

The S200 reports each weigh-in over an authenticated, encrypted Bluetooth
session, and also broadcasts the final weight in an encrypted advertisement,
though not reliably. This project implements both in small `no_std`, sans-io
Rust crates and drives them from a Home Assistant integration. The integration does all Bluetooth I/O through
Home Assistant's own Bluetooth stack, so local adapters and ESPHome
Bluetooth proxies both work.

The weight shows up as a **standard Home Assistant scale**, a weight sensor
in kilograms with long-term statistics, so other health integrations can use
it as a source. An event fires on every weigh-in, so automations can
announce each one.

See [`docs/design.md`](docs/design.md) for the architecture and the reasons
behind it, and [`docs/protocol.md`](docs/protocol.md) for the protocol.

## Requirements

- Home Assistant 2026.10 or later, on Home Assistant OS or the official
  container (x86_64 or aarch64). The bundled native module is built for
  their Alpine (musl) Python.
- A Bluetooth adapter or an ESPHome Bluetooth proxy in range of the scale.
  The proxy must allow active connections (`bluetooth_proxy: active: true`)
  and have a free connection slot.
- The scale's three credentials, all required:
  - its **token**, 24 hexadecimal digits, to log in to the scale;
  - its **beacon key**, 32 hexadecimal digits, to decrypt the weigh-ins it
    broadcasts;
  - the **account ID** of the Xiaomi account it is paired with, which the
    scale is told with every weigh-in.

### The credentials

The token and beacon key are created when the scale is first paired with a
Xiaomi account, and the scale checks a signature from Xiaomi's servers
during pairing, so they cannot be made locally. Get them once, then never
again:

1. Add the scale to the Mi Home app once. If the app refuses a scale from
   another region, switch the app's region to match the scale's (for
   example Mainland China).
2. Read the device's credentials with a cloud token extractor such as
   [Xiaomi-cloud-tokens-extractor](https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor):
   the token is its `TOKEN`, the beacon key its `BLE KEY`.
3. The account ID is the numeric ID of the Xiaomi account you paired the
   scale with (the account number, not the email address or phone number).

After that, nothing talks to Xiaomi: the integration talks to the scale
directly. The token and beacon key only change if the scale is
factory-reset and paired again. Home Assistant asks for new credentials
when it notices: the scale rejects the token, or its advertisements stop
decrypting. To change them yourself, use *Reconfigure* on the
integration.

## Installing

Not yet published. To install by hand, build the archive and copy it in:

```sh
make dist    # needs Rust, the x86_64/aarch64 musl targets, and uv
```

Unpack `dist/miscale.zip` into `config/custom_components/miscale/` and
restart Home Assistant. Once the repository is published with a release,
it can be added to HACS as a custom repository, which installs the same
archive.

## Setting up

Step on the scale or tap it so it advertises. Home Assistant discovers it
(*Settings → Devices & services*): confirm it and enter its token, beacon key
and account ID. From then on, every time the scale wakes up, the integration
connects, reads the weight and disconnects. When the scale broadcasts a
final weight, that is recorded too, without connecting; a weigh-in seen both
ways is recorded once.

## Entities

| entity | what it is |
|--------|------------|
| Weight | The last measured weight: device class *weight*, kg, state class *measurement*. Kept across restarts. |
| Weigh-in | An event that fires on every measurement, with `weight`, `unit_of_measurement` and `source`: `final` (read over the connection), `broadcast` (from the scale's advertisement), or `estimated` (the scale sent no final value). |
| Last weigh-in | When the last weight was measured. |
| Live weight | The value while the load settles. Disabled by default. |

### Announcing each weigh-in

For example, for someone who cannot read the scale's display:

```yaml
automation:
  - alias: Announce weigh-ins
    triggers:
      - trigger: state
        entity_id: event.smart_scale_s200_xxxx_weigh_in
        not_from: unavailable
    actions:
      - action: tts.speak
        target:
          entity_id: tts.home_assistant_cloud
        data:
          media_player_entity_id: media_player.bathroom
          message: >-
            {{ trigger.to_state.attributes.weight | round(1) }} kilograms
```

(The `xxxx` is the end of the scale's address; adjust the ids to yours.)

## Privacy and security

- The token and beacon key never leave Home Assistant. They are stored in
  the config entry, never logged, never sent back to the browser, and
  redacted from diagnostics, along with the account ID and the scale's
  address.
- Nothing is sent to Xiaomi or anywhere else at runtime.
- See [`SECURITY.md`](SECURITY.md) to report a vulnerability.

## Workspace

| crate | what it does |
|-------|--------------|
| [`mible-transport`](crates/mible-transport) | control-frame and parcel framing |
| [`mible-crypto`](crates/mible-crypto) | login token, key schedule, proofs, session cipher; beacon key and MiBeacon cipher |
| [`mible-beacon`](crates/mible-beacon) | MiBeacon advertisement codec and v4/v5 decryption |
| [`mible-auth`](crates/mible-auth) | login state machine |
| [`mible-spec`](crates/mible-spec) | spec frames and the encrypted spec channel |
| [`miscale`](crates/miscale) | the S200 weigh session and advertisement reader |
| [`miscale-sim`](crates/miscale-sim) | a simulated S200, for tests |
| [`miscale-py`](crates/miscale-py) | Python bindings (PyO3) for Home Assistant |

Everything but the Python binding is `no_std` and allocation-free, and none
of it does I/O. The [Home Assistant integration](custom_components/miscale)
is the only part that touches Bluetooth.

## Developing

```sh
make check   # formatting, clippy, tests, docs, typos, taplo, cargo-deny,
             # machete, the no_std build, and `make py`
make py      # build the native module into a uv virtualenv; ruff, mypy, pytest
make dist    # the release archive; `make dist-smoke` imports it on Alpine
make ci      # the full GitHub Actions workflow, locally, under act
```

Python tooling is managed by [uv](https://docs.astral.sh/uv/); the
native module is built with [maturin](https://www.maturin.rs/).

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the lint policy and commit
conventions.

## Credits

The login protocol is documented by
[miauth](https://github.com/dnandha/miauth) (whose published test vectors
the crypto tests use) and [Gadgetbridge](https://codeberg.org/Freeyourgadget/Gadgetbridge);
the S200's product ids come from
[xiaomi-ble](https://github.com/Bluetooth-Devices/xiaomi-ble). This project
reimplements the protocol from those descriptions and from observed traffic;
it contains no code from them.

## Licence

Licensed under either of

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))
- MIT licence ([`LICENSE-MIT`](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
licence, shall be dual licensed as above, without any additional terms or
conditions.
