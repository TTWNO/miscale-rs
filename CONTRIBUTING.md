# Contributing

Thanks for helping. This project reads a health measurement for people who
may rely on it (it started as an accessibility project), so it is
deliberately strict.

## Ground rules

- **Never commit secrets or captures.** No real login tokens, bind keys,
  MAC addresses, account ids, device serials, or Bluetooth captures (btsnoop,
  pcap). Tests use synthetic keys or published known-answer vectors. CI runs
  `gitleaks` over the full history, but it cannot recognise *your* token, so
  this is on you.
- **No I/O below the integration.** Every Rust crate except the PyO3 binding
  is `#![no_std]`, allocation-free and sans-io: bytes in, bytes and events
  out. The caller supplies time and randomness.
- **No panics.** Library code must not panic on any input. Errors become
  events; capacities are checked; indexing and arithmetic are checked.

## Checks

`make check` runs the fast gates locally, including a build of every
library for a bare-metal target (`thumbv7em-none-eabihf`) to keep them
`no_std`; `make msrv` checks the minimum supported Rust version (1.89).
`make ci` runs the real GitHub Actions workflow under
[`act`](https://github.com/nektos/act) (build its runner image once with
`make act-image`); please run it before opening a pull request.

### Lint policy

Lints are configured once, in the workspace `Cargo.toml`, as warnings; CI
turns every warning into an error (`-D warnings`). That keeps builds working
on future compilers that add lints while still gating merges.

- `clippy::all`, `pedantic`, `nursery` and `cargo` are enabled wholesale.
- A curated set of `restriction` lints is enabled. The notable ones:
  - `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`,
    `arithmetic_side_effects`, `as_conversions`: library code cannot panic
    or silently truncate. Tests may unwrap, index and panic (`clippy.toml`).
  - `std_instead_of_core`, `alloc_instead_of_core`: keep `no_std` honest.
  - `allow_attributes`, `allow_attributes_without_reason`: use
    `#[expect(lint, reason = "...")]`, so stale suppressions fail the build.
  - `exhaustive_enums`, `exhaustive_structs`: public types are
    `#[non_exhaustive]` unless there is a reason not to be.
  - `missing_docs_in_private_items`: everything is documented, tests too
    (say what the test pins down).
  - `host_endian_bytes`: wire formats are always explicit about endianness.
- `unsafe_code` is forbidden.

## Commits

- [Conventional Commits](https://www.conventionalcommits.org/), checked by
  [`committed`](https://github.com/crate-ci/committed) (`committed.toml`).
- One logical change per commit; every commit builds and passes the checks.
- Write the body for a reviewer: what changed and why, not how.

## Licence

By contributing you agree that your contributions are dual licensed under
MIT OR Apache-2.0, as described in the README.
