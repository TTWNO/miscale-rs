# Local entry points that mirror .github/workflows/ci.yml.
# `make check` runs the fast gates; `make ci` runs the workflow itself under act.

CARGO ?= cargo
MSRV := 1.89
ACT_SOCKET ?= unix:///run/user/$(shell id -u)/podman/podman.sock

.PHONY: check fmt fmt-check clippy test doc deny machete typos taplo nostd msrv py py-env dist dist-smoke ci act-image

check: fmt-check clippy test doc typos taplo deny machete nostd py

fmt:
	$(CARGO) fmt --all
	taplo fmt

fmt-check:
	$(CARGO) fmt --all --check

clippy:
	$(CARGO) clippy --workspace --all-targets --all-features --locked -- -D warnings

test:
	$(CARGO) nextest run --workspace --all-features --locked
	$(CARGO) test --workspace --exclude miscale-py --all-features --locked --doc

doc:
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --workspace --all-features --no-deps --locked

deny:
	$(CARGO) deny --all-features check

machete:
	$(CARGO) machete

typos:
	typos

# Library targets of every crate but the Python binding must build without std.
NOSTD_TARGET := thumbv7em-none-eabihf
nostd:
	$(CARGO) build --workspace --exclude miscale-py --locked --target $(NOSTD_TARGET)

msrv:
	$(CARGO) +$(MSRV) check --workspace --all-targets --all-features --locked

# Python: build the native module (with the test simulator) into a uv-managed
# virtualenv, then lint, type-check and test the Python side.
UV ?= uv
CONTAINER ?= podman
py-env:
	$(UV) sync --locked
	$(UV) run --no-sync maturin develop --uv --locked -m crates/miscale-py/Cargo.toml --features sim

py: py-env
	$(UV) run --no-sync ruff format --check
	$(UV) run --no-sync ruff check
	$(UV) run --no-sync mypy
	$(UV) run --no-sync pytest

# Release archive for HACS: the integration plus stripped native modules for
# x86_64 and aarch64 musl (Home Assistant OS and container), cross-built with
# zig. Needs the two rustup targets.
DIST_TARGETS := x86_64-unknown-linux-musl aarch64-unknown-linux-musl
WHEELS := target/dist-wheels
dist:
	rm -rf $(WHEELS)
	for target in $(DIST_TARGETS); do \
		$(UV) run --locked --group dist maturin build --release --locked --strip --zig \
			--target $$target --compatibility musllinux_1_2 \
			-m crates/miscale-py/Cargo.toml --out $(WHEELS) || exit 1; \
	done
	$(UV) run --no-sync python scripts/package.py --out dist/miscale.zip $(WHEELS)/*.whl

# Import each packaged module through the integration's own loader in a bare
# Alpine CPython, the libc and Python of Home Assistant OS (arm64 needs
# qemu-user binfmt on an x86_64 host).
SMOKE_IMAGE ?= docker.io/library/python:3.14-alpine
SMOKE_PLATFORMS ?= linux/amd64 linux/arm64
dist-smoke:
	for platform in $(SMOKE_PLATFORMS); do \
		$(CONTAINER) run --rm --platform $$platform --network none \
			-v "$(CURDIR):/src:ro" -w /src $(SMOKE_IMAGE) \
			python scripts/smoke_bundle.py dist/miscale.zip || exit 1; \
	done

taplo:
	taplo fmt --check
	taplo lint

# Run the GitHub Actions workflow locally under act (needs a Docker-compatible
# socket). ACT_FLAGS defaults suit rootless podman: no socket mount into job
# containers, no re-pull, and an oom_score_adj equal to the podman service's
# (rootless crun cannot lower it on `exec`). Override as needed.
ACT_IMAGE ?= localhost/act-rust:latest
ACT_FLAGS ?= -P ubuntu-latest=$(ACT_IMAGE) --container-daemon-socket - --pull=false \
	--container-options=--oom-score-adj=200 --concurrent-jobs 2
ci:
	DOCKER_HOST=$(ACT_SOCKET) act $(ACT_FLAGS)

# Build the local runner image used by `make ci` (see .github/act/Containerfile).
act-image:
	$(CONTAINER) build --network host -t $(ACT_IMAGE) -f .github/act/Containerfile .github/act
