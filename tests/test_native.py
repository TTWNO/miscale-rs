"""Loading the native module."""

from __future__ import annotations

from pathlib import Path
import sys

import miscale_native
import pytest

from custom_components.miscale.const import NATIVE_VERSION
from custom_components.miscale.native import MODULE_NAME, bundled_path, load


@pytest.mark.parametrize(
    ("machine", "soabi", "expected"),
    [
        ("x86_64", "cpython-313-x86_64-linux-musl", "x86_64-linux-musl"),
        ("aarch64", "cpython-314-aarch64-linux-musl", "aarch64-linux-musl"),
        ("arm64", "cpython-314-aarch64-linux-musl", "aarch64-linux-musl"),
        ("AMD64", "cpython-314-x86_64-linux-musl", "x86_64-linux-musl"),
    ],
)
def test_bundled_path_on_alpine(machine: str, soabi: str, expected: str) -> None:
    """Home Assistant OS and the container get the matching musl build."""
    path = bundled_path(machine, soabi, Path("/x/native"))
    assert path == Path("/x/native") / NATIVE_VERSION / expected / "miscale_native.abi3.so"


@pytest.mark.parametrize(
    ("machine", "soabi"),
    [
        ("x86_64", "cpython-314-x86_64-linux-gnu"),
        ("armv7l", "cpython-314-arm-linux-musleabihf"),
        ("riscv64", "cpython-314-riscv64-linux-musl"),
    ],
)
def test_no_bundle_elsewhere(machine: str, soabi: str) -> None:
    """Other platforms fall back to an installed module."""
    assert bundled_path(machine, soabi) is None


def test_load_reuses_the_module() -> None:
    """The module is initialised once per process and then reused."""
    assert load() is sys.modules[MODULE_NAME] is miscale_native


def test_versions_agree() -> None:
    """The integration expects the native module it is shipped with."""
    assert miscale_native.__version__ == NATIVE_VERSION
