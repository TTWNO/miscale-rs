"""Load the `miscale_native` extension module, once per process.

Release builds of this integration bundle prebuilt shared objects under
`native/<version>/<arch>-linux-musl/` (Home Assistant OS and the official
container run CPython on Alpine). The directory is versioned so an update
never overwrites a library the running process has mapped; a restart picks
up the new one. Without a bundled build (development, tests), an installed
`miscale_native` is imported instead.

A PyO3 module can only be initialised once per process, so a module already
in `sys.modules` is always reused (for example after an integration reload).
"""

from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path
import platform
import sys
import sysconfig
from typing import TYPE_CHECKING

from .const import NATIVE_VERSION

if TYPE_CHECKING:
    from types import ModuleType

MODULE_NAME = "miscale_native"

_ARCHES = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}


def bundled_path(
    machine: str | None = None,
    soabi: str | None = None,
    base: Path | None = None,
) -> Path | None:
    """Return where the bundled module for this interpreter would live.

    None if this platform is not one a bundle is built for (anything but
    x86_64/aarch64 musl CPython).
    """
    machine = (machine if machine is not None else platform.machine()).lower()
    soabi = soabi if soabi is not None else (sysconfig.get_config_var("SOABI") or "")
    arch = _ARCHES.get(machine)
    if arch is None or "linux-musl" not in soabi:
        return None
    base = base if base is not None else Path(__file__).parent / "native"
    return base / NATIVE_VERSION / f"{arch}-linux-musl" / f"{MODULE_NAME}.abi3.so"


def load() -> ModuleType:
    """Return the native module, loading it on first use."""
    if (module := sys.modules.get(MODULE_NAME)) is not None:
        return module
    path = bundled_path()
    if path is not None and path.is_file():
        spec = importlib.util.spec_from_file_location(MODULE_NAME, path)
        if spec is None or spec.loader is None:
            msg = f"cannot load {path}"
            raise ImportError(msg)
        module = importlib.util.module_from_spec(spec)
        sys.modules[MODULE_NAME] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            del sys.modules[MODULE_NAME]
            raise
        return module
    return importlib.import_module(MODULE_NAME)


if TYPE_CHECKING:
    import miscale_native as native
else:
    native = load()

__all__ = ["MODULE_NAME", "bundled_path", "load", "native"]
