"""Smoke-test a packaged integration's native module on the current platform.

Meant to run inside a bare Alpine CPython container (the libc and Python of
Home Assistant OS and the official container), with only the standard
library. It unpacks the archive, then imports the native module through the
integration's own loader (native.py), as Home Assistant would, and drives
the first step of a weigh session.

usage: python scripts/smoke_bundle.py dist/miscale.zip
"""

from __future__ import annotations

import importlib
from pathlib import Path
import platform
import sys
import tempfile
import zipfile


def main() -> int:
    """Run the smoke test."""
    archive = Path(sys.argv[1])
    with tempfile.TemporaryDirectory() as tmp:
        package = Path(tmp) / "miscale_bundle"
        package.mkdir()
        with zipfile.ZipFile(archive) as contents:
            for name in contents.namelist():
                if name in {"const.py", "native.py"} or name.startswith("native/"):
                    contents.extract(name, package)
        # The loader only needs its constants; the rest needs Home Assistant.
        (package / "__init__.py").write_text("")
        sys.path.insert(0, tmp)
        native = importlib.import_module("miscale_bundle.native")
        path = native.bundled_path()
        if path is None or not path.is_file():
            print(f"no bundled module for {platform.machine()}: {path}")  # noqa: T201
            return 1
        module = native.load()
        if Path(module.__file__).resolve() != path.resolve():
            print(f"loaded {module.__file__}, expected {path}")  # noqa: T201
            return 1
        module.validate_token("00112233445566778899aabb")
        session = module.WeighSession("00112233445566778899aabb", bytes(16), 0, 0)
        first = session.poll_transmit()
        if first != (0x10, bytes([0x24, 0, 0, 0])):
            print(f"unexpected first write: {first!r}")  # noqa: T201
            return 1
        if hasattr(module, "SimulatedScale"):
            print("the test simulator must not ship")  # noqa: T201
            return 1
        print(f"ok: {platform.machine()} {module.__version__} from {path.name}")  # noqa: T201
    return 0


if __name__ == "__main__":
    sys.exit(main())
