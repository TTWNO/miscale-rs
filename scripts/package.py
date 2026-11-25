"""Package the Home Assistant integration with its native modules.

Builds `dist/miscale.zip`, the file a HACS release serves (`zip_release`):
the contents of custom_components/miscale at the root of the archive, plus
the prebuilt native module for each architecture:

    native/<version>/<arch>-linux-musl/miscale_native.abi3.so
    native/<version>/<arch>-linux-musl/sbom.cyclonedx.json

The inputs are maturin wheels built for the musllinux targets (see
`make dist`). The archive is deterministic: sorted entries, fixed
timestamps. Packaging stops if the integration's manifest, its expected
native version and the Rust workspace's version disagree.

usage: python scripts/package.py --out dist/miscale.zip WHEEL [WHEEL ...]
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parent.parent
INTEGRATION = ROOT / "custom_components" / "miscale"
FIXED_TIME = (1980, 1, 1, 0, 0, 0)
WHEEL_ARCH = re.compile(r"-musllinux_\d+_\d+_(?P<arch>x86_64|aarch64)\.whl$")


def versions() -> tuple[str, str, str]:
    """Return the manifest, expected-native and Rust workspace versions."""
    manifest = json.loads((INTEGRATION / "manifest.json").read_text())["version"]
    const = (INTEGRATION / "const.py").read_text()
    match = re.search(r'^NATIVE_VERSION: Final = "([^"]+)"$', const, re.MULTILINE)
    if match is None:
        msg = "NATIVE_VERSION not found in const.py"
        raise SystemExit(msg)
    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    return manifest, match.group(1), cargo


def add(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    """Add a file with a fixed timestamp and ordinary permissions."""
    info = zipfile.ZipInfo(name, FIXED_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    archive.writestr(info, data)


def native_files(wheel: Path, version: str) -> dict[str, bytes]:
    """Return the archive entries a wheel contributes."""
    match = WHEEL_ARCH.search(wheel.name)
    if match is None:
        msg = f"{wheel.name}: not a musllinux x86_64/aarch64 wheel"
        raise SystemExit(msg)
    prefix = f"native/{version}/{match['arch']}-linux-musl"
    with zipfile.ZipFile(wheel) as contents:
        names = contents.namelist()
        library = next((n for n in names if n.endswith("miscale_native.abi3.so")), None)
        sbom = next((n for n in names if n.endswith(".cyclonedx.json")), None)
        if library is None:
            msg = f"{wheel.name}: no miscale_native.abi3.so inside"
            raise SystemExit(msg)
        files = {f"{prefix}/miscale_native.abi3.so": contents.read(library)}
        if sbom is not None:
            files[f"{prefix}/sbom.cyclonedx.json"] = contents.read(sbom)
    return files


def main() -> int:
    """Build the archive."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("wheels", type=Path, nargs="+")
    args = parser.parse_args()

    manifest, native, cargo = versions()
    if len({manifest, native, cargo}) != 1:
        print(  # noqa: T201
            f"version mismatch: manifest {manifest}, NATIVE_VERSION {native}, Cargo {cargo}",
            file=sys.stderr,
        )
        return 1

    entries: dict[str, bytes] = {
        path.relative_to(INTEGRATION).as_posix(): path.read_bytes()
        for path in INTEGRATION.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }
    for wheel in args.wheels:
        entries.update(native_files(wheel, native))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.out, "w") as archive:
        for name in sorted(entries):
            add(archive, name, entries[name])
    digest = hashlib.sha256(args.out.read_bytes()).hexdigest()
    print(f"{digest}  {args.out}")  # noqa: T201
    return 0


if __name__ == "__main__":
    sys.exit(main())
