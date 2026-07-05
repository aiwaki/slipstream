#!/usr/bin/env python3
"""Sync Slipstream version metadata from the root VERSION file."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")


def read_version(explicit: str | None) -> str:
    version = explicit or (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not VERSION_RE.match(version):
        raise SystemExit(f"invalid version: {version!r}")
    return version


def write_if_changed(path: Path, text: str, check: bool, changed: list[Path]) -> None:
    current = path.read_text(encoding="utf-8")
    if current == text:
        return
    changed.append(path)
    if not check:
        path.write_text(text, encoding="utf-8")


def sync_json(path: Path, updates: dict[tuple[str, ...], str], version: str, check: bool, changed: list[Path]) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    updated = False
    for keys, value in updates.items():
        node = data
        for key in keys[:-1]:
            node = node[key]
        new_value = value.format(version=version)
        if node[keys[-1]] != new_value:
            node[keys[-1]] = new_value
            updated = True
    if not updated:
        return
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    write_if_changed(path, text, check, changed)


def sync_cargo_toml(path: Path, version: str, check: bool, changed: list[Path]) -> None:
    text = path.read_text(encoding="utf-8")
    new_text, count = re.subn(
        r'(?m)^version = "[^"]+"$',
        f'version = "{version}"',
        text,
        count=1,
    )
    if count != 1:
        raise SystemExit(f"could not find package version in {path}")
    write_if_changed(path, new_text, check, changed)


def sync_cargo_lock(path: Path, version: str, check: bool, changed: list[Path]) -> None:
    text = path.read_text(encoding="utf-8")
    blocks = text.split("[[package]]")
    output = [blocks[0]]
    updated = False

    for block in blocks[1:]:
        if re.search(r'(?m)^name = "slipstream"$', block):
            block, count = re.subn(
                r'(?m)^version = "[^"]+"$',
                f'version = "{version}"',
                block,
                count=1,
            )
            if count != 1:
                raise SystemExit(f"could not find slipstream version in {path}")
            updated = True
        output.append("[[package]]" + block)

    if not updated:
        raise SystemExit(f"could not find slipstream package in {path}")
    write_if_changed(path, "".join(output), check, changed)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", help="Version to sync instead of reading VERSION")
    parser.add_argument("--check", action="store_true", help="Fail if generated files are out of sync")
    args = parser.parse_args()

    version = read_version(args.version)
    changed: list[Path] = []

    sync_json(
        ROOT / "app-tauri/package.json",
        {("version",): "{version}"},
        version,
        args.check,
        changed,
    )
    sync_json(
        ROOT / "app-tauri/package-lock.json",
        {
            ("version",): "{version}",
            ("packages", "", "version"): "{version}",
        },
        version,
        args.check,
        changed,
    )
    sync_json(
        ROOT / "app-tauri/src-tauri/tauri.conf.json",
        {("version",): "{version}"},
        version,
        args.check,
        changed,
    )
    sync_cargo_toml(ROOT / "app-tauri/src-tauri/Cargo.toml", version, args.check, changed)
    sync_cargo_lock(ROOT / "app-tauri/src-tauri/Cargo.lock", version, args.check, changed)

    if args.check and changed:
        for path in changed:
            print(f"out of sync: {path.relative_to(ROOT)}", file=sys.stderr)
        return 1

    if changed:
        paths = ", ".join(str(path.relative_to(ROOT)) for path in changed)
        print(f"synced {version}: {paths}")
    else:
        print(f"version metadata already synced: {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
