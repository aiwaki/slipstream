#!/usr/bin/env python3
"""Copy a complete, checksum-bound Cargo.lock registry cache without network use.

The output must be fresh. Failures leave an unsealed partial output for inspection;
this helper never deletes caller data. Sparse index entries are opaque snapshots,
not authenticated metadata. A subsequent offline Cargo resolution is still needed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tomllib

import geph_native_sqlite as native
import geph_vendor_source as vendor

REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
NAMESPACE = re.compile(r"index\.crates\.io-[0-9a-f]{16}\Z")
NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,63}\Z")
NUMBER = r"(?:0|[1-9][0-9]*)"
PRERELEASE = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
VERSION = re.compile(NUMBER + r"\." + NUMBER + r"\." + NUMBER
                     + r"(?:-" + PRERELEASE + r"(?:\." + PRERELEASE + r")*)?"
                     + r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z")
REGISTRY_CONFIG = {"dl": "https://static.crates.io/crates", "api": "https://crates.io"}
CHUNK_BYTES = 1024 * 1024
MAX_LOCK_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_ARCHIVES_TOTAL = 2 * 1024 * 1024 * 1024
MAX_INDEX_BYTES = 16 * 1024 * 1024
MAX_INDEX_TOTAL = 256 * 1024 * 1024
MAX_CONFIG_BYTES = 4096
MAX_PACKAGES = 10_000
MAX_NAMESPACE_ENTRIES = 1024
RECEIPT = "cache-seal.json"


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def index_path(name: str) -> str:
    """Cargo's registry path mapping, independent of archive name casing."""
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise ValueError("unsafe Cargo package name")
    name = name.lower()
    if len(name) < 3:
        return f"{len(name)}/{name}"
    if len(name) == 3:
        return f"3/{name[0]}/{name}"
    return f"{name[:2]}/{name[2:4]}/{name}"


def _packages(payload: bytes, source: dict) -> list[dict]:
    lock = tomllib.loads(payload.decode("utf-8"))
    packages = lock.get("package")
    if (type(lock.get("version")) is not int or lock["version"] not in (3, 4)
            or not isinstance(packages, list) or not 0 < len(packages) <= MAX_PACKAGES):
        raise ValueError("invalid or oversized Cargo.lock package list/version")
    local = {(source["crate"]["name"], source["crate"]["version"])}
    local.update((p["name"], p["version"])
                 for p in source.get("embedded_packages", {}).get("packages", []))
    seen, found_local, registry = set(), set(), []
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError("invalid Cargo.lock package")
        name, version = package.get("name"), package.get("version")
        index_path(name)
        if (not isinstance(version, str) or len(version) > 128
                or not VERSION.fullmatch(version)):
            raise ValueError("unsafe Cargo package version")
        identity = (name.lower(), version)
        if identity in seen:
            raise ValueError("duplicate Cargo.lock package identity")
        seen.add(identity)
        if "source" not in package:
            if (name, version) not in local or "checksum" in package:
                raise ValueError("unreviewed source-less Cargo.lock package")
            found_local.add((name, version))
            continue
        if package["source"] != REGISTRY:
            raise ValueError("only crates.io registry Cargo.lock sources are supported")
        checksum = package.get("checksum")
        if not isinstance(checksum, str) or not native.SHA256.fullmatch(checksum):
            raise ValueError("registry package requires a SHA-256 lock checksum")
        registry.append({"name": name, "version": version, "sha256": checksum})
    if (source["crate"]["name"], source["crate"]["version"]) not in found_local:
        raise ValueError("Cargo.lock is missing the source-owned Geph root")
    if not registry:
        raise ValueError("Cargo.lock has no registry packages")
    return sorted(registry, key=lambda item: (item["name"].lower(), item["version"]))


def _namespace(directory: Path) -> str:
    fd = native._open_physical(directory, directory=True)
    try:
        matches = []
        with os.scandir(fd) as entries:
            for count, entry in enumerate(entries, 1):
                if count > MAX_NAMESPACE_ENTRIES:
                    raise ValueError("too many Cargo registry namespace entries")
                if NAMESPACE.fullmatch(entry.name):
                    if not entry.is_dir(follow_symlinks=False):
                        raise ValueError("Cargo registry namespace is not a physical directory")
                    matches.append(entry.name)
        if len(matches) != 1:
            raise ValueError("exactly one crates.io sparse registry namespace is required")
        return matches[0]
    finally:
        os.close(fd)


def _size(path: Path, limit: int) -> int:
    fd = native._open_physical(path)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError(f"input is not a bounded regular file: {path}")
        return info.st_size
    finally:
        os.close(fd)


def _snapshot(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _new_file(root_fd: int, relative: str) -> int:
    """Create only owned descendants, rejecting replacement symlinks throughout."""
    parts = relative.split("/")
    if any(not part or part in (".", "..") for part in parts):
        raise ValueError("unsafe output path")
    fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, mode=0o700, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                       0o600, dir_fd=fd)
    finally:
        os.close(fd)


def _write_bytes(root_fd: int, relative: str, payload: bytes) -> tuple[dict, tuple]:
    with os.fdopen(_new_file(root_fd, relative), "wb") as stream:
        stream.write(payload)
        stream.flush()
        snapshot = _snapshot(os.fstat(stream.fileno()))
    return {"path": relative, "size": len(payload), "sha256": _sha(payload)}, snapshot


def _copy_stream(path: Path, root_fd: int, relative: str, limit: int,
                 checksum: str | None = None) -> tuple[dict, tuple]:
    fd = native._open_physical(path)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            raise ValueError(f"input is not a bounded regular file: {path}")
        digest, size = hashlib.sha256(), 0
        with os.fdopen(_new_file(root_fd, relative), "wb") as output:
            while chunk := os.read(fd, min(CHUNK_BYTES, limit - size + 1)):
                size += len(chunk)
                if size > limit:
                    raise ValueError("copy exceeds file or total byte limit")
                digest.update(chunk)
                output.write(chunk)
            if size != before.st_size or _snapshot(before) != _snapshot(os.fstat(fd)):
                raise ValueError("input changed during cache snapshot")
            if checksum is not None and digest.hexdigest() != checksum:
                raise ValueError(f"Cargo archive checksum mismatch: {path.name}")
            output.flush()
            snapshot = _snapshot(os.fstat(output.fileno()))
        return {"path": relative, "size": size, "sha256": digest.hexdigest()}, snapshot
    finally:
        os.close(fd)


def _same_root(output: Path, info: os.stat_result) -> None:
    fd = native._open_physical(output, directory=True)
    try:
        current = os.fstat(fd)
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("output root changed during cache preparation")
    finally:
        os.close(fd)


def _verify_output(root_fd: int, snapshots: list[tuple[str, tuple]]) -> None:
    """Check the exact owned output tree; never traverse the fetched index."""
    expected = {}
    for relative, snapshot in snapshots:
        parts, branch = relative.split("/"), expected
        for part in parts[:-1]:
            branch = branch.setdefault(part, {})
        branch[parts[-1]] = snapshot

    def visit(fd: int, children: dict) -> None:
        seen = set()
        with os.scandir(fd) as entries:
            for entry in entries:
                if entry.name not in children or entry.name in seen:
                    raise ValueError("unexpected file or directory in prepared cache (extra/duplicate)")
                seen.add(entry.name)
                expected_child = children[entry.name]
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                if isinstance(expected_child, dict):
                    flags |= os.O_DIRECTORY
                child = os.open(entry.name, flags, dir_fd=fd)
                try:
                    if isinstance(expected_child, dict):
                        visit(child, expected_child)
                    elif _snapshot(os.fstat(child)) != expected_child:
                        raise ValueError("prepared cache file changed before sealing")
                finally:
                    os.close(child)
        if seen != children.keys():
            raise ValueError("prepared cache file or directory is missing")

    visit(root_fd, expected)


def seal_cache(*, source_path: Path, lock_path: Path,
               fetched_cargo_home: Path, output: Path) -> dict:
    # These exact bytes remain authoritative even if caller paths are replaced.
    source_bytes = native.read_regular(Path(source_path), vendor.MAX_SOURCE_BYTES)
    source = vendor._json_object(source_bytes, "Geph source contract")
    vendor._validate_source_contract(source)
    if "native_sqlite" not in source:
        raise ValueError("reviewed native SQLite SOURCE is required")
    lock_bytes = native.read_regular(Path(lock_path), MAX_LOCK_BYTES)
    if _sha(lock_bytes) != source["lock_sha256"]:
        raise ValueError("Cargo.lock hash disagrees with frozen SOURCE")
    packages = _packages(lock_bytes, source)
    native.verify_wrapper_lock(source["native_sqlite"], lock_bytes, source["lock_sha256"])

    home = Path(fetched_cargo_home).absolute()
    cache, index = home / "registry/cache", home / "registry/index"
    namespace = _namespace(cache)
    if _namespace(index) != namespace:
        raise ValueError("Cargo cache and index namespaces do not match")
    config_bytes = native.read_regular(index / namespace / "config.json", MAX_CONFIG_BYTES)
    if vendor._json_object(config_bytes, "Cargo registry config") != REGISTRY_CONFIG:
        raise ValueError("Cargo registry config must contain only reviewed dl/api URLs")

    archives, indexes = [], []
    for package in packages:
        relative = f"registry/cache/{namespace}/{package['name']}-{package['version']}.crate"
        archives.append((home / relative, relative, package))
    for name in sorted({package["name"].lower() for package in packages}):
        relative = f"registry/index/{namespace}/.cache/{index_path(name)}"
        indexes.append((home / relative, relative, name))
    # Fail a production-only/incomplete fetched cache before copying any payload.
    if sum(_size(path, MAX_ARCHIVE_BYTES) for path, _, _ in archives) > MAX_ARCHIVES_TOTAL:
        raise ValueError("Cargo archives exceed total byte limit")
    if sum(_size(path, MAX_INDEX_BYTES) for path, _, _ in indexes) > MAX_INDEX_TOTAL:
        raise ValueError("Cargo sparse index exceeds total byte limit")

    output = Path(output).absolute()
    parent_fd = native._open_physical(output.parent, directory=True)
    root_fd = -1
    try:
        os.mkdir(output.name, mode=0o700, dir_fd=parent_fd)
        root_fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                          dir_fd=parent_fd)
        root_info = os.fstat(root_fd)
        config, config_snapshot = _write_bytes(root_fd, f"registry/index/{namespace}/config.json", config_bytes)
        snapshots = [(config["path"], config_snapshot)]
        archive_records, index_records = [], []
        remaining = MAX_ARCHIVES_TOTAL
        for path, relative, package in archives:
            entry, snapshot = _copy_stream(path, root_fd, relative,
                                           min(MAX_ARCHIVE_BYTES, remaining), package["sha256"])
            remaining -= entry["size"]
            archive_records.append({**entry, "name": package["name"], "version": package["version"]})
            snapshots.append((relative, snapshot))
        remaining = MAX_INDEX_TOTAL
        for path, relative, name in indexes:
            entry, snapshot = _copy_stream(path, root_fd, relative, min(MAX_INDEX_BYTES, remaining))
            remaining -= entry["size"]
            index_records.append({**entry, "name": name})
            snapshots.append((relative, snapshot))
        receipt = {"schema_version": 1, "scope": "full-lock-crates.io-offline-cache-preparation",
                   "source_sha256": _sha(source_bytes), "lock_sha256": _sha(lock_bytes),
                   "native_descriptor_sha256": native.descriptor_sha256(source["native_sqlite"]),
                   "registry_namespace": namespace, "registry_package_count": len(packages),
                   "index_name_count": len(index_records), "registry_config": config,
                   "archives": archive_records, "index": index_records,
                   "archive_assurance": "every selected archive matches its full-lock SHA-256",
                   "index_assurance": "opaque whole-file snapshot; not filtered or authenticated",
                   "offline_cargo_resolution": "not_performed"}
        payload = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
        _same_root(output, root_info)
        _verify_output(root_fd, snapshots)
        _same_root(output, root_info)
        _write_bytes(root_fd, RECEIPT, payload)  # The only completion marker; written last.
        return receipt
    finally:
        if root_fd >= 0:
            os.close(root_fd)
        os.close(parent_fd)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("source", "cargo-lock", "fetched-cargo-home", "output"):
        parser.add_argument("--" + flag, type=Path, required=True)
    args = parser.parse_args()
    try:
        receipt = seal_cache(source_path=args.source, lock_path=args.cargo_lock,
                             fetched_cargo_home=args.fetched_cargo_home, output=args.output)
    except (OSError, ValueError, UnicodeError) as exc:
        raise SystemExit(f"Cargo cache seal failed: {exc}") from exc
    print(json.dumps({"receipt": str(args.output.absolute() / RECEIPT),
                      "registry_packages": receipt["registry_package_count"],
                      "index_names": receipt["index_name_count"]}))


if __name__ == "__main__":
    main()
