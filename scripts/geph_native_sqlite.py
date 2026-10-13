"""Narrow, source-only contract for Geph's reviewed external SQLite amalgamation.

No network, compiler invocation or build claim belongs to this module. The
separate build verifier must bind these bytes to the linked release artifacts.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tomllib
import zipfile

PATH = "slipstream-native/sqlite"
TARGETS = ["aarch64-apple-darwin", "x86_64-apple-darwin"]
WRAPPER = {"name": "libsqlite3-sys", "version": "0.30.1",
           "sha256": "2e99fb7a497b1e3339bc746195567ed8d3e24945ecd636e3619d20b9de9e9149"}
COMPILE_DEFINITIONS = [
    "SQLITE_CORE", "SQLITE_DEFAULT_FOREIGN_KEYS=1", "SQLITE_ENABLE_API_ARMOR",
    "SQLITE_ENABLE_COLUMN_METADATA", "SQLITE_ENABLE_DBSTAT_VTAB", "SQLITE_ENABLE_FTS3",
    "SQLITE_ENABLE_FTS3_PARENTHESIS", "SQLITE_ENABLE_FTS5", "SQLITE_ENABLE_JSON1",
    "SQLITE_ENABLE_LOAD_EXTENSION=1", "SQLITE_ENABLE_MEMORY_MANAGEMENT", "SQLITE_ENABLE_RTREE",
    "SQLITE_ENABLE_STAT4", "SQLITE_SOUNDEX", "SQLITE_THREADSAFE=1", "SQLITE_USE_URI",
    "HAVE_USLEEP=1", "HAVE_ISNAN", "_POSIX_THREAD_SAFE_FUNCTIONS", "SQLITE_ENABLE_UNLOCK_NOTIFY",
]
MAX_ARCHIVE_BYTES = 10 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_UNPACKED_BYTES = 24 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
NOTICE = b"""** The author disclaims copyright to this source code.  In place of
** a legal notice, here is a blessing:
**
**    May you do good and not evil.
**    May you find forgiveness for yourself and forgive others.
**    May you share freely, never taking more than you give."""


def _keys(value: object, fields: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"native SQLite {label} fields do not match schema")


def _digest(value: object, label: str) -> None:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise ValueError(f"native SQLite {label} SHA256 is invalid")


def validate_descriptor(value: object) -> None:
    version = value.get("schema_version") if isinstance(value, dict) else None
    if type(version) is not int or version not in (1, 2):
        raise ValueError("native SQLite schema version is invalid")
    _keys(value, {"schema_version", "version", "source_id", "path", "archive", "files",
                  "compile_definitions", "linkage", "targets", "wrapper"}
          | ({"producer_helper_sha256"} if version == 2 else set()), "descriptor")
    if version == 2:
        _digest(value["producer_helper_sha256"], "producer helper")
    version = value["version"]
    if not isinstance(version, str) or not re.fullmatch(r"3\.(?:0|[1-9][0-9]?)\.(?:0|[1-9][0-9]?)", version):
        raise ValueError("native SQLite version is invalid")
    major, minor, patch = map(int, version.split("."))
    serial = str(major * 1000000 + minor * 10000 + patch * 100)
    source_id = value["source_id"]
    if not isinstance(source_id, str) or not re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9a-f]{64}", source_id):
        raise ValueError("native SQLite source ID is invalid")
    if value["path"] != PATH or value["linkage"] != "static" or value["targets"] != TARGETS:
        raise ValueError("native SQLite path/linkage/targets are not reviewed")
    if value["wrapper"] != WRAPPER or value["compile_definitions"] != COMPILE_DEFINITIONS:
        raise ValueError("native SQLite wrapper/compile definitions are not reviewed")
    archive = value["archive"]
    _keys(archive, {"url", "size", "sha256", "root"}, "archive")
    root = "sqlite-amalgamation-" + serial
    if archive["root"] != root or archive["url"] != f"https://sqlite.org/{source_id[:4]}/{root}.zip":
        raise ValueError("native SQLite archive URL/root do not match version/source ID")
    if type(archive["size"]) is not int or not 0 < archive["size"] <= MAX_ARCHIVE_BYTES:
        raise ValueError("native SQLite archive size is invalid")
    _digest(archive["sha256"], "archive")
    files = value["files"]
    if not isinstance(files, list) or len(files) != 2:
        raise ValueError("native SQLite files must contain exactly C and header")
    for item, name in zip(files, ("sqlite3.c", "sqlite3.h")):
        _keys(item, {"path", "size", "sha256"}, "file")
        if item["path"] != name or type(item["size"]) is not int or not 0 < item["size"] <= MAX_FILE_BYTES:
            raise ValueError("native SQLite file path/size is invalid")
        _digest(item["sha256"], "file")


def descriptor_sha256(value: dict) -> str:
    validate_descriptor(value)
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verify_wrapper_lock(descriptor: dict, payload: bytes, lock_sha256: str) -> None:
    validate_descriptor(descriptor)
    if hashlib.sha256(payload).hexdigest() != lock_sha256:
        raise ValueError("native SQLite Cargo.lock hash mismatch")
    packages = tomllib.loads(payload.decode())["package"]
    wrappers = [item for item in packages if item.get("name") == WRAPPER["name"]]
    if len(wrappers) != 1 or any(wrappers[0].get(field) != expected for field, expected in {
        "version": WRAPPER["version"], "checksum": WRAPPER["sha256"],
        "source": "registry+https://github.com/rust-lang/crates.io-index",
    }.items()):
        raise ValueError("native SQLite registry wrapper identity/checksum disagrees with SOURCE")


def read_regular(path: Path, limit: int) -> bytes:
    """Pin one regular inode; never follow a symlink or read an unbounded stream."""
    fd = _open_physical(path)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError("native SQLite input is not a bounded regular file")
        payload = handle.read(limit + 1)
        if len(payload) != info.st_size or len(payload) > limit:
            raise ValueError("native SQLite input changed size or exceeds limit")
        return payload


def _open_physical(path: Path, *, directory: bool = False) -> int:
    """Pin every absolute path component with openat/O_NOFOLLOW."""
    absolute = path.absolute()
    if any(part in {".", ".."} for part in absolute.parts):
        raise ValueError("native SQLite input path must be canonical")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(absolute.parts[1:]):
            is_dir = directory or index < len(absolute.parts) - 2
            child = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                            | (os.O_DIRECTORY if is_dir else 0), dir_fd=fd)
            os.close(fd)
            fd = child
        result, fd = fd, -1
        return result
    finally:
        if fd >= 0:
            os.close(fd)


def _verify_bytes(descriptor: dict, contents: dict[str, bytes]) -> None:
    if set(contents) != {"sqlite3.c", "sqlite3.h"}:
        raise ValueError("native SQLite materialized file set is invalid")
    for entry in descriptor["files"]:
        payload = contents[entry["path"]]
        if len(payload) != entry["size"] or hashlib.sha256(payload).hexdigest() != entry["sha256"]:
            raise ValueError("native SQLite source file size/hash mismatch")
        for define, expected in ((b"SQLITE_VERSION", descriptor["version"]), (b"SQLITE_SOURCE_ID", descriptor["source_id"])):
            found = re.findall(rb'^#define[ \t]+' + define + rb'[ \t]+"([^"\r\n]+)"[ \t]*$', payload, re.MULTILINE)
            if found != [expected.encode()]:
                raise ValueError("native SQLite source version/source ID mismatch")
    if NOTICE not in contents["sqlite3.h"][:2048]:
        raise ValueError("native SQLite original header notice is missing")


def verify_materialized(descriptor: dict, source_root: Path) -> dict[str, bytes]:
    validate_descriptor(descriptor)
    root = source_root.absolute()
    native = root / PATH
    # Pin every component below the already physical root against replacement.
    fd = _open_physical(root, directory=True)
    try:
        for part in PATH.split("/"):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        if set(os.listdir(fd)) != {"sqlite3.c", "sqlite3.h"}:
            raise ValueError("native SQLite materialized file set is invalid")
        contents = {}
        for entry in descriptor["files"]:
            child = os.open(entry["path"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            with os.fdopen(child, "rb") as handle:
                if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                    raise ValueError("native SQLite source is not a regular file")
                contents[entry["path"]] = handle.read(entry["size"] + 1)
        _verify_bytes(descriptor, contents)
        return contents
    finally:
        os.close(fd)


def materialize(descriptor: dict, archive_path: Path, source_root: Path) -> Path:
    validate_descriptor(descriptor)
    # Hash and extract the same private byte snapshot; path replacement cannot
    # swap an unchecked archive between verification and extraction.
    payload = read_regular(archive_path, MAX_ARCHIVE_BYTES)
    archive = descriptor["archive"]
    if len(payload) != archive["size"] or hashlib.sha256(payload).hexdigest() != archive["sha256"]:
        raise ValueError("native SQLite archive size/hash mismatch")
    contents = {}
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as zipped:
            members = zipped.infolist()
            prefix = archive["root"] + "/"
            allowed = {prefix, *(prefix + name for name in ("sqlite3.c", "sqlite3.h", "sqlite3ext.h", "shell.c"))}
            names = [item.filename for item in members]
            if len(names) != len(set(names)) or not set(names) <= allowed or len(names) > 5:
                raise ValueError("native SQLite archive paths/duplicates are invalid")
            if sum(item.file_size for item in members) > MAX_UNPACKED_BYTES:
                raise ValueError("native SQLite archive expanded size exceeds limit")
            for item in members:
                mode = item.external_attr >> 16
                if item.flag_bits & 1 or (stat.S_IFMT(mode) not in {0, stat.S_IFDIR if item.is_dir() else stat.S_IFREG}):
                    raise ValueError("native SQLite archive contains encrypted/symlink/special member")
                name = item.filename.removeprefix(prefix)
                if name in {"sqlite3.c", "sqlite3.h"}:
                    expected = next(entry for entry in descriptor["files"] if entry["path"] == name)
                    if item.file_size != expected["size"]:
                        raise ValueError("native SQLite archive member size mismatch")
                    with zipped.open(item) as handle:
                        contents[name] = handle.read(expected["size"] + 1)
    except (zipfile.BadZipFile, RuntimeError) as exc:
        raise ValueError("native SQLite archive is invalid") from exc
    _verify_bytes(descriptor, contents)
    root = source_root.absolute()
    namespace = root / "slipstream-native"
    # A crate is not allowed to prepopulate or alias this owned namespace.
    target = namespace / "sqlite"
    root_fd = _open_physical(root, directory=True)
    namespace_fd = stage_fd = None
    stage = ".sqlite-" + secrets.token_hex(12)
    published = False
    try:
        os.mkdir("slipstream-native", mode=0o755, dir_fd=root_fd)
        namespace_fd = os.open("slipstream-native", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        os.mkdir(stage, mode=0o755, dir_fd=namespace_fd)
        stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=namespace_fd)
        for name, body in contents.items():
            file_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=stage_fd)
            with os.fdopen(file_fd, "wb") as handle:
                handle.write(body)
        os.rename(stage, "sqlite", src_dir_fd=namespace_fd, dst_dir_fd=namespace_fd)
        published = True
    finally:
        if stage_fd is not None:
            if not published:
                for name in os.listdir(stage_fd):
                    os.unlink(name, dir_fd=stage_fd)
            os.close(stage_fd)
            if not published:
                os.rmdir(stage, dir_fd=namespace_fd)
        if namespace_fd is not None:
            os.close(namespace_fd)
        os.close(root_fd)
    verify_materialized(descriptor, root)
    return target
