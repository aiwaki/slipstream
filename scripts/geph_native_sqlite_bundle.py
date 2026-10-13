"""Deterministic transport for the complete, independently verified native proof.

Only regular USTAR entries with canonical metadata are accepted. The archive is
an evidence container, never a substitute for provenance or advisory coverage.
Compiler/SDK paths in receipts describe the original producer; they are not
copied or executed by this consumer.
"""
from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import tempfile

import geph_native_sqlite as native
import geph_native_sqlite_build as build

BUNDLE_NAME = "geph5-client-native-sqlite-evidence.tar"
MANIFEST = "__slipstream_native_bundle__.json"
SCOPE = "native-sqlite-evidence-bundle"
MAX_BUNDLE_BYTES = 1024 * 1024 * 1024
MAX_MEMBERS = 64
MAX_MANIFEST_BYTES = 64 * 1024
ZERO_BLOCK = b"\0" * 512


def _name(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("unsafe bundle member path")
    path = PurePosixPath(value)
    if not path.parts or path.is_absolute() or str(path) != value or any(p in (".", "..") for p in path.parts):
        raise ValueError("unsafe bundle member path")
    if len(value) > 255 or any(ord(c) < 32 or ord(c) > 126 for c in value):
        raise ValueError("bundle member path must be bounded printable ASCII")
    return value


def _header(name: str, size: int) -> bytes:
    item = tarfile.TarInfo(_name(name))
    if type(size) is not int or not 0 < size <= build.MAX_BYTES:
        raise ValueError("invalid bundle member size")
    item.size = size
    item.mode = 0o644
    try:
        return item.tobuf(tarfile.USTAR_FORMAT, encoding="ascii", errors="strict")
    except (ValueError, UnicodeError) as exc:
        raise ValueError("bundle member cannot use canonical USTAR header") from exc


def _encode(files: dict[str, bytes]) -> bytes:
    if not 1 <= len(files) <= MAX_MEMBERS:
        raise ValueError("bundle member count exceeds bound")
    parts, total = [], 1024
    for name, data in sorted(files.items()):
        header = _header(name, len(data))
        padding = b"\0" * (-len(data) % 512)
        total += 512 + len(data) + len(padding)
        if total > MAX_BUNDLE_BYTES:
            raise ValueError("bundle exceeds total size bound")
        parts.extend((header, data, padding))
    return b"".join([*parts, ZERO_BLOCK, ZERO_BLOCK])


def _decode(payload: bytes) -> dict[str, bytes]:
    if len(payload) > MAX_BUNDLE_BYTES or len(payload) % 512:
        raise ValueError("invalid bundle size/alignment")
    files, offset, previous = {}, 0, ""
    while offset + 512 <= len(payload):
        header = payload[offset:offset + 512]
        if header == ZERO_BLOCK:
            if payload[offset:] != ZERO_BLOCK * 2:
                raise ValueError("bundle must end with exactly two zero blocks")
            if not files:
                raise ValueError("empty bundle")
            return files
        try:
            item = tarfile.TarInfo.frombuf(header, "ascii", "strict")
        except (tarfile.HeaderError, UnicodeError, ValueError) as exc:
            raise ValueError("invalid bundle header") from exc
        name = _name(item.name)
        # Exact header equality also forbids GNU/PAX/sparse extensions, links,
        # devices, directories, base-256 fields and noncanonical metadata.
        if item.type != tarfile.REGTYPE or header != _header(name, item.size):
            raise ValueError("bundle requires canonical regular USTAR files")
        if name <= previous or name in files or len(files) >= MAX_MEMBERS:
            raise ValueError("duplicate/unordered or excess bundle members")
        end = offset + 512 + item.size
        padded_end = end + (-item.size % 512)
        if padded_end > len(payload) or any(payload[end:padded_end]):
            raise ValueError("truncated bundle or nonzero member padding")
        files[name] = payload[offset + 512:end]
        previous, offset = name, padded_end
    raise ValueError("truncated bundle terminator")


def _closure(receipt_name: str, read) -> dict[str, bytes]:
    """Follow only the three explicit receipt schemas, never arbitrary JSON."""
    contents = {}

    def add(name, record=None, *, receipt=False):
        name = _name(name)
        if name == MANIFEST:
            raise ValueError("reserved bundle manifest path")
        limit = 1024 * 1024 if receipt else build.MAX_BYTES
        data = read(name, limit)
        if record is not None:
            build._keys(record, ("path", "size", "sha256"), "bundle reference")
            if record["path"] != name or type(record["size"]) is not int or len(data) != record["size"] or build.sha(data) != record["sha256"]:
                raise ValueError("bundle reference hash/size mismatch")
        if name in contents and contents[name] != data:
            raise ValueError("bundle input changed during snapshot")
        contents[name] = data
        if len(contents) >= MAX_MEMBERS or sum(map(len, contents.values())) > MAX_BUNDLE_BYTES - 1024:
            raise ValueError("bundle closure exceeds bounds")
        return build._json(data) if receipt else data

    release = add(receipt_name, receipt=True)
    build._keys(release.get("linked_receipts"), native.TARGETS, "bundle linked receipts")
    add(release["final_binary"]["path"], release["final_binary"])
    for record in release["linked_receipts"].values():
        linked = add(record["path"], record, receipt=True)
        build._keys(linked.get("files"), ("sys_build_output", "rlib", "link_map", "binary", "cargo_metadata"), "bundle linked files")
        for entry in linked["files"].values():
            add(entry["path"], entry)
        record = linked["native_receipt"]
        compiled = add(record["path"], record, receipt=True)
        build._keys(compiled.get("files"), ("include/sqlite3.c", "include/sqlite3.h", "sqlite3.o", "libsqlite3.a"), "bundle native files")
        for entry in compiled["files"].values():
            add(entry["path"], entry)
    return contents


def _json(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _manifest(files, receipt_name, descriptor, source_sha256, lock_sha256):
    return {"schema_version": 1, "scope": SCOPE, "receipt_path": receipt_name,
            "descriptor_sha256": native.descriptor_sha256(descriptor),
            "source_sha256": source_sha256, "lock_sha256": lock_sha256,
            "files": {name: {"size": len(data), "sha256": build.sha(data)} for name, data in sorted(files.items())}}


def _mkdir_and_write(root: Path, contents: dict[str, bytes]):
    """Create one fresh owned tree using pinned directory FDs and no links."""
    parent = native._open_physical(root.parent, directory=True)
    root_fd, created = None, False
    try:
        os.mkdir(root.name, 0o700, dir_fd=parent)
        created = True
        root_fd = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        identity = os.fstat(root_fd)
        if os.listdir(root_fd):
            raise ValueError("fresh bundle destination was replaced or is not empty")
        for name, payload in contents.items():
            fd = os.dup(root_fd)
            try:
                components = _name(name).split("/")
                for part in components[:-1]:
                    try:
                        os.mkdir(part, 0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd)
                    fd = child
                target = os.open(components[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                with os.fdopen(target, "wb") as handle:
                    handle.write(payload)
            finally:
                os.close(fd)
        return identity
    except BaseException as exc:
        if created:
            exc.add_note(f"Unverified evidence retained at {root}; use a fresh destination for retry.")
        raise
    finally:
        if root_fd is not None:
            os.close(root_fd)
        os.close(parent)


def _assert_tree(root, files, identity):
    """Check the physical tree, including unexpected empty directories/links."""
    fd = native._open_physical(root, directory=True)
    seen_files, seen_dirs = set(), set()
    expected_dirs = {str(parent) for name in files for parent in PurePosixPath(name).parents if str(parent) != "."}

    def visit(directory_fd, prefix):
        for name in os.listdir(directory_fd):
            relative = f"{prefix}/{name}" if prefix else name
            entry = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
            try:
                info = os.fstat(entry)
                if stat.S_ISDIR(info.st_mode):
                    if relative not in expected_dirs:
                        raise ValueError("unexpected directory in bundle destination")
                    seen_dirs.add(relative)
                    visit(entry, relative)
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and relative in files:
                    if info.st_size != len(files[relative]):
                        raise ValueError("bundle destination file changed size")
                    with os.fdopen(os.dup(entry), "rb") as handle:
                        if handle.read(info.st_size + 1) != files[relative]:
                            raise ValueError("bundle destination bytes changed")
                    seen_files.add(relative)
                else:
                    raise ValueError("unexpected file/link in bundle destination")
            finally:
                os.close(entry)
    try:
        current = os.fstat(fd)
        if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino):
            raise ValueError("bundle destination directory identity changed")
        visit(fd, "")
        if seen_files != set(files) or seen_dirs != expected_dirs:
            raise ValueError("bundle destination physical file set differs from closure")
    finally:
        os.close(fd)


def _verify_snapshot(root, receipt_name, files, descriptor, source_sha256, lock_sha256, published):
    proof = build.verify_release_evidence(descriptor, root / receipt_name, root, source_sha256, lock_sha256)
    closure = _closure(receipt_name, lambda name, limit: native.read_regular(root / name, limit))
    if closure != files:
        raise ValueError("bundle file set is not the exact release evidence closure")
    if closure[proof["final_binary"]["path"]] != published:
        raise ValueError("native evidence final binary differs from independently published binary")
    return proof


def _report(proof, root, receipt_name, payload, count):
    return {"receipt_path": str(root / receipt_name), "artifacts_root": str(root),
            "receipt_sha256": proof["receipt_sha256"], "final_binary_sha256": proof["final_binary_sha256"],
            "bundle_sha256": build.sha(payload), "size": len(payload), "file_count": count}


def pack_bundle(receipt_path: Path, artifacts_root: Path, output_path: Path, descriptor: dict,
                source_sha256: str, lock_sha256: str, published_binary: Path) -> dict:
    """Snapshot, verify and package every bound input; never overwrite an asset."""
    root = build._root(artifacts_root)
    receipt_name = _name(str(Path(receipt_path).absolute().relative_to(root)))
    build.verify_release_evidence(descriptor, root / receipt_name, root, source_sha256, lock_sha256)
    files = _closure(receipt_name, lambda name, limit: native.read_regular(root / name, limit))
    published = native.read_regular(Path(published_binary), build.MAX_BYTES)
    with tempfile.TemporaryDirectory(prefix="native-bundle-check-") as temporary:
        stage = Path(temporary).resolve() / "evidence"
        identity = _mkdir_and_write(stage, files)
        _assert_tree(stage, files, identity)
        proof = _verify_snapshot(stage, receipt_name, files, descriptor, source_sha256, lock_sha256, published)
        _assert_tree(stage, files, identity)
    manifest = _json(_manifest(files, receipt_name, descriptor, source_sha256, lock_sha256))
    if len(manifest) > MAX_MANIFEST_BYTES:
        raise ValueError("bundle manifest exceeds bound")
    payload = _encode(files | {MANIFEST: manifest})
    output = Path(output_path).absolute()
    parent = native._open_physical(output.parent, directory=True)
    try:
        fd = os.open(output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
    finally:
        os.close(parent)
    return _report(proof, root, receipt_name, payload, len(files))


def unpack_bundle(bundle_path: Path, output_root: Path, descriptor: dict,
                  source_sha256: str, lock_sha256: str, published_binary: Path) -> dict:
    """Verify immutable inputs into a new private destination.

    Failure retains unverified evidence and never deletes by pathname. An inode
    check followed by rmtree cannot prevent a replacement-directory race. A
    retry therefore requires a different fresh destination.
    """
    native.validate_descriptor(descriptor)
    build._digest(source_sha256)
    build._digest(lock_sha256)
    payload = native.read_regular(Path(bundle_path), MAX_BUNDLE_BYTES)
    published = native.read_regular(Path(published_binary), build.MAX_BYTES)
    files = _decode(payload)
    manifest_bytes = files.pop(MANIFEST, b"")
    if not 0 < len(manifest_bytes) <= MAX_MANIFEST_BYTES:
        raise ValueError("bundle manifest missing or exceeds bound")
    manifest = build._json(manifest_bytes)
    build._keys(manifest, ("schema_version", "scope", "receipt_path", "descriptor_sha256", "source_sha256", "lock_sha256", "files"), "bundle manifest")
    receipt_name = _name(manifest["receipt_path"])
    if manifest_bytes != _json(_manifest(files, receipt_name, descriptor, source_sha256, lock_sha256)):
        raise ValueError("bundle manifest identity or exact file hashes mismatch")
    root = Path(output_root).absolute()
    if root.parent.resolve(strict=True) != root.parent or root.name in (".", ".."):
        raise ValueError("bundle destination must have a physical parent")
    identity = _mkdir_and_write(root, files)
    try:
        _assert_tree(root, files, identity)
        proof = _verify_snapshot(root, receipt_name, files, descriptor, source_sha256, lock_sha256, published)
        _assert_tree(root, files, identity)
        return _report(proof, root, receipt_name, payload, len(files))
    except BaseException as exc:
        exc.add_note(f"Unverified evidence retained at {root}; use a fresh destination for retry.")
        raise
