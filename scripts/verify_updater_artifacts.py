#!/usr/bin/env python3
"""Fail-closed offline verification for Slipstream macOS updater artifacts.

The publisher runs this verifier against the already-built candidate.  It does
not invoke Cargo, Tauri, a browser, or the network.  In particular, matching an
appcast signature string is not sufficient: the signature must authenticate
the exact archive under the updater public key compiled into the application.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import plistlib
import stat
import sys
import tarfile
from pathlib import Path, PurePosixPath


SCHEMA_VERSION = 1
ARCHIVE_NAME = "Slipstream.app.tar.gz"
SIGNATURE_NAME = f"{ARCHIVE_NAME}.sig"
APP_ROOT = "Slipstream.app"
INFO_PLIST = f"{APP_ROOT}/Contents/Info.plist"
MAIN_EXECUTABLE = f"{APP_ROOT}/Contents/MacOS/slipstream"
EXPECTED_IDENTIFIER = "dev.slipstream.tray"
EXPECTED_EXECUTABLE = "slipstream"
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 768 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 4_096
MAX_ARCHIVE_ENTRY_BYTES = 256 * 1024 * 1024
MAX_PLIST_BYTES = 256 * 1024
MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
MAX_SIGNATURE_BYTES = 64 * 1024
MAX_CONFIG_BYTES = 1024 * 1024
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TAURI_CONFIG = ROOT / "app-tauri/src-tauri/tauri.conf.json"


# RFC 8032 Ed25519 verification.  This deliberately uses only Python's
# standard library so the immutable-candidate publisher does not install a
# package (or run package lifecycle code) after downloading release inputs.
_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)
_IDENTITY = (0, 1)


def _inverse(value: int) -> int:
    return pow(value, _Q - 2, _Q)


def _recover_x(y: int, sign: int) -> int:
    if y >= _Q:
        raise ValueError("minisign point encoding is not canonical")
    xx = ((y * y - 1) * _inverse(_D * y * y + 1)) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q:
        x = (x * _I) % _Q
    if (x * x - xx) % _Q:
        raise ValueError("minisign point is not on Ed25519")
    if (x & 1) != sign:
        x = _Q - x
    if x == 0 and sign:
        raise ValueError("minisign point encoding is not canonical")
    return x


def _decode_point(encoded: bytes) -> tuple[int, int]:
    if len(encoded) != 32:
        raise ValueError("Ed25519 point must contain 32 bytes")
    value = int.from_bytes(encoded, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    return (_recover_x(y, sign), y)


def _point_add(
    left: tuple[int, int], right: tuple[int, int]
) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    product = (_D * x1 * x2 * y1 * y2) % _Q
    return (
        ((x1 * y2 + y1 * x2) * _inverse(1 + product)) % _Q,
        ((y1 * y2 + x1 * x2) * _inverse(1 - product)) % _Q,
    )


def _scalar_multiply(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = _IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


_BASE = (_recover_x((4 * _inverse(5)) % _Q, 0), (4 * _inverse(5)) % _Q)


def _verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> None:
    if len(public_key) != 32 or len(signature) != 64:
        raise ValueError("invalid Ed25519 public key or signature length")
    encoded_r = signature[:32]
    scalar_s = int.from_bytes(signature[32:], "little")
    if scalar_s >= _L:
        raise ValueError("non-canonical Ed25519 signature scalar")
    point_a = _decode_point(public_key)
    point_r = _decode_point(encoded_r)
    if (
        point_a == _IDENTITY
        or _scalar_multiply(point_a, _L) != _IDENTITY
        or _scalar_multiply(point_r, _L) != _IDENTITY
    ):
        raise ValueError("Ed25519 key or signature point is not in the prime-order subgroup")
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(), "little"
    ) % _L
    if _scalar_multiply(_BASE, scalar_s) != _point_add(
        point_r, _scalar_multiply(point_a, challenge)
    ):
        raise ValueError("updater archive minisign verification failed")


def _strict_b64(value: str, label: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"{label} is not canonical base64") from exc


def _decode_outer_text(value: str, label: str) -> str:
    raw = _strict_b64(value.strip(), label)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} does not contain UTF-8 minisign text") from exc


def _parse_public_key(outer_public_key: str) -> tuple[bytes, bytes, bytes]:
    inner = _decode_outer_text(outer_public_key, "Tauri updater public key")
    lines = inner.splitlines()
    if len(lines) != 2 or not lines[0].startswith("untrusted comment: "):
        raise ValueError("Tauri updater public key has invalid minisign framing")
    binary = _strict_b64(lines[1], "minisign public key")
    if len(binary) != 42 or binary[:2] not in {b"Ed", b"ED"}:
        raise ValueError("Tauri updater public key has invalid minisign payload")
    return binary[2:10], binary[10:], inner.encode("utf-8")


def _parse_signature(
    outer_signature: str,
) -> tuple[bytes, bytes, bytes, bytes]:
    inner = _decode_outer_text(outer_signature, "Tauri updater signature")
    lines = inner.splitlines()
    if (
        len(lines) != 4
        or not lines[0].startswith("untrusted comment: ")
        or not lines[2].startswith("trusted comment: ")
    ):
        raise ValueError("Tauri updater signature has invalid minisign framing")
    primary = _strict_b64(lines[1], "minisign primary signature")
    global_signature = _strict_b64(lines[3], "minisign global signature")
    if len(primary) != 74 or primary[:2] != b"ED":
        raise ValueError("updater signature must use minisign prehashed mode")
    if len(global_signature) != 64:
        raise ValueError("minisign global signature has invalid length")
    trusted_comment = lines[2][len("trusted comment: ") :].encode("utf-8")
    return primary[2:10], primary[10:], trusted_comment, global_signature


def _read_regular(path: Path, *, limit: int, label: str) -> tuple[bytes, dict]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"cannot open {label} safely: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
            raise ValueError(f"{label} must be a non-empty regular file")
        if before.st_size > limit:
            raise ValueError(f"{label} exceeds its size limit")
        chunks: list[bytes] = []
        size = 0
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, min(1024 * 1024, limit + 1 - size))
            if not block:
                break
            chunks.append(block)
            digest.update(block)
            size += len(block)
            if size > limit:
                raise ValueError(f"{label} exceeds its size limit")
        after = os.fstat(descriptor)
        if (
            size != before.st_size
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise ValueError(f"{label} changed while it was read")
        return b"".join(chunks), {"sha256": digest.hexdigest(), "size": size}
    finally:
        os.close(descriptor)


def _hash_archive(path: Path) -> tuple[bytes, dict]:
    """Hash an updater archive without buffering it in publisher memory."""
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"cannot open updater archive safely: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not 0 < before.st_size <= MAX_ARCHIVE_BYTES
        ):
            raise ValueError("updater archive must be a bounded non-empty regular file")
        sha256 = hashlib.sha256()
        blake2b = hashlib.blake2b(digest_size=64)
        size = 0
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            size += len(block)
            sha256.update(block)
            blake2b.update(block)
        after = os.fstat(descriptor)
        if (
            size != before.st_size
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise ValueError("updater archive changed while it was hashed")
        return blake2b.digest(), {"sha256": sha256.hexdigest(), "size": size}
    finally:
        os.close(descriptor)


def _load_tauri_public_key(
    tauri_config: Path, *, version: str
) -> tuple[str, dict, str]:
    raw, identity = _read_regular(
        tauri_config, limit=MAX_CONFIG_BYTES, label="Tauri configuration"
    )
    try:
        config = json.loads(raw)
        outer_key = config["plugins"]["updater"]["pubkey"]
        minimum_system_version = config["bundle"]["macOS"]["minimumSystemVersion"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError("Tauri configuration is missing required updater metadata") from exc
    required = {
        "identifier": EXPECTED_IDENTIFIER,
        "mainBinaryName": EXPECTED_EXECUTABLE,
        "version": version,
    }
    for key, expected in required.items():
        if config.get(key) != expected:
            raise ValueError(f"Tauri configuration {key} must be {expected!r}")
    if (
        not isinstance(minimum_system_version, str)
        or not minimum_system_version.strip()
    ):
        raise ValueError("Tauri minimum macOS version must be a non-empty string")
    if not isinstance(outer_key, str) or not outer_key.strip():
        raise ValueError("Tauri updater public key must be a non-empty string")
    identity["pubkey_sha256"] = hashlib.sha256(outer_key.encode("ascii")).hexdigest()
    identity["minimum_system_version"] = minimum_system_version
    return outer_key, identity, minimum_system_version


def _safe_member_name(member: tarfile.TarInfo) -> str:
    name = member.name
    if not name or name.startswith("/") or "\\" in name or "\x00" in name:
        raise ValueError("updater archive contains an unsafe path")
    path = PurePosixPath(name)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"updater archive contains an unsafe path: {name}")
    canonical = path.as_posix()
    if canonical != name.rstrip("/"):
        raise ValueError(f"updater archive path is not canonical: {name}")
    if not path.parts or path.parts[0] != APP_ROOT:
        raise ValueError("updater archive must contain only one Slipstream.app root")
    return canonical


def _safe_link_target(member_name: str, link_name: str) -> str:
    if not link_name or link_name.startswith("/") or "\\" in link_name or "\x00" in link_name:
        raise ValueError(f"updater archive contains an unsafe link: {member_name}")
    target = PurePosixPath(link_name)
    if ".." in target.parts:
        raise ValueError(
            f"updater archive link contains parent traversal: {member_name}"
        )
    canonical = target.as_posix()
    if canonical != link_name.rstrip("/"):
        raise ValueError(f"updater archive contains an unsafe link: {member_name}")
    return canonical


def _read_tar_member(
    archive: tarfile.TarFile, member: tarfile.TarInfo, *, limit: int, label: str
) -> bytes:
    if not member.isfile() or member.size < 0 or member.size > limit:
        raise ValueError(f"{label} is missing, unsafe, or exceeds its size limit")
    stream = archive.extractfile(member)
    if stream is None:
        raise ValueError(f"cannot read {label} from updater archive")
    data = stream.read(limit + 1)
    if len(data) != member.size or len(data) > limit:
        raise ValueError(f"{label} changed or exceeds its size limit")
    return data


def _inspect_archive(
    archive_path: Path,
    *,
    version: str,
    minimum_system_version: str,
    outer_public_key: str,
) -> dict:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(archive_path, flags)
    except OSError as exc:
        raise ValueError(f"cannot open updater archive safely: {archive_path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_ARCHIVE_BYTES:
            raise ValueError("updater archive must be a bounded non-empty regular file")
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb", closefd=False) as fileobj:
            while True:
                block = fileobj.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
            if fileobj.tell() != before.st_size:
                raise ValueError("updater archive changed while it was hashed")
            fileobj.seek(0)
            try:
                archive = tarfile.open(fileobj=fileobj, mode="r:gz")
            except (tarfile.TarError, OSError) as exc:
                raise ValueError("updater archive is not a valid gzip-compressed tar") from exc
            with archive:
                members = archive.getmembers()
                if not 0 < len(members) <= MAX_ARCHIVE_ENTRIES:
                    raise ValueError("updater archive has an invalid entry count")
                seen: dict[str, tarfile.TarInfo] = {}
                uncompressed_size = 0
                for member in members:
                    name = _safe_member_name(member)
                    if name in seen:
                        raise ValueError(f"updater archive contains duplicate path: {name}")
                    if not (
                        member.isdir() or member.isfile() or member.issym()
                    ) or member.sparse is not None:
                        raise ValueError(
                            f"updater archive contains unsupported entry type: {name}"
                        )
                    if member.issym():
                        _safe_link_target(name, member.linkname)
                    if member.size < 0:
                        raise ValueError(f"updater archive contains invalid size: {name}")
                    if member.mode & 0o7000:
                        raise ValueError(f"updater archive contains unsafe mode bits: {name}")
                    if member.size > MAX_ARCHIVE_ENTRY_BYTES:
                        raise ValueError(
                            f"updater archive entry exceeds its size limit: {name}"
                        )
                    uncompressed_size += member.size
                    if uncompressed_size > MAX_UNCOMPRESSED_BYTES:
                        raise ValueError("updater archive exceeds its uncompressed size limit")
                    seen[name] = member
                root = seen.get(APP_ROOT)
                if root is None or not root.isdir():
                    raise ValueError("updater archive is missing its Slipstream.app directory")
                for required_directory in (
                    f"{APP_ROOT}/Contents",
                    f"{APP_ROOT}/Contents/MacOS",
                ):
                    directory = seen.get(required_directory)
                    if directory is None or not directory.isdir():
                        raise ValueError(
                            f"updater archive is missing directory: {required_directory}"
                        )
                plist_member = seen.get(INFO_PLIST)
                if plist_member is None:
                    raise ValueError("updater archive is missing Info.plist")
                plist_data = _read_tar_member(
                    archive,
                    plist_member,
                    limit=MAX_PLIST_BYTES,
                    label="Info.plist",
                )
                executable_member = seen.get(MAIN_EXECUTABLE)
                if executable_member is None or executable_member.mode & 0o111 == 0:
                    raise ValueError("updater archive main executable is missing or not executable")
                executable = _read_tar_member(
                    archive,
                    executable_member,
                    limit=MAX_EXECUTABLE_BYTES,
                    label="main executable",
                )
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise ValueError("updater archive changed while it was inspected")
    finally:
        os.close(descriptor)

    try:
        info = plistlib.loads(plist_data)
    except (plistlib.InvalidFileException, ValueError) as exc:
        raise ValueError("updater archive Info.plist is invalid") from exc
    required = {
        "CFBundleIdentifier": EXPECTED_IDENTIFIER,
        "CFBundleExecutable": EXPECTED_EXECUTABLE,
        "CFBundleShortVersionString": version,
        "CFBundleVersion": version,
        "CFBundlePackageType": "APPL",
        "LSMinimumSystemVersion": minimum_system_version,
    }
    for key, expected in required.items():
        if info.get(key) != expected:
            raise ValueError(f"updater archive {key} must be {expected!r}")
    if info.get("LSUIElement") is not True:
        raise ValueError("updater archive must set LSUIElement=true")
    embedded_key_count = executable.count(outer_public_key.encode("ascii"))
    if embedded_key_count != 1:
        raise ValueError(
            "updater archive executable must embed the exact Tauri updater public key once"
        )
    return {
        "sha256": digest.hexdigest(),
        "size": before.st_size,
        "entries": len(members),
        "uncompressed_size": uncompressed_size,
        "executable_sha256": hashlib.sha256(executable).hexdigest(),
        "embedded_pubkey_count": embedded_key_count,
        "bundle_identifier": info["CFBundleIdentifier"],
        "bundle_version": info["CFBundleVersion"],
        "lsui_element": True,
    }


def verify_updater_artifacts(
    *, release_dir: Path, version: str, tauri_config: Path = DEFAULT_TAURI_CONFIG
) -> dict:
    if not isinstance(version, str) or not version.strip():
        raise ValueError("updater version is required")
    release_dir = release_dir.resolve()
    archive_path = release_dir / ARCHIVE_NAME
    signature_path = release_dir / SIGNATURE_NAME
    outer_public_key, config_identity, minimum_system_version = _load_tauri_public_key(
        tauri_config.resolve(), version=version
    )
    key_id, public_key, _ = _parse_public_key(outer_public_key)
    archive_blake2b, archive_identity = _hash_archive(archive_path)
    signature_raw, signature_identity = _read_regular(
        signature_path, limit=MAX_SIGNATURE_BYTES, label="updater signature"
    )
    try:
        outer_signature = signature_raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("updater signature must be ASCII") from exc
    signature_key_id, primary_signature, trusted_comment, global_signature = (
        _parse_signature(outer_signature)
    )
    if signature_key_id != key_id:
        raise ValueError("updater signature was produced by a different key")
    _verify_ed25519(
        public_key,
        archive_blake2b,
        primary_signature,
    )
    _verify_ed25519(
        public_key,
        primary_signature + trusted_comment,
        global_signature,
    )
    inspected = _inspect_archive(
        archive_path,
        version=version,
        minimum_system_version=minimum_system_version,
        outer_public_key=outer_public_key,
    )
    if (
        archive_identity["sha256"] != inspected["sha256"]
        or archive_identity["size"] != inspected["size"]
    ):
        raise ValueError("updater archive changed between signature and metadata verification")
    return {
        "schema_version": SCHEMA_VERSION,
        "verified": True,
        "version": version,
        "key_id": key_id.hex(),
        "tauri_config": config_identity,
        "signature": signature_identity,
        "archive": inspected,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-dir", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--tauri-config", type=Path, default=DEFAULT_TAURI_CONFIG)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    proof = verify_updater_artifacts(
        release_dir=args.release_dir,
        version=args.version,
        tauri_config=args.tauri_config,
    )
    print(json.dumps(proof, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
