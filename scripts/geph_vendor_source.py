#!/usr/bin/env python3
"""Prepare and verify the exact source contract for the vendored Geph client."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
from pathlib import Path, PurePosixPath


SCHEMA_VERSION = 1
CRATE_NAME = "geph5-client"
CRATE_URL = "https://static.crates.io/crates/{name}/{name}-{version}.crate"
FEATURES = ("aws_lambda",)
TARGETS = ("aarch64-apple-darwin", "x86_64-apple-darwin")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json_object(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _require_exact_keys(value: dict, expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ValueError(f"{label} fields do not match schema")


def _version_file(path: Path) -> str:
    version = path.read_text(encoding="utf-8").strip()
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError("Geph version file is invalid")
    return version


def load_source_contract(path: Path) -> dict:
    source = _read_json_object(path, "Geph source contract")
    _require_exact_keys(
        source,
        {
            "schema_version",
            "crate",
            "features",
            "targets",
            "lock_sha256",
            "release_revision",
        },
        "Geph source contract",
    )
    if source["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unsupported Geph source contract schema")

    crate = source.get("crate")
    if not isinstance(crate, dict):
        raise ValueError("Geph crate source is required")
    _require_exact_keys(crate, {"name", "version", "url", "sha256"}, "Geph crate")
    version = crate.get("version")
    if crate.get("name") != CRATE_NAME or not isinstance(version, str):
        raise ValueError("Geph crate identity is invalid")
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError("Geph crate version is invalid")
    if crate.get("url") != CRATE_URL.format(name=CRATE_NAME, version=version):
        raise ValueError("Geph crate URL is not the canonical crates.io asset")
    if not SHA256_PATTERN.fullmatch(str(crate.get("sha256", ""))):
        raise ValueError("Geph crate SHA-256 is invalid")
    if source.get("features") != list(FEATURES):
        raise ValueError("Geph build features do not match the reviewed contract")
    if source.get("targets") != list(TARGETS):
        raise ValueError("Geph build targets do not match the reviewed contract")
    if not SHA256_PATTERN.fullmatch(str(source.get("lock_sha256", ""))):
        raise ValueError("Geph Cargo.lock SHA-256 is invalid")
    revision = source.get("release_revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise ValueError("Geph release revision is invalid")
    return source


def verify_source_contract(
    *,
    source_path: Path,
    version_path: Path,
    cargo_lock_path: Path,
    crate_path: Path | None = None,
    expected_version: str | None = None,
    expected_crate_sha256: str | None = None,
) -> dict:
    source = load_source_contract(source_path)
    crate = source["crate"]
    version = _version_file(version_path)
    if version != crate["version"]:
        raise ValueError("Geph source contract and VERSION disagree")
    if hash_file(cargo_lock_path) != source["lock_sha256"]:
        raise ValueError("Geph Cargo.lock does not match the source contract")
    if expected_version is not None and version != expected_version:
        raise ValueError("reviewed Geph version is not the requested upstream version")
    if expected_crate_sha256 is not None:
        if not SHA256_PATTERN.fullmatch(expected_crate_sha256):
            raise ValueError("expected Geph crate SHA-256 is invalid")
        if crate["sha256"] != expected_crate_sha256:
            raise ValueError("reviewed Geph crate digest is not the upstream digest")
    if crate_path is not None and hash_file(crate_path) != crate["sha256"]:
        raise ValueError("downloaded Geph crate does not match the source contract")
    return {
        "crate": CRATE_NAME,
        "features": list(FEATURES),
        "lock_sha256": source["lock_sha256"],
        "sha256": crate["sha256"],
        "targets": list(TARGETS),
        "version": version,
        "release_tag": f"geph-vendor-{version}-r{source['release_revision']}",
    }


def _safe_members(archive: tarfile.TarFile, expected_root: str) -> list[tarfile.TarInfo]:
    members = archive.getmembers()
    if not members:
        raise ValueError("Geph crate archive is empty")
    names: set[str] = set()
    for member in members:
        path = PurePosixPath(member.name)
        if (
            path.is_absolute()
            or ".." in path.parts
            or not path.parts
            or path.parts[0] != expected_root
            or member.issym()
            or member.islnk()
            or not (member.isfile() or member.isdir())
        ):
            raise ValueError(f"unsafe Geph crate member: {member.name}")
        normalized = path.as_posix()
        if normalized in names:
            raise ValueError(f"duplicate Geph crate member: {member.name}")
        names.add(normalized)
    return members


def extract_crate(*, crate_path: Path, version: str, output: Path) -> Path:
    expected_root = f"{CRATE_NAME}-{version}"
    output.mkdir(parents=True, exist_ok=True)
    root = output / expected_root
    if root.exists() or root.is_symlink():
        raise ValueError("Geph crate output root already exists")
    with tarfile.open(crate_path, mode="r:gz") as archive:
        members = _safe_members(archive, expected_root)
        archive.extractall(output, members=members, filter="data")
    if not root.is_dir() or not (root / "Cargo.toml").is_file():
        raise ValueError("Geph crate archive has no expected Cargo.toml")
    return root


def _verify_manifest(root: Path, version: str) -> None:
    with (root / "Cargo.toml").open("rb") as handle:
        manifest = tomllib.load(handle)
    package = manifest.get("package")
    if not isinstance(package, dict):
        raise ValueError("Geph crate manifest has no package table")
    if package.get("name") != CRATE_NAME or package.get("version") != version:
        raise ValueError("Geph crate manifest identity does not match the contract")


def _write_atomic(path: Path, payload: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def prepare_source_contract(
    *,
    crate_path: Path,
    version: str,
    crate_sha256: str,
    output_dir: Path,
    release_revision: int = 1,
) -> dict:
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError("Geph version is invalid")
    if not SHA256_PATTERN.fullmatch(crate_sha256):
        raise ValueError("Geph crate SHA-256 is invalid")
    if hash_file(crate_path) != crate_sha256:
        raise ValueError("downloaded Geph crate digest does not match crates.io")
    if (
        not isinstance(release_revision, int)
        or isinstance(release_revision, bool)
        or release_revision < 1
    ):
        raise ValueError("Geph release revision is invalid")

    with tempfile.TemporaryDirectory(prefix="slipstream-geph-source-") as temporary:
        root = extract_crate(crate_path=crate_path, version=version, output=Path(temporary))
        _verify_manifest(root, version)
        (root / "Cargo.lock").unlink(missing_ok=True)
        completed = subprocess.run(
            ("cargo", "generate-lockfile", "--manifest-path", str(root / "Cargo.toml")),
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise RuntimeError(f"cargo generate-lockfile failed: {detail}")
        lock = (root / "Cargo.lock").read_bytes()

    lock_sha256 = hashlib.sha256(lock).hexdigest()
    contract = {
        "schema_version": SCHEMA_VERSION,
        "crate": {
            "name": CRATE_NAME,
            "version": version,
            "url": CRATE_URL.format(name=CRATE_NAME, version=version),
            "sha256": crate_sha256,
        },
        "features": list(FEATURES),
        "targets": list(TARGETS),
        "lock_sha256": lock_sha256,
        "release_revision": release_revision,
    }
    _write_atomic(output_dir / "VERSION", f"{version}\n".encode())
    _write_atomic(output_dir / "Cargo.lock", lock)
    _write_atomic(
        output_dir / "SOURCE.json",
        (json.dumps(contract, indent=2, sort_keys=True) + "\n").encode(),
    )
    return contract


def materialize_source(
    *, source_path: Path, version_path: Path, cargo_lock_path: Path, crate_path: Path, output: Path
) -> Path:
    summary = verify_source_contract(
        source_path=source_path,
        version_path=version_path,
        cargo_lock_path=cargo_lock_path,
        crate_path=crate_path,
    )
    root = extract_crate(crate_path=crate_path, version=summary["version"], output=output)
    _verify_manifest(root, summary["version"])
    shutil.copyfile(cargo_lock_path, root / "Cargo.lock")
    return root


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--crate", required=True, type=Path)
    prepare.add_argument("--version", required=True)
    prepare.add_argument("--crate-sha256", required=True)
    prepare.add_argument("--output-dir", required=True, type=Path)
    prepare.add_argument("--release-revision", type=int, default=1)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--source", required=True, type=Path)
    verify.add_argument("--version-file", required=True, type=Path)
    verify.add_argument("--cargo-lock", required=True, type=Path)
    verify.add_argument("--crate", type=Path)
    verify.add_argument("--expected-version")
    verify.add_argument("--expected-crate-sha256")

    extract = subparsers.add_parser("extract")
    extract.add_argument("--source", required=True, type=Path)
    extract.add_argument("--version-file", required=True, type=Path)
    extract.add_argument("--cargo-lock", required=True, type=Path)
    extract.add_argument("--crate", required=True, type=Path)
    extract.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.command == "prepare":
        result = prepare_source_contract(
            crate_path=args.crate,
            version=args.version,
            crate_sha256=args.crate_sha256,
            output_dir=args.output_dir,
            release_revision=args.release_revision,
        )
    elif args.command == "verify":
        result = verify_source_contract(
            source_path=args.source,
            version_path=args.version_file,
            cargo_lock_path=args.cargo_lock,
            crate_path=args.crate,
            expected_version=args.expected_version,
            expected_crate_sha256=args.expected_crate_sha256,
        )
    else:
        root = materialize_source(
            source_path=args.source,
            version_path=args.version_file,
            cargo_lock_path=args.cargo_lock,
            crate_path=args.crate,
            output=args.output,
        )
        result = {"root": str(root)}
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
