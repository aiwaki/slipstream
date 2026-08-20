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
EXACT_SEMVER_PATTERN = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
H2_TRANSITION_EXCEPTION_ID = "geph-h2-0.4.15-awaiting-vendor-r2"


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
    schema_version = source["schema_version"]
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != SCHEMA_VERSION
    ):
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


def _exact_semver(version: str, label: str) -> tuple[int, int, int]:
    match = EXACT_SEMVER_PATTERN.fullmatch(version)
    if match is None:
        raise ValueError(f"{label} must be an exact semantic version (x.y.z)")
    return tuple(int(component) for component in match.groups())


def _cargo_lock_has_h2_0_4_15(
    path: Path,
    expected_sha256: str | None,
    label: str,
) -> bool:
    payload = path.read_bytes()
    if (
        expected_sha256 is not None
        and hashlib.sha256(payload).hexdigest() != expected_sha256
    ):
        raise ValueError(f"{label} does not match the source contract")
    try:
        lock = tomllib.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"{label} is not valid TOML") from exc

    packages = lock.get("package")
    if not isinstance(packages, list) or not packages:
        raise ValueError(f"{label} has no package array")
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError(f"{label} package entry is invalid")
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise ValueError(f"{label} package identity is invalid")
        if name == "h2" and version == "0.4.15":
            return True
    return False


def _load_geph_policy(path: Path, label: str) -> dict:
    policy = _read_json_object(path, label)
    exceptions = policy.get("exceptions")
    if not isinstance(exceptions, list):
        raise ValueError(f"{label} exceptions must be an array")
    return policy


def _verify_h2_transition_exception(
    *,
    policy: dict,
    label: str,
    h2_present: bool,
) -> dict | None:
    matching = _h2_transition_exceptions(policy=policy, label=label)

    if h2_present:
        if len(matching) != 1:
            raise ValueError(
                f"{label} requires exactly one {H2_TRANSITION_EXCEPTION_ID} exception "
                "while h2 0.4.15 is locked"
            )
        return matching[0]
    if matching:
        raise ValueError(
            f"{H2_TRANSITION_EXCEPTION_ID} is forbidden in {label} "
            "when h2 0.4.15 is absent"
        )
    return None


def _h2_transition_exceptions(*, policy: dict, label: str) -> list[dict]:
    matching: list[dict] = []
    for exception in policy["exceptions"]:
        if not isinstance(exception, dict) or not isinstance(exception.get("id"), str):
            raise ValueError(f"{label} exception is invalid")
        if exception["id"] == H2_TRANSITION_EXCEPTION_ID:
            if exception.get("package") != "h2" or exception.get("version") != "0.4.15":
                raise ValueError(
                    f"{H2_TRANSITION_EXCEPTION_ID} has the wrong package identity"
                )
            matching.append(exception)
    return matching


def retire_h2_transition_exception(*, cargo_lock_path: Path, policy_path: Path) -> dict:
    """Atomically retire the temporary h2 bridge when the lock no longer needs it."""

    h2_present = _cargo_lock_has_h2_0_4_15(
        cargo_lock_path,
        None,
        "Geph Cargo.lock",
    )
    policy = _load_geph_policy(policy_path, "Geph dependency audit policy")
    matching = _h2_transition_exceptions(
        policy=policy,
        label="Geph dependency audit policy",
    )
    if len(matching) > 1:
        raise ValueError(
            f"Geph dependency audit policy has duplicate {H2_TRANSITION_EXCEPTION_ID} entries"
        )
    if h2_present:
        if not matching:
            raise ValueError(
                f"h2 0.4.15 still requires {H2_TRANSITION_EXCEPTION_ID}"
            )
        changed = False
    elif not matching:
        changed = False
    else:
        updated = dict(policy)
        updated["exceptions"] = [
            exception
            for exception in policy["exceptions"]
            if exception["id"] != H2_TRANSITION_EXCEPTION_ID
        ]
        mode = policy_path.stat().st_mode & 0o777
        _write_atomic(
            policy_path,
            (json.dumps(updated, indent=2, sort_keys=True) + "\n").encode(),
            mode=mode,
        )
        changed = True
    return {
        "changed": changed,
        "h2_0_4_15_present": h2_present,
        "removed_exception": H2_TRANSITION_EXCEPTION_ID if changed else None,
    }


def _verify_policy_transition(
    *,
    previous_policy: dict,
    current_policy: dict,
    previous_h2_present: bool,
    current_h2_present: bool,
) -> str:
    def canonical(value: dict) -> str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    if canonical(current_policy) == canonical(previous_policy):
        return "unchanged"

    if not previous_h2_present or current_h2_present:
        raise ValueError("Geph dependency audit policy additions or changes are forbidden")

    expected_current = dict(previous_policy)
    expected_current["exceptions"] = [
        exception
        for exception in previous_policy["exceptions"]
        if exception["id"] != H2_TRANSITION_EXCEPTION_ID
    ]
    if canonical(current_policy) != canonical(expected_current):
        raise ValueError(
            "Geph dependency audit policy may only remove the exact temporary h2 exception"
        )
    return "removed-temporary-h2-exception"


def verify_source_transition(
    *,
    previous_source_path: Path,
    previous_version_path: Path,
    previous_cargo_lock_path: Path,
    previous_policy_path: Path,
    current_source_path: Path,
    current_version_path: Path,
    current_cargo_lock_path: Path,
    current_policy_path: Path,
) -> dict:
    """Verify an immutable Geph vendor release transition and its temporary policy."""

    previous_summary = verify_source_contract(
        source_path=previous_source_path,
        version_path=previous_version_path,
        cargo_lock_path=previous_cargo_lock_path,
    )
    current_summary = verify_source_contract(
        source_path=current_source_path,
        version_path=current_version_path,
        cargo_lock_path=current_cargo_lock_path,
    )
    previous = load_source_contract(previous_source_path)
    current = load_source_contract(current_source_path)

    for field in ("schema_version", "features", "targets"):
        if current[field] != previous[field]:
            raise ValueError(f"Geph {field} must not change during a vendor transition")
    if current["crate"]["name"] != previous["crate"]["name"]:
        raise ValueError("Geph crate name must not change during a vendor transition")

    previous_version = _exact_semver(previous_summary["version"], "previous Geph version")
    current_version = _exact_semver(current_summary["version"], "current Geph version")
    previous_revision = previous["release_revision"]
    current_revision = current["release_revision"]

    if current_version < previous_version:
        raise ValueError("Geph vendor version downgrade is forbidden")
    if current_version > previous_version:
        if current_revision != 1:
            raise ValueError("an upgraded Geph version must start at release revision 1")
        transition = "upgrade"
    else:
        if current["crate"] != previous["crate"]:
            raise ValueError("same-version Geph transition must preserve crate identity")
        if current_revision <= previous_revision:
            raise ValueError("same-version Geph release revision is reused or decreases")
        if current_revision != previous_revision + 1:
            raise ValueError("same-version Geph release revision must increase by exactly one")
        transition = "revision"

    previous_h2_present = _cargo_lock_has_h2_0_4_15(
        previous_cargo_lock_path,
        previous["lock_sha256"],
        "previous Geph Cargo.lock",
    )
    current_h2_present = _cargo_lock_has_h2_0_4_15(
        current_cargo_lock_path,
        current["lock_sha256"],
        "current Geph Cargo.lock",
    )
    previous_policy = _load_geph_policy(
        previous_policy_path,
        "previous Geph dependency audit policy",
    )
    current_policy = _load_geph_policy(
        current_policy_path,
        "current Geph dependency audit policy",
    )
    _verify_h2_transition_exception(
        policy=previous_policy,
        label="previous Geph dependency audit policy",
        h2_present=previous_h2_present,
    )
    _verify_h2_transition_exception(
        policy=current_policy,
        label="current Geph dependency audit policy",
        h2_present=current_h2_present,
    )
    policy_transition = _verify_policy_transition(
        previous_policy=previous_policy,
        current_policy=current_policy,
        previous_h2_present=previous_h2_present,
        current_h2_present=current_h2_present,
    )
    return {
        "current_release_tag": current_summary["release_tag"],
        "h2_0_4_15_present": current_h2_present,
        "policy_transition": policy_transition,
        "previous_release_tag": previous_summary["release_tag"],
        "transition": transition,
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

    transition = subparsers.add_parser("verify-transition")
    transition.add_argument("--previous-source", required=True, type=Path)
    transition.add_argument("--previous-version-file", required=True, type=Path)
    transition.add_argument("--previous-cargo-lock", required=True, type=Path)
    transition.add_argument("--previous-policy", required=True, type=Path)
    transition.add_argument("--current-source", "--source", required=True, type=Path)
    transition.add_argument(
        "--current-version-file", "--version-file", required=True, type=Path
    )
    transition.add_argument("--current-cargo-lock", "--cargo-lock", required=True, type=Path)
    transition.add_argument("--current-policy", "--policy", required=True, type=Path)

    retire = subparsers.add_parser("retire-h2-transition-exception")
    retire.add_argument("--cargo-lock", required=True, type=Path)
    retire.add_argument("--policy", required=True, type=Path)

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
    elif args.command == "verify-transition":
        result = verify_source_transition(
            previous_source_path=args.previous_source,
            previous_version_path=args.previous_version_file,
            previous_cargo_lock_path=args.previous_cargo_lock,
            previous_policy_path=args.previous_policy,
            current_source_path=args.current_source,
            current_version_path=args.current_version_file,
            current_cargo_lock_path=args.current_cargo_lock,
            current_policy_path=args.current_policy,
        )
    elif args.command == "retire-h2-transition-exception":
        result = retire_h2_transition_exception(
            cargo_lock_path=args.cargo_lock,
            policy_path=args.policy,
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
