#!/usr/bin/env python3
"""Prepare and verify the exact source contract for the vendored Geph client."""

from __future__ import annotations

import argparse
import copy
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

import geph_native_sqlite


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
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_EMBEDDED_FILE_BYTES = 256 * 1024
MAX_EMBEDDED_BYTES = 1024 * 1024
MAX_CRATE_BYTES = 64 * 1024 * 1024
MAX_CRATE_UNPACKED_BYTES = 128 * 1024 * 1024
MAX_CRATE_ENTRIES = 4096
REPOSITORY_MIT_SHA256 = "418510c495b074f7466c6c3c51af379889e8c28479da0a4f2006cf08e5e60a15"
# Standard template from https://opensource.org/license/isc, including literal
# <YEAR>/<OWNER> placeholders; this is not a recovered upstream copyright notice.
ISC_STANDARD_TEXT_SHA256 = "242238da85b3c2178895de4294e0a43a5394e479b318762f5b2575f0af551eee"
# Deliberately not a general path-package or build-script extension point.
EMBEDDED_PACKAGES = {
    "slipstream-vendor/mizaru-client": {
        "name": "mizaru2-slipstream-client", "version": "0.1.0", "license": "ISC",
        "upstream": ("mizaru2", "0.2.21"), "sources": {"src/lib.rs"},
        "local_dependency": ("backend", "slipstream-rsa-client", "../aws-lc-backend"),
    },
    "slipstream-vendor/aws-lc-backend": {
        "name": "slipstream-rsa-client", "version": "0.1.0", "license": "MIT",
        "upstream": None, "sources": {"src/lib.rs", "src/owned.rs"},
        "local_dependency": None,
    },
    "slipstream-vendor/geph5-broker-protocol": {
        "name": "geph5-broker-protocol", "version": "0.4.3", "license": "ISC",
        "upstream": ("geph5-broker-protocol", "0.4.3"),
        "sources": {"src/lib.rs", "src/bridge.rs", "src/exit.rs", "src/mac.rs",
                    "src/puzzle.rs", "src/route.rs", "src/signed.rs"},
        "local_dependency": ("mizaru2", "mizaru2-slipstream-client", "../mizaru-client"),
    },
}


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_bounded_json(path: Path, label: str) -> bytes:
    with path.open("rb") as handle:
        payload = handle.read(MAX_SOURCE_BYTES + 1)
    if len(payload) > MAX_SOURCE_BYTES:
        raise ValueError(f"{label} exceeds size limit")
    return payload


def _json_object(payload: bytes, label: str) -> dict:
    def unique_object(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} has a duplicate JSON field")
            result[key] = value
        return result

    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=unique_object)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _read_json_object(path: Path, label: str) -> dict:
    return _json_object(_read_bounded_json(path, label), label)


def _require_exact_keys(value: dict, expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ValueError(f"{label} fields do not match schema")


def _version_file(path: Path) -> str:
    version = path.read_text(encoding="utf-8").strip()
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError("Geph version file is invalid")
    return version


def load_source_contract(path: Path) -> dict:
    return _source_contract_snapshot(path)[0]


def _source_contract_snapshot(path: Path) -> tuple[dict, str]:
    payload = _read_bounded_json(path, "Geph source contract")
    source = _json_object(payload, "Geph source contract")
    _validate_source_contract(source)
    return source, hashlib.sha256(payload).hexdigest()


def _validate_source_contract(source: dict) -> None:
    _require_exact_keys(
        source,
        {
            "schema_version",
            "crate",
            "features",
            "targets",
            "lock_sha256",
            "release_revision",
        } | ({"source_edits"} if "source_edits" in source else set())
        | ({"embedded_packages"} if "embedded_packages" in source else set())
        | ({"native_sqlite"} if "native_sqlite" in source else set()),
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
    edits = source.get("source_edits", [])
    if not isinstance(edits, list) or len(edits) > 16:
        raise ValueError("invalid Geph source edits")
    for edit in edits:
        if not isinstance(edit, dict):
            raise ValueError("invalid Geph source edit")
        _require_exact_keys(edit, {"path", "before_sha256", "after_sha256", "before", "after"}, "Geph source edit")
        if not isinstance(edit["path"], str) or not re.fullmatch(r"(?:Cargo\.toml|src/(?:[A-Za-z0-9_]+/)*[A-Za-z0-9_]+\.rs)", edit["path"]):
            raise ValueError("invalid Geph source edit path")
        for field in ("before_sha256", "after_sha256"):
            if not isinstance(edit[field], str) or not SHA256_PATTERN.fullmatch(edit[field]):
                raise ValueError("invalid Geph source edit digest")
        for field in ("before", "after"):
            if not isinstance(edit[field], str) or not edit[field] or len(edit[field]) > 131072:
                raise ValueError("invalid Geph source edit text")
    if "embedded_packages" in source:
        _validate_embedded_packages(source["embedded_packages"])
    if "native_sqlite" in source:
        geph_native_sqlite.validate_descriptor(source["native_sqlite"])


def _canonical_digest(value: dict) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")).hexdigest()


def _manifest_text(text: str, label: str) -> dict:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"{label} is not valid TOML") from exc


def _validate_embedded_manifest(manifest: dict, spec: dict) -> None:
    if not set(manifest).issubset({"package", "lib", "dependencies", "features"}):
        raise ValueError("embedded manifest has unreviewed build/configuration tables")
    package = manifest.get("package")
    allowed = {"name", "version", "license", "edition", "publish", "build", "autolib",
               "autobins", "autoexamples", "autotests", "autobenches", "description",
               "readme", "repository", "resolver"}
    if not isinstance(package, dict) or not set(package).issubset(allowed):
        raise ValueError("embedded manifest package fields are invalid")
    if any(package.get(key) != spec[key] for key in ("name", "version", "license")):
        raise ValueError("embedded manifest identity does not match descriptor")
    if package.get("build", False) is not False or package.get("readme", False) is not False:
        raise ValueError("embedded manifest must not load undeclared build/readme files")
    if package.get("publish") is not False:
        raise ValueError("embedded local package must disable registry publication")
    lib = manifest.get("lib", {})
    if not isinstance(lib, dict) or not set(lib).issubset({"name", "path"}):
        raise ValueError("embedded library target is invalid")
    if lib.get("path", "src/lib.rs") != "src/lib.rs":
        raise ValueError("embedded library target escapes reviewed source")
    dependencies = manifest.get("dependencies", {})
    if not isinstance(dependencies, dict):
        raise ValueError("embedded dependencies must be a table")
    local = []
    for alias, dependency in dependencies.items():
        if isinstance(dependency, str):
            continue
        if not isinstance(dependency, dict) or not set(dependency).issubset({
            "version", "features", "default-features", "optional", "package", "path",
        }):
            raise ValueError("embedded dependency uses an unreviewed source/configuration")
        if "path" in dependency:
            local.append((alias, dependency.get("package", alias), dependency["path"]))
    expected = [spec["local_dependency"]] if spec["local_dependency"] else []
    if local != expected:
        raise ValueError("embedded local dependency edges do not match reviewed packages")


def _validate_embedded_packages(section: object) -> None:
    if not isinstance(section, dict):
        raise ValueError("embedded packages must be an object")
    _require_exact_keys(section, {"schema_version", "packages"}, "embedded packages")
    if type(section["schema_version"]) is not int or section["schema_version"] != 1:
        raise ValueError("unsupported embedded packages schema")
    packages = section["packages"]
    if not isinstance(packages, list) or len(packages) != len(EMBEDDED_PACKAGES):
        raise ValueError("exactly three reviewed embedded packages are required")
    seen = set()
    total_bytes = 0
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError("invalid embedded package")
        _require_exact_keys(package, {"path", "name", "version", "license", "provenance",
                                      "files", "sha256"}, "embedded package")
        path = package["path"]
        if not isinstance(path, str) or path not in EMBEDDED_PACKAGES or path in seen:
            raise ValueError("unknown or duplicate embedded package path")
        seen.add(path)
        spec = EMBEDDED_PACKAGES[path]
        if any(package[key] != spec[key] for key in ("name", "version", "license")):
            raise ValueError("embedded package identity is not reviewed")
        descriptor = {key: value for key, value in package.items() if key != "sha256"}
        if package["sha256"] != _canonical_digest(descriptor):
            raise ValueError("embedded package descriptor digest mismatch")
        file_list = package["files"]
        mandatory = {"Cargo.toml"} | spec["sources"]
        mandatory |= {"SOURCE-NOTICE.md", "provenance/Cargo.toml", "LICENSE-ISC.txt"} if spec["upstream"] else {"LICENSE"}
        if not isinstance(file_list, list) or len(file_list) != len(mandatory):
            raise ValueError("embedded package file set is incomplete or unreviewed")
        contents = {}
        for entry in file_list:
            if not isinstance(entry, dict):
                raise ValueError("invalid embedded file")
            _require_exact_keys(entry, {"path", "sha256", "content"}, "embedded file")
            name = entry["path"]
            if not isinstance(name, str) or name not in mandatory or name in contents:
                raise ValueError("unknown or duplicate embedded file path")
            content = entry["content"]
            if not isinstance(content, str) or not content or "\0" in content:
                raise ValueError("invalid embedded UTF-8 content")
            try:
                payload = content.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError("invalid embedded UTF-8 content") from exc
            total_bytes += len(payload)
            if len(payload) > MAX_EMBEDDED_FILE_BYTES or total_bytes > MAX_EMBEDDED_BYTES:
                raise ValueError("embedded source exceeds size limit")
            if entry["sha256"] != hashlib.sha256(payload).hexdigest():
                raise ValueError("embedded file digest mismatch")
            contents[name] = content
        _validate_embedded_manifest(_manifest_text(contents["Cargo.toml"], "embedded manifest"), spec)
        provenance = package["provenance"]
        if not isinstance(provenance, dict):
            raise ValueError("embedded provenance must be an object")
        if spec["upstream"]:
            if hashlib.sha256(contents["LICENSE-ISC.txt"].encode()).hexdigest() != ISC_STANDARD_TEXT_SHA256:
                raise ValueError("embedded derivative must preserve the standard ISC license text")
            _require_exact_keys(provenance, {"kind", "name", "version", "url", "sha256",
                                             "original_files"}, "embedded derivative provenance")
            name, version = spec["upstream"]
            if (provenance["kind"] != "derivative" or provenance["name"] != name
                    or provenance["version"] != version
                    or provenance["url"] != CRATE_URL.format(name=name, version=version)
                    or not isinstance(provenance["sha256"], str)
                    or not SHA256_PATTERN.fullmatch(provenance["sha256"])):
                raise ValueError("embedded upstream identity is invalid")
            originals = provenance["original_files"]
            if not isinstance(originals, dict) or set(originals) != {"Cargo.toml"} | spec["sources"]:
                raise ValueError("embedded original source file set is invalid")
            if any(not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest)
                   for digest in originals.values()):
                raise ValueError("embedded original source digest is invalid")
            if originals["Cargo.toml"] != hashlib.sha256(contents["provenance/Cargo.toml"].encode()).hexdigest():
                raise ValueError("embedded upstream manifest digest mismatch")
            original = _manifest_text(contents["provenance/Cargo.toml"], "upstream manifest").get("package", {})
            if not isinstance(original, dict) or (original.get("name"), original.get("version"), original.get("license")) != (name, version, "ISC"):
                raise ValueError("embedded upstream license declaration/identity mismatch")
        else:
            if provenance != {"kind": "first-party", "repository": "https://github.com/aiwaki/slipstream"}:
                raise ValueError("embedded first-party provenance is invalid")
            if hashlib.sha256(contents["LICENSE"].encode()).hexdigest() != REPOSITORY_MIT_SHA256:
                raise ValueError("embedded backend must preserve the repository MIT license")


def verify_source_contract(
    *,
    source_path: Path,
    version_path: Path,
    cargo_lock_path: Path,
    crate_path: Path | None = None,
    expected_version: str | None = None,
    expected_crate_sha256: str | None = None,
) -> dict:
    source, source_sha256 = _source_contract_snapshot(source_path)
    return _verify_source_contract_files(
        source=source, source_sha256=source_sha256, version_path=version_path,
        cargo_lock_path=cargo_lock_path, crate_path=crate_path,
        expected_version=expected_version, expected_crate_sha256=expected_crate_sha256,
    )


def _verify_source_contract_files(
    *, source: dict, source_sha256: str, version_path: Path, cargo_lock_path: Path,
    crate_path: Path | None = None, expected_version: str | None = None,
    expected_crate_sha256: str | None = None,
) -> dict:
    crate = source["crate"]
    version = _version_file(version_path)
    if version != crate["version"]:
        raise ValueError("Geph source contract and VERSION disagree")
    if hash_file(cargo_lock_path) != source["lock_sha256"]:
        raise ValueError("Geph Cargo.lock does not match the source contract")
    if "native_sqlite" in source:
        geph_native_sqlite.verify_wrapper_lock(
            source["native_sqlite"], cargo_lock_path.read_bytes(), source["lock_sha256"])
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
        "source_sha256": source_sha256,
        "embedded_packages": {
            package["name"]: package["sha256"]
            for package in source.get("embedded_packages", {}).get("packages", [])
        },
        **({"native_sqlite": geph_native_sqlite.descriptor_sha256(source["native_sqlite"])}
           if "native_sqlite" in source else {}),
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

    previous, previous_digest = _source_contract_snapshot(previous_source_path)
    current, current_digest = _source_contract_snapshot(current_source_path)
    previous_summary = _verify_source_contract_files(
        source=previous, source_sha256=previous_digest,
        version_path=previous_version_path,
        cargo_lock_path=previous_cargo_lock_path,
    )
    current_summary = _verify_source_contract_files(
        source=current, source_sha256=current_digest,
        version_path=current_version_path,
        cargo_lock_path=current_cargo_lock_path,
    )
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
        "previous_source_sha256": previous_summary["source_sha256"],
        "current_source_sha256": current_summary["source_sha256"],
        "transition": transition,
    }


def _safe_members(archive: tarfile.TarFile, expected_root: str) -> list[tarfile.TarInfo]:
    members = []
    names: set[str] = set()
    unpacked_bytes = 0
    for member in archive:
        unpacked_bytes += member.size
        if len(members) >= MAX_CRATE_ENTRIES or unpacked_bytes > MAX_CRATE_UNPACKED_BYTES:
            raise ValueError("Geph crate contents exceed size limit")
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
        normalized = path.as_posix().casefold()
        if normalized in names:
            raise ValueError(f"duplicate Geph crate member: {member.name}")
        names.add(normalized)
        members.append(member)
    if not members:
        raise ValueError("Geph crate archive is empty")
    return members


def extract_crate(
    *, crate_path: Path, version: str, output: Path, expected_sha256: str | None = None,
) -> Path:
    expected_root = f"{CRATE_NAME}-{version}"
    output.mkdir(parents=True, exist_ok=True)
    root = output / expected_root
    try:
        root.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise ValueError("Geph crate output root already exists") from exc
    # Hash the exact bounded private snapshot that tarfile consumes. Reopening
    # an externally replaceable pathname after verification loses that binding.
    with tempfile.TemporaryFile() as snapshot, crate_path.open("rb") as original:
        digest = hashlib.sha256()
        size = 0
        while block := original.read(1024 * 1024):
            size += len(block)
            if size > MAX_CRATE_BYTES:
                raise ValueError("Geph crate exceeds size limit")
            digest.update(block)
            snapshot.write(block)
        if expected_sha256 is not None and digest.hexdigest() != expected_sha256:
            raise ValueError("Geph extracted crate does not match the source contract")
        snapshot.seek(0)
        with tarfile.open(fileobj=snapshot, mode="r:gz") as archive:
            members = _safe_members(archive, expected_root)
            relative_members = []
            for member in members:
                parts = PurePosixPath(member.name).parts[1:]
                if not parts:
                    continue
                relative = copy.copy(member)
                relative.name = PurePosixPath(*parts).as_posix()
                relative.mode = 0o700 if relative.isdir() else 0o644
                relative_members.append(relative)
            archive.extractall(root, members=relative_members, filter="data")
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
        root = extract_crate(crate_path=crate_path, version=version, output=Path(temporary),
                             expected_sha256=crate_sha256)
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


def apply_source_edits(root: Path, edits: list[dict]) -> None:
    """Apply reviewed exact edits, bound to complete before/after file digests.

    Edits travel inside SOURCE.json, so released source contracts reproduce
    the binary without unpublished patch files. Never accept fuzzy hunks.
    """
    for edit in edits:
        path = root / edit["path"]
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError("Geph edit escapes extracted source")
        if hash_file(path) != edit["before_sha256"]:
            raise ValueError("Geph source edit input digest mismatch")
        original = path.read_bytes().decode("utf-8")
        if original.count(edit["before"]) != 1:
            raise ValueError("Geph source edit must match exactly once")
        changed = original.replace(edit["before"], edit["after"], 1).encode("utf-8")
        if hashlib.sha256(changed).hexdigest() != edit["after_sha256"]:
            raise ValueError("Geph source edit output digest mismatch")
        path.write_bytes(changed)


def _materialize_embedded_packages(root: Path, section: dict) -> None:
    _validate_embedded_packages(section)
    # The upstream archive cannot preseed this namespace, including a spelling
    # that aliases it on a case-insensitive filesystem.
    if any(path.name.casefold() == "slipstream-vendor" for path in root.iterdir()):
        raise ValueError("embedded source namespace already exists in upstream crate")
    root.chmod(0o700)
    for package in sorted(section["packages"], key=lambda value: value["path"]):
        for entry in sorted(package["files"], key=lambda value: value["path"]):
            destination = root / package["path"] / entry["path"]
            current = root
            for part in destination.relative_to(root).parts[:-1]:
                current /= part
                try:
                    current.mkdir(mode=0o700)
                except FileExistsError:
                    if current.is_symlink() or not current.is_dir():
                        raise ValueError("embedded source parent is not a private directory")
            payload = entry["content"].encode("utf-8")
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
            if hash_file(destination) != entry["sha256"]:
                raise ValueError("materialized embedded file digest mismatch")


def _verify_embedded_root_edges(root: Path) -> None:
    manifest = _manifest_text((root / "Cargo.toml").read_text(encoding="utf-8"), "Geph manifest")
    expected = {
        ("dependencies", "mizaru2"): ("mizaru2-slipstream-client", "slipstream-vendor/mizaru-client"),
        ("patch", "crates-io", "geph5-broker-protocol"): ("geph5-broker-protocol", "slipstream-vendor/geph5-broker-protocol"),
    }
    found = {}

    def visit(value: object, location: tuple[str, ...]) -> None:
        if isinstance(value, dict):
            if "path" in value and location[:1] in {("dependencies",), ("patch",), ("target",), ("build-dependencies",), ("dev-dependencies",), ("replace",), ("workspace",)}:
                found[location] = (value.get("package", location[-1]), value["path"])
                if any(key in value for key in ("git", "registry", "registry-index", "workspace")):
                    raise ValueError("Geph embedded dependency has conflicting source")
            for key, child in value.items():
                visit(child, (*location, key))
        elif isinstance(value, list):
            for child in value:
                visit(child, location)

    visit(manifest, ())
    if found != expected:
        raise ValueError("Geph manifest does not select exactly the reviewed embedded packages")


def materialize_source(
    *, source_path: Path, version_path: Path, cargo_lock_path: Path, crate_path: Path, output: Path,
    native_sqlite_archive: Path | None = None,
) -> Path:
    # Parse and bind one SOURCE snapshot; never verify one set of descriptors
    # and then re-read potentially replaced embedded bytes before materializing.
    source, source_sha256 = _source_contract_snapshot(source_path)
    if ("native_sqlite" in source) != (native_sqlite_archive is not None):
        raise ValueError("native SQLite SOURCE and explicit archive must be supplied together")
    summary = _verify_source_contract_files(
        source=source, source_sha256=source_sha256,
        version_path=version_path,
        cargo_lock_path=cargo_lock_path,
        crate_path=crate_path,
    )
    root = extract_crate(crate_path=crate_path, version=summary["version"], output=output,
                         expected_sha256=source["crate"]["sha256"])
    _verify_manifest(root, summary["version"])
    shutil.copyfile(cargo_lock_path, root / "Cargo.lock")
    if hash_file(root / "Cargo.lock") != source["lock_sha256"]:
        raise ValueError("materialized Geph Cargo.lock does not match the source contract")
    apply_source_edits(root, source.get("source_edits", []))
    # Dependency-only manifest edits cannot rewrite the attested crate identity.
    _verify_manifest(root, summary["version"])
    if "embedded_packages" in source:
        _verify_embedded_root_edges(root)
        _materialize_embedded_packages(root, source["embedded_packages"])
    if "native_sqlite" in source:
        geph_native_sqlite.materialize(source["native_sqlite"], native_sqlite_archive, root)
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
    extract.add_argument("--native-sqlite-archive", type=Path)
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
            native_sqlite_archive=args.native_sqlite_archive,
        )
        result = {"root": str(root)}
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
