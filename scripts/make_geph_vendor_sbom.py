#!/usr/bin/env python3
"""Build and verify the deterministic SPDX inventory for vendored Geph."""

from __future__ import annotations

import argparse
import json
import hashlib
import os
import stat
import tomllib
from pathlib import Path
from urllib.parse import quote

import geph_vendor_source
from make_release_sbom import (
    DATA_LICENSE,
    DOCUMENT_SPDX_ID,
    SPDX_VERSION,
    Component,
    SOURCE_COMMIT_PATTERN,
    _cargo_components,
    _cargo_registry_component,
    _cargo_lock_checksums,
    _reachable_cargo_package_ids,
    _component_package,
    _purl,
    utc_timestamp,
    write_json_atomic,
)


GENERATOR = "slipstream-geph-vendor-sbom-1"
ROOT_SPDX_ID = "SPDXRef-Package-geph5-client"
VENDOR_TARGET = "macos-universal"


def _metadata_argument(value: str) -> tuple[str, Path]:
    target, separator, raw_path = value.partition("=")
    if not separator or not target or not raw_path:
        raise argparse.ArgumentTypeError("Cargo metadata must use TARGET=PATH")
    return target, Path(raw_path)


def _embedded_descriptors(source: dict) -> list[dict]:
    geph_vendor_source._validate_source_contract(source)
    return source.get("embedded_packages", {}).get("packages", [])


def _source_digest(source_sha256: str | None) -> str:
    if not isinstance(source_sha256, str) or not geph_vendor_source.SHA256_PATTERN.fullmatch(source_sha256):
        raise ValueError("embedded Geph SBOM requires the exact SOURCE file SHA256")
    return source_sha256


def _read_owned_file(root_fd: int, relative: str, limit: int) -> bytes:
    """Read one bounded regular file beneath a pinned directory without symlinks."""
    parts = relative.split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("invalid materialized source path")
    descriptor = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        with os.fdopen(file_fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise ValueError("materialized source is not a regular file")
            payload = handle.read(limit + 1)
            if len(payload) > limit:
                raise ValueError("materialized source file exceeds size limit")
            return payload
    finally:
        os.close(descriptor)


def _owned_tree_files(root_fd: int, relative: str) -> set[str]:
    descriptor = os.dup(root_fd)
    try:
        for part in relative.split("/"):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        found = set()
        visited = 0
        def visit(directory: int, prefix: str) -> None:
            nonlocal visited
            for name in os.listdir(directory):
                visited += 1
                if visited > 64:
                    raise ValueError("embedded source tree exceeds reviewed inventory size")
                info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                path = prefix + name
                if stat.S_ISREG(info.st_mode):
                    found.add(path)
                elif stat.S_ISDIR(info.st_mode):
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                    try:
                        visit(child, path + "/")
                    finally:
                        os.close(child)
                else:
                    raise ValueError("embedded source tree contains a symlink or special file")
        visit(descriptor, "")
        return found
    finally:
        os.close(descriptor)


def _materialized_embedded_source(source: dict, source_root: Path, cargo_lock: Path) -> tuple[Path, bytes]:
    descriptors = _embedded_descriptors(source)
    root = source_root.absolute()
    if root.resolve(strict=True) != root:
        raise ValueError("materialized source root must be physical and without symlinks")
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        lock_bytes = cargo_lock.read_bytes()
        if hashlib.sha256(lock_bytes).hexdigest() != source["lock_sha256"]:
            raise ValueError("Geph lock does not match SOURCE")
        if _read_owned_file(descriptor, "Cargo.lock", len(lock_bytes)) != lock_bytes:
            raise ValueError("materialized lock does not match SOURCE")
        manifest_bytes = _read_owned_file(descriptor, "Cargo.toml", geph_vendor_source.MAX_SOURCE_BYTES)
        manifest = tomllib.loads(manifest_bytes.decode("utf-8"))
        declared = manifest.get("package", {})
        if (declared.get("name"), declared.get("version")) != (source["crate"]["name"], source["crate"]["version"]):
            raise ValueError("materialized root manifest identity disagrees with SOURCE")
        manifest_edits = [edit for edit in source.get("source_edits", []) if edit["path"] == "Cargo.toml"]
        if manifest_edits and hashlib.sha256(manifest_bytes).hexdigest() != manifest_edits[-1]["after_sha256"]:
            raise ValueError("materialized root manifest disagrees with final reviewed edit")
        # Validate the local dependency declarations from the bytes already read.
        expected_edges = {
            ("dependencies", "mizaru2"): ("mizaru2-slipstream-client", "slipstream-vendor/mizaru-client"),
            ("patch", "crates-io", "geph5-broker-protocol"): ("geph5-broker-protocol", "slipstream-vendor/geph5-broker-protocol"),
        }
        found_edges = {}
        def visit(value: object, location: tuple[str, ...]) -> None:
            if isinstance(value, dict):
                if "path" in value and location[:1] in {("dependencies",), ("patch",), ("target",), ("build-dependencies",), ("dev-dependencies",), ("replace",), ("workspace",)}:
                    found_edges[location] = (value.get("package", location[-1]), value["path"])
                    if any(key in value for key in ("git", "registry", "registry-index", "workspace")):
                        raise ValueError("materialized root dependency has conflicting source")
                for key, child in value.items():
                    visit(child, (*location, key))
            elif isinstance(value, list):
                for child in value:
                    visit(child, location)
        visit(manifest, ())
        if found_edges != expected_edges:
            raise ValueError("materialized root embedded edges disagree with SOURCE")
        locked = tomllib.loads(lock_bytes.decode("utf-8"))["package"]
        local_identities = [(source["crate"]["name"], source["crate"]["version"])]
        local_identities.extend((package["name"], package["version"]) for package in descriptors)
        local_lock = [(item.get("name"), item.get("version")) for item in locked if "source" not in item and "checksum" not in item]
        if sorted(local_lock) != sorted(local_identities):
            raise ValueError("local Cargo.lock package identities disagree with SOURCE")
        all_files = {package["path"].removeprefix("slipstream-vendor/") + "/" + entry["path"] for package in descriptors for entry in package["files"]}
        if _owned_tree_files(descriptor, "slipstream-vendor") != all_files:
            raise ValueError("materialized embedded namespace file set disagrees with SOURCE")
        for package in descriptors:
            expected = {entry["path"] for entry in package["files"]}
            if _owned_tree_files(descriptor, package["path"]) != expected:
                raise ValueError("materialized embedded file set disagrees with SOURCE")
            for entry in package["files"]:
                payload = _read_owned_file(descriptor, package["path"] + "/" + entry["path"], geph_vendor_source.MAX_EMBEDDED_FILE_BYTES)
                if payload != entry["content"].encode("utf-8"):
                    raise ValueError("materialized embedded file bytes disagree with SOURCE")
    finally:
        os.close(descriptor)
    return root, lock_bytes


def _source_owned_inventory(source: dict, source_commit: str, source_sha256: str | None) -> tuple[list[dict], list[dict], list[dict]]:
    descriptors = _embedded_descriptors(source)
    if not descriptors:
        return [], [], []
    source_sha256 = _source_digest(source_sha256)
    packages, files, relationships = [], [], []
    for descriptor in sorted(descriptors, key=lambda value: value["path"]):
        package_id = "SPDXRef-Package-source-" + descriptor["sha256"]
        sha1s = []
        for entry in sorted(descriptor["files"], key=lambda value: value["path"]):
            relative = descriptor["path"] + "/" + entry["path"]
            file_id = "SPDXRef-File-" + hashlib.sha256((descriptor["sha256"] + "\0" + relative).encode()).hexdigest()
            sha1 = hashlib.sha1(entry["content"].encode("utf-8")).hexdigest()
            sha1s.append(sha1)
            files.append({
                "SPDXID": file_id, "fileName": "./" + relative,
                "checksums": [{"algorithm": "SHA1", "checksumValue": sha1},
                              {"algorithm": "SHA256", "checksumValue": entry["sha256"]}],
                "licenseConcluded": "NOASSERTION", "licenseInfoInFiles": ["NOASSERTION"],
                "copyrightText": "NOASSERTION",
            })
            relationships.append({"spdxElementId": package_id, "relationshipType": "CONTAINS", "relatedSpdxElement": file_id})
        # SPDX 2.3 section 7.9: SHA1 of concatenated, sorted per-file SHA1 hex.
        verification = hashlib.sha1("".join(sorted(sha1s)).encode("ascii")).hexdigest()
        source_info = {"kind": "slipstream-source-owned", "repository_commit": source_commit,
                       "source_sha256": source_sha256, "descriptor_sha256": descriptor["sha256"],
                       "path": descriptor["path"], "provenance": descriptor["provenance"]}
        packages.append({
            "SPDXID": package_id, "name": descriptor["name"], "versionInfo": descriptor["version"],
            "downloadLocation": "NOASSERTION", "filesAnalyzed": True,
            "packageVerificationCode": {"packageVerificationCodeValue": verification},
            "licenseConcluded": "NOASSERTION", "licenseDeclared": descriptor["license"],
            "licenseInfoFromFiles": ["NOASSERTION"], "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": "LIBRARY",
            "sourceInfo": json.dumps(source_info, sort_keys=True, separators=(",", ":")),
            "licenseComments": "Manifest declaration only; source and distribution notice review remain separate gates.",
        })
    return packages, files, relationships


def collect_components(
    *, cargo_lock: Path, cargo_metadata: list[tuple[str, Path]], expected_targets: list[str],
    source: dict | None = None, source_root: Path | None = None,
) -> list[Component]:
    labels = [target for target, _ in cargo_metadata]
    if labels != expected_targets:
        raise ValueError("Geph Cargo metadata targets do not match the source contract")
    descriptors = _embedded_descriptors(source) if source else []
    root = None
    if descriptors:
        if source_root is None:
            raise ValueError("embedded Geph SBOM generation requires explicit materialized source_root")
        root, lock_bytes = _materialized_embedded_source(source, source_root, cargo_lock)
    unique: dict[str, Component] = {}
    for _, metadata_path in cargo_metadata:
        if not descriptors:
            components = _cargo_components(metadata_path, cargo_lock)
        else:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            reachable = _reachable_cargo_package_ids(metadata, metadata_path)
            package_list = metadata.get("packages", [])
            if not all(isinstance(item, dict) and isinstance(item.get("id"), str) for item in package_list):
                raise ValueError("invalid Geph Cargo package metadata")
            by_id = {item["id"]: item for item in package_list}
            nodes = metadata["resolve"]["nodes"]
            if len(by_id) != len(package_list) or len({item["id"] for item in nodes}) != len(nodes):
                raise ValueError("duplicate Geph Cargo graph identity")
            root_id = metadata["resolve"]["root"]
            expected_local = {(item["name"], item["version"]): item for item in descriptors}
            root_descriptor = {"name": source["crate"]["name"], "version": source["crate"]["version"], "path": "", "license": "MPL-2.0"}
            expected_local[(root_descriptor["name"], root_descriptor["version"])] = root_descriptor
            seen_local = set()
            checksums = _cargo_lock_checksums(cargo_lock, payload=lock_bytes)
            components = []
            for package_id in sorted(reachable | {root_id}):
                package = by_id.get(package_id)
                if package is None:
                    raise ValueError("Geph metadata is missing a reachable package")
                identity = (package.get("name"), package.get("version"))
                local = expected_local.get(identity)
                if local is not None:
                    expected_manifest = str(root / local["path"] / "Cargo.toml")
                    if (package.get("source") is not None or package.get("manifest_path") != expected_manifest
                            or package.get("license") != local["license"] or identity in seen_local
                            or (package_id == root_id) != (local is root_descriptor)):
                        raise ValueError("Geph local metadata identity/path disagrees with SOURCE")
                    seen_local.add(identity)
                else:
                    components.append(_cargo_registry_component(package, checksums))
            if seen_local != set(expected_local):
                raise ValueError("Geph metadata is missing a reviewed embedded package")
        for component in components:
            existing = unique.get(component.spdx_id)
            if existing is not None and existing != component:
                raise ValueError(f"SPDX identity collision for {component.name}")
            unique[component.spdx_id] = component
    return sorted(
        unique.values(),
        key=lambda component: (
            component.ecosystem,
            component.name.lower(),
            component.version,
            component.spdx_id,
        ),
    )


def _namespace(
    repository: str,
    version: str,
    release_revision: int,
    target: str,
    source_commit: str,
) -> str:
    return (
        f"https://github.com/{repository}/releases/tag/"
        f"geph-vendor-{quote(version, safe='')}-r{release_revision}/sbom/"
        f"{quote(target, safe='')}/{source_commit}"
    )


def _root_source_info(source: dict, source_commit: str, source_sha256: str | None = None) -> str:
    crate = source["crate"]
    suffix = f"; SOURCE sha256 {_source_digest(source_sha256)}" if source.get("embedded_packages") else ""
    return (
        f"Slipstream commit {source_commit}; exact crates.io archive sha256 "
        f"{crate['sha256']}; Cargo.lock sha256 {source['lock_sha256']}; "
        f"features {','.join(source['features'])}; targets {','.join(source['targets'])}{suffix}"
    )


def build_spdx_document(
    *,
    repository: str,
    source_commit: str,
    source_date_epoch: int,
    target: str,
    source: dict,
    components: list[Component],
    source_sha256: str | None = None,
) -> dict:
    if not SOURCE_COMMIT_PATTERN.fullmatch(source_commit):
        raise ValueError("source commit must be a full lowercase Git object ID")
    if target != VENDOR_TARGET:
        raise ValueError("Geph vendor target must be macos-universal")
    crate = source["crate"]
    root = {
        "SPDXID": ROOT_SPDX_ID,
        "name": crate["name"],
        "versionInfo": crate["version"],
        "downloadLocation": crate["url"],
        "filesAnalyzed": False,
        "licenseConcluded": "MPL-2.0",
        "licenseDeclared": "MPL-2.0",
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "APPLICATION",
        "homepage": "https://github.com/geph-official/geph5",
        "sourceInfo": _root_source_info(source, source_commit, source_sha256),
        "checksums": [{"algorithm": "SHA256", "checksumValue": crate["sha256"]}],
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": _purl("cargo", crate["name"], crate["version"]),
            }
        ],
    }
    owned_packages, files, file_relationships = _source_owned_inventory(source, source_commit, source_sha256)
    packages = [_component_package(component) for component in components] + owned_packages
    relationships = [
        {
            "spdxElementId": DOCUMENT_SPDX_ID,
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": ROOT_SPDX_ID,
        },
        *(
            {
                "spdxElementId": ROOT_SPDX_ID,
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": package["SPDXID"],
            }
            for package in packages
        ),
    ]
    relationships.extend(file_relationships)
    relationships.sort(
        key=lambda item: (
            item["spdxElementId"],
            item["relationshipType"],
            item["relatedSpdxElement"],
        )
    )
    return {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": DATA_LICENSE,
        "SPDXID": DOCUMENT_SPDX_ID,
        "name": f"geph5-client-{crate['version']}-{target}",
        "documentNamespace": _namespace(
            repository,
            crate["version"],
            source["release_revision"],
            target,
            source_commit,
        ),
        "creationInfo": {
            "created": utc_timestamp(source_date_epoch),
            "creators": [f"Tool: {GENERATOR}"],
        },
        "documentDescribes": [ROOT_SPDX_ID],
        "packages": [root, *packages],
        "relationships": relationships,
        **({"files": files} if files else {}),
    }


def validate_spdx_document(
    data: object,
    *,
    repository: str,
    source_commit: str,
    target: str,
    source: dict,
    source_date_epoch: int | None = None,
    source_sha256: str | None = None,
) -> dict:
    if not isinstance(data, dict):
        raise ValueError("Geph SBOM must be a JSON object")
    crate = source["crate"]
    expected = {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": DATA_LICENSE,
        "SPDXID": DOCUMENT_SPDX_ID,
        "name": f"geph5-client-{crate['version']}-{target}",
        "documentNamespace": _namespace(
            repository,
            crate["version"],
            source["release_revision"],
            target,
            source_commit,
        ),
        "documentDescribes": [ROOT_SPDX_ID],
    }
    for key, value in expected.items():
        if data.get(key) != value:
            raise ValueError(f"Geph SBOM {key} does not match the source contract")
    creation = data.get("creationInfo")
    if not isinstance(creation, dict) or creation.get("creators") != [f"Tool: {GENERATOR}"]:
        raise ValueError("Geph SBOM creator is invalid")
    created = creation.get("created")
    if not isinstance(created, str) or not created.endswith("Z"):
        raise ValueError("Geph SBOM creation timestamp is invalid")
    if source_date_epoch is not None and created != utc_timestamp(source_date_epoch):
        raise ValueError("Geph SBOM timestamp does not match the source commit")

    packages = data.get("packages")
    if not isinstance(packages, list) or len(packages) < 2:
        raise ValueError("Geph SBOM does not contain its resolved dependencies")
    package_ids: list[str] = []
    root = None
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("SPDXID"), str):
            raise ValueError("Geph SBOM package is invalid")
        package_ids.append(package["SPDXID"])
        if package["SPDXID"] == ROOT_SPDX_ID:
            root = package
    if len(package_ids) != len(set(package_ids)):
        raise ValueError("Geph SBOM package IDs are not unique")
    if not isinstance(root, dict):
        raise ValueError("Geph SBOM does not describe geph5-client")
    if root.get("versionInfo") != crate["version"]:
        raise ValueError("Geph SBOM version is invalid")
    if root.get("sourceInfo") != _root_source_info(source, source_commit, source_sha256):
        raise ValueError("Geph SBOM sourceInfo is invalid")
    if root.get("checksums") != [
        {"algorithm": "SHA256", "checksumValue": crate["sha256"]}
    ]:
        raise ValueError("Geph SBOM crate checksum is invalid")

    expected_owned, expected_files, expected_file_relationships = _source_owned_inventory(source, source_commit, source_sha256)
    owned_names = {item["name"] for item in expected_owned}
    actual_owned = [item for item in packages if item["SPDXID"].startswith("SPDXRef-Package-source-") or item.get("name") in owned_names]
    if sorted(actual_owned, key=lambda item: item["SPDXID"]) != sorted(expected_owned, key=lambda item: item["SPDXID"]):
        raise ValueError("Geph SBOM source-owned package set/content disagrees with SOURCE")
    if data.get("files", []) != expected_files:
        raise ValueError("Geph SBOM embedded file set/content disagrees with SOURCE")
    relationships = data.get("relationships")
    if not isinstance(relationships, list):
        raise ValueError("Geph SBOM relationships are required")
    relationship_keys = {
        (
            item.get("spdxElementId"),
            item.get("relationshipType"),
            item.get("relatedSpdxElement"),
        )
        for item in relationships
        if isinstance(item, dict)
    }
    if (DOCUMENT_SPDX_ID, "DESCRIBES", ROOT_SPDX_ID) not in relationship_keys:
        raise ValueError("Geph SBOM document does not describe its root package")
    for package_id in package_ids:
        if package_id != ROOT_SPDX_ID and (
            ROOT_SPDX_ID,
            "CONTAINS",
            package_id,
        ) not in relationship_keys:
            raise ValueError(f"Geph SBOM does not contain package {package_id}")
    expected_relationships = [{"spdxElementId": DOCUMENT_SPDX_ID, "relationshipType": "DESCRIBES", "relatedSpdxElement": ROOT_SPDX_ID}]
    expected_relationships.extend({"spdxElementId": ROOT_SPDX_ID, "relationshipType": "CONTAINS", "relatedSpdxElement": package_id} for package_id in package_ids if package_id != ROOT_SPDX_ID)
    expected_relationships.extend(expected_file_relationships)
    if sorted(relationships, key=lambda item: json.dumps(item, sort_keys=True)) != sorted(expected_relationships, key=lambda item: json.dumps(item, sort_keys=True)):
        raise ValueError("Geph SBOM exact relationship set disagrees with source inventory")
    return {
        "dependency_count": len(packages) - 1,
        "format": SPDX_VERSION,
        "package_count": len(packages),
        "target": target,
        "version": crate["version"],
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("generate", "verify"):
        item = subparsers.add_parser(command)
        item.add_argument("--source", required=True, type=Path)
        item.add_argument("--version-file", required=True, type=Path)
        item.add_argument("--cargo-lock", required=True, type=Path)
        item.add_argument("--repository", required=True)
        item.add_argument("--source-commit", required=True)
        item.add_argument("--target", default=VENDOR_TARGET)
        if command == "generate":
            item.add_argument("--source-root", type=Path, help="Required for embedded SOURCE: exact materialized crate root")
            item.add_argument("--output", required=True, type=Path)
            item.add_argument("--source-date-epoch", required=True, type=int)
            item.add_argument(
                "--cargo-metadata",
                required=True,
                action="append",
                type=_metadata_argument,
            )
        else:
            item.add_argument("--sbom", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    source, source_sha256 = geph_vendor_source._source_contract_snapshot(args.source)
    geph_vendor_source._verify_source_contract_files(
        source=source, source_sha256=source_sha256,
        version_path=args.version_file,
        cargo_lock_path=args.cargo_lock,
    )
    if args.command == "generate":
        components = collect_components(
            cargo_lock=args.cargo_lock,
            cargo_metadata=args.cargo_metadata,
            expected_targets=source["targets"],
            source=source, source_root=args.source_root,
        )
        document = build_spdx_document(
            repository=args.repository,
            source_commit=args.source_commit,
            source_date_epoch=args.source_date_epoch,
            target=args.target,
            source=source, source_sha256=source_sha256,
            components=components,
        )
        result = validate_spdx_document(
            document,
            repository=args.repository,
            source_commit=args.source_commit,
            source_date_epoch=args.source_date_epoch,
            target=args.target,
            source=source, source_sha256=source_sha256,
        )
        write_json_atomic(args.output, document)
    else:
        document = json.loads(args.sbom.read_text(encoding="utf-8"))
        result = validate_spdx_document(
            document,
            repository=args.repository,
            source_commit=args.source_commit,
            target=args.target,
            source=source, source_sha256=source_sha256,
        )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
