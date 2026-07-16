#!/usr/bin/env python3
"""Build and verify the deterministic SPDX inventory for vendored Geph."""

from __future__ import annotations

import argparse
import json
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


def collect_components(
    *, cargo_lock: Path, cargo_metadata: list[tuple[str, Path]], expected_targets: list[str]
) -> list[Component]:
    labels = [target for target, _ in cargo_metadata]
    if labels != expected_targets:
        raise ValueError("Geph Cargo metadata targets do not match the source contract")
    unique: dict[str, Component] = {}
    for _, metadata_path in cargo_metadata:
        for component in _cargo_components(metadata_path, cargo_lock):
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


def _root_source_info(source: dict, source_commit: str) -> str:
    crate = source["crate"]
    return (
        f"Slipstream commit {source_commit}; exact crates.io archive sha256 "
        f"{crate['sha256']}; Cargo.lock sha256 {source['lock_sha256']}; "
        f"features {','.join(source['features'])}; targets {','.join(source['targets'])}"
    )


def build_spdx_document(
    *,
    repository: str,
    source_commit: str,
    source_date_epoch: int,
    target: str,
    source: dict,
    components: list[Component],
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
        "sourceInfo": _root_source_info(source, source_commit),
        "checksums": [{"algorithm": "SHA256", "checksumValue": crate["sha256"]}],
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": _purl("cargo", crate["name"], crate["version"]),
            }
        ],
    }
    packages = [_component_package(component) for component in components]
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
    }


def validate_spdx_document(
    data: object,
    *,
    repository: str,
    source_commit: str,
    target: str,
    source: dict,
    source_date_epoch: int | None = None,
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
    if root.get("sourceInfo") != _root_source_info(source, source_commit):
        raise ValueError("Geph SBOM sourceInfo is invalid")
    if root.get("checksums") != [
        {"algorithm": "SHA256", "checksumValue": crate["sha256"]}
    ]:
        raise ValueError("Geph SBOM crate checksum is invalid")

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
    source = geph_vendor_source.load_source_contract(args.source)
    geph_vendor_source.verify_source_contract(
        source_path=args.source,
        version_path=args.version_file,
        cargo_lock_path=args.cargo_lock,
    )
    if args.command == "generate":
        components = collect_components(
            cargo_lock=args.cargo_lock,
            cargo_metadata=args.cargo_metadata,
            expected_targets=source["targets"],
        )
        document = build_spdx_document(
            repository=args.repository,
            source_commit=args.source_commit,
            source_date_epoch=args.source_date_epoch,
            target=args.target,
            source=source,
            components=components,
        )
        result = validate_spdx_document(
            document,
            repository=args.repository,
            source_commit=args.source_commit,
            source_date_epoch=args.source_date_epoch,
            target=args.target,
            source=source,
        )
        write_json_atomic(args.output, document)
    else:
        document = json.loads(args.sbom.read_text(encoding="utf-8"))
        result = validate_spdx_document(
            document,
            repository=args.repository,
            source_commit=args.source_commit,
            target=args.target,
            source=source,
        )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
