#!/usr/bin/env python3
"""Build a deterministic SPDX 2.3 SBOM for a Slipstream release."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import tempfile
import tomllib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote


SPDX_VERSION = "SPDX-2.3"
DATA_LICENSE = "CC0-1.0"
DOCUMENT_SPDX_ID = "SPDXRef-DOCUMENT"
ROOT_SPDX_ID = "SPDXRef-Package-slipstream"
GENERATOR = "slipstream-release-sbom-1"
SOURCE_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REQUIREMENT_PATTERN = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)")


@dataclass(frozen=True)
class Component:
    ecosystem: str
    name: str
    version: str
    download_location: str
    purl: str
    license_declared: str = "NOASSERTION"
    purpose: str = "LIBRARY"
    checksum_algorithm: str | None = None
    checksum_value: str | None = None

    @property
    def spdx_id(self) -> str:
        identity = "\0".join(
            (self.ecosystem, self.name, self.version, self.download_location)
        )
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
        return f"SPDXRef-Package-{self.ecosystem}-{digest}"


def utc_timestamp(source_date_epoch: int) -> str:
    if source_date_epoch < 0:
        raise ValueError("source date epoch must be non-negative")
    return (
        datetime.fromtimestamp(source_date_epoch, tz=UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _require_version_file(path: Path, label: str) -> str:
    value = path.read_text(encoding="utf-8").strip()
    if not value or "\n" in value or "\r" in value:
        raise ValueError(f"{label} version must be one non-empty line")
    return value


def _purl(package_type: str, name: str, version: str) -> str:
    safe_name = "/" if package_type in {"github", "npm"} else ""
    return (
        f"pkg:{package_type}/{quote(name, safe=safe_name)}"
        f"@{quote(version, safe='')}"
    )


def _python_components(path: Path) -> list[Component]:
    components: list[Component] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = REQUIREMENT_PATTERN.match(line)
        if not match:
            continue
        raw_name, version = match.groups()
        name = re.sub(r"[-_.]+", "-", raw_name).lower()
        components.append(
            Component(
                ecosystem="pypi",
                name=name,
                version=version,
                download_location=(
                    f"https://pypi.org/project/{quote(name, safe='')}/"
                    f"{quote(version, safe='')}/"
                ),
                purl=_purl("pypi", name, version),
            )
        )
    if not components:
        raise ValueError(f"no Python packages found in {path}")
    return components


def _cargo_lock_checksums(path: Path) -> dict[tuple[str, str, str | None], str]:
    with path.open("rb") as handle:
        lock = tomllib.load(handle)
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise ValueError(f"{path} does not contain Cargo packages")

    checksums: dict[tuple[str, str, str | None], str] = {}
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError(f"invalid Cargo package in {path}")
        name = package.get("name")
        version = package.get("version")
        source = package.get("source")
        if not all(isinstance(value, str) and value for value in (name, version)):
            raise ValueError(f"Cargo package is missing name/version in {path}")
        if source is not None and not isinstance(source, str):
            raise ValueError(f"invalid Cargo source for {name} {version}")

        checksum = package.get("checksum")
        if checksum is None:
            continue
        if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise ValueError(f"invalid Cargo checksum for {name} {version}")
        key = (name, version, source)
        if key in checksums and checksums[key] != checksum:
            raise ValueError(f"ambiguous Cargo checksum for {name} {version}")
        checksums[key] = checksum
    return checksums


def _reachable_cargo_package_ids(metadata: dict, path: Path) -> set[str]:
    resolve = metadata.get("resolve")
    if not isinstance(resolve, dict):
        raise ValueError(f"{path} does not contain a resolved Cargo graph")
    root = resolve.get("root")
    nodes = resolve.get("nodes")
    if not isinstance(root, str) or not root or not isinstance(nodes, list):
        raise ValueError(f"{path} Cargo resolve graph is incomplete")

    dependencies: dict[str, tuple[str, ...]] = {}
    for node in nodes:
        if not isinstance(node, dict):
            raise ValueError(f"invalid Cargo resolve node in {path}")
        package_id = node.get("id")
        node_dependencies = node.get("deps")
        if not isinstance(package_id, str) or not isinstance(node_dependencies, list):
            raise ValueError(f"invalid Cargo resolve node in {path}")
        runtime_dependencies: list[str] = []
        for dependency in node_dependencies:
            if not isinstance(dependency, dict):
                raise ValueError(f"invalid Cargo dependency for {package_id}")
            dependency_id = dependency.get("pkg")
            dependency_kinds = dependency.get("dep_kinds")
            if not isinstance(dependency_id, str) or not isinstance(
                dependency_kinds, list
            ):
                raise ValueError(f"invalid Cargo dependency for {package_id}")
            if not dependency_kinds or not all(
                isinstance(kind, dict) and kind.get("kind") in {None, "build", "dev"}
                for kind in dependency_kinds
            ):
                raise ValueError(f"invalid Cargo dependency kind for {package_id}")
            if any(kind.get("kind") != "dev" for kind in dependency_kinds):
                runtime_dependencies.append(dependency_id)
        dependencies[package_id] = tuple(runtime_dependencies)
    if root not in dependencies:
        raise ValueError(f"Cargo resolve root is missing from {path}")

    reachable: set[str] = set()
    pending = [root]
    while pending:
        package_id = pending.pop()
        if package_id in reachable:
            continue
        reachable.add(package_id)
        try:
            pending.extend(dependencies[package_id])
        except KeyError as exc:
            raise ValueError(
                f"Cargo dependency {package_id} is missing from {path}"
            ) from exc
    reachable.remove(root)
    return reachable


def _cargo_components(metadata_path: Path, lock_path: Path) -> list[Component]:
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if not isinstance(metadata, dict):
        raise ValueError(f"{metadata_path} must contain a Cargo metadata object")
    packages = metadata.get("packages")
    if not isinstance(packages, list):
        raise ValueError(f"{metadata_path} does not contain Cargo packages")
    reachable = _reachable_cargo_package_ids(metadata, metadata_path)
    checksums = _cargo_lock_checksums(lock_path)

    packages_by_id: dict[str, dict] = {}
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("id"), str):
            raise ValueError(f"invalid Cargo package in {metadata_path}")
        packages_by_id[package["id"]] = package
    missing = sorted(reachable - packages_by_id.keys())
    if missing:
        raise ValueError(f"Cargo metadata is missing resolved package {missing[0]}")

    components: list[Component] = []
    for package_id in sorted(reachable):
        package = packages_by_id[package_id]
        name = package.get("name")
        version = package.get("version")
        source = package.get("source")
        if not all(isinstance(value, str) and value for value in (name, version)):
            raise ValueError(
                f"Cargo package is missing name/version in {metadata_path}"
            )
        if source is not None and not isinstance(source, str):
            raise ValueError(f"invalid Cargo source for {name} {version}")
        checksum_value = checksums.get((name, version, source))

        if isinstance(source, str) and source.startswith("registry+"):
            download_location = (
                f"https://crates.io/api/v1/crates/{quote(name, safe='')}/"
                f"{quote(version, safe='')}/download"
            )
        elif isinstance(source, str) and source.startswith("git+"):
            download_location = source.removeprefix("git+")
        else:
            download_location = "NOASSERTION"

        components.append(
            Component(
                ecosystem="cargo",
                name=name,
                version=version,
                download_location=download_location,
                purl=_purl("cargo", name, version),
                license_declared=(
                    package["license"]
                    if isinstance(package.get("license"), str) and package["license"]
                    else "NOASSERTION"
                ),
                checksum_algorithm="SHA256" if checksum_value else None,
                checksum_value=checksum_value,
            )
        )
    if not components:
        raise ValueError(f"no Cargo dependencies found in {path}")
    return components


def _npm_checksum(integrity: object) -> tuple[str | None, str | None]:
    if not isinstance(integrity, str):
        return None, None
    for token in integrity.split():
        if not token.startswith("sha512-"):
            continue
        try:
            value = base64.b64decode(token.removeprefix("sha512-"), validate=True)
        except ValueError as exc:
            raise ValueError("invalid npm SHA-512 integrity value") from exc
        return "SHA512", value.hex()
    return None, None


def _npm_components(path: Path) -> list[Component]:
    lock = json.loads(path.read_text(encoding="utf-8"))
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        raise ValueError(f"{path} does not contain npm packages")

    components: list[Component] = []
    for package_path, package in packages.items():
        if not package_path or not isinstance(package, dict) or package.get("dev"):
            continue
        name = package.get("name")
        if not isinstance(name, str) or not name:
            name = package_path.rsplit("node_modules/", 1)[-1]
        version = package.get("version")
        if not isinstance(version, str) or not version:
            raise ValueError(f"npm package {name!r} is missing a version")
        resolved = package.get("resolved")
        download_location = (
            resolved if isinstance(resolved, str) and resolved else "NOASSERTION"
        )
        algorithm, checksum = _npm_checksum(package.get("integrity"))
        components.append(
            Component(
                ecosystem="npm",
                name=name,
                version=version,
                download_location=download_location,
                purl=_purl("npm", name, version),
                checksum_algorithm=algorithm,
                checksum_value=checksum,
            )
        )
    if not components:
        raise ValueError(f"no production npm dependencies found in {path}")
    return components


def collect_components(
    *,
    cargo_lock: Path,
    cargo_metadata: Path,
    npm_lock: Path,
    python_lock: Path,
    geph_version_file: Path,
    tg_ws_proxy_version_file: Path,
) -> list[Component]:
    geph_version = _require_version_file(geph_version_file, "Geph")
    tg_ws_proxy_version = _require_version_file(
        tg_ws_proxy_version_file, "tg-ws-proxy"
    )
    components = [
        *_cargo_components(cargo_metadata, cargo_lock),
        *_npm_components(npm_lock),
        *_python_components(python_lock),
        Component(
            ecosystem="cargo",
            name="geph5-client",
            version=geph_version,
            download_location="https://github.com/geph-official/geph5",
            purl=_purl("cargo", "geph5-client", geph_version),
            license_declared="MPL-2.0",
            purpose="APPLICATION",
        ),
        Component(
            ecosystem="github",
            name="Flowseal/tg-ws-proxy",
            version=tg_ws_proxy_version,
            download_location="https://github.com/Flowseal/tg-ws-proxy",
            purl=_purl("github", "Flowseal/tg-ws-proxy", tg_ws_proxy_version),
            license_declared="MIT",
            purpose="APPLICATION",
        ),
    ]

    unique: dict[str, Component] = {}
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


def _component_package(component: Component) -> dict:
    package = {
        "SPDXID": component.spdx_id,
        "name": component.name,
        "versionInfo": component.version,
        "downloadLocation": component.download_location,
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": component.license_declared,
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": component.purpose,
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": component.purl,
            }
        ],
    }
    if component.checksum_algorithm and component.checksum_value:
        package["checksums"] = [
            {
                "algorithm": component.checksum_algorithm,
                "checksumValue": component.checksum_value,
            }
        ]
    return package


def _document_namespace(
    repository: str,
    tag: str,
    target: str,
    source_commit: str,
) -> str:
    return (
        f"https://github.com/{repository}/releases/tag/{quote(tag, safe='')}/"
        f"sbom/{quote(target, safe='')}/{source_commit}"
    )


def build_spdx_document(
    *,
    version: str,
    tag: str,
    repository: str,
    source_commit: str,
    source_date_epoch: int,
    target: str,
    components: list[Component],
) -> dict:
    if not version.strip() or not tag.strip() or not target.strip():
        raise ValueError("version, tag, and target are required")
    if not REPOSITORY_PATTERN.fullmatch(repository):
        raise ValueError("repository must use owner/name form")
    if not SOURCE_COMMIT_PATTERN.fullmatch(source_commit):
        raise ValueError("source commit must be a full lowercase Git object ID")

    created_at = utc_timestamp(source_date_epoch)
    root_package = {
        "SPDXID": ROOT_SPDX_ID,
        "name": "Slipstream",
        "versionInfo": version,
        "downloadLocation": f"https://github.com/{repository}/tree/{source_commit}",
        "filesAnalyzed": False,
        "licenseConcluded": "MIT",
        "licenseDeclared": "MIT",
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "APPLICATION",
        "homepage": f"https://github.com/{repository}",
        "sourceInfo": f"Git commit {source_commit}; target {target}",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": _purl("github", repository, version),
            }
        ],
    }
    component_packages = [_component_package(component) for component in components]
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
            for package in component_packages
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
        "name": f"Slipstream-{version}-{target}",
        "documentNamespace": _document_namespace(
            repository, tag, target, source_commit
        ),
        "creationInfo": {
            "created": created_at,
            "creators": [f"Tool: {GENERATOR}"],
        },
        "documentDescribes": [ROOT_SPDX_ID],
        "packages": [root_package, *component_packages],
        "relationships": relationships,
    }


def validate_spdx_document(
    data: object,
    *,
    version: str,
    tag: str,
    repository: str,
    source_commit: str,
    source_date_epoch: int,
    target: str,
) -> dict:
    if not isinstance(data, dict):
        raise ValueError("SBOM must be a JSON object")
    expected = {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": DATA_LICENSE,
        "SPDXID": DOCUMENT_SPDX_ID,
        "name": f"Slipstream-{version}-{target}",
        "documentNamespace": _document_namespace(
            repository, tag, target, source_commit
        ),
        "documentDescribes": [ROOT_SPDX_ID],
    }
    for key, value in expected.items():
        if data.get(key) != value:
            raise ValueError(f"SBOM {key} does not match release metadata")
    creation_info = data.get("creationInfo")
    if not isinstance(creation_info, dict):
        raise ValueError("SBOM creationInfo is required")
    if creation_info.get("created") != utc_timestamp(source_date_epoch):
        raise ValueError("SBOM creation timestamp does not match source date epoch")
    if creation_info.get("creators") != [f"Tool: {GENERATOR}"]:
        raise ValueError("SBOM creator is not the Slipstream release generator")

    packages = data.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ValueError("SBOM packages are required")
    package_ids: list[str] = []
    root_package = None
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError("SBOM package must be an object")
        spdx_id = package.get("SPDXID")
        if not isinstance(spdx_id, str) or not spdx_id.startswith("SPDXRef-"):
            raise ValueError("SBOM package SPDXID is invalid")
        package_ids.append(spdx_id)
        if spdx_id == ROOT_SPDX_ID:
            root_package = package
    if len(package_ids) != len(set(package_ids)):
        raise ValueError("SBOM package SPDXIDs must be unique")
    if not isinstance(root_package, dict):
        raise ValueError("SBOM does not describe Slipstream")
    if root_package.get("versionInfo") != version:
        raise ValueError("SBOM Slipstream version does not match release")
    expected_source = f"Git commit {source_commit}; target {target}"
    if root_package.get("sourceInfo") != expected_source:
        raise ValueError("SBOM sourceInfo does not match release")

    relationships = data.get("relationships")
    if not isinstance(relationships, list):
        raise ValueError("SBOM relationships are required")
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
        raise ValueError("SBOM document must describe Slipstream")
    for package_id in package_ids:
        if package_id == ROOT_SPDX_ID:
            continue
        if (ROOT_SPDX_ID, "CONTAINS", package_id) not in relationship_keys:
            raise ValueError(f"SBOM does not contain package {package_id}")
    return {
        "format": SPDX_VERSION,
        "package_count": len(packages),
        "dependency_count": len(packages) - 1,
        "created": creation_info["created"],
    }


def write_json_atomic(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("--target", required=True)
    parser.add_argument("--cargo-lock", required=True, type=Path)
    parser.add_argument("--cargo-metadata", required=True, type=Path)
    parser.add_argument("--npm-lock", required=True, type=Path)
    parser.add_argument("--python-lock", required=True, type=Path)
    parser.add_argument("--geph-version-file", required=True, type=Path)
    parser.add_argument("--tg-ws-proxy-version-file", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    components = collect_components(
        cargo_lock=args.cargo_lock,
        cargo_metadata=args.cargo_metadata,
        npm_lock=args.npm_lock,
        python_lock=args.python_lock,
        geph_version_file=args.geph_version_file,
        tg_ws_proxy_version_file=args.tg_ws_proxy_version_file,
    )
    document = build_spdx_document(
        version=args.version,
        tag=args.tag,
        repository=args.repository,
        source_commit=args.source_commit,
        source_date_epoch=args.source_date_epoch,
        target=args.target,
        components=components,
    )
    validate_spdx_document(
        document,
        version=args.version,
        tag=args.tag,
        repository=args.repository,
        source_commit=args.source_commit,
        source_date_epoch=args.source_date_epoch,
        target=args.target,
    )
    write_json_atomic(args.output, document)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "package_count": len(document["packages"]),
                "target": args.target,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
