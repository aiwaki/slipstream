#!/usr/bin/env python3
"""Scan and validate Slipstream's exact release SBOM against a review policy."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import ssl
import stat
import subprocess
import sys
import tempfile
import urllib.request
from urllib.parse import unquote
from datetime import date, datetime, timezone
from pathlib import Path


POLICY_SCHEMA_VERSION = 1
LEGACY_REPORT_SCHEMA_VERSION = 1
NATIVE_REPORT_SCHEMA_VERSION = 2
SOURCE_OWNED_REPORT_SCHEMA_VERSION = 3
GENERATOR = "slipstream-dependency-audit-1"
REPORT_NAME = "dependency-audit.json"
DEFAULT_POLICY = (
    Path(__file__).resolve().parents[1] / "security/dependency-audit-policy.json"
)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
SOURCE_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
MAX_SCANNER_BYTES = 128 * 1024 * 1024
MAX_OSV_EVIDENCE_BYTES = 64 * 1024 * 1024
OSV_SCAN_TIMEOUT_SECONDS = 300
VENDORED_TRANSITIVE_COVERAGE = ("top-level-only", "full")
INTEGRITY_ONLY_FIELDS = {
    "expires",
    "name",
    "purl",
    "reason",
    "sha256",
    "version",
}


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json_object(path: Path, label: str) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{label} must be a JSON object")
    return data


def load_policy(path: Path) -> dict:
    policy = _read_json_object(path, "dependency audit policy")
    if policy.get("schema_version") != POLICY_SCHEMA_VERSION:
        raise ValueError("unsupported dependency audit policy schema")
    rules = policy.get("rules")
    if rules != {"informational": "record", "unreviewed": "block"}:
        raise ValueError("dependency audit policy rules are not fail-closed")
    scanner = policy.get("scanner")
    if not isinstance(scanner, dict):
        raise ValueError("dependency audit scanner policy is required")
    if scanner.get("repository") != "google/osv-scanner":
        raise ValueError("dependency audit scanner repository is not trusted")
    version = scanner.get("version")
    if not isinstance(version, str) or not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+", version
    ):
        raise ValueError("dependency audit scanner version is invalid")
    assets = scanner.get("assets")
    if not isinstance(assets, dict) or not assets:
        raise ValueError("dependency audit scanner assets are required")
    for platform, asset in assets.items():
        if not isinstance(platform, str) or not isinstance(asset, dict):
            raise ValueError("dependency audit scanner asset is invalid")
        if not isinstance(asset.get("name"), str) or not SHA256_PATTERN.fullmatch(
            str(asset.get("sha256", ""))
        ):
            raise ValueError(f"dependency audit scanner asset {platform} is invalid")

    exceptions = policy.get("exceptions")
    if not isinstance(exceptions, list):
        raise ValueError("dependency audit exceptions must be a list")
    exception_ids: set[str] = set()
    exception_keys: set[tuple[str, str, str, str]] = set()
    for exception in exceptions:
        if not isinstance(exception, dict):
            raise ValueError("dependency audit exception is invalid")
        required_strings = (
            "id",
            "ecosystem",
            "package",
            "version",
            "expires",
            "reason",
        )
        if not all(
            isinstance(exception.get(key), str) and exception[key]
            for key in required_strings
        ):
            raise ValueError("dependency audit exception is incomplete")
        if exception["id"] in exception_ids:
            raise ValueError(f"duplicate dependency audit exception {exception['id']}")
        exception_ids.add(exception["id"])
        try:
            date.fromisoformat(exception["expires"])
        except ValueError as exc:
            raise ValueError(f"invalid expiry for exception {exception['id']}") from exc
        advisories = exception.get("advisories")
        if not isinstance(advisories, list) or not advisories or not all(
            isinstance(value, str) and value for value in advisories
        ):
            raise ValueError(f"invalid advisories for exception {exception['id']}")
        for advisory_id in advisories:
            key = (
                exception["ecosystem"],
                _canonical_package_name(exception["ecosystem"], exception["package"]),
                exception["version"],
                advisory_id,
            )
            if key in exception_keys:
                raise ValueError(
                    "dependency audit exceptions overlap for "
                    f"{exception['package']} {exception['version']} {advisory_id}"
                )
            exception_keys.add(key)

    integrity_only = policy.get("integrity_only")
    if integrity_only is not None:
        if not isinstance(integrity_only, list):
            raise ValueError("dependency audit integrity-only policy must be a list")
        integrity_keys: set[tuple[str, str]] = set()
        for package in integrity_only:
            if not isinstance(package, dict) or set(package) != INTEGRITY_ONLY_FIELDS:
                raise ValueError(
                    "dependency audit integrity-only package is incomplete"
                )
            if not all(
                isinstance(package.get(key), str) and package[key]
                for key in INTEGRITY_ONLY_FIELDS
            ):
                raise ValueError(
                    "dependency audit integrity-only package is incomplete"
                )
            if not SHA256_PATTERN.fullmatch(package["sha256"]):
                raise ValueError("dependency audit integrity-only checksum is invalid")
            expected_purl = f"pkg:generic/{package['name']}@{package['version']}"
            if package["purl"] != expected_purl:
                raise ValueError("dependency audit integrity-only purl is invalid")
            try:
                date.fromisoformat(package["expires"])
            except ValueError as exc:
                raise ValueError(
                    "dependency audit integrity-only expiry is invalid"
                ) from exc
            key = (package["name"], package["version"])
            if key in integrity_keys:
                raise ValueError(
                    "dependency audit integrity-only package identities overlap"
                )
            integrity_keys.add(key)
    return policy


def scanner_asset(policy: dict, platform: str) -> dict:
    asset = policy["scanner"]["assets"].get(platform)
    if not isinstance(asset, dict):
        raise ValueError(f"unsupported dependency scanner platform: {platform}")
    return asset


def _tls_context() -> ssl.SSLContext:
    try:
        import certifi
    except ImportError:
        return ssl.create_default_context()
    return ssl.create_default_context(cafile=certifi.where())


def expected_scanner_metadata(policy: dict, platform: str) -> dict:
    asset = scanner_asset(policy, platform)
    return {
        "asset": asset["name"],
        "name": "osv-scanner",
        "platform": platform,
        "sha256": asset["sha256"],
        "version": policy["scanner"]["version"],
    }


def fetch_scanner(*, policy_path: Path, platform: str, output: Path) -> dict:
    policy = load_policy(policy_path)
    scanner = policy["scanner"]
    asset = scanner_asset(policy, platform)
    url = (
        f"https://github.com/{scanner['repository']}/releases/download/"
        f"v{scanner['version']}/{asset['name']}"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", dir=output.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        request = urllib.request.Request(url, headers={"User-Agent": GENERATOR})
        with urllib.request.urlopen(
            request, timeout=60, context=_tls_context()
        ) as response, temporary.open("wb") as handle:
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > MAX_SCANNER_BYTES:
                raise ValueError("dependency scanner asset exceeds the size limit")
            received = 0
            while block := response.read(1024 * 1024):
                received += len(block)
                if received > MAX_SCANNER_BYTES:
                    raise ValueError("dependency scanner asset exceeds the size limit")
                handle.write(block)
        actual_sha256 = hash_file(temporary)
        if actual_sha256 != asset["sha256"]:
            raise ValueError(
                "downloaded dependency scanner checksum does not match policy"
            )
        temporary.chmod(0o755)
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "name": asset["name"],
        "platform": platform,
        "sha256": asset["sha256"],
        "url": url,
        "version": scanner["version"],
    }


def verify_scanner(*, scanner_path: Path, policy: dict, platform: str) -> dict:
    asset = scanner_asset(policy, platform)
    metadata = scanner_path.stat()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(scanner_path, os.X_OK):
        raise ValueError("dependency scanner must be an executable regular file")
    actual_sha256 = hash_file(scanner_path)
    if actual_sha256 != asset["sha256"]:
        raise ValueError("dependency scanner checksum does not match policy")
    completed = subprocess.run(
        (str(scanner_path), "--version"),
        capture_output=True,
        text=True,
        check=False,
        shell=False,
        timeout=15,
    )
    version_output = f"{completed.stdout}\n{completed.stderr}"
    expected_version = policy["scanner"]["version"]
    if completed.returncode != 0 or not re.search(
        rf"(?<![0-9.]){re.escape(expected_version)}(?![0-9.])", version_output
    ):
        raise ValueError("dependency scanner version does not match policy")
    return expected_scanner_metadata(policy, platform)


def run_osv_scan(*, scanner_path: Path, sbom_path: Path) -> dict:
    descriptor, output_name = tempfile.mkstemp(prefix="slipstream-osv-", suffix=".json")
    os.close(descriptor)
    output = Path(output_name)
    try:
        completed = subprocess.run(
            (
                str(scanner_path),
                "scan",
                "source",
                "--format",
                "json",
                "--all-packages",
                "-L",
                str(sbom_path),
                "--output-file",
                str(output),
            ),
            capture_output=True,
            text=True,
            check=False,
            shell=False,
            timeout=300,
        )
        if completed.returncode not in {0, 1}:
            detail = (completed.stderr or completed.stdout).strip().splitlines()
            suffix = f": {detail[-1]}" if detail else ""
            message = (
                f"dependency scanner failed with exit code "
                f"{completed.returncode}{suffix}"
            )
            raise RuntimeError(message)
        return _read_json_object(output, "OSV scanner result")
    finally:
        output.unlink(missing_ok=True)


def _informational_kind(vulnerability: dict) -> str | None:
    kinds: set[str] = set()
    database_specific = vulnerability.get("database_specific")
    if isinstance(database_specific, dict) and database_specific.get("informational"):
        kinds.add(str(database_specific["informational"]))
    affected = vulnerability.get("affected")
    if isinstance(affected, list):
        for entry in affected:
            if not isinstance(entry, dict):
                continue
            details = entry.get("database_specific")
            if isinstance(details, dict) and details.get("informational"):
                kinds.add(str(details["informational"]))
    return ",".join(sorted(kinds)) or None


def _advisory_ids(vulnerability: dict) -> tuple[str, ...]:
    values = [vulnerability.get("id")]
    aliases = vulnerability.get("aliases")
    if isinstance(aliases, list):
        values.extend(aliases)
    ids = sorted({value for value in values if isinstance(value, str) and value})
    if not ids:
        raise ValueError("OSV vulnerability is missing an identifier")
    return tuple(ids)


def _matching_exception(
    *, policy: dict, package: dict, advisory_ids: tuple[str, ...]
) -> dict | None:
    matches = []
    advisory_set = set(advisory_ids)
    for exception in policy["exceptions"]:
        if (
            exception["ecosystem"] == package.get("ecosystem")
            and _canonical_package_name(exception["ecosystem"], exception["package"])
            == _canonical_package_name(package["ecosystem"], package["name"])
            and exception["version"] == package.get("version")
            and advisory_set.intersection(exception["advisories"])
        ):
            matches.append(exception)
    if len(matches) > 1:
        raise ValueError(
            f"multiple dependency audit exceptions match {advisory_ids[0]}"
        )
    return matches[0] if matches else None


def _sbom_packages(path: Path) -> list[dict]:
    sbom = _read_json_object(path, "release SBOM")
    packages = sbom.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ValueError("release SBOM does not contain packages")
    if not all(isinstance(package, dict) for package in packages):
        raise ValueError("release SBOM contains an invalid package")
    return packages


def _canonical_package_name(ecosystem: str, name: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem == "GitHub Actions":
        return name.lower()
    return name


def _sbom_scan_identities(
    packages: list[dict], native_package_id: str | None = None,
    source_owned_package_ids: tuple[str, ...] = (),
) -> tuple[set[tuple[str, str, str]], set[tuple[str, str]], set[str]]:
    """Bind scanner coordinates to the package URLs that this generator emits.

    Generic packages remain subject to the existing exact integrity-only policy.
    Source-owned packages without registry identities require a separate review
    contract; assigning them a registry coordinate here would falsify coverage.
    """
    ecosystems = {
        "cargo": "crates.io", "pypi": "PyPI", "npm": "npm",
        "github": "GitHub Actions", "generic": "",
    }
    ids: set[str] = set()
    identities: set[tuple[str, str, str]] = set()
    native_ids: set[str] = set()
    owned_ids = set(source_owned_package_ids)
    owned_seen: set[str] = set()
    if len(owned_ids) != len(source_owned_package_ids) or native_package_id in owned_ids:
        raise ValueError("reviewed source-owned and native package identities overlap or repeat")
    for package in packages:
        spdx_id = package.get("SPDXID")
        if not isinstance(spdx_id, str) or not spdx_id:
            raise ValueError("release SBOM package identity is missing")
        if spdx_id in ids:
            raise ValueError("release SBOM contains a duplicate package identity")
        ids.add(spdx_id)
        references = package.get("externalRefs")
        if spdx_id == native_package_id or spdx_id in owned_ids:
            if references is not None and (not isinstance(references, list) or any(
                isinstance(ref, dict) and ref.get("referenceType") == "purl" for ref in references
            )):
                raise ValueError("reviewed package must not acquire a scanner purl")
            (native_ids if spdx_id == native_package_id else owned_seen).add(spdx_id)
            continue
        if not isinstance(references, list):
            raise ValueError("release SBOM package purl is missing")
        purls = [
            ref for ref in references
            if isinstance(ref, dict) and ref.get("referenceType") == "purl"
        ]
        if len(purls) != 1 or purls[0].get("referenceCategory") != "PACKAGE-MANAGER":
            raise ValueError("release SBOM package must have exactly one package-manager purl")
        locator = purls[0].get("referenceLocator")
        if not isinstance(locator, str) or re.search(r"%(?![0-9A-Fa-f]{2})", locator):
            raise ValueError("release SBOM package purl is invalid")
        match = re.fullmatch(r"pkg:([a-z]+)/([^?#]+)@([^@?#]+)", locator)
        if not match or match[1] not in ecosystems:
            raise ValueError("release SBOM package purl type or syntax is unsupported")
        package_type = match[1]
        try:
            name, version = (unquote(value, errors="strict") for value in match.group(2, 3))
        except UnicodeDecodeError as exc:
            raise ValueError("release SBOM package purl encoding is invalid") from exc
        if any(not value or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value) for value in (name, version)):
            raise ValueError("release SBOM package purl coordinates are invalid")
        if package_type == "github":
            valid_name = re.fullmatch(r"[^/@]+/[^/@]+", name)
        elif package_type == "npm":
            valid_name = re.fullmatch(r"(?:@[^/@]+/)?[^/@]+", name)
        else:
            valid_name = re.fullmatch(r"[^/@]+", name)
        if not valid_name:
            raise ValueError("release SBOM package purl name is invalid")
        ecosystem = ecosystems[package_type]
        name = _canonical_package_name(ecosystem, name)
        declared_name = package.get("name")
        if (
            package.get("versionInfo") != version
            or not isinstance(declared_name, str)
            or not declared_name
            or (package_type != "github" and _canonical_package_name(ecosystem, declared_name) != name)
        ):
            raise ValueError("release SBOM package purl identity does not match package")
        identity = (ecosystem, name, version)
        if identity in identities:
            raise ValueError("release SBOM contains duplicate package coordinates")
        identities.add(identity)
    if native_package_id is not None and native_ids != {native_package_id}:
        raise ValueError("reviewed native package identity is absent from SBOM")
    if owned_seen != owned_ids:
        raise ValueError("reviewed source-owned package identity is absent from SBOM")
    return (
        {identity for identity in identities if identity[0]},
        {(name, version) for ecosystem, name, version in identities if not ecosystem},
        native_ids,
    )


def _native_review(*, policy: dict, sbom_path: Path, evaluated_on: date,
                   source_path: Path | None, native_receipt: Path | None,
                   native_artifacts_root: Path | None, evidence_root: Path | None = None,
                   require_evidence: bool = False) -> dict | None:
    inputs = (source_path, native_receipt, native_artifacts_root)
    if "native_sqlite_review" not in policy:
        # SOURCE is shared with the independently verified source-owned lane.
        unclaimed_source = source_path if "source_owned_review" not in policy else None
        if any(value is not None for value in (unclaimed_source, native_receipt, native_artifacts_root, evidence_root)):
            raise ValueError("native audit inputs require trusted native_sqlite_review policy")
        return None
    if any(value is None for value in inputs) or (require_evidence and evidence_root is None):
        raise ValueError("native audit requires explicit SOURCE, receipt, artifacts and scan evidence")
    # Lazy import preserves the legacy standalone audit API.
    from geph_native_sqlite_advisories import validate_native_review
    return validate_native_review(
        policy["native_sqlite_review"], sbom=_read_json_object(sbom_path, "release SBOM"),
        source_path=source_path, native_receipt=native_receipt,
        native_artifacts_root=native_artifacts_root, evaluated_on=evaluated_on,
        evidence_root=evidence_root,
    )


def _source_owned_review(*, policy: dict, sbom_path: Path, evaluated_on: date,
                         source_path: Path | None, evidence_root: Path | None,
                         source_commit: str) -> dict | None:
    if "source_owned_review" not in policy:
        if evidence_root is not None:
            raise ValueError("source-owned evidence requires trusted source_owned_review policy")
        return None
    if source_path is None or evidence_root is None:
        raise ValueError("source-owned audit requires explicit SOURCE and review evidence")
    from geph_source_owned_advisories import validate_source_owned_review
    return validate_source_owned_review(policy["source_owned_review"],
        sbom=_read_json_object(sbom_path, "release SBOM"), source_path=source_path,
        evidence_root=evidence_root, evaluated_on=evaluated_on, source_commit=source_commit)


def _native_partition(packages: list[dict], package_id: str) -> dict:
    return _reviewed_partition(packages, package_id)


def _reviewed_partition(packages: list[dict], native_id: str | None,
                        source_owned_ids: tuple[str, ...] = ()) -> dict:
    # Call only after the native verifier and exact PURL validation. SPDXIDs,
    # not counts, bind every package to exactly one independently checked lane.
    partition = {"scanned": [], "integrity_only": [], "native": []}
    if source_owned_ids:
        partition["source_owned"] = []
    for package in packages:
        spdx_id = package["SPDXID"]
        if spdx_id == native_id:
            lane = "native"
        elif spdx_id in source_owned_ids:
            lane = "source_owned"
        else:
            locator = next(ref["referenceLocator"] for ref in package["externalRefs"]
                           if isinstance(ref, dict) and ref.get("referenceType") == "purl")
            lane = "integrity_only" if locator.startswith("pkg:generic/") else "scanned"
        partition[lane].append(spdx_id)
    sets = [set(values) for values in partition.values()]
    if (set.union(*sets) != {package["SPDXID"] for package in packages}
            or any(left & right for i, left in enumerate(sets) for right in sets[i + 1:])):
        raise ValueError("native audit package partition does not cover SBOM exactly")
    return {name: sorted(values) for name, values in partition.items()}


def _native_scanner_sbom(sbom: dict, package_id: str) -> bytes:
    projected = dict(sbom)
    projected["packages"] = [package for package in sbom["packages"] if package["SPDXID"] != package_id]
    if "relationships" in sbom:
        projected["relationships"] = [relation for relation in sbom["relationships"]
            if relation.get("spdxElementId") != package_id and relation.get("relatedSpdxElement") != package_id]
    if "documentDescribes" in sbom:
        projected["documentDescribes"] = [identity for identity in sbom["documentDescribes"] if identity != package_id]
    return (json.dumps(projected, indent=2, sort_keys=True) + "\n").encode()


def _reviewed_scanner_sbom(sbom: dict, native_id: str | None,
                           source_owned_ids: tuple[str, ...] = ()) -> bytes:
    if not source_owned_ids:
        return _native_scanner_sbom(sbom, native_id)
    # Preserve the full release document. Only the OSV input omits packages
    # whose exact bytes and findings are covered by independent review lanes.
    excluded = set(source_owned_ids) | ({native_id} if native_id else set())
    file_ids = {relation["relatedSpdxElement"] for relation in sbom.get("relationships", [])
        if relation.get("spdxElementId") in excluded and relation.get("relationshipType") == "CONTAINS"}
    projected = dict(sbom)
    projected["packages"] = [p for p in sbom["packages"] if p["SPDXID"] not in excluded]
    # CONTAINS may also target packages. Remove file entries only by file ID.
    excluded |= {f["SPDXID"] for f in sbom.get("files", []) if f["SPDXID"] in file_ids}
    if "files" in sbom:
        projected["files"] = [f for f in sbom["files"] if f["SPDXID"] not in excluded]
    if "relationships" in sbom:
        projected["relationships"] = [r for r in sbom["relationships"]
            if r.get("spdxElementId") not in excluded and r.get("relatedSpdxElement") not in excluded]
    if "documentDescribes" in sbom:
        projected["documentDescribes"] = [p for p in sbom["documentDescribes"] if p not in excluded]
    return (json.dumps(projected, indent=2, sort_keys=True) + "\n").encode()


def _source_owned_summary(review: dict) -> dict:
    return {"packages_source_owned": len(review["package_ids"]),
            "source_owned_unresolved": review["summary"]["unresolved"],
            "source_owned_affected": review["summary"]["affected"]}


def _check_review_source_binding(native_review: dict | None, owned_review: dict | None) -> None:
    # Independently valid proofs must concern the same SOURCE snapshot.
    if native_review is not None and owned_review is not None:
        if native_review["binding"]["source_sha256"] != owned_review["binding"]["source_sha256"]:
            raise ValueError("native and source-owned reviews bind different SOURCE snapshots")


def _native_summary(review: dict) -> dict:
    return {"packages_native": 1, "native_unresolved": review["summary"]["unresolved"],
            "native_affected": review["summary"]["affected"]}


def _identity_evidence(identities: set[tuple[str, str, str]]) -> list[dict]:
    return [
        {"ecosystem": ecosystem, "name": name, "version": version}
        for ecosystem, name, version in sorted(identities)
    ]


def _matching_integrity_only_policy(
    *, policy: dict, name: str, version: str
) -> dict:
    matches = [
        package
        for package in policy.get("integrity_only", [])
        if package["name"] == name and package["version"] == version
    ]
    if not matches:
        raise ValueError(
            "OSV scanner incomplete package is not integrity-only allowlisted"
        )
    if len(matches) != 1:
        raise ValueError("multiple integrity-only policies match an incomplete package")
    return matches[0]


def _verify_integrity_only_sbom_package(
    *, sbom_packages: list[dict], policy_package: dict, evaluated_on: date
) -> dict:
    if evaluated_on > date.fromisoformat(policy_package["expires"]):
        raise ValueError("dependency audit integrity-only policy is expired")
    matches = [
        package
        for package in sbom_packages
        if package.get("name") == policy_package["name"]
        and package.get("versionInfo") == policy_package["version"]
    ]
    if len(matches) != 1:
        raise ValueError(
            "integrity-only package does not have one exact SBOM identity"
        )
    package = matches[0]
    external_refs = package.get("externalRefs")
    if not isinstance(external_refs, list):
        raise ValueError("integrity-only SBOM package purl is missing")
    purls = [
        reference.get("referenceLocator")
        for reference in external_refs
        if isinstance(reference, dict)
        and reference.get("referenceCategory") == "PACKAGE-MANAGER"
        and reference.get("referenceType") == "purl"
    ]
    if purls != [policy_package["purl"]]:
        raise ValueError("integrity-only SBOM package purl does not match policy")
    checksums = package.get("checksums")
    if not isinstance(checksums, list):
        raise ValueError("integrity-only SBOM package checksum is missing")
    sha256_values = [
        checksum.get("checksumValue")
        for checksum in checksums
        if isinstance(checksum, dict) and checksum.get("algorithm") == "SHA256"
    ]
    if sha256_values != [policy_package["sha256"]]:
        raise ValueError("integrity-only SBOM package checksum does not match policy")
    return {key: policy_package[key] for key in sorted(INTEGRITY_ONLY_FIELDS)}


def evaluate_osv_result(
    *,
    result: dict,
    policy: dict,
    evaluated_on: date,
    sbom_path: Path,
    native_package_id: str | None = None,
    source_owned_package_ids: tuple[str, ...] = (),
) -> tuple[list[dict], int, list[dict], list[dict]]:
    results = result.get("results")
    if not isinstance(results, list):
        raise ValueError("OSV scanner result is missing results")
    findings: list[dict] = []
    packages_seen: set[tuple[str, str, str]] = set()
    integrity_only_seen: dict[tuple[str, str], dict] = {}
    findings_seen: set[tuple[str, str, str, tuple[str, ...]]] = set()
    sbom_packages = _sbom_packages(sbom_path)
    expected_scanned, expected_integrity, _ = _sbom_scan_identities(sbom_packages, native_package_id, source_owned_package_ids)
    for source in results:
        if not isinstance(source, dict) or not isinstance(source.get("packages"), list):
            raise ValueError("OSV scanner result contains an invalid package source")
        for entry in source["packages"]:
            if not isinstance(entry, dict) or not isinstance(
                entry.get("package"), dict
            ):
                raise ValueError("OSV scanner result contains an invalid package")
            package = entry["package"]
            vulnerabilities = entry.get("vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                raise ValueError("OSV scanner vulnerabilities must be a list")
            ecosystem = package.get("ecosystem")
            name = package.get("name")
            version = package.get("version")
            if (
                ecosystem == ""
                and isinstance(name, str)
                and name
                and isinstance(version, str)
                and version
            ):
                if vulnerabilities:
                    raise ValueError(
                        "OSV scanner incomplete package contains vulnerabilities"
                    )
                policy_package = _matching_integrity_only_policy(
                    policy=policy,
                    name=name,
                    version=version,
                )
                integrity_key = (name, version)
                if integrity_key in integrity_only_seen:
                    raise ValueError(
                        "OSV scanner contains a duplicate integrity-only package"
                    )
                integrity_only_seen[integrity_key] = (
                    _verify_integrity_only_sbom_package(
                        sbom_packages=sbom_packages,
                        policy_package=policy_package,
                        evaluated_on=evaluated_on,
                    )
                )
                continue
            coordinates = (ecosystem, name, version)
            if not all(
                isinstance(value, str) and bool(value.strip())
                for value in coordinates
            ):
                raise ValueError("OSV scanner package coordinates are incomplete")
            coordinates = (ecosystem, _canonical_package_name(ecosystem, name), version)
            if coordinates in packages_seen:
                raise ValueError("OSV scanner contains a duplicate package identity")
            if coordinates not in expected_scanned:
                raise ValueError("OSV scanner package identity does not match release SBOM")
            packages_seen.add(coordinates)
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    raise ValueError("OSV scanner vulnerability is invalid")
                advisory_ids = _advisory_ids(vulnerability)
                finding_key = (*coordinates, advisory_ids)
                if finding_key in findings_seen:
                    continue
                findings_seen.add(finding_key)
                finding = {
                    "aliases": list(advisory_ids[1:]),
                    "id": advisory_ids[0],
                    "package": {
                        "ecosystem": coordinates[0],
                        "name": coordinates[1],
                        "version": coordinates[2],
                    },
                }
                if vulnerability.get("withdrawn"):
                    finding["classification"] = "withdrawn"
                elif informational := _informational_kind(vulnerability):
                    finding["classification"] = "informational"
                    finding["informational"] = informational
                else:
                    exception = _matching_exception(
                        policy=policy,
                        package=package,
                        advisory_ids=advisory_ids,
                    )
                    if exception is None:
                        finding["classification"] = "blocking"
                    else:
                        expiry = date.fromisoformat(exception["expires"])
                        finding["exception"] = {
                            "expires": exception["expires"],
                            "id": exception["id"],
                        }
                        finding["classification"] = (
                            "accepted_exception"
                            if evaluated_on <= expiry
                            else "blocking"
                        )
                        if evaluated_on > expiry:
                            finding["reason"] = "expired_exception"
                findings.append(finding)
    if packages_seen != expected_scanned or set(integrity_only_seen) != expected_integrity:
        raise ValueError("OSV scanner package identities do not cover the release SBOM")
    findings.sort(
        key=lambda item: (
            item["package"]["ecosystem"],
            item["package"]["name"].lower(),
            item["package"]["version"],
            item["id"],
        )
    )
    integrity_only = sorted(
        integrity_only_seen.values(),
        key=lambda item: (item["name"].lower(), item["version"], item["purl"]),
    )
    return findings, len(packages_seen), integrity_only, _identity_evidence(packages_seen)


def build_audit_report(
    *,
    osv_result: dict,
    policy: dict,
    policy_path: Path,
    sbom_path: Path,
    scanner: dict,
    source_commit: str,
    target: str,
    evaluated_on: date,
    vendored_transitive_dependencies: str = "top-level-only",
    source_path: Path | None = None,
    native_receipt: Path | None = None,
    native_artifacts_root: Path | None = None,
    native_advisory_evidence: Path | None = None,
    source_owned_evidence: Path | None = None,
) -> dict:
    if not SOURCE_COMMIT_PATTERN.fullmatch(source_commit):
        raise ValueError("source commit must be a full lowercase Git object ID")
    if not target:
        raise ValueError("release target is required")
    if vendored_transitive_dependencies not in VENDORED_TRANSITIVE_COVERAGE:
        raise ValueError("vendored transitive dependency coverage is invalid")
    native_review = _native_review(policy=policy, sbom_path=sbom_path, evaluated_on=evaluated_on,
        source_path=source_path, native_receipt=native_receipt,
        native_artifacts_root=native_artifacts_root, evidence_root=native_advisory_evidence,
        require_evidence=True)
    native_id = native_review["package_id"] if native_review is not None else None
    owned_review = _source_owned_review(policy=policy, sbom_path=sbom_path, evaluated_on=evaluated_on,
        source_path=source_path, evidence_root=source_owned_evidence, source_commit=source_commit)
    owned_ids = tuple(owned_review["package_ids"]) if owned_review else ()
    _check_review_source_binding(native_review, owned_review)
    findings, packages_scanned, integrity_only, scanned_identities = evaluate_osv_result(
        result=osv_result,
        policy=policy,
        evaluated_on=evaluated_on,
        sbom_path=sbom_path, native_package_id=native_id, source_owned_package_ids=owned_ids,
    )
    sbom_package_count = _sbom_package_count(sbom_path)
    packages_integrity_only = len(integrity_only)
    if packages_scanned + packages_integrity_only + (1 if native_review else 0) + len(owned_ids) != sbom_package_count:
        raise ValueError(
            "dependency audit package counts do not match the release SBOM"
        )
    counts = {
        classification: sum(
            finding["classification"] == classification for finding in findings
        )
        for classification in (
            "accepted_exception",
            "blocking",
            "informational",
            "withdrawn",
        )
    }
    report = {
        "coverage": {
            "sbom_packages": "all",
            "vendored_transitive_dependencies": vendored_transitive_dependencies,
        },
        "evaluated_on": evaluated_on.isoformat(),
        "findings": findings,
        "generator": GENERATOR,
        "inputs": {
            "policy_sha256": hash_file(policy_path),
            "sbom_sha256": hash_file(sbom_path),
        },
        "scanner": scanner,
        "scanned_packages": scanned_identities,
        "schema_version": LEGACY_REPORT_SCHEMA_VERSION,
        "source": {"commit": source_commit, "target": target},
        "status": "fail" if counts["blocking"] else "pass",
        "summary": {
            **counts,
            "advisories": len(findings),
            "packages_scanned": packages_scanned,
        },
    }
    if "integrity_only" in policy:
        report["integrity_only"] = integrity_only
        report["summary"]["packages_integrity_only"] = packages_integrity_only
    if native_review is not None:
        report["schema_version"] = NATIVE_REPORT_SCHEMA_VERSION
        report["native_sqlite_review"] = native_review
        report["summary"].update(_native_summary(native_review))
        if native_review["status"] != "pass":
            report["status"] = "fail"
    if owned_review is not None:
        report["schema_version"] = SOURCE_OWNED_REPORT_SCHEMA_VERSION
        report["source_owned_review"] = owned_review
        report["summary"].update(_source_owned_summary(owned_review))
        if owned_review["status"] != "pass":
            report["status"] = "fail"
    if native_review is not None or owned_review is not None:
        report["coverage"]["sbom_packages"] = "partitioned"
        report["package_partition"] = _reviewed_partition(_sbom_packages(sbom_path), native_id, owned_ids)
        report["inputs"]["scanner_sbom_sha256"] = hashlib.sha256(_reviewed_scanner_sbom(
            _read_json_object(sbom_path, "release SBOM"), native_id, owned_ids)).hexdigest()
    return report


def write_json_atomic(path: Path, data: dict, *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _snapshot_audit_input(source: Path, destination: Path, limit: int) -> dict:
    """Copy once; the scanner and evaluator must consume these same bytes."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | os.O_NONBLOCK
    descriptor = os.open(source, flags)
    digest = hashlib.sha256()
    size = 0
    created = False
    try:
        with os.fdopen(descriptor, "rb") as incoming:
            if not stat.S_ISREG(os.fstat(incoming.fileno()).st_mode):
                raise ValueError("audit input must be a regular file")
            with destination.open("xb") as outgoing:
                created = True
                os.chmod(destination, 0o600)
                for block in iter(lambda: incoming.read(1024 * 1024), b""):
                    size += len(block)
                    if size > limit:
                        raise ValueError("audit input exceeds the evidence size limit")
                    outgoing.write(block)
                    digest.update(block)
                outgoing.flush()
                os.fsync(outgoing.fileno())
        os.chmod(destination, 0o400)
    except Exception:
        if created:
            destination.unlink(missing_ok=True)
        raise
    return {"path": destination.name, "sha256": digest.hexdigest(), "size_bytes": size}


def _retain_osv_output(source: Path, destination: Path) -> dict:
    """Preserve exact bytes, including invalid/partial output, within a bound."""
    try:
        metadata = source.lstat()
    except FileNotFoundError:
        return {"state": "missing"}
    if not stat.S_ISREG(metadata.st_mode):
        return {"state": "invalid_file"}
    size = metadata.st_size
    if size > MAX_OSV_EVIDENCE_BYTES:
        return {"state": "oversized", "size_bytes": size}
    retained = _snapshot_audit_input(source, destination, MAX_OSV_EVIDENCE_BYTES)
    destination.chmod(0o600)
    return retained | {"state": "partial"}


def scan_with_evidence(args: argparse.Namespace) -> int:
    """Retain diagnostic evidence without changing audit policy or report schema."""
    evidence = args.evidence_dir.absolute()
    receipt: dict = {
        "schema_version": 1,
        "generator": "slipstream-dependency-audit-evidence-1",
        "status": "started", "stage": "prepare",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "evaluator_sha256": hash_file(Path(__file__)),
        "source": {"commit": args.source_commit, "target": args.target},
        "evaluation_date": args.evaluation_date.isoformat(),
        "platform": args.platform,
        "vendored_transitive_dependencies": args.vendored_transitive_dependencies,
        "inputs": {}, "scan": {"state": "not_started"},
    }
    created = False
    try:
        if args.output.resolve().is_relative_to(evidence.resolve()):
            raise ValueError("audit report must be outside the evidence directory")
        evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
        created = True
        os.chmod(evidence, 0o700)
        write_json_atomic(evidence / "receipt.json", receipt, mode=0o600)
        sbom = evidence / "input.spdx.json"
        policy_path = evidence / "policy.json"
        receipt["inputs"]["sbom"] = _snapshot_audit_input(args.sbom, sbom, 16 * 1024 * 1024)
        receipt["inputs"]["policy"] = _snapshot_audit_input(args.policy, policy_path, 1024 * 1024)
        policy = load_policy(policy_path)
        native_inputs = {"source_path": args.source, "native_receipt": args.native_receipt,
                         "native_artifacts_root": args.native_artifacts_root,
                         "native_advisory_evidence": args.native_advisory_evidence}
        owned_evidence = getattr(args, "source_owned_evidence", None)
        snapshot_paths = {"sbom": sbom, "policy": policy_path}
        scanner_sbom = sbom
        if "native_sqlite_review" in policy:
            if any(value is None for value in native_inputs.values()):
                raise ValueError("native scan requires explicit SOURCE, receipt, artifacts and advisory evidence")
            receipt["stage"] = "native_evidence"
            for name, argument in (("source", "source_path"), ("native_receipt", "native_receipt")):
                destination = evidence / (name + ".json")
                receipt["inputs"][name] = _snapshot_audit_input(native_inputs[argument], destination, 4 * 1024 * 1024)
                snapshot_paths[name] = destination
                if argument == "source_path":
                    native_inputs[argument] = destination
                # The native verifier requires the receipt inside its proof
                # root. Retain this copy for diagnostics and bind both live
                # proof checks to its exact bytes below.
            from geph_native_sqlite_advisories import retain_native_review_evidence
            retained = retain_native_review_evidence(policy["native_sqlite_review"],
                args.native_advisory_evidence, evidence / "native-advisories")
            native_inputs["native_advisory_evidence"] = Path(retained["root"])
            receipt["native_advisory_evidence"] = {key: value for key, value in retained.items() if key != "root"}
            receipt["native_advisory_evidence"]["path"] = "native-advisories"
        if "source_owned_review" in policy:
            if args.source is None or owned_evidence is None:
                raise ValueError("source-owned scan requires explicit SOURCE and review evidence")
            receipt["stage"] = "source_owned_evidence"
            if "source" not in snapshot_paths:
                destination = evidence / "source.json"
                receipt["inputs"]["source"] = _snapshot_audit_input(args.source, destination, 4 * 1024 * 1024)
                snapshot_paths["source"] = destination
                native_inputs["source_path"] = destination
            from geph_source_owned_advisories import retain_source_owned_review_evidence
            retained = retain_source_owned_review_evidence(policy["source_owned_review"],
                owned_evidence, evidence / "source-owned")
            owned_evidence = Path(retained["root"])
            receipt["source_owned_evidence"] = {key: value for key, value in retained.items() if key != "root"}
            receipt["source_owned_evidence"]["path"] = "source-owned"
        native_review = _native_review(policy=policy, sbom_path=sbom, evaluated_on=args.evaluation_date,
            source_path=native_inputs["source_path"], native_receipt=native_inputs["native_receipt"],
            native_artifacts_root=native_inputs["native_artifacts_root"],
            evidence_root=native_inputs["native_advisory_evidence"], require_evidence=True)
        owned_review = _source_owned_review(policy=policy, sbom_path=sbom, evaluated_on=args.evaluation_date,
            source_path=native_inputs["source_path"], evidence_root=owned_evidence,
            source_commit=args.source_commit)
        native_id = native_review["package_id"] if native_review is not None else None
        owned_ids = tuple(owned_review["package_ids"]) if owned_review else ()
        _check_review_source_binding(native_review, owned_review)
        if native_review is not None:
            if native_review["binding"]["native_receipt_sha256"] != receipt["inputs"]["native_receipt"]["sha256"]:
                raise ValueError("native receipt differs from retained audit input")
        if native_review is not None or owned_review is not None:
            _sbom_scan_identities(_sbom_packages(sbom), native_id, owned_ids)
            projection = _reviewed_scanner_sbom(_read_json_object(sbom, "release SBOM"), native_id, owned_ids)
            scanner_sbom = evidence / ("reviewed-scanner.spdx.json" if owned_review else "native-scanner.spdx.json")
            with scanner_sbom.open("xb") as stream:
                stream.write(projection)
            scanner_sbom.chmod(0o400)
            receipt["inputs"]["scanner_sbom"] = {"path": scanner_sbom.name,
                "sha256": hashlib.sha256(projection).hexdigest(), "size_bytes": len(projection)}
            snapshot_paths["scanner_sbom"] = scanner_sbom
        receipt["stage"] = "scanner_verification"
        write_json_atomic(evidence / "receipt.json", receipt, mode=0o600)
        # Do not retain a large executable in an uploadable evidence directory.
        # Verify and execute the owned copy, never the mutable caller path.
        with tempfile.TemporaryDirectory(prefix="slipstream-audit-scanner-") as temporary:
            scanner_path = Path(temporary) / "osv-scanner"
            raw_path = Path(temporary) / "osv.json"
            _snapshot_audit_input(args.scanner, scanner_path, MAX_SCANNER_BYTES)
            scanner_path.chmod(0o700)
            receipt["scanner"] = verify_scanner(
                scanner_path=scanner_path, policy=policy, platform=args.platform,
            )
            receipt["stage"] = "scan"
            receipt["scan"] = {"state": "running"}
            write_json_atomic(evidence / "receipt.json", receipt, mode=0o600)
            try:
                completed = subprocess.run(
                    (str(scanner_path), "scan", "source", "--format", "json",
                     "--all-packages", "-L", scanner_sbom.name, "--output-file", str(raw_path)),
                    cwd=evidence, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    check=False, shell=False, timeout=OSV_SCAN_TIMEOUT_SECONDS,
                )
                receipt["scan"] = {"state": "completed", "exit_code": completed.returncode}
            except subprocess.TimeoutExpired:
                receipt["scan"] = {"state": "timeout"}
                raise
            finally:
                # Scanner-owned output stays outside the upload tree until it
                # is proven to be a bounded regular file, never a link/FIFO/dir.
                receipt["raw"] = _retain_osv_output(raw_path, evidence / "osv.json")
                write_json_atomic(evidence / "receipt.json", receipt, mode=0o600)
        if completed.returncode not in {0, 1}:
            raise RuntimeError("dependency scanner failed")
        receipt["stage"] = "parse"
        if receipt["raw"]["state"] != "partial":
            raise ValueError("dependency scanner did not produce bounded regular output")
        try:
            osv_result = _read_json_object(evidence / "osv.json", "OSV scanner result")
        except (ValueError, UnicodeError):
            receipt["raw"]["state"] = "invalid"
            raise
        receipt["raw"]["state"] = "complete"
        receipt["stage"] = "audit"
        for name, path in snapshot_paths.items():
            if hash_file(path) != receipt["inputs"][name]["sha256"]:
                raise ValueError("audit input snapshot changed during scanning")
        report = build_audit_report(
            osv_result=osv_result, policy=policy, policy_path=policy_path,
            sbom_path=sbom, scanner=receipt["scanner"], source_commit=args.source_commit,
            target=args.target, evaluated_on=args.evaluation_date,
            vendored_transitive_dependencies=args.vendored_transitive_dependencies,
            source_owned_evidence=owned_evidence,
            **native_inputs,
        )
        if native_review is not None:
            if report["native_sqlite_review"]["binding"]["native_receipt_sha256"] != receipt["inputs"]["native_receipt"]["sha256"]:
                raise ValueError("native receipt differs from retained audit input")
        receipt["stage"] = "report"
        write_json_atomic(args.output, report)
        receipt["report"] = {"sha256": hash_file(args.output), "status": report["status"]}
        receipt["status"] = report["status"]
        receipt["stage"] = "complete"
        result = report["summary"] | {"status": report["status"]}
        exit_code = 0 if report["status"] == "pass" else 1
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        receipt["status"] = "error"
        receipt["error_type"] = type(exc).__name__
        # Paths, environment values and arbitrary scanner diagnostics do not
        # belong in uploadable evidence (or the structured console summary).
        result = {"status": "error", "stage": receipt["stage"], "error_type": type(exc).__name__}
        exit_code = 1
    if created:
        receipt["finished_at"] = datetime.now(timezone.utc).isoformat()
        write_json_atomic(evidence / "receipt.json", receipt, mode=0o600)
    print(json.dumps(result, sort_keys=True))
    return exit_code


def _sbom_package_count(path: Path) -> int:
    return len(_sbom_packages(path))


def validate_audit_report(
    report: object,
    *,
    policy_path: Path,
    sbom_path: Path,
    source_commit: str,
    target: str,
    vendored_transitive_dependencies: str = "top-level-only",
    source_path: Path | None = None,
    native_receipt: Path | None = None,
    native_artifacts_root: Path | None = None,
    source_owned_evidence: Path | None = None,
) -> dict:
    if not isinstance(report, dict):
        raise ValueError("dependency audit report must be a JSON object")
    if vendored_transitive_dependencies not in VENDORED_TRANSITIVE_COVERAGE:
        raise ValueError("vendored transitive dependency coverage is invalid")
    policy = load_policy(policy_path)
    evaluated_value = report.get("evaluated_on")
    try:
        evaluated_on = date.fromisoformat(evaluated_value)
    except (TypeError, ValueError) as exc:
        raise ValueError("dependency audit evaluation date is invalid") from exc
    native_review = _native_review(policy=policy, sbom_path=sbom_path, evaluated_on=evaluated_on,
        source_path=source_path, native_receipt=native_receipt, native_artifacts_root=native_artifacts_root)
    native_id = native_review["package_id"] if native_review is not None else None
    owned_review = _source_owned_review(policy=policy, sbom_path=sbom_path, evaluated_on=evaluated_on,
        source_path=source_path, evidence_root=source_owned_evidence, source_commit=source_commit)
    owned_ids = tuple(owned_review["package_ids"]) if owned_review else ()
    _check_review_source_binding(native_review, owned_review)
    expected = {
        "schema_version": (SOURCE_OWNED_REPORT_SCHEMA_VERSION if owned_review else
                           NATIVE_REPORT_SCHEMA_VERSION if native_review else LEGACY_REPORT_SCHEMA_VERSION),
        "generator": GENERATOR,
        "status": "pass",
        "source": {"commit": source_commit, "target": target},
        "coverage": {
            "sbom_packages": "partitioned" if native_review or owned_review else "all",
            "vendored_transitive_dependencies": vendored_transitive_dependencies,
        },
    }
    for key, value in expected.items():
        if report.get(key) != value:
            raise ValueError(f"dependency audit report {key} does not match release")
    expected_inputs = {"policy_sha256": hash_file(policy_path), "sbom_sha256": hash_file(sbom_path)}
    if native_review is not None or owned_review is not None:
        expected_inputs["scanner_sbom_sha256"] = hashlib.sha256(_reviewed_scanner_sbom(
            _read_json_object(sbom_path, "release SBOM"), native_id, owned_ids)).hexdigest()
    elif "package_partition" in report:
        raise ValueError("dependency audit package partition has no trusted policy")
    if native_review is not None:
        if json.dumps(report.get("native_sqlite_review"), sort_keys=True, allow_nan=False) != json.dumps(
            native_review, sort_keys=True, allow_nan=False
        ):
            raise ValueError("dependency audit native review does not match trusted policy and proof")
        if native_review["status"] != "pass":
            raise ValueError("dependency audit native review has unresolved or affected groups")
    elif "native_sqlite_review" in report:
        raise ValueError("dependency audit native evidence has no trusted policy")
    if owned_review is not None:
        if json.dumps(report.get("source_owned_review"), sort_keys=True, allow_nan=False) != json.dumps(
            owned_review, sort_keys=True, allow_nan=False
        ):
            raise ValueError("dependency audit source-owned review does not match trusted policy and evidence")
        if owned_review["status"] != "pass":
            raise ValueError("dependency audit source-owned review has unresolved or affected findings")
    elif "source_owned_review" in report:
        raise ValueError("dependency audit source-owned evidence has no trusted policy")
    if report.get("inputs") != expected_inputs:
        raise ValueError("dependency audit input hashes do not match release")
    scanner = report.get("scanner")
    if not isinstance(scanner, dict):
        raise ValueError("dependency audit scanner metadata is missing")
    platform = scanner.get("platform")
    if not isinstance(platform, str):
        raise ValueError("dependency audit scanner platform is missing")
    expected_scanner = expected_scanner_metadata(policy, platform)
    if scanner != expected_scanner:
        raise ValueError("dependency audit scanner metadata does not match policy")
    findings = report.get("findings")
    summary = report.get("summary")
    if not isinstance(findings, list) or not isinstance(summary, dict):
        raise ValueError("dependency audit findings and summary are required")
    counts = {
        classification: sum(
            isinstance(finding, dict)
            and finding.get("classification") == classification
            for finding in findings
        )
        for classification in (
            "accepted_exception",
            "blocking",
            "informational",
            "withdrawn",
        )
    }
    if counts["blocking"]:
        raise ValueError("dependency audit report contains blocking findings")
    if summary.get("advisories") != len(findings):
        raise ValueError("dependency audit advisory count is inconsistent")
    if any(summary.get(key) != value for key, value in counts.items()):
        raise ValueError("dependency audit finding counts are inconsistent")
    packages_scanned = summary.get("packages_scanned")
    if (
        not isinstance(packages_scanned, int)
        or isinstance(packages_scanned, bool)
        or packages_scanned < 0
    ):
        raise ValueError("dependency audit scanned package count is invalid")
    sbom_packages = _sbom_packages(sbom_path)
    policy_has_integrity_only = "integrity_only" in policy
    packages_integrity_only = 0
    if policy_has_integrity_only:
        integrity_only = report.get("integrity_only")
        packages_integrity_only = summary.get("packages_integrity_only")
        if not isinstance(integrity_only, list) or not isinstance(
            packages_integrity_only, int
        ) or isinstance(packages_integrity_only, bool):
            raise ValueError("dependency audit integrity-only evidence is missing")
        if packages_integrity_only < 0 or packages_integrity_only != len(
            integrity_only
        ):
            raise ValueError("dependency audit integrity-only count is inconsistent")
        policy_integrity = {
            (item["name"], item["version"]): item
            for item in policy["integrity_only"]
        }
        evidence_seen: set[tuple[str, str]] = set()
        for evidence in integrity_only:
            if not isinstance(evidence, dict):
                raise ValueError("dependency audit integrity-only evidence is invalid")
            name = evidence.get("name")
            version = evidence.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                raise ValueError("dependency audit integrity-only evidence is invalid")
            key = (name, version)
            if key in evidence_seen:
                raise ValueError(
                    "dependency audit integrity-only evidence is duplicated"
                )
            evidence_seen.add(key)
            policy_package = policy_integrity.get(key)
            if policy_package is None or evidence != policy_package:
                raise ValueError(
                    "dependency audit integrity-only evidence does not match policy"
                )
            expected_evidence = _verify_integrity_only_sbom_package(
                sbom_packages=sbom_packages,
                policy_package=policy_package,
                evaluated_on=evaluated_on,
            )
            if evidence != expected_evidence:
                raise ValueError(
                    "dependency audit integrity-only evidence does not match SBOM"
                )
    elif "integrity_only" in report or "packages_integrity_only" in summary:
        raise ValueError(
            "dependency audit report has integrity-only data without policy"
        )
    if packages_scanned + packages_integrity_only + (1 if native_review else 0) + len(owned_ids) != len(sbom_packages):
        raise ValueError(
            "dependency audit package counts do not match the release SBOM"
        )
    expected_scanned, expected_integrity, _ = _sbom_scan_identities(sbom_packages, native_id, owned_ids)
    if native_review is not None or owned_review is not None:
        if report.get("package_partition") != _reviewed_partition(sbom_packages, native_id, owned_ids):
            raise ValueError("dependency audit reviewed package partition does not match SBOM")
    if native_review is not None:
        if any(type(summary.get(key)) is not int or summary[key] != value
               for key, value in _native_summary(native_review).items()):
            raise ValueError("dependency audit native summary counts are inconsistent")
    elif any(key in summary for key in ("packages_native", "native_unresolved", "native_affected")):
        raise ValueError("dependency audit native counts have no trusted policy")
    if owned_review is not None:
        if any(type(summary.get(key)) is not int or summary[key] != value
               for key, value in _source_owned_summary(owned_review).items()):
            raise ValueError("dependency audit source-owned summary counts are inconsistent")
    elif any(key in summary for key in ("packages_source_owned", "source_owned_unresolved", "source_owned_affected")):
        raise ValueError("dependency audit source-owned counts have no trusted policy")
    evidence = report.get("scanned_packages")
    if not isinstance(evidence, list):
        raise ValueError(
            "dependency audit scanned package identity evidence is missing; "
            "rebuild the report from the original OSV result"
        )
    if evidence != _identity_evidence(expected_scanned) or len(evidence) != packages_scanned:
        raise ValueError("dependency audit scanned package identity evidence does not match SBOM")
    if policy_has_integrity_only and evidence_seen != expected_integrity:
        raise ValueError("dependency audit integrity-only identities do not match SBOM")
    if not policy_has_integrity_only and expected_integrity:
        raise ValueError("dependency audit integrity-only identity evidence is missing")
    exceptions = {item["id"]: item for item in policy["exceptions"]}
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("dependency audit finding is invalid")
        classification = finding.get("classification")
        if classification not in counts:
            raise ValueError("dependency audit finding classification is invalid")
        package = finding.get("package")
        if not isinstance(package, dict) or not all(
            isinstance(package.get(key), str) and package[key]
            for key in ("ecosystem", "name", "version")
        ):
            raise ValueError("dependency audit finding package is invalid")
        finding_identity = (
            package["ecosystem"],
            _canonical_package_name(package["ecosystem"], package["name"]),
            package["version"],
        )
        if finding_identity not in expected_scanned:
            raise ValueError("dependency audit finding package identity does not match SBOM")
        advisory_id = finding.get("id")
        aliases = finding.get("aliases")
        if not isinstance(advisory_id, str) or not advisory_id:
            raise ValueError("dependency audit finding identifier is invalid")
        if not isinstance(aliases, list) or not all(
            isinstance(value, str) and value for value in aliases
        ):
            raise ValueError("dependency audit finding aliases are invalid")
        if classification != "accepted_exception":
            continue
        exception_ref = finding.get("exception")
        if not isinstance(exception_ref, dict):
            raise ValueError("dependency audit exception reference is missing")
        exception = exceptions.get(exception_ref.get("id"))
        if exception is None or exception_ref.get("expires") != exception["expires"]:
            raise ValueError("dependency audit exception does not match policy")
        if package != {
            "ecosystem": exception["ecosystem"],
            "name": _canonical_package_name(exception["ecosystem"], exception["package"]),
            "version": exception["version"],
        }:
            raise ValueError("dependency audit exception package does not match policy")
        if not {advisory_id, *aliases}.intersection(exception["advisories"]):
            raise ValueError(
                "dependency audit exception advisory does not match policy"
            )
        if evaluated_on > date.fromisoformat(exception["expires"]):
            raise ValueError("dependency audit report uses an expired exception")
    return {
        "advisories": len(findings),
        "accepted_exceptions": counts["accepted_exception"],
        "informational": counts["informational"],
        "packages_integrity_only": packages_integrity_only,
        "packages_scanned": packages_scanned,
        "scanner_version": scanner["version"],
        **(_native_summary(native_review) if native_review else {}),
        **(_source_owned_summary(owned_review) if owned_review else {}),
    }


def validate_audit_report_file(
    *,
    report_path: Path,
    policy_path: Path,
    sbom_path: Path,
    source_commit: str,
    target: str,
    vendored_transitive_dependencies: str = "top-level-only",
    source_path: Path | None = None,
    native_receipt: Path | None = None,
    native_artifacts_root: Path | None = None,
    source_owned_evidence: Path | None = None,
) -> dict:
    report = _read_json_object(report_path, "dependency audit report")
    return validate_audit_report(
        report,
        policy_path=policy_path,
        sbom_path=sbom_path,
        source_commit=source_commit,
        target=target,
        vendored_transitive_dependencies=vendored_transitive_dependencies,
        source_path=source_path, native_receipt=native_receipt, native_artifacts_root=native_artifacts_root,
        source_owned_evidence=source_owned_evidence,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    fetch = subparsers.add_parser("fetch-scanner")
    fetch.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    fetch.add_argument("--platform", required=True)
    fetch.add_argument("--output", required=True, type=Path)

    scan = subparsers.add_parser("scan")
    scan.add_argument("--scanner", required=True, type=Path)
    scan.add_argument("--platform", required=True)
    scan.add_argument("--sbom", required=True, type=Path)
    scan.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    scan.add_argument("--source-commit", required=True)
    scan.add_argument("--target", required=True)
    scan.add_argument("--evaluation-date", required=True, type=date.fromisoformat)
    scan.add_argument("--output", required=True, type=Path)
    scan.add_argument(
        "--evidence-dir", type=Path,
        help="Fresh private directory for exact scan inputs, raw OSV output and receipt; separate from --output",
    )
    scan.add_argument(
        "--vendored-transitive-dependencies",
        choices=VENDORED_TRANSITIVE_COVERAGE,
        default="top-level-only",
    )

    verify = subparsers.add_parser("verify")
    verify.add_argument("--report", required=True, type=Path)
    verify.add_argument("--sbom", required=True, type=Path)
    verify.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    verify.add_argument("--source-commit", required=True)
    verify.add_argument("--target", required=True)
    verify.add_argument(
        "--vendored-transitive-dependencies",
        choices=VENDORED_TRANSITIVE_COVERAGE,
        default="top-level-only",
    )
    for command in (scan, verify):
        for flag in ("source", "native-receipt", "native-artifacts-root", "source-owned-evidence"):
            command.add_argument("--" + flag, type=Path)
    scan.add_argument("--native-advisory-evidence", type=Path)
    args = parser.parse_args(argv)
    if args.command in ("scan", "verify"):
        native = any(value is not None for value in (args.native_receipt, args.native_artifacts_root,
                                                    getattr(args, "native_advisory_evidence", None)))
        owned = args.source_owned_evidence is not None
        if native and any(value is None for value in (args.source, args.native_receipt, args.native_artifacts_root)):
            parser.error("native audit requires --source, --native-receipt and --native-artifacts-root together")
        if owned and args.source is None:
            parser.error("--source-owned-evidence requires --source")
        if args.source is not None and not native and not owned:
            parser.error("--source requires native inputs or --source-owned-evidence")
        if args.command == "scan":
            if native and (args.native_advisory_evidence is None or args.evidence_dir is None):
                parser.error("native scan requires --native-advisory-evidence and --evidence-dir")
            if owned and args.evidence_dir is None:
                parser.error("source-owned scan requires --evidence-dir")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.command == "fetch-scanner":
        result = fetch_scanner(
            policy_path=args.policy,
            platform=args.platform,
            output=args.output,
        )
    elif args.command == "scan":
        if args.evidence_dir is not None:
            return scan_with_evidence(args)
        policy = load_policy(args.policy)
        if "native_sqlite_review" in policy or "source_owned_review" in policy:
            raise ValueError("reviewed source scan requires explicit evidence inputs and --evidence-dir")
        scanner = verify_scanner(
            scanner_path=args.scanner,
            policy=policy,
            platform=args.platform,
        )
        osv_result = run_osv_scan(scanner_path=args.scanner, sbom_path=args.sbom)
        report = build_audit_report(
            osv_result=osv_result,
            policy=policy,
            policy_path=args.policy,
            sbom_path=args.sbom,
            scanner=scanner,
            source_commit=args.source_commit,
            target=args.target,
            evaluated_on=args.evaluation_date,
            vendored_transitive_dependencies=args.vendored_transitive_dependencies,
        )
        write_json_atomic(args.output, report)
        result = report["summary"] | {"status": report["status"]}
        if report["status"] != "pass":
            print(json.dumps(result, sort_keys=True))
            return 1
    else:
        result = validate_audit_report_file(
            report_path=args.report,
            policy_path=args.policy,
            sbom_path=args.sbom,
            source_commit=args.source_commit,
            target=args.target,
            vendored_transitive_dependencies=args.vendored_transitive_dependencies,
            source_path=args.source, native_receipt=args.native_receipt,
            native_artifacts_root=args.native_artifacts_root,
            source_owned_evidence=args.source_owned_evidence,
        )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
