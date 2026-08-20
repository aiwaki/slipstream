#!/usr/bin/env python3
"""Bind downloaded Geph release assets to the reviewed source contract.

GitHub attestations establish who produced each downloaded file.  This
offline verifier complements that proof by requiring the exact immutable
asset set, a strict SHA256SUMS manifest, and byte-identical reviewed source,
lock, version, and license files before the binary can enter the app bundle.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path

CHECKSUM_NAME = "SHA256SUMS"
BINARY_NAME = "geph5-client"
CHECKSUMMED_ASSETS = frozenset(
    {
        BINARY_NAME,
        "geph5-client.Cargo.lock",
        "geph5-client.LICENSE",
        "geph5-client.SOURCE.json",
        "geph5-client.VERSION",
        "geph5-client.spdx.json",
        "geph5-client-dependency-audit.json",
    }
)
REQUIRED_ASSETS = CHECKSUMMED_ASSETS | {CHECKSUM_NAME}
REFERENCE_ASSETS = {
    "geph5-client.Cargo.lock": "cargo_lock",
    "geph5-client.LICENSE": "license",
    "geph5-client.SOURCE.json": "source",
    "geph5-client.VERSION": "version",
}
MAX_BYTES = {
    BINARY_NAME: 512 * 1024 * 1024,
    "geph5-client.Cargo.lock": 64 * 1024 * 1024,
    "geph5-client.LICENSE": 4 * 1024 * 1024,
    "geph5-client.SOURCE.json": 4 * 1024 * 1024,
    "geph5-client.VERSION": 1024,
    "geph5-client.spdx.json": 64 * 1024 * 1024,
    "geph5-client-dependency-audit.json": 64 * 1024 * 1024,
    CHECKSUM_NAME: 64 * 1024,
}
MAX_RELEASE_METADATA_BYTES = 1024 * 1024
MAX_PROVENANCE_JSON_BYTES = 8 * 1024 * 1024
MAX_SPDX_ATTESTATION_JSON_BYTES = 128 * 1024 * 1024
MAX_ATTESTATION_RESULTS = 30
CHECKSUM_LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$")
API_SHA256_DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
SPDX_PREDICATE_TYPE = "https://spdx.dev/Document/v2.3"


def _hash_regular(path: Path, *, limit: int, label: str) -> dict[str, object]:
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
        digest = hashlib.sha256()
        size = 0
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            size += len(block)
            if size > limit:
                raise ValueError(f"{label} exceeds its size limit")
        after = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        final_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if size != before.st_size or identity != final_identity:
            raise ValueError(f"{label} changed while it was read")
        return {"sha256": digest.hexdigest(), "size": size}
    finally:
        os.close(descriptor)


def _read_regular(
    path: Path, *, limit: int, label: str
) -> tuple[bytes, dict[str, object]]:
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
        content = bytearray()
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, min(1024 * 1024, limit + 1 - len(content)))
            if not block:
                break
            content.extend(block)
            digest.update(block)
            if len(content) > limit:
                raise ValueError(f"{label} exceeds its size limit")
        after = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        final_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if len(content) != before.st_size or identity != final_identity:
            raise ValueError(f"{label} changed while it was read")
        return bytes(content), {
            "sha256": digest.hexdigest(),
            "size": len(content),
        }
    finally:
        os.close(descriptor)


def _read_checksums(path: Path) -> tuple[dict[str, str], dict[str, object]]:
    content, metadata = _read_regular(
        path,
        limit=MAX_BYTES[CHECKSUM_NAME],
        label="Geph checksum manifest",
    )
    try:
        text = content.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("Geph checksum manifest must be canonical ASCII") from exc
    if not text.endswith("\n") or "\r" in text:
        raise ValueError("Geph checksum manifest must end with one Unix newline")
    lines = text.splitlines()
    if len(lines) != len(CHECKSUMMED_ASSETS):
        raise ValueError("Geph checksum manifest has an unexpected entry count")
    checksums: dict[str, str] = {}
    for line in lines:
        match = CHECKSUM_LINE.fullmatch(line)
        if match is None:
            raise ValueError("Geph checksum manifest contains an invalid line")
        digest, name = match.groups()
        if name in checksums:
            raise ValueError(f"duplicate Geph checksum entry: {name}")
        checksums[name] = digest
    if set(checksums) != CHECKSUMMED_ASSETS:
        raise ValueError(
            "Geph checksum manifest names do not match the release contract"
        )
    # Keep the manifest itself in the final result without trusting a second
    # path read for its identity.
    checksums[CHECKSUM_NAME] = str(metadata["sha256"])
    return checksums, metadata


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON value is forbidden: {value}")


def _read_json_regular(
    path: Path, *, limit: int, label: str
) -> tuple[object, dict[str, object]]:
    content, metadata = _read_regular(path, limit=limit, label=label)
    try:
        value = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_json_object,
            parse_constant=_reject_json_constant,
        )
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    return value, metadata


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _verified_statements(
    value: object, *, predicate_type: str, label: str
) -> list[dict[str, object]]:
    if not isinstance(value, list) or not value or len(value) > MAX_ATTESTATION_RESULTS:
        raise ValueError(f"{label} must contain a bounded non-empty result array")
    statements: list[dict[str, object]] = []
    for result in value:
        if not isinstance(result, dict):
            raise ValueError(f"{label} result must be an object")
        verification = result.get("verificationResult")
        if not isinstance(verification, dict):
            raise ValueError(f"{label} result has no verificationResult")
        statement = verification.get("statement")
        if not isinstance(statement, dict):
            raise ValueError(f"{label} result has no verified statement")
        if statement.get("predicateType") != predicate_type:
            raise ValueError(f"{label} result has the wrong predicate type")
        statements.append(statement)
    return statements


def _subject_digests(statement: dict[str, object], *, label: str) -> dict[str, str]:
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects:
        raise ValueError(f"{label} statement has no subjects")
    result: dict[str, str] = {}
    for subject in subjects:
        if not isinstance(subject, dict):
            raise ValueError(f"{label} subject must be an object")
        name = subject.get("name")
        digest = subject.get("digest")
        if not isinstance(name, str) or not name or name in result:
            raise ValueError(f"{label} subject name is invalid or duplicated")
        if (
            not isinstance(digest, dict)
            or set(digest) != {"sha256"}
            or not isinstance(digest.get("sha256"), str)
            or CHECKSUM_LINE.fullmatch(f"{digest['sha256']}  {name}") is None
        ):
            raise ValueError(f"{label} subject digest is invalid: {name}")
        result[name] = digest["sha256"]
    return result


def verify_attestation_results(
    *, release_dir: Path, provenance_json: Path, spdx_json: Path
) -> dict[str, object]:
    if not release_dir.is_dir() or release_dir.is_symlink():
        raise ValueError("Geph release directory is missing or unsafe")
    names = {entry.name for entry in release_dir.iterdir()}
    if names != REQUIRED_ASSETS:
        raise ValueError(
            "Geph attestation release asset set does not match the contract"
        )

    expected_subjects: dict[str, str] = {}
    for name in sorted(REQUIRED_ASSETS):
        metadata = _hash_regular(
            release_dir / name,
            limit=MAX_BYTES[name],
            label=f"Geph attestation subject {name}",
        )
        expected_subjects[name] = str(metadata["sha256"])

    provenance, _ = _read_json_regular(
        provenance_json,
        limit=MAX_PROVENANCE_JSON_BYTES,
        label="verified Geph provenance JSON",
    )
    provenance_statements = _verified_statements(
        provenance,
        predicate_type=SLSA_PREDICATE_TYPE,
        label="verified Geph provenance JSON",
    )
    matching_provenance = [
        statement
        for statement in provenance_statements
        if _subject_digests(statement, label="Geph provenance") == expected_subjects
    ]
    if not matching_provenance:
        raise ValueError(
            "no verified Geph provenance statement binds the exact release asset set"
        )

    sbom, sbom_metadata = _read_json_regular(
        release_dir / "geph5-client.spdx.json",
        limit=MAX_BYTES["geph5-client.spdx.json"],
        label="downloaded Geph SPDX SBOM",
    )
    if not isinstance(sbom, dict):
        raise ValueError("downloaded Geph SPDX SBOM must be a JSON object")
    spdx, _ = _read_json_regular(
        spdx_json,
        limit=MAX_SPDX_ATTESTATION_JSON_BYTES,
        label="verified Geph SPDX attestation JSON",
    )
    spdx_statements = _verified_statements(
        spdx,
        predicate_type=SPDX_PREDICATE_TYPE,
        label="verified Geph SPDX attestation JSON",
    )
    expected_binary_subject = {BINARY_NAME: expected_subjects[BINARY_NAME]}
    matching_spdx = [
        statement
        for statement in spdx_statements
        if _subject_digests(statement, label="Geph SPDX attestation")
        == expected_binary_subject
        and statement.get("predicate") == sbom
    ]
    if not matching_spdx:
        raise ValueError(
            "no verified Geph SPDX attestation binds the exact binary and SBOM"
        )

    return {
        "provenance_result_count": len(provenance_statements),
        "provenance_subject_count": len(expected_subjects),
        "spdx_result_count": len(spdx_statements),
        "sbom_sha256": sbom_metadata["sha256"],
        "sbom_canonical_sha256": hashlib.sha256(_canonical_json(sbom)).hexdigest(),
    }


def verify_release_assets(
    *,
    release_dir: Path,
    metadata_path: Path,
    expected_tag: str,
    source: Path,
    cargo_lock: Path,
    version: Path,
    license_file: Path,
) -> dict[str, object]:
    if not release_dir.is_dir() or release_dir.is_symlink():
        raise ValueError("Geph release directory is missing or unsafe")
    names = {entry.name for entry in release_dir.iterdir()}
    if names != REQUIRED_ASSETS:
        missing = sorted(REQUIRED_ASSETS - names)
        unexpected = sorted(names - REQUIRED_ASSETS)
        raise ValueError(
            "Geph release asset set does not match the contract"
            f"; missing={missing}; unexpected={unexpected}"
        )

    api_metadata = verify_release_metadata(
        metadata_path=metadata_path,
        expected_tag=expected_tag,
    )
    checksums, checksum_metadata = _read_checksums(release_dir / CHECKSUM_NAME)
    downloaded_metadata: dict[str, dict[str, object]] = {
        CHECKSUM_NAME: checksum_metadata
    }
    for name in sorted(CHECKSUMMED_ASSETS):
        metadata = _hash_regular(
            release_dir / name,
            limit=MAX_BYTES[name],
            label=f"Geph release asset {name}",
        )
        if metadata["sha256"] != checksums[name]:
            raise ValueError(f"Geph release asset checksum mismatch: {name}")
        downloaded_metadata[name] = metadata

    if downloaded_metadata != api_metadata["assets"]:
        raise ValueError(
            "downloaded Geph asset sizes or digests differ from release metadata"
        )

    references = {
        "source": source,
        "cargo_lock": cargo_lock,
        "version": version,
        "license": license_file,
    }
    for asset_name, reference_name in REFERENCE_ASSETS.items():
        reference = references[reference_name]
        expected = _hash_regular(
            reference,
            limit=MAX_BYTES[asset_name],
            label=f"reviewed Geph {reference_name}",
        )
        if downloaded_metadata[asset_name] != expected:
            raise ValueError(
                f"Geph release asset differs from reviewed {reference_name}: "
                f"{asset_name}"
            )

    return {
        "asset_count": len(REQUIRED_ASSETS),
        "binary_sha256": downloaded_metadata[BINARY_NAME]["sha256"],
        "binary_size": downloaded_metadata[BINARY_NAME]["size"],
        "checksums_sha256": checksums[CHECKSUM_NAME],
    }


def verify_release_metadata(
    *, metadata_path: Path, expected_tag: str
) -> dict[str, object]:
    if not expected_tag or any(character.isspace() for character in expected_tag):
        raise ValueError("expected Geph release tag is invalid")
    release, metadata = _read_json_regular(
        metadata_path,
        limit=MAX_RELEASE_METADATA_BYTES,
        label="Geph release metadata",
    )
    if not isinstance(release, dict):
        raise ValueError("Geph release metadata must be a JSON object")
    if release.get("tag_name") != expected_tag:
        raise ValueError("Geph release metadata has an unexpected tag")
    if release.get("draft") is not False:
        raise ValueError("Geph dependency release must not be a draft")
    if release.get("prerelease") is not True:
        raise ValueError("Geph dependency release must be an internal prerelease")
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise ValueError("Geph release metadata must contain its asset inventory")
    asset_metadata: dict[str, dict[str, object]] = {}
    for asset in assets:
        if not isinstance(asset, dict):
            raise ValueError("Geph release asset metadata must be an object")
        name = asset.get("name")
        size = asset.get("size")
        digest = asset.get("digest")
        digest_match = (
            API_SHA256_DIGEST.fullmatch(digest) if isinstance(digest, str) else None
        )
        if not isinstance(name, str) or name in asset_metadata:
            raise ValueError("Geph release asset metadata has an invalid name")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
            or asset.get("state") != "uploaded"
        ):
            raise ValueError(f"Geph release asset is not complete: {name}")
        if digest_match is None:
            raise ValueError(f"Geph release asset digest is invalid: {name}")
        asset_metadata[name] = {
            "sha256": digest_match.group(1),
            "size": size,
        }
    if set(asset_metadata) != REQUIRED_ASSETS:
        raise ValueError("Geph release metadata asset set does not match the contract")
    return {
        "tag": expected_tag,
        "draft": False,
        "prerelease": True,
        "asset_count": len(asset_metadata),
        "assets": asset_metadata,
        "metadata_sha256": metadata["sha256"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    metadata = subparsers.add_parser("verify-metadata")
    metadata.add_argument("--metadata", required=True, type=Path)
    metadata.add_argument("--expected-tag", required=True)
    assets = subparsers.add_parser("verify-assets")
    assets.add_argument("--release-dir", required=True, type=Path)
    assets.add_argument("--metadata", required=True, type=Path)
    assets.add_argument("--expected-tag", required=True)
    assets.add_argument("--source", required=True, type=Path)
    assets.add_argument("--cargo-lock", required=True, type=Path)
    assets.add_argument("--version-file", required=True, type=Path)
    assets.add_argument("--license", required=True, type=Path)
    attestations = subparsers.add_parser("verify-attestations")
    attestations.add_argument("--release-dir", required=True, type=Path)
    attestations.add_argument("--provenance-json", required=True, type=Path)
    attestations.add_argument("--spdx-json", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "verify-metadata":
        result = verify_release_metadata(
            metadata_path=args.metadata,
            expected_tag=args.expected_tag,
        )
    elif args.command == "verify-assets":
        result = verify_release_assets(
            release_dir=args.release_dir,
            metadata_path=args.metadata,
            expected_tag=args.expected_tag,
            source=args.source,
            cargo_lock=args.cargo_lock,
            version=args.version_file,
            license_file=args.license,
        )
    else:
        result = verify_attestation_results(
            release_dir=args.release_dir,
            provenance_json=args.provenance_json,
            spdx_json=args.spdx_json,
        )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
