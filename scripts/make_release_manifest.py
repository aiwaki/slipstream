#!/usr/bin/env python3
"""Create and verify Slipstream's deterministic release artifact manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path

import dependency_audit
import make_release_sbom


MANIFEST_SCHEMA_VERSION = 1
MANIFEST_GENERATOR = "slipstream-release-manifest-1"
MANIFEST_NAME = "artifact-manifest.json"
SBOM_NAME = "Slipstream.spdx.json"
DEPENDENCY_AUDIT_NAME = dependency_audit.REPORT_NAME
IGNORED_RELEASE_FILES = {MANIFEST_NAME, "release-notes.md"}
FIXED_ARTIFACT_TYPES = {
    "Slipstream-macos-arm64.zip": ("first-install", "application/zip"),
    "Slipstream.app.tar.gz": ("updater-archive", "application/gzip"),
    "Slipstream.app.tar.gz.sig": ("updater-signature", "text/plain"),
    "latest.json": ("updater-index", "application/json"),
    "route-policy.json": ("route-policy", "application/json"),
    "route-policy-latest.json": ("route-policy-index", "application/json"),
    "route-policy-keys.json": ("route-policy-keys", "application/json"),
    SBOM_NAME: ("sbom", "application/spdx+json"),
    DEPENDENCY_AUDIT_NAME: ("dependency-audit", "application/json"),
}
APP_REQUIRED_ASSETS = {
    "Slipstream-macos-arm64.zip",
    "Slipstream.app.tar.gz",
    "Slipstream.app.tar.gz.sig",
    "latest.json",
    SBOM_NAME,
    DEPENDENCY_AUDIT_NAME,
}
ROUTE_POLICY_REQUIRED_ASSETS = {
    "route-policy.json",
    "route-policy-latest.json",
    "route-policy-keys.json",
}
TARGETS = {
    "aarch64-apple-darwin": {"platform": "macos", "architecture": "arm64"},
}


def _artifact_type(name: str) -> tuple[str, str]:
    fixed = FIXED_ARTIFACT_TYPES.get(name)
    if fixed is not None:
        return fixed
    if name.startswith("Slipstream") and name.endswith(".dmg"):
        return "disk-image", "application/x-apple-diskimage"
    raise ValueError(f"unexpected release artifact: {name}")


def hash_regular_file(path: Path) -> tuple[str, int]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"cannot open release artifact safely: {path.name}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"release artifact is not a regular file: {path.name}")
        if metadata.st_size <= 0:
            raise ValueError(f"empty release artifact: {path.name}")
        digest = hashlib.sha256()
        size = 0
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            size += len(block)
        final_metadata = os.fstat(descriptor)
        identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
        )
        final_identity = (
            final_metadata.st_dev,
            final_metadata.st_ino,
            final_metadata.st_size,
            final_metadata.st_mtime_ns,
        )
        if size != metadata.st_size or final_identity != identity:
            raise ValueError(f"release artifact changed while hashing: {path.name}")
        return digest.hexdigest(), size
    finally:
        os.close(descriptor)


def collect_release_artifacts(release_dir: Path) -> list[dict]:
    if not release_dir.is_dir():
        raise ValueError(f"release directory does not exist: {release_dir}")
    artifacts: list[dict] = []
    for path in sorted(release_dir.iterdir(), key=lambda item: item.name):
        if path.name in IGNORED_RELEASE_FILES:
            continue
        if path.is_symlink():
            raise ValueError(f"release artifact must not be a symlink: {path.name}")
        kind, media_type = _artifact_type(path.name)
        sha256, size = hash_regular_file(path)
        artifacts.append(
            {
                "name": path.name,
                "kind": kind,
                "media_type": media_type,
                "sha256": sha256,
                "size": size,
            }
        )
    return artifacts


def _require_artifact_set(artifacts: list[dict], channel: str) -> None:
    names = {artifact["name"] for artifact in artifacts}
    required = set(APP_REQUIRED_ASSETS)
    if channel == "stable":
        required.update(ROUTE_POLICY_REQUIRED_ASSETS)
    missing = sorted(required - names)
    if missing:
        raise ValueError("missing release artifacts: " + ", ".join(missing))
    if channel == "preview":
        unexpected_policy = sorted(names & ROUTE_POLICY_REQUIRED_ASSETS)
        if unexpected_policy:
            raise ValueError(
                "preview release must not contain route policy assets: "
                + ", ".join(unexpected_policy)
            )


def build_artifact_manifest(
    *,
    release_dir: Path,
    repository: str,
    version: str,
    tag: str,
    channel: str,
    source_commit: str,
    source_date_epoch: int,
    target: str,
) -> dict:
    if channel not in {"stable", "preview"}:
        raise ValueError(f"invalid release channel: {channel!r}")
    if target not in TARGETS:
        raise ValueError(f"unsupported release target: {target}")
    if not make_release_sbom.REPOSITORY_PATTERN.fullmatch(repository):
        raise ValueError("repository must use owner/name form")
    if not make_release_sbom.SOURCE_COMMIT_PATTERN.fullmatch(source_commit):
        raise ValueError("source commit must be a full lowercase Git object ID")
    artifacts = collect_release_artifacts(release_dir)
    _require_artifact_set(artifacts, channel)
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "generator": MANIFEST_GENERATOR,
        "product": "Slipstream",
        "repository": repository,
        "version": version,
        "tag": tag,
        "channel": channel,
        "source": {
            "commit": source_commit,
            "source_date_epoch": source_date_epoch,
            "created_at": make_release_sbom.utc_timestamp(source_date_epoch),
        },
        "build": {
            "target": target,
            **TARGETS[target],
        },
        "artifacts": artifacts,
    }


def validate_artifact_manifest(
    *,
    release_dir: Path,
    repository: str,
    version: str,
    tag: str,
    channel: str,
    source_commit: str,
    target: str,
) -> dict:
    if channel not in {"stable", "preview"}:
        raise ValueError(f"invalid release channel: {channel!r}")
    if target not in TARGETS:
        raise ValueError(f"unsupported release target: {target}")
    if not make_release_sbom.REPOSITORY_PATTERN.fullmatch(repository):
        raise ValueError("repository must use owner/name form")
    if not make_release_sbom.SOURCE_COMMIT_PATTERN.fullmatch(source_commit):
        raise ValueError("source commit must be a full lowercase Git object ID")
    path = release_dir / MANIFEST_NAME
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{MANIFEST_NAME} is not valid JSON") from exc
    if not isinstance(manifest, dict):
        raise ValueError(f"{MANIFEST_NAME} must be a JSON object")
    expected_scalars = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "generator": MANIFEST_GENERATOR,
        "product": "Slipstream",
        "repository": repository,
        "version": version,
        "tag": tag,
        "channel": channel,
    }
    for key, value in expected_scalars.items():
        if manifest.get(key) != value:
            raise ValueError(f"artifact manifest {key} does not match release")
    expected_build = {"target": target, **TARGETS.get(target, {})}
    if manifest.get("build") != expected_build:
        raise ValueError("artifact manifest build target does not match release")
    source = manifest.get("source")
    if not isinstance(source, dict) or source.get("commit") != source_commit:
        raise ValueError("artifact manifest source commit does not match release")
    source_date_epoch = source.get("source_date_epoch")
    if not isinstance(source_date_epoch, int) or isinstance(source_date_epoch, bool):
        raise ValueError("artifact manifest source date epoch is invalid")
    if source.get("created_at") != make_release_sbom.utc_timestamp(source_date_epoch):
        raise ValueError("artifact manifest source timestamp is inconsistent")

    actual_artifacts = collect_release_artifacts(release_dir)
    _require_artifact_set(actual_artifacts, channel)
    if manifest.get("artifacts") != actual_artifacts:
        raise ValueError("artifact manifest hashes, sizes, or files do not match release")

    sbom_path = release_dir / SBOM_NAME
    try:
        sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{SBOM_NAME} is not valid JSON") from exc
    sbom_summary = make_release_sbom.validate_spdx_document(
        sbom,
        version=version,
        tag=tag,
        repository=repository,
        source_commit=source_commit,
        source_date_epoch=source_date_epoch,
        target=target,
    )
    dependency_audit_summary = dependency_audit.validate_audit_report_file(
        report_path=release_dir / DEPENDENCY_AUDIT_NAME,
        policy_path=dependency_audit.DEFAULT_POLICY,
        sbom_path=sbom_path,
        source_commit=source_commit,
        target=target,
    )
    manifest_sha256, manifest_size = hash_regular_file(path)
    return {
        "sha256": manifest_sha256,
        "size": manifest_size,
        "artifact_count": len(actual_artifacts),
        "sbom": sbom_summary,
        "dependency_audit": dependency_audit_summary,
        "source_date_epoch": source_date_epoch,
        "target": target,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-dir", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--channel", choices=("stable", "preview"), required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("--target", choices=tuple(TARGETS), required=True)
    parser.add_argument(
        "--output", type=Path, default=None, help=f"default: RELEASE_DIR/{MANIFEST_NAME}"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    output = args.output or args.release_dir / MANIFEST_NAME
    expected_output = (args.release_dir / MANIFEST_NAME).resolve()
    if output.resolve() != expected_output:
        raise ValueError(f"artifact manifest output must be {expected_output}")
    manifest = build_artifact_manifest(
        release_dir=args.release_dir,
        repository=args.repository,
        version=args.version,
        tag=args.tag,
        channel=args.channel,
        source_commit=args.source_commit,
        source_date_epoch=args.source_date_epoch,
        target=args.target,
    )
    make_release_sbom.write_json_atomic(output, manifest)
    validation = validate_artifact_manifest(
        release_dir=args.release_dir,
        repository=args.repository,
        version=args.version,
        tag=args.tag,
        channel=args.channel,
        source_commit=args.source_commit,
        target=args.target,
    )
    print(
        json.dumps(
            {
                "output": str(output),
                "artifact_count": validation["artifact_count"],
                "target": args.target,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
