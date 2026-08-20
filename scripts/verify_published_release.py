#!/usr/bin/env python3
"""Verify that GitHub published the exact locally verified app release."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
from pathlib import Path

import make_release_manifest


MAX_API_JSON_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SOURCE_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40,64}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
CHANNELS = ("preview", "stable")
RELEASE_STATES = ("draft", "published")
ARCHIVAL_MARKER = "архивная"


def archival_release_name(name: str) -> str:
    """Return one stable archival title or reject an ambiguous existing marker."""
    if not isinstance(name, str) or not name or "\n" in name or "\r" in name:
        raise ValueError("previous release title is invalid")
    marker_count = name.count(ARCHIVAL_MARKER)
    if marker_count:
        valid_suffix = name.endswith(f"({ARCHIVAL_MARKER})") or name.endswith(
            f", {ARCHIVAL_MARKER})"
        )
        if marker_count != 1 or not valid_suffix:
            raise ValueError("previous release title has an ambiguous archival marker")
        return name
    if name.endswith(")"):
        return f"{name[:-1]}, {ARCHIVAL_MARKER})"
    return f"{name} ({ARCHIVAL_MARKER})"


def _read_regular(path: Path, *, limit: int, label: str) -> bytes:
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
        while True:
            block = os.read(descriptor, min(1024 * 1024, limit + 1 - len(content)))
            if not block:
                break
            content.extend(block)
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
        return bytes(content)
    finally:
        os.close(descriptor)


def _read_json(path: Path, *, limit: int, label: str) -> dict:
    content = _read_regular(path, limit=limit, label=label)
    try:
        value = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} must be valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _manifest_assets(
    *,
    release_dir: Path,
    repository: str,
    version: str,
    tag: str,
    channel: str,
    source_commit: str,
    target: str,
) -> dict[str, dict[str, object]]:
    if not release_dir.is_dir() or release_dir.is_symlink():
        raise ValueError("release directory is missing or unsafe")
    manifest_path = release_dir / make_release_manifest.MANIFEST_NAME
    manifest = _read_json(
        manifest_path,
        limit=MAX_MANIFEST_BYTES,
        label="artifact manifest",
    )
    expected = {
        "schema_version": make_release_manifest.MANIFEST_SCHEMA_VERSION,
        "generator": make_release_manifest.MANIFEST_GENERATOR,
        "product": "Slipstream",
        "repository": repository,
        "version": version,
        "tag": tag,
        "channel": channel,
    }
    for key, value in expected.items():
        if manifest.get(key) != value:
            raise ValueError(f"artifact manifest has invalid {key}")
    source = manifest.get("source")
    if not isinstance(source, dict) or source.get("commit") != source_commit:
        raise ValueError("artifact manifest source commit does not match release")
    build = manifest.get("build")
    if not isinstance(build, dict) or build.get("target") != target:
        raise ValueError("artifact manifest target does not match release")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("artifact manifest must contain release artifacts")
    expected_assets: dict[str, dict[str, object]] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ValueError("artifact manifest entry must be an object")
        name = artifact.get("name")
        digest = artifact.get("sha256")
        size = artifact.get("size")
        if (
            not isinstance(name, str)
            or not name
            or Path(name).name != name
            or name in {make_release_manifest.MANIFEST_NAME, "release-notes.md"}
            or name in expected_assets
        ):
            raise ValueError("artifact manifest contains an invalid asset name")
        if not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest):
            raise ValueError(f"artifact manifest has invalid digest for {name}")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise ValueError(f"artifact manifest has invalid size for {name}")
        local_digest, local_size = make_release_manifest.hash_regular_file(
            release_dir / name
        )
        if local_digest != digest or local_size != size:
            raise ValueError(f"local release asset differs from manifest: {name}")
        expected_assets[name] = {"sha256": digest, "size": size}

    manifest_digest, manifest_size = make_release_manifest.hash_regular_file(
        manifest_path
    )
    expected_assets[make_release_manifest.MANIFEST_NAME] = {
        "sha256": manifest_digest,
        "size": manifest_size,
    }
    allowed_local_names = set(expected_assets) | {"release-notes.md"}
    local_names = {entry.name for entry in release_dir.iterdir()}
    if local_names != allowed_local_names:
        raise ValueError("local publication file set differs from artifact manifest")
    if "release-notes.md" in local_names:
        make_release_manifest.hash_regular_file(release_dir / "release-notes.md")
    return expected_assets


def verify_published_release(
    *,
    release_metadata_path: Path,
    tag_ref_path: Path | None,
    release_dir: Path,
    repository: str,
    version: str,
    tag: str,
    channel: str,
    release_name: str,
    source_commit: str,
    target: str,
    release_id: int,
    state: str,
) -> dict[str, object]:
    if not REPOSITORY_PATTERN.fullmatch(repository):
        raise ValueError("repository must use owner/name form")
    if not SOURCE_COMMIT_PATTERN.fullmatch(source_commit):
        raise ValueError("source commit must be a full lowercase Git object ID")
    if channel not in CHANNELS:
        raise ValueError("release channel is invalid")
    if state not in RELEASE_STATES:
        raise ValueError("published release state is invalid")
    if isinstance(release_id, bool) or release_id <= 0:
        raise ValueError("published release ID is invalid")
    if not tag or not release_name or not version:
        raise ValueError("release identity fields must be non-empty")

    expected_assets = _manifest_assets(
        release_dir=release_dir,
        repository=repository,
        version=version,
        tag=tag,
        channel=channel,
        source_commit=source_commit,
        target=target,
    )
    if state == "published":
        if tag_ref_path is None:
            raise ValueError("published release requires its exact tag ref")
        tag_ref = _read_json(
            tag_ref_path,
            limit=MAX_API_JSON_BYTES,
            label="published tag ref",
        )
        if tag_ref.get("ref") != f"refs/tags/{tag}":
            raise ValueError("published tag ref name does not match release")
        tag_object = tag_ref.get("object")
        if not isinstance(tag_object, dict):
            raise ValueError("published tag ref object is missing")
        if tag_object.get("type") != "commit":
            raise ValueError("published tag must be a lightweight commit ref")
        if tag_object.get("sha") != source_commit:
            raise ValueError("published tag does not point to the source commit")
    elif tag_ref_path is not None:
        raise ValueError("draft release must not have a published tag ref")

    release = _read_json(
        release_metadata_path,
        limit=MAX_API_JSON_BYTES,
        label="published release metadata",
    )
    expected_release = {
        "id": release_id,
        "tag_name": tag,
        "target_commitish": source_commit,
        "name": release_name,
        "draft": state == "draft",
        "prerelease": channel == "preview",
    }
    for key, value in expected_release.items():
        actual = release.get(key)
        if isinstance(value, bool):
            matches = actual is value
        else:
            matches = actual == value and not (
                isinstance(value, int) and isinstance(actual, bool)
            )
        if not matches:
            raise ValueError(f"published release has invalid {key}")
    published_at = release.get("published_at")
    if state == "draft":
        if published_at is not None:
            raise ValueError("draft release unexpectedly has published_at")
    elif not isinstance(published_at, str) or not published_at.strip():
        raise ValueError("published release is missing published_at")

    assets = release.get("assets")
    if not isinstance(assets, list):
        raise ValueError("published release asset inventory is missing")
    remote_assets: dict[str, dict[str, object]] = {}
    for asset in assets:
        if not isinstance(asset, dict):
            raise ValueError("published release asset entry must be an object")
        name = asset.get("name")
        if not isinstance(name, str) or name in remote_assets:
            raise ValueError("published release contains an invalid asset name")
        expected_asset = expected_assets.get(name)
        if expected_asset is None:
            raise ValueError(f"published release contains an unexpected asset: {name}")
        if asset.get("state") != "uploaded":
            raise ValueError(f"published release asset is incomplete: {name}")
        remote_size = asset.get("size")
        if (
            not isinstance(remote_size, int)
            or isinstance(remote_size, bool)
            or remote_size != expected_asset["size"]
        ):
            raise ValueError(f"published release asset size mismatch: {name}")
        if asset.get("digest") != f"sha256:{expected_asset['sha256']}":
            raise ValueError(f"published release asset digest mismatch: {name}")
        remote_assets[name] = expected_asset
    if set(remote_assets) != set(expected_assets):
        missing = sorted(set(expected_assets) - set(remote_assets))
        raise ValueError("published release is missing assets: " + ", ".join(missing))

    return {
        "tag": tag,
        "source_commit": source_commit,
        "prerelease": channel == "preview",
        "release_id": release_id,
        "state": state,
        "asset_count": len(remote_assets),
        "published_at": published_at,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-metadata", required=True, type=Path)
    parser.add_argument("--tag-ref", type=Path)
    parser.add_argument("--release-dir", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--channel", choices=CHANNELS, required=True)
    parser.add_argument("--release-name", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--release-id", required=True, type=int)
    parser.add_argument("--state", choices=RELEASE_STATES, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = verify_published_release(
        release_metadata_path=args.release_metadata,
        tag_ref_path=args.tag_ref,
        release_dir=args.release_dir,
        repository=args.repository,
        version=args.version,
        tag=args.tag,
        channel=args.channel,
        release_name=args.release_name,
        source_commit=args.source_commit,
        target=args.target,
        release_id=args.release_id,
        state=args.state,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
