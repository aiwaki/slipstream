#!/usr/bin/env python3
"""Verify Slipstream release artifacts before publishing them."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import make_appcast
import make_route_policy_bundle


REQUIRED_ASSETS = (
    "Slipstream-macos-arm64.zip",
    "Slipstream.app.tar.gz",
    "Slipstream.app.tar.gz.sig",
    "latest.json",
    "route-policy.json",
    "route-policy-latest.json",
    "route-policy-keys.json",
)


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path.name} is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path.name} must be a JSON object")
    return data


def _require_nonempty_file(path: Path) -> None:
    if not path.is_file():
        raise ValueError(f"missing release artifact: {path.name}")
    if path.stat().st_size <= 0:
        raise ValueError(f"empty release artifact: {path.name}")


def _expected_route_policy_url(repository: str, tag: str) -> str:
    return f"https://github.com/{repository}/releases/download/{tag}/route-policy.json"


def _validate_appcast(
    *,
    release_dir: Path,
    repository: str,
    tag: str,
    version: str,
) -> dict:
    appcast = _read_json(release_dir / "latest.json")
    signature = (release_dir / "Slipstream.app.tar.gz.sig").read_text(encoding="utf-8").strip()
    expected_url = make_appcast.updater_archive_url(repository, tag)

    if appcast.get("version") != version:
        raise ValueError(f"latest.json version must be {version}")
    platform = appcast.get("platforms", {}).get(make_appcast.PLATFORM)
    if not isinstance(platform, dict):
        raise ValueError(f"latest.json missing {make_appcast.PLATFORM} platform")
    if platform.get("url") != expected_url:
        raise ValueError("appcast URL does not match release repository/tag")
    if platform.get("signature", "").strip() != signature:
        raise ValueError("appcast signature does not match Slipstream.app.tar.gz.sig")
    return {
        "url": expected_url,
        "signature_bytes": len(signature),
    }


def _validate_route_policy_channel(
    *,
    release_dir: Path,
    repository: str,
    tag: str,
) -> dict:
    bundle_path = release_dir / "route-policy.json"
    keys_path = release_dir / "route-policy-keys.json"
    channel_path = release_dir / "route-policy-latest.json"
    bundle = _read_json(bundle_path)
    channel = _read_json(channel_path)

    key_id = bundle.get("key_id")
    if not isinstance(key_id, str) or not key_id.strip():
        raise ValueError("route-policy.json key_id is required")
    make_route_policy_bundle.verify_signed_route_policy_bundle_file(
        bundle_path=bundle_path,
        public_keys_path=keys_path,
    )

    expected_url = _expected_route_policy_url(repository, tag)
    if channel.get("bundle_url") != expected_url:
        raise ValueError("route-policy-latest.json bundle_url does not match release")
    expected_hash = make_route_policy_bundle.hash_file(bundle_path)
    if channel.get("sha256") != expected_hash:
        raise ValueError("route-policy-latest.json sha256 does not match route-policy.json")
    if channel.get("key_id") != key_id:
        raise ValueError("route-policy-latest.json key_id does not match bundle")
    if channel.get("source") != bundle.get("manifest", {}).get("source"):
        raise ValueError("route-policy-latest.json source does not match bundle manifest")

    return {
        "bundle_url": expected_url,
        "sha256": expected_hash,
        "key_id": key_id,
        "source": channel.get("source", ""),
    }


def verify_release_artifacts(
    *,
    release_dir: Path,
    repository: str,
    tag: str,
    version: str,
) -> dict:
    release_dir = release_dir.resolve()
    for name in REQUIRED_ASSETS:
        _require_nonempty_file(release_dir / name)
    make_appcast.validate_release_inputs(
        version,
        tag,
        repository,
        (release_dir / "Slipstream.app.tar.gz.sig").read_text(encoding="utf-8"),
    )
    appcast = _validate_appcast(
        release_dir=release_dir,
        repository=repository,
        tag=tag,
        version=version,
    )
    channel = _validate_route_policy_channel(
        release_dir=release_dir,
        repository=repository,
        tag=tag,
    )
    return {
        "version": version,
        "tag": tag,
        "repository": repository,
        "appcast": appcast,
        "route_policy": {
            "key_id": channel["key_id"],
            "sha256": channel["sha256"],
        },
        "route_policy_channel": channel,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-dir", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--version", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    result = verify_release_artifacts(
        release_dir=args.release_dir,
        repository=args.repository,
        tag=args.tag,
        version=args.version,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
