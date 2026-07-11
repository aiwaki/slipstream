#!/usr/bin/env python3
"""Build the Tauri updater appcast for a Slipstream release."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path


VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
PLATFORM = "darwin-aarch64"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def release_channel_for_tag(version: str, tag: str) -> str:
    if not VERSION_RE.match(version):
        raise ValueError(f"invalid version: {version!r}")
    stable_tag = f"v{version}"
    preview_tag = re.compile(rf"^{re.escape(stable_tag)}-preview\.[1-9][0-9]*$")
    if tag == stable_tag:
        return "stable"
    if preview_tag.match(tag):
        return "preview"
    raise ValueError(f"tag {tag!r} must be {stable_tag} or {stable_tag}-preview.<run>")


def validate_release_inputs(version: str, tag: str, repository: str, signature: str) -> None:
    release_channel_for_tag(version, tag)
    if not REPOSITORY_RE.match(repository):
        raise ValueError(f"invalid repository: {repository!r}")
    if not signature.strip():
        raise ValueError("empty updater signature")


def updater_archive_url(repository: str, tag: str) -> str:
    return (
        f"https://github.com/{repository}/releases/download/"
        f"{tag}/Slipstream.app.tar.gz"
    )


def build_appcast(
    *,
    version: str,
    tag: str,
    repository: str,
    signature: str,
    pub_date: str | None = None,
) -> dict:
    validate_release_inputs(version, tag, repository, signature)
    return {
        "version": version,
        "notes": "See the release notes.",
        "pub_date": pub_date or utc_now(),
        "platforms": {
            PLATFORM: {
                "signature": signature.strip(),
                "url": updater_archive_url(repository, tag),
            }
        },
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--signature-file", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--pub-date", help="UTC timestamp; defaults to now")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    signature = args.signature_file.read_text(encoding="utf-8")
    appcast = build_appcast(
        version=args.version,
        tag=args.tag,
        repository=args.repository,
        signature=signature,
        pub_date=args.pub_date,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(appcast, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
