#!/usr/bin/env python3
"""Fetch and verify the pinned local Chromium headless-shell runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import ssl
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "vendor/chromium-headless-shell/SOURCE.json"
REQUIRED = {"chrome-headless-shell", "LICENSE.headless_shell", "ABOUT"}


def _download_tls_context() -> ssl.SSLContext:
    """Use the reviewed system trust store when framework Python omits it."""

    system_ca = Path("/etc/ssl/cert.pem")
    if sys.platform == "darwin" and system_ca.is_file():
        return ssl.create_default_context(cafile=str(system_ca))
    return ssl.create_default_context()


def load_source() -> dict:
    source = json.loads(SOURCE.read_text(encoding="utf-8"))
    archive = source.get("archive")
    if not isinstance(archive, dict):
        raise ValueError("headless-shell source archive is missing")
    sha256 = archive.get("sha256")
    url = archive.get("url")
    length = archive.get("length")
    if not isinstance(sha256, str) or len(sha256) != 64:
        raise ValueError("headless-shell archive SHA-256 is invalid")
    if not isinstance(url, str) or not url.startswith(
        "https://storage.googleapis.com/chrome-for-testing-public/"
    ):
        raise ValueError("headless-shell archive URL is not the reviewed upstream")
    if not isinstance(length, int) or isinstance(length, bool) or length <= 0:
        raise ValueError("headless-shell archive length is invalid")
    if f"/{source.get('version')}/{source.get('platform')}/" not in url:
        raise ValueError("headless-shell version/platform do not match URL")
    canonical_url = (
        "https://storage.googleapis.com/chrome-for-testing-public/"
        f"{source.get('version')}/{source.get('platform')}/"
        f"chrome-headless-shell-{source.get('platform')}.zip"
    )
    if url != canonical_url:
        raise ValueError("headless-shell archive URL is not canonical")
    if source.get("license_path") != "LICENSE.headless_shell":
        raise ValueError("headless-shell license path is invalid")
    return source


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def materialize(output: Path, archive_override: Path | None = None) -> dict:
    source = load_source()
    archive_contract = source["archive"]
    with tempfile.TemporaryDirectory() as temporary:
        temporary_path = Path(temporary)
        archive = archive_override or temporary_path / "headless-shell.zip"
        if archive_override is None:
            last_error: Exception | None = None
            for attempt in range(1, 4):
                try:
                    with urllib.request.urlopen(
                        archive_contract["url"],
                        timeout=180,
                        context=_download_tls_context(),
                    ) as response:
                        with archive.open("wb") as destination:
                            shutil.copyfileobj(response, destination)
                    last_error = None
                    break
                except (OSError, urllib.error.URLError) as exc:
                    last_error = exc
                    archive.unlink(missing_ok=True)
                    if attempt < 3:
                        time.sleep(attempt)
            if last_error is not None:
                raise ValueError("failed to download pinned headless-shell") from last_error
        if archive.stat().st_size != archive_contract["length"]:
            raise ValueError("headless-shell archive length mismatch")
        if _hash(archive) != archive_contract["sha256"]:
            raise ValueError("headless-shell archive SHA-256 mismatch")
        stage = temporary_path / "stage"
        stage.mkdir()
        with zipfile.ZipFile(archive) as bundle:
            names = bundle.namelist()
            roots = {PurePosixPath(name).parts[0] for name in names if name}
            if roots != {"chrome-headless-shell-mac-arm64"}:
                raise ValueError("headless-shell archive root is unexpected")
            for info in bundle.infolist():
                relative = PurePosixPath(info.filename)
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError("unsafe path in headless-shell archive")
            bundle.extractall(stage)
        extracted = stage / "chrome-headless-shell-mac-arm64"
        missing = sorted(name for name in REQUIRED if not (extracted / name).is_file())
        if missing:
            raise ValueError("headless-shell archive is incomplete: " + ", ".join(missing))
        executable = extracted / "chrome-headless-shell"
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
        parent = output.parent
        parent.mkdir(parents=True, exist_ok=True)
        staged_output = parent / f".{output.name}.staging-{os.getpid()}"
        if staged_output.exists():
            shutil.rmtree(staged_output)
        shutil.copytree(extracted, staged_output, symlinks=False)
        manifest = {
            "schema_version": 1,
            "component": source["component"],
            "version": source["version"],
            "platform": source["platform"],
            "archive_url": archive_contract["url"],
            "archive_length": archive_contract["length"],
            "archive_sha256": archive_contract["sha256"],
            "executable_sha256": _hash(staged_output / "chrome-headless-shell"),
            "license": source["license_path"],
        }
        (staged_output / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        if output.exists():
            shutil.rmtree(output)
        staged_output.rename(output)
        return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args(argv)
    print(json.dumps(materialize(args.output, args.archive), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
