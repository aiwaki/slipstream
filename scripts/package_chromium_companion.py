from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import stat
import tempfile
import zipfile
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE_DIR = REPO_ROOT / "browser-companion" / "chromium"
DEFAULT_NATIVE_HOST_SOURCE = (
    REPO_ROOT / "app-tauri" / "src-tauri" / "src" / "native_messaging.rs"
)
EXPECTED_EXTENSION_ID = "cecdingohhpfggapnlbghppcegbaciam"
EXPECTED_EXTENSION_ORIGIN = f"chrome-extension://{EXPECTED_EXTENSION_ID}/"
EXPECTED_NATIVE_HOST_NAME = "dev.slipstream.semantic"
FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)

PACKAGE_PATHS = (
    "content.js",
    "detector.js",
    "icons/icon-128.png",
    "manifest.json",
    "service-worker-core.js",
    "service-worker.js",
)
SOURCE_ONLY_PATHS = (
    "PRIVACY.md",
    "STORE_LISTING.md",
    "tests/detector.test.mjs",
    "tests/service-worker-core.test.mjs",
    "tests/service-worker.test.mjs",
)
EXPECTED_MANIFEST_KEYS = {
    "background",
    "content_scripts",
    "description",
    "host_permissions",
    "icons",
    "key",
    "manifest_version",
    "minimum_chrome_version",
    "name",
    "permissions",
    "short_name",
    "version",
}
FORBIDDEN_CODE_PATTERNS = (
    re.compile(r"\beval\s*\("),
    re.compile(r"\bnew\s+Function\s*\("),
    re.compile(r"\bimport\s*\("),
    re.compile(r"\bfetch\s*\("),
    re.compile(r"\bXMLHttpRequest\b"),
    re.compile(r"\bWebSocket\b"),
    re.compile(r"\bEventSource\b"),
    re.compile(r"\bWebAssembly\b"),
    re.compile(r"createElement\s*\(\s*['\"]script['\"]\s*\)"),
)


class PackageError(ValueError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def chrome_extension_id(public_key: str) -> str:
    try:
        decoded = base64.b64decode(public_key, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise PackageError("manifest key is not valid base64") from exc
    if not decoded:
        raise PackageError("manifest key is empty")
    prefix = hashlib.sha256(decoded).digest()[:16]
    return "".join(
        chr(ord("a") + (byte >> 4)) + chr(ord("a") + (byte & 0x0F))
        for byte in prefix
    )


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackageError(f"cannot read valid JSON from {path}") from exc
    if not isinstance(payload, dict):
        raise PackageError(f"{path} must contain one JSON object")
    return payload


def validate_manifest(manifest: dict[str, Any]) -> tuple[str, str]:
    if set(manifest) != EXPECTED_MANIFEST_KEYS:
        missing = sorted(EXPECTED_MANIFEST_KEYS - set(manifest))
        extra = sorted(set(manifest) - EXPECTED_MANIFEST_KEYS)
        raise PackageError(f"manifest key drift: missing={missing}, extra={extra}")
    if manifest["manifest_version"] != 3:
        raise PackageError("only Manifest V3 is allowed")
    if manifest["name"] != "Slipstream Browser Companion":
        raise PackageError("extension name drifted")
    if manifest["short_name"] != "Slipstream":
        raise PackageError("extension short name drifted")
    description = manifest["description"]
    if not isinstance(description, str) or not description or len(description) > 132:
        raise PackageError("description must contain 1-132 characters")
    version = manifest["version"]
    if not isinstance(version, str) or not re.fullmatch(
        r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){1,3}", version
    ):
        raise PackageError("extension version is not a Chrome manifest version")
    if manifest["minimum_chrome_version"] != "102":
        raise PackageError("minimum Chrome version drifted")
    extension_id = chrome_extension_id(manifest["key"])
    if extension_id != EXPECTED_EXTENSION_ID:
        raise PackageError(
            f"manifest key derives unexpected extension ID {extension_id}"
        )
    if manifest["icons"] != {"128": "icons/icon-128.png"}:
        raise PackageError("extension icon contract drifted")
    if manifest["permissions"] != ["nativeMessaging", "storage", "webRequest"]:
        raise PackageError("extension permission contract drifted")
    if manifest["host_permissions"] != ["https://*/*"]:
        raise PackageError("extension host permission contract drifted")
    if manifest["background"] != {"service_worker": "service-worker.js"}:
        raise PackageError("service worker contract drifted")
    expected_content_scripts = [
        {
            "matches": ["https://*/*"],
            "js": ["detector.js", "content.js"],
            "run_at": "document_idle",
            "all_frames": False,
        }
    ]
    if manifest["content_scripts"] != expected_content_scripts:
        raise PackageError("content-script contract drifted")
    return extension_id, version


def validate_source_tree(source_dir: Path) -> None:
    expected = set(PACKAGE_PATHS) | set(SOURCE_ONLY_PATHS)
    actual: set[str] = set()
    for path in source_dir.rglob("*"):
        if path.is_symlink():
            raise PackageError(f"symlinks are forbidden in extension source: {path}")
        if path.is_file():
            actual.add(path.relative_to(source_dir).as_posix())
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise PackageError(f"source tree drift: missing={missing}, extra={extra}")

    for relative in PACKAGE_PATHS:
        path = source_dir / relative
        size = path.stat().st_size
        if size <= 0 or size > 1024 * 1024:
            raise PackageError(f"package file has invalid size: {relative} ({size})")

    icon = (source_dir / "icons" / "icon-128.png").read_bytes()
    if (
        len(icon) < 24
        or icon[:8] != b"\x89PNG\r\n\x1a\n"
        or icon[12:16] != b"IHDR"
        or int.from_bytes(icon[16:20], "big") != 128
        or int.from_bytes(icon[20:24], "big") != 128
    ):
        raise PackageError("icons/icon-128.png must be an exact 128x128 PNG")

    for relative in PACKAGE_PATHS:
        if not relative.endswith(".js"):
            continue
        try:
            source = (source_dir / relative).read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise PackageError(f"JavaScript is not UTF-8: {relative}") from exc
        for pattern in FORBIDDEN_CODE_PATTERNS:
            if pattern.search(source):
                raise PackageError(
                    f"remote or dynamic code marker {pattern.pattern!r} in {relative}"
                )

    worker_source = (source_dir / "service-worker.js").read_text(encoding="utf-8")
    local_imports = re.findall(
        r"\bimportScripts\s*\(\s*['\"]([^'\"]+)['\"]\s*\)",
        worker_source,
    )
    if local_imports != ["service-worker-core.js"]:
        raise PackageError(
            "service worker must import only local service-worker-core.js"
        )


def _rust_string_constant(source: str, name: str) -> str:
    match = re.search(
        rf"pub const {re.escape(name)}: &str = \"([^\"]+)\";",
        source,
    )
    if not match:
        raise PackageError(f"native host constant {name} is missing")
    return match.group(1)


def validate_native_host(path: Path) -> None:
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise PackageError(f"cannot read native host source {path}") from exc
    expected = {
        "NATIVE_HOST_NAME": EXPECTED_NATIVE_HOST_NAME,
        "CHROMIUM_EXTENSION_ID": EXPECTED_EXTENSION_ID,
        "CHROMIUM_EXTENSION_ORIGIN": EXPECTED_EXTENSION_ORIGIN,
    }
    for name, value in expected.items():
        actual = _rust_string_constant(source, name)
        if actual != value:
            raise PackageError(
                f"native host {name} mismatch: expected {value!r}, got {actual!r}"
            )


def _zip_info(relative: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(relative, FIXED_ZIP_TIMESTAMP)
    info.create_system = 3
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    return info


def _write_zip_atomic(source_dir: Path, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=output_path.parent,
        prefix=f".{output_path.name}.",
        suffix=".tmp",
        delete=False,
    ) as temporary:
        temporary_path = Path(temporary.name)
    try:
        with zipfile.ZipFile(temporary_path, "w") as archive:
            for relative in sorted(PACKAGE_PATHS):
                archive.writestr(
                    _zip_info(relative),
                    (source_dir / relative).read_bytes(),
                )
        os.replace(temporary_path, output_path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as temporary:
        temporary.write(serialized)
        temporary_path = Path(temporary.name)
    try:
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def package_companion(
    *,
    source_dir: Path,
    native_host_source: Path,
    output_dir: Path,
) -> dict[str, Any]:
    validate_source_tree(source_dir)
    manifest_path = source_dir / "manifest.json"
    manifest = _load_json_object(manifest_path)
    extension_id, version = validate_manifest(manifest)
    validate_native_host(native_host_source)

    archive_name = f"slipstream-chromium-companion-{version}.zip"
    archive_path = output_dir / archive_name
    _write_zip_atomic(source_dir, archive_path)

    files = [
        {
            "path": relative,
            "sha256": sha256_file(source_dir / relative),
            "size": (source_dir / relative).stat().st_size,
        }
        for relative in sorted(PACKAGE_PATHS)
    ]
    disclosures = {
        name: {
            "sha256": sha256_file(source_dir / name),
            "size": (source_dir / name).stat().st_size,
        }
        for name in ("PRIVACY.md", "STORE_LISTING.md")
    }
    provenance: dict[str, Any] = {
        "schema_version": 1,
        "package_format": "chrome-web-store-upload-zip-v1",
        "archive": {
            "name": archive_name,
            "sha256": sha256_file(archive_path),
            "size": archive_path.stat().st_size,
        },
        "extension": {
            "id": extension_id,
            "version": version,
            "manifest_version": manifest["manifest_version"],
            "minimum_chrome_version": manifest["minimum_chrome_version"],
        },
        "native_host": {
            "name": EXPECTED_NATIVE_HOST_NAME,
            "allowed_origin": EXPECTED_EXTENSION_ORIGIN,
        },
        "permissions": {
            "required": manifest["permissions"],
            "hosts": manifest["host_permissions"],
        },
        "files": files,
        "disclosures": disclosures,
        "remote_code": False,
    }
    provenance_path = output_dir / f"{archive_name}.provenance.json"
    _write_json_atomic(provenance_path, provenance)
    return {
        "archive_path": archive_path,
        "provenance_path": provenance_path,
        "provenance": provenance,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the deterministic Chrome Web Store upload package."
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=DEFAULT_SOURCE_DIR,
        help="Chromium companion source directory",
    )
    parser.add_argument(
        "--native-host-source",
        type=Path,
        default=DEFAULT_NATIVE_HOST_SOURCE,
        help="Rust native-host implementation used to bind the extension origin",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output directory for the ZIP and provenance JSON",
    )
    args = parser.parse_args()
    try:
        result = package_companion(
            source_dir=args.source.resolve(),
            native_host_source=args.native_host_source.resolve(),
            output_dir=args.output.resolve(),
        )
    except PackageError as exc:
        parser.error(str(exc))
    provenance = result["provenance"]
    print(f"archive={result['archive_path']}")
    print(f"archive_sha256={provenance['archive']['sha256']}")
    print(f"provenance={result['provenance_path']}")
    print(f"extension_id={provenance['extension']['id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
