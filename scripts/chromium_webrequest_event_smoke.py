#!/usr/bin/env python3
"""Qualify Chromium's real incomplete-response event without Geph or PF."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

import chromium_semantic_packaged_smoke as semantic


MAX_NATIVE_MESSAGE = 64 * 1024


def _write_owner_file(
    path: Path,
    payload: bytes,
    *,
    mode: int,
    uid: int,
    gid: int,
) -> None:
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        mode,
    )
    try:
        remaining = memoryview(payload)
        while remaining:
            written = os.write(fd, remaining)
            if written <= 0:
                raise semantic.QualificationError(
                    f"owner file write made no progress: {path}"
                )
            remaining = remaining[written:]
        os.fsync(fd)
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def _native_stub_source(signal_path: Path) -> bytes:
    response = json.dumps(
        {
            "schema_version": 1,
            "accepted": True,
            "action": "confirm_exact_host_geo_exit",
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    source = f"""#!{sys.executable}
import json
import struct
import sys

MAX_NATIVE_MESSAGE = {MAX_NATIVE_MESSAGE}
SIGNAL_PATH = {str(signal_path)!r}
RESPONSE = {response!r}


def read_exact(size):
    chunks = []
    remaining = size
    while remaining:
        chunk = sys.stdin.buffer.read(remaining)
        if not chunk:
            raise SystemExit(2)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


header = read_exact(4)
length = struct.unpack("<I", header)[0]
if length <= 0 or length > MAX_NATIVE_MESSAGE:
    raise SystemExit(3)
payload = read_exact(length)
signal = json.loads(payload.decode("utf-8"))
encoded = json.dumps(signal, separators=(",", ":"), sort_keys=True).encode("utf-8")
with open(SIGNAL_PATH, "wb") as output:
    output.write(encoded)
sys.stdout.buffer.write(struct.pack("<I", len(RESPONSE)))
sys.stdout.buffer.write(RESPONSE)
sys.stdout.buffer.flush()
"""
    return source.encode("utf-8")


def _validate_signal(path: Path, uid: int) -> dict[str, object]:
    payload = semantic._read_private_json(path, uid)
    expected_keys = {
        "category",
        "confidence_bps",
        "host",
        "observed_at_unix_ms",
        "schema_version",
        "signal_id",
        "source",
        "top_level",
    }
    if set(payload) != expected_keys:
        raise semantic.QualificationError("native stub received expanded signal")
    if (
        payload.get("schema_version") != 2
        or payload.get("source") != "browser_extension"
        or payload.get("host") != semantic.INCOMPLETE_FIXTURE_HOST
        or payload.get("category") != "incomplete_response"
        or payload.get("confidence_bps") != 10_000
        or payload.get("top_level") is not True
    ):
        raise semantic.QualificationError(
            "native stub received an unexpected incomplete-response signal"
        )
    signal_id = payload.get("signal_id")
    observed_at = payload.get("observed_at_unix_ms")
    if (
        not isinstance(signal_id, str)
        or len(signal_id) != 32
        or any(character not in "0123456789abcdef" for character in signal_id)
        or not isinstance(observed_at, int)
        or isinstance(observed_at, bool)
        or observed_at <= 0
    ):
        raise semantic.QualificationError(
            "native stub received malformed replay identity"
        )
    return payload


def run(chrome_executable: Path, extension: Path) -> dict[str, object]:
    uid, gid = semantic._require_disposable_ci()
    chrome_executable = semantic._validate_chrome_for_testing(chrome_executable)
    extension = semantic._validate_extension(extension)
    root = Path(tempfile.mkdtemp(prefix="slipstream-webrequest-smoke-"))
    fixture = semantic.SemanticHttpsFixture(
        semantic.INCOMPLETE_FIXTURE_HOST,
        semantic.INCOMPLETE_RESPONSE_SCENARIO,
    )
    signal_path = root / "signal.json"
    stub_path = root / "native-stub"
    manifest_path = root / "native-host.json"
    failure: BaseException | None = None
    cleanup_errors: list[str] = []
    result: dict[str, object] = {}
    try:
        os.chown(root, uid, gid)
        root.chmod(0o700)
        _write_owner_file(
            signal_path,
            b"",
            mode=stat.S_IRUSR | stat.S_IWUSR,
            uid=uid,
            gid=gid,
        )
        _write_owner_file(
            stub_path,
            _native_stub_source(signal_path),
            mode=stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR,
            uid=uid,
            gid=gid,
        )
        manifest = {
            "allowed_origins": [semantic.NATIVE_HOST_ORIGIN],
            "name": semantic.NATIVE_HOST_NAME,
            "path": str(stub_path),
            "type": "stdio",
        }
        _write_owner_file(
            manifest_path,
            json.dumps(
                manifest,
                indent=2,
                sort_keys=True,
            ).encode("utf-8")
            + b"\n",
            mode=stat.S_IRUSR | stat.S_IWUSR,
            uid=uid,
            gid=gid,
        )
        fixture.start()
        snapshot = semantic._run_chrome(
            uid,
            gid,
            extension,
            fixture,
            chrome_executable,
            manifest_path,
            stub_path,
        )
        semantic._assert_fixture_complete(snapshot)
        signal = _validate_signal(signal_path, uid)
        result = {
            "result": "pass",
            "restricted_to": "disposable GitHub Actions macOS runner",
            "browser": "Chrome for Testing with a fresh owner-only profile",
            "observer": "real read-only webRequest incomplete-response event",
            "native_boundary": "owner-only fixed-response stub",
            "signal_schema_version": signal["schema_version"],
            "reloads": snapshot.root_visits - 1,
            "browser_ready_callbacks": snapshot.ready_requests,
            "mandatory_resources": {
                "css": snapshot.css_requests,
                "javascript": snapshot.script_requests,
                "image": snapshot.image_requests,
            },
            "system_network_state": "not mutated",
        }
    except BaseException as exc:
        failure = exc
    finally:
        try:
            fixture.close()
        except Exception as exc:
            cleanup_errors.append(f"fixture cleanup: {exc}")
        try:
            shutil.rmtree(root)
        except Exception as exc:
            cleanup_errors.append(f"private fixture cleanup: {exc}")

    if cleanup_errors:
        raise semantic.QualificationError("; ".join(cleanup_errors)) from failure
    if failure is not None:
        raise failure
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--chrome-executable", type=Path, required=True)
    parser.add_argument(
        "--extension",
        type=Path,
        default=semantic.DEFAULT_EXTENSION,
    )
    args = parser.parse_args(argv)
    try:
        result = run(args.chrome_executable, args.extension)
    except Exception as exc:
        print(f"Chromium webRequest qualification failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
