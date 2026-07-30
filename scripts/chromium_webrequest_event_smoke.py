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


def _native_stub_source(signal_path: Path, trace_path: Path) -> bytes:
    accepted_response = json.dumps(
        {
            "schema_version": 1,
            "accepted": True,
            "action": "confirm_exact_host_geo_exit",
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    rejected_response = json.dumps(
        {
            "schema_version": 1,
            "accepted": False,
            "action": "none",
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    source = f"""#!{sys.executable}
import json
import os
import struct
import sys

MAX_NATIVE_MESSAGE = {MAX_NATIVE_MESSAGE}
SIGNAL_PATH = {str(signal_path)!r}
TRACE_PATH = {str(trace_path)!r}
ACCEPTED_RESPONSE = {accepted_response!r}
REJECTED_RESPONSE = {rejected_response!r}


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
if signal.get("schema_version") == 2:
    with open(SIGNAL_PATH, "wb") as output:
        output.write(encoded)
    response = ACCEPTED_RESPONSE
else:
    descriptor = os.open(TRACE_PATH, os.O_WRONLY | os.O_APPEND)
    try:
        os.write(descriptor, encoded + b"\\n")
    finally:
        os.close(descriptor)
    response = REJECTED_RESPONSE
sys.stdout.buffer.write(struct.pack("<I", len(response)))
sys.stdout.buffer.write(response)
sys.stdout.buffer.flush()
"""
    return source.encode("utf-8")


def _diagnostic_worker_source(host: str) -> bytes:
    source = f"""

// CI-only observer appended to an owner-only copy of the reviewed extension.
const SLIPSTREAM_CI_FIXTURE_HOST = {host!r};
const SLIPSTREAM_CI_WARMUP_TYPE = "slipstream.qualification_warmup";
function slipstreamCiWebRequestTrace(phase, details) {{
  let host = null;
  try {{
    host = new URL(details.url).hostname.toLowerCase();
  }} catch (_error) {{
    return;
  }}
  if (host !== SLIPSTREAM_CI_FIXTURE_HOST) {{
    return;
  }}
  const trace = {{
    schema_version: 0,
    source: "ci_webrequest_trace",
    phase,
    keys: Object.keys(details).sort(),
    type: typeof details.type === "string" ? details.type : null,
    method: typeof details.method === "string" ? details.method : null,
    frame_id: Number.isInteger(details.frameId) ? details.frameId : null,
    parent_frame_id_present: Object.prototype.hasOwnProperty.call(
      details,
      "parentFrameId"
    ),
    parent_frame_id: Number.isInteger(details.parentFrameId)
      ? details.parentFrameId
      : null,
    status_code: Number.isInteger(details.statusCode)
      ? details.statusCode
      : null,
    error: typeof details.error === "string" ? details.error : null
  }};
  chrome.runtime.sendNativeMessage(NATIVE_HOST, trace).catch(() => {{}});
}}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {{
  if (message?.type !== SLIPSTREAM_CI_WARMUP_TYPE) {{
    return;
  }}
  chrome.runtime.sendNativeMessage(NATIVE_HOST, {{
    schema_version: 0,
    source: "ci_worker_ready",
    phase: "worker_ready"
  }})
    .then(() => sendResponse({{ ready: true }}))
    .catch(() => sendResponse({{ ready: false }}));
  return true;
}});

for (const [phase, event] of [
  ["before_request", chrome.webRequest.onBeforeRequest],
  ["headers_received", chrome.webRequest.onHeadersReceived],
  ["before_redirect", chrome.webRequest.onBeforeRedirect],
  ["completed", chrome.webRequest.onCompleted],
  ["error", chrome.webRequest.onErrorOccurred]
]) {{
  event.addListener(
    (details) => slipstreamCiWebRequestTrace(phase, details),
    {{
      urls: ["https://*/*"],
      types: ["main_frame"]
    }}
  );
}}
"""
    return source.encode("utf-8")


def _copy_diagnostic_extension(
    source: Path,
    destination: Path,
    *,
    host: str,
    target_url: str,
    uid: int,
    gid: int,
) -> Path:
    shutil.copytree(source, destination, symlinks=False)
    worker_path = destination / "service-worker.js"
    with worker_path.open("ab") as worker:
        worker.write(_diagnostic_worker_source(host))
    (destination / "qualification-warmup.html").write_text(
        (
            "<!doctype html><meta charset=\"utf-8\">"
            "<title>Slipstream qualification</title>"
            "<script src=\"qualification-warmup.js\"></script>"
        ),
        encoding="utf-8",
    )
    (destination / "qualification-warmup.js").write_text(
        (
            f"const target = {json.dumps(target_url)};\n"
            "const maxAttempts = 40;\n"
            "let attempts = 0;\n"
            "function warmWorker() {\n"
            "  attempts += 1;\n"
            "  chrome.runtime.sendMessage({"
            'type: "slipstream.qualification_warmup"'
            "  }).then((response) => {\n"
            "    if (response?.ready === true) {\n"
            "      location.replace(target);\n"
            "      return;\n"
            "    }\n"
            "    retry();\n"
            "  }).catch(retry);\n"
            "}\n"
            "function retry() {\n"
            "  if (attempts >= maxAttempts) {\n"
            '    document.body.textContent = "worker warmup failed";\n'
            "    return;\n"
            "  }\n"
            "  setTimeout(warmWorker, 250);\n"
            "}\n"
            "warmWorker();\n"
        ),
        encoding="utf-8",
    )
    for root, directories, files in os.walk(destination):
        root_path = Path(root)
        os.chown(root_path, uid, gid)
        root_path.chmod(0o700)
        for directory in directories:
            path = root_path / directory
            os.chown(path, uid, gid)
            path.chmod(0o700)
        for filename in files:
            path = root_path / filename
            os.chown(path, uid, gid)
            path.chmod(0o600)
    return destination


def _read_trace(path: Path, uid: int) -> list[dict[str, object]]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > MAX_NATIVE_MESSAGE
        ):
            raise semantic.QualificationError(
                f"{path} is not a bounded owner-private trace"
            )
        payload = os.read(descriptor, MAX_NATIVE_MESSAGE + 1)
    finally:
        os.close(descriptor)
    if not payload:
        return []
    traces: list[dict[str, object]] = []
    for line in payload.splitlines():
        if not line:
            continue
        trace = semantic._decode_json_object(line, path)
        traces.append(trace)
    return traces


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
    diagnostic_extension = root / "extension"
    fixture = semantic.SemanticHttpsFixture(
        semantic.INCOMPLETE_FIXTURE_HOST,
        semantic.INCOMPLETE_RESPONSE_SCENARIO,
    )
    signal_path = root / "signal.json"
    trace_path = root / "trace.jsonl"
    stub_path = root / "native-stub"
    manifest_path = root / "native-host.json"
    failure: BaseException | None = None
    cleanup_errors: list[str] = []
    result: dict[str, object] = {}
    trace: list[dict[str, object]] = []
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
            trace_path,
            b"",
            mode=stat.S_IRUSR | stat.S_IWUSR,
            uid=uid,
            gid=gid,
        )
        _write_owner_file(
            stub_path,
            _native_stub_source(signal_path, trace_path),
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
        target_url = (
            f"https://{fixture.host}:{fixture.port}/"
            "?slipstream-webrequest=1"
        )
        diagnostic_extension = _copy_diagnostic_extension(
            extension,
            diagnostic_extension,
            host=fixture.host,
            target_url=target_url,
            uid=uid,
            gid=gid,
        )
        snapshot = semantic._run_chrome(
            uid,
            gid,
            diagnostic_extension,
            fixture,
            chrome_executable,
            manifest_path,
            stub_path,
            initial_url=(
                f"{semantic.NATIVE_HOST_ORIGIN}"
                "qualification-warmup.html"
            ),
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
            trace = _read_trace(trace_path, uid)
        except FileNotFoundError:
            trace = []
        except Exception as exc:
            cleanup_errors.append(f"sanitized trace read: {exc}")
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
        raise semantic.QualificationError(
            f"{failure}; sanitized webRequest trace: "
            f"{json.dumps(trace, separators=(',', ':'), sort_keys=True)}"
        ) from failure
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
