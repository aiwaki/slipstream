#!/usr/bin/env python3
"""Qualify one exact packaged macOS update notification without UI activation.

The production binary hook consumed by this gate is intentionally unavailable
to ordinary launches.  A disposable macOS runner mints an unlinked, root-owned
capability file, passes its descriptor through a privilege-dropping exec, and
binds it to the exact process, user, candidate tree, executable and deadline.

The gate never reads notification content.  It observes only a new record
count attributed by macOS to ``dev.slipstream.tray`` and samples CoreGraphics,
LaunchServices, Dock classification and the frontmost application.  A native
permission denial is reported separately from successful OS submission; the
gate does not claim that macOS displayed a banner when notifications are
disabled by the user or runner policy.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import select
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import BinaryIO

import release_candidate


SCHEMA_VERSION = 1
BUNDLE_IDENTIFIER = "dev.slipstream.tray"
BUNDLE_EXECUTABLE = "slipstream"
CAPABILITY_PURPOSE = "slipstream_update_notification_qualification"
CAPABILITY_FD = 3
CAPABILITY_MAX_BYTES = 16 * 1024
CAPABILITY_MAX_LIFETIME_MS = 30_000
INFO_PLIST_MAX_BYTES = 256 * 1024
HOOK_TIMEOUT_SECONDS = 20.0
OS_OBSERVATION_TIMEOUT_SECONDS = 8.0
VISIBILITY_SAMPLE_SECONDS = 0.05
LSAPPINFO = "/usr/bin/lsappinfo"
LSREGISTER = (
    "/System/Library/Frameworks/CoreServices.framework/Frameworks/"
    "LaunchServices.framework/Support/lsregister"
)
PRIVILEGED_MODE = "--privileged-notification-capability-exec"
HOOK_ARGUMENT = "--qualify-update-notification"
HOOK_CAPABILITY_ENV = "SLIPSTREAM_UPDATE_NOTIFICATION_QUALIFICATION_FD"
OUTCOMES = frozenset({"submitted", "terminal"})
TERMINAL_REASONS = frozenset(
    {
        "capability_invalid",
        "identity_unavailable",
        "native_submission_failed",
    }
)
GENERIC_FAILURE_CODE = "qualification_failed"
INTERNAL_FAILURE_CODE = "internal_error"
FAILURE_REPORT_MAX_BYTES = 512
FAILURE_CODES = TERMINAL_REASONS | frozenset(
    {
        GENERIC_FAILURE_CODE,
        INTERNAL_FAILURE_CODE,
        "hook_cleanup_failed",
        "hook_launch_failed",
        "os_attribution_invalid",
        "os_attribution_missing",
        "os_observation_failed",
        "visibility_violation",
    }
)
HEX_64 = re.compile(r"[0-9a-f]{64}")
HEX_32_BYTES = re.compile(r"[0-9a-f]{64}")
FORBIDDEN_LAUNCH_SERVICES_EVENTS = (
    "PostShowProcess",
    "showRequest",
    "becameFrontmost",
    "bringForwardRequest",
    "kLSNotifyApplicationShown",
    "kLSNotifyShowRequest",
    "kLSNotifyBecameFrontmost",
    "kLSNotifyBringForwardRequest",
)
USERNOTED_DB_RELATIVE = Path(
    "Library/Group Containers/group.com.apple.usernoted/db2/db"
)


class NotificationQualificationError(RuntimeError):
    """The exact packaged notification qualification did not complete."""

    def __init__(
        self,
        message: str,
        *,
        failure_code: str = GENERIC_FAILURE_CODE,
    ) -> None:
        if failure_code not in FAILURE_CODES:
            raise ValueError("notification failure code is not whitelisted")
        super().__init__(message)
        self.failure_code = failure_code


def _failure_report(error: BaseException) -> dict:
    failure_code = INTERNAL_FAILURE_CODE
    if isinstance(error, NotificationQualificationError):
        candidate = error.failure_code
        if candidate in FAILURE_CODES:
            failure_code = candidate
    report = {
        "schema_version": SCHEMA_VERSION,
        "outcome": "terminal",
        "failure_code": failure_code,
    }
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(encoded) > FAILURE_REPORT_MAX_BYTES:
        raise AssertionError("notification failure report exceeded its bound")
    return report


def _with_failure_code(
    error: BaseException,
    *,
    failure_code: str,
    message: str,
) -> NotificationQualificationError:
    if (
        isinstance(error, NotificationQualificationError)
        and error.failure_code != GENERIC_FAILURE_CODE
    ):
        failure_code = error.failure_code
    return NotificationQualificationError(message, failure_code=failure_code)


@dataclass(frozen=True)
class CandidateIdentity:
    app_bundle: Path
    executable: Path
    app_tree_sha256: str
    executable_sha256: str
    manifest_sha256: str
    candidate_id: str


@dataclass(frozen=True)
class NotificationRecordSnapshot:
    maximum_record_id: int
    record_count: int


@dataclass(frozen=True)
class LaunchServicesEntry:
    pid: int | None
    executable_path: str | None
    application_type: str | None
    dock_visible: bool


@dataclass(frozen=True)
class VisibilitySnapshot:
    frontmost_asn: str
    window_ids: frozenset[int]
    launch_services_entries: tuple[LaunchServicesEntry, ...]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _read_bounded_regular_file(path: Path, maximum: int) -> bytes:
    try:
        before = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink == 0
            or before.st_size > maximum
        ):
            raise NotificationQualificationError(
                "packaged app metadata is unsafe"
            )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (
                (opened.st_dev, opened.st_ino, opened.st_size)
                != (before.st_dev, before.st_ino, before.st_size)
            ):
                raise NotificationQualificationError(
                    "packaged app metadata changed while opening"
                )
            payload = stream.read(maximum + 1)
        after = path.lstat()
    except NotificationQualificationError:
        raise
    except OSError as exc:
        raise NotificationQualificationError(
            "packaged app metadata is unavailable"
        ) from exc
    if (
        len(payload) != before.st_size
        or len(payload) > maximum
        or (after.st_dev, after.st_ino, after.st_size)
        != (before.st_dev, before.st_ino, before.st_size)
    ):
        raise NotificationQualificationError(
            "packaged app metadata changed while reading"
        )
    return payload


def _canonical_json(value: dict) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _read_bounded_json(stream: BinaryIO, *, label: str) -> dict:
    payload = stream.read(CAPABILITY_MAX_BYTES + 1)
    if len(payload) > CAPABILITY_MAX_BYTES:
        raise NotificationQualificationError(f"{label} exceeded its size limit")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NotificationQualificationError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise NotificationQualificationError(f"{label} must be a JSON object")
    return value


def _require_disposable_macos_ci() -> None:
    if sys.platform != "darwin":
        raise NotificationQualificationError(
            "notification qualification requires macOS"
        )
    if not (
        os.environ.get("CI") == "true"
        and os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("SLIPSTREAM_DISPOSABLE_CI") == "1"
    ):
        raise NotificationQualificationError(
            "notification qualification requires disposable GitHub Actions"
        )


def _validate_packaged_bundle(app_bundle: Path) -> tuple[Path, dict]:
    try:
        bundle_metadata = app_bundle.lstat()
    except OSError as exc:
        raise NotificationQualificationError(
            "packaged app bundle is unavailable"
        ) from exc
    if app_bundle.is_symlink() or not stat.S_ISDIR(bundle_metadata.st_mode):
        raise NotificationQualificationError("packaged app bundle is unsafe")
    resolved = app_bundle.resolve(strict=True)
    if not resolved.is_dir():
        raise NotificationQualificationError("packaged app bundle is unsafe")
    info_path = resolved / "Contents/Info.plist"
    executable = resolved / "Contents/MacOS" / BUNDLE_EXECUTABLE
    try:
        info = plistlib.loads(
            _read_bounded_regular_file(info_path, INFO_PLIST_MAX_BYTES)
        )
    except plistlib.InvalidFileException as exc:
        raise NotificationQualificationError(
            "packaged app metadata is invalid"
        ) from exc
    if not isinstance(info, dict):
        raise NotificationQualificationError("packaged app metadata is invalid")
    if info.get("CFBundleIdentifier") != BUNDLE_IDENTIFIER:
        raise NotificationQualificationError("packaged bundle identifier mismatch")
    if info.get("CFBundleExecutable") != BUNDLE_EXECUTABLE:
        raise NotificationQualificationError("packaged executable identity mismatch")
    if info.get("LSUIElement") is not True:
        raise NotificationQualificationError("packaged app must set LSUIElement=true")
    metadata = executable.lstat()
    if (
        executable.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & 0o111 == 0
    ):
        raise NotificationQualificationError("packaged executable is not executable")
    signature = subprocess.run(
        ("/usr/bin/codesign", "--verify", "--strict", str(resolved)),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=False,
    )
    if signature.returncode != 0:
        raise NotificationQualificationError("packaged code signature is invalid")
    return executable.resolve(strict=True), info


def _validated_candidate_identity(
    *,
    candidate_dir: Path,
    app_bundle: Path,
    repository: str,
    source_commit: str,
    candidate_run_id: int,
    candidate_run_attempt: int,
) -> CandidateIdentity:
    manifest = release_candidate._read_object(
        candidate_dir / release_candidate.MANIFEST_NAME,
        "candidate manifest",
    )
    source = manifest.get("source")
    if (
        not isinstance(source, dict)
        or source.get("repository") != repository
        or source.get("commit") != source_commit
    ):
        raise NotificationQualificationError(
            "candidate source does not match exact repository and SHA"
        )
    verified = release_candidate.validate_manifest(
        candidate_dir=candidate_dir,
        repository=repository,
        version=manifest.get("version", ""),
        source_commit=source_commit,
        source_tree=source.get("tree", ""),
        source_archive_sha256=source.get("archive_sha256", ""),
        source_date_epoch=source.get("source_date_epoch", -1),
        target=manifest.get("target", ""),
        expected_workflow_run_id=candidate_run_id,
        expected_workflow_run_attempt=candidate_run_attempt,
        app_tree=app_bundle,
    )
    executable, _ = _validate_packaged_bundle(app_bundle)
    app_tree_sha256 = manifest.get("app_tree_sha256")
    if not isinstance(app_tree_sha256, str) or not HEX_64.fullmatch(
        app_tree_sha256
    ):
        raise NotificationQualificationError("candidate app tree digest is invalid")
    return CandidateIdentity(
        app_bundle=app_bundle.resolve(strict=True),
        executable=executable,
        app_tree_sha256=app_tree_sha256,
        executable_sha256=_sha256(executable),
        manifest_sha256=verified["manifest_sha256"],
        candidate_id=verified["candidate_id"],
    )


def build_capability_template(
    identity: CandidateIdentity,
    *,
    uid: int,
    gid: int,
    home: Path,
    nonce: str,
    issued_at_unix_ms: int,
) -> dict:
    if uid <= 0 or gid <= 0:
        raise NotificationQualificationError(
            "notification qualification must target a non-root user"
        )
    if not HEX_32_BYTES.fullmatch(nonce):
        raise NotificationQualificationError("capability nonce is invalid")
    resolved_home = home.resolve(strict=True)
    deadline = issued_at_unix_ms + CAPABILITY_MAX_LIFETIME_MS
    return {
        "schema_version": SCHEMA_VERSION,
        "purpose": CAPABILITY_PURPOSE,
        "nonce": nonce,
        "issued_at_unix_ms": issued_at_unix_ms,
        "deadline_unix_ms": deadline,
        "expected_uid": uid,
        "expected_gid": gid,
        "home": str(resolved_home),
        "app_bundle": str(identity.app_bundle),
        "executable": str(identity.executable),
        "executable_sha256": identity.executable_sha256,
        "app_tree_sha256": identity.app_tree_sha256,
        "candidate_manifest_sha256": identity.manifest_sha256,
        "candidate_id": identity.candidate_id,
        "bundle_identifier": BUNDLE_IDENTIFIER,
    }


def validate_capability_template(value: dict, *, now_unix_ms: int) -> dict:
    expected_keys = {
        "schema_version",
        "purpose",
        "nonce",
        "issued_at_unix_ms",
        "deadline_unix_ms",
        "expected_uid",
        "expected_gid",
        "home",
        "app_bundle",
        "executable",
        "executable_sha256",
        "app_tree_sha256",
        "candidate_manifest_sha256",
        "candidate_id",
        "bundle_identifier",
    }
    if set(value) != expected_keys:
        raise NotificationQualificationError("capability fields are invalid")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise NotificationQualificationError("capability schema is invalid")
    if value.get("purpose") != CAPABILITY_PURPOSE:
        raise NotificationQualificationError("capability purpose is invalid")
    if value.get("bundle_identifier") != BUNDLE_IDENTIFIER:
        raise NotificationQualificationError("capability bundle identity is invalid")
    if not isinstance(value.get("nonce"), str) or not HEX_32_BYTES.fullmatch(
        value["nonce"]
    ):
        raise NotificationQualificationError("capability nonce is invalid")
    for field in (
        "executable_sha256",
        "app_tree_sha256",
        "candidate_manifest_sha256",
    ):
        if not isinstance(value.get(field), str) or not HEX_64.fullmatch(
            value[field]
        ):
            raise NotificationQualificationError(
                "capability digest fields are invalid"
            )
    if not isinstance(value.get("candidate_id"), str) or not re.fullmatch(
        r"release-candidate-(?:[0-9a-f]{40}|[0-9a-f]{64})",
        value["candidate_id"],
    ):
        raise NotificationQualificationError("capability candidate ID is invalid")
    issued = value.get("issued_at_unix_ms")
    deadline = value.get("deadline_unix_ms")
    if (
        not isinstance(issued, int)
        or isinstance(issued, bool)
        or not isinstance(deadline, int)
        or isinstance(deadline, bool)
        or issued > now_unix_ms + 1_000
        or deadline <= now_unix_ms
        or deadline - issued != CAPABILITY_MAX_LIFETIME_MS
    ):
        raise NotificationQualificationError("capability deadline is invalid")
    for field in ("expected_uid", "expected_gid"):
        if (
            not isinstance(value.get(field), int)
            or isinstance(value[field], bool)
            or value[field] <= 0
        ):
            raise NotificationQualificationError("capability user identity is invalid")
    for field in ("home", "app_bundle", "executable"):
        if not isinstance(value.get(field), str) or not value[field].startswith("/"):
            raise NotificationQualificationError("capability path fields are invalid")
    return value


def finalize_root_capability(template: dict, *, pid: int, now_unix_ms: int) -> bytes:
    validated = validate_capability_template(template, now_unix_ms=now_unix_ms)
    if pid <= 1:
        raise NotificationQualificationError("capability process identity is invalid")
    capability = dict(validated)
    capability["expected_pid"] = pid
    return _canonical_json(capability)


def _privileged_capability_exec() -> int:
    if sys.platform != "darwin" or os.geteuid() != 0:
        raise NotificationQualificationError(
            "capability launcher must run as root on macOS"
        )
    template = _read_bounded_json(sys.stdin.buffer, label="capability template")
    now_unix_ms = time.time_ns() // 1_000_000
    capability = finalize_root_capability(
        template,
        pid=os.getpid(),
        now_unix_ms=now_unix_ms,
    )
    expected_uid = template["expected_uid"]
    expected_gid = template["expected_gid"]
    executable = Path(template["executable"])
    if _sha256(executable) != template["executable_sha256"]:
        raise NotificationQualificationError(
            "capability executable changed before privileged exec"
        )

    with tempfile.TemporaryFile(prefix="slipstream-notification-capability-") as stream:
        stream.write(capability)
        stream.flush()
        os.fsync(stream.fileno())
        stream.seek(0)
        metadata = os.fstat(stream.fileno())
        if (
            metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 0
        ):
            raise NotificationQualificationError(
                "root-owned unlinked capability invariant failed"
            )
        if stream.fileno() != CAPABILITY_FD:
            os.dup2(stream.fileno(), CAPABILITY_FD, inheritable=True)
        else:
            os.set_inheritable(CAPABILITY_FD, True)
        capability_sha256 = hashlib.sha256(capability).hexdigest()
        handshake = {
            "schema_version": SCHEMA_VERSION,
            "pid": os.getpid(),
            "capability_sha256": capability_sha256,
        }
        print(_canonical_json(handshake).decode("ascii"), flush=True)

        os.setgroups([expected_gid])
        os.setgid(expected_gid)
        os.setuid(expected_uid)
        environment = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": template["home"],
            "USER": str(expected_uid),
            "LOGNAME": str(expected_uid),
            "CI": "true",
            "GITHUB_ACTIONS": "true",
            "SLIPSTREAM_DISPOSABLE_CI": "1",
            HOOK_CAPABILITY_ENV: str(CAPABILITY_FD),
        }
        os.execve(
            str(executable),
            (str(executable), HOOK_ARGUMENT),
            environment,
        )
    raise AssertionError("privileged capability exec returned")


def _run_text(command: tuple[str, ...], *, timeout: float = 5.0) -> str:
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise NotificationQualificationError(
            "macOS visibility observation is unavailable"
        )
    return result.stdout


def _set_launch_services_registration(app_bundle: Path, *, register: bool) -> None:
    action = "-f" if register else "-u"
    result = subprocess.run(
        (LSREGISTER, action, str(app_bundle)),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        operation = "registration" if register else "cleanup"
        raise NotificationQualificationError(
            f"exact notification identity {operation} failed"
        )


def _frontmost_asn() -> str:
    frontmost = _run_text((LSAPPINFO, "front")).strip()
    if not frontmost.startswith("ASN:"):
        raise NotificationQualificationError(
            "frontmost application observation is unavailable"
        )
    return frontmost


def _launch_services_entries(
    listing: str,
    *,
    app_bundle: Path,
    executable: Path,
    pid: int | None,
) -> tuple[LaunchServicesEntry, ...]:
    entries: list[LaunchServicesEntry] = []
    for block in re.split(r"(?m)(?=^\s*\d+\) )", listing):
        lowered = block.lower()
        pid_match = re.search(r'\bpid"?\s*=\s*(\d+)', block, re.I)
        block_pid = int(pid_match.group(1)) if pid_match else None
        attributable = (
            BUNDLE_IDENTIFIER.lower() in lowered
            or str(app_bundle).lower() in lowered
            or str(executable).lower() in lowered
            or (pid is not None and block_pid == pid)
        )
        if not attributable:
            continue
        executable_match = re.search(
            r'executable path\s*=\s*"([^"]+)"', block, re.I
        )
        type_match = re.search(
            r'(?:applicationtype|type)"?\s*=\s*"([^"]+)"',
            block,
            re.I,
        )
        application_type = type_match.group(1) if type_match else None
        entries.append(
            LaunchServicesEntry(
                pid=block_pid,
                executable_path=(
                    executable_match.group(1) if executable_match else None
                ),
                application_type=application_type,
                dock_visible=(
                    application_type is not None
                    and application_type.lower() == "foreground"
                ),
            )
        )
    return tuple(entries)


def _window_ids(pid: int | None) -> frozenset[int]:
    core_graphics = ctypes.util.find_library("CoreGraphics")
    core_foundation = ctypes.util.find_library("CoreFoundation")
    if not core_graphics or not core_foundation:
        raise NotificationQualificationError(
            "CoreGraphics visibility API is unavailable"
        )
    cg = ctypes.CDLL(core_graphics)
    cf = ctypes.CDLL(core_foundation)
    cg.CGWindowListCopyWindowInfo.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    cg.CGWindowListCopyWindowInfo.restype = ctypes.c_void_p
    cf.CFArrayGetCount.argtypes = [ctypes.c_void_p]
    cf.CFArrayGetCount.restype = ctypes.c_long
    cf.CFArrayGetValueAtIndex.argtypes = [ctypes.c_void_p, ctypes.c_long]
    cf.CFArrayGetValueAtIndex.restype = ctypes.c_void_p
    cf.CFDictionaryGetValue.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    cf.CFDictionaryGetValue.restype = ctypes.c_void_p
    cf.CFStringCreateWithCString.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_uint32,
    ]
    cf.CFStringCreateWithCString.restype = ctypes.c_void_p
    cf.CFStringGetCString.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_long,
        ctypes.c_uint32,
    ]
    cf.CFStringGetCString.restype = ctypes.c_bool
    cf.CFNumberGetValue.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
    ]
    cf.CFNumberGetValue.restype = ctypes.c_bool
    cf.CFRelease.argtypes = [ctypes.c_void_p]

    def key(name: bytes) -> int:
        return cf.CFStringCreateWithCString(None, name, 0x08000100)

    owner_name_key = key(b"kCGWindowOwnerName")
    owner_pid_key = key(b"kCGWindowOwnerPID")
    number_key = key(b"kCGWindowNumber")
    windows = cg.CGWindowListCopyWindowInfo(0, 0)
    values = (owner_name_key, owner_pid_key, number_key, windows)
    if any(not value for value in values):
        for value in values:
            if value:
                cf.CFRelease(value)
        raise NotificationQualificationError("CoreGraphics snapshot failed")
    found: set[int] = set()
    try:
        for index in range(cf.CFArrayGetCount(windows)):
            entry = cf.CFArrayGetValueAtIndex(windows, index)
            owner_name = cf.CFDictionaryGetValue(entry, owner_name_key)
            owner_pid = cf.CFDictionaryGetValue(entry, owner_pid_key)
            number = cf.CFDictionaryGetValue(entry, number_key)
            if not owner_name or not owner_pid or not number:
                continue
            buffer = ctypes.create_string_buffer(512)
            if not cf.CFStringGetCString(
                owner_name, buffer, len(buffer), 0x08000100
            ):
                continue
            observed_pid = ctypes.c_int64()
            window_id = ctypes.c_int64()
            if not cf.CFNumberGetValue(owner_pid, 4, ctypes.byref(observed_pid)):
                continue
            if not cf.CFNumberGetValue(number, 4, ctypes.byref(window_id)):
                continue
            owner = buffer.value.decode("utf-8", "replace").lower()
            if "slipstream" in owner or (
                pid is not None and int(observed_pid.value) == pid
            ):
                found.add(int(window_id.value))
    finally:
        for value in values:
            cf.CFRelease(value)
    return frozenset(found)


def _visibility_snapshot(
    *, app_bundle: Path, executable: Path, pid: int | None
) -> VisibilitySnapshot:
    listing = _run_text((LSAPPINFO, "list"))
    return VisibilitySnapshot(
        frontmost_asn=_frontmost_asn(),
        window_ids=_window_ids(pid),
        launch_services_entries=_launch_services_entries(
            listing,
            app_bundle=app_bundle,
            executable=executable,
            pid=pid,
        ),
    )


class VisibilityMonitor:
    def __init__(self, *, app_bundle: Path, executable: Path) -> None:
        self.app_bundle = app_bundle
        self.executable = executable
        self.pid: int | None = None
        self.pid_lock = threading.Lock()
        self.before = _visibility_snapshot(
            app_bundle=app_bundle,
            executable=executable,
            pid=None,
        )
        if self.before.window_ids or self.before.launch_services_entries:
            raise NotificationQualificationError(
                "notification qualification requires a clean app baseline"
            )
        self.samples: list[VisibilitySnapshot] = []
        self.events: list[str] = []
        self.failure: BaseException | None = None
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.thread: threading.Thread | None = None
        self.listener: subprocess.Popen[str] | None = None

    def set_pid(self, pid: int) -> None:
        if pid <= 1:
            raise NotificationQualificationError("qualified PID is invalid")
        with self.pid_lock:
            if self.pid is not None:
                raise NotificationQualificationError("qualified PID changed")
            self.pid = pid

    def _pid(self) -> int | None:
        with self.pid_lock:
            return self.pid

    def start(self) -> None:
        self.listener = subprocess.Popen(
            (LSAPPINFO, "listen", "+all", "wait", "-duration", "30"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        time.sleep(0.1)
        if self.listener.poll() is not None:
            self.listener.communicate(timeout=5)
            raise NotificationQualificationError(
                "LaunchServices listener exited before qualification"
            )
        self.thread = threading.Thread(target=self._sample, daemon=True)
        self.thread.start()
        if not self.ready.wait(2):
            self.close()
            raise NotificationQualificationError(
                "visibility sampler did not start"
            )
        if self.failure is not None:
            self.close()
            raise NotificationQualificationError("visibility sampler failed")

    def _sample(self) -> None:
        try:
            while not self.stop.is_set():
                self.samples.append(
                    _visibility_snapshot(
                        app_bundle=self.app_bundle,
                        executable=self.executable,
                        pid=self._pid(),
                    )
                )
                self.ready.set()
                if self.stop.wait(VISIBILITY_SAMPLE_SECONDS):
                    break
        except BaseException as exc:
            self.failure = exc
            self.ready.set()

    def close(self) -> VisibilitySnapshot:
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=5)
            if self.thread.is_alive():
                raise NotificationQualificationError(
                    "visibility sampler survived cleanup"
                )
        if self.listener is not None:
            self.listener.terminate()
            try:
                output, _ = self.listener.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                self.listener.kill()
                output, _ = self.listener.communicate(timeout=5)
            self.events = output.splitlines()
        after = _visibility_snapshot(
            app_bundle=self.app_bundle,
            executable=self.executable,
            pid=self._pid(),
        )
        self.samples.append(after)
        if self.failure is not None:
            raise NotificationQualificationError(
                "visibility sampler failed"
            ) from self.failure
        return after

    def assert_invisible(self, after: VisibilitySnapshot) -> dict:
        if self.pid is None:
            raise NotificationQualificationError("qualified PID was not observed")
        if after.frontmost_asn != self.before.frontmost_asn or any(
            sample.frontmost_asn != self.before.frontmost_asn
            for sample in self.samples
        ):
            raise NotificationQualificationError(
                "notification changed the frontmost application"
            )
        if any(sample.window_ids for sample in self.samples):
            raise NotificationQualificationError(
                "notification qualification created an application window"
            )
        if any(
            entry.dock_visible
            for sample in self.samples
            for entry in sample.launch_services_entries
        ):
            raise NotificationQualificationError(
                "notification qualification exposed a Dock application"
            )
        if after.launch_services_entries:
            raise NotificationQualificationError(
                "notification qualification leaked LaunchServices state"
            )
        relevant_events = 0
        path_markers = (
            str(self.app_bundle).lower(),
            str(self.executable).lower(),
            BUNDLE_IDENTIFIER,
        )
        for event in self.events:
            lowered = event.lower()
            event_pid = re.search(r'\bpid"?\s*=\s*(\d+)', event, re.I)
            attributable = (
                event_pid is not None and int(event_pid.group(1)) == self.pid
            ) or any(
                marker in lowered for marker in path_markers
            )
            if not attributable:
                continue
            relevant_events += 1
            if any(
                marker.lower() in lowered
                for marker in FORBIDDEN_LAUNCH_SERVICES_EVENTS
            ):
                raise NotificationQualificationError(
                    "notification qualification emitted a visible activation event"
                )
            if re.search(
                r'(?:applicationtype|type)"?\s*=\s*"foreground"',
                event,
                re.I,
            ):
                raise NotificationQualificationError(
                    "notification qualification became a foreground application"
                )
        return {
            "sample_count": len(self.samples),
            "launch_services_event_count": relevant_events,
            "window_count": 0,
            "dock_visible": False,
            "frontmost_unchanged": True,
        }


def _notification_record_snapshot(home: Path) -> NotificationRecordSnapshot:
    database = home / USERNOTED_DB_RELATIVE
    try:
        metadata = database.lstat()
    except FileNotFoundError:
        return NotificationRecordSnapshot(0, 0)
    if database.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise NotificationQualificationError("usernoted database path is unsafe")
    if metadata.st_uid != os.getuid():
        raise NotificationQualificationError("usernoted database owner mismatch")
    try:
        connection = sqlite3.connect(
            f"file:{database}?mode=ro",
            uri=True,
            timeout=0.5,
        )
        try:
            row = connection.execute(
                """
                SELECT COALESCE(MAX(record.rec_id), 0), COUNT(record.rec_id)
                  FROM record
                  JOIN app USING(app_id)
                 WHERE app.identifier = ?
                """,
                (BUNDLE_IDENTIFIER,),
            ).fetchone()
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise NotificationQualificationError(
            "usernoted attribution observation is unavailable"
        ) from exc
    if row is None or len(row) != 2:
        raise NotificationQualificationError(
            "usernoted attribution observation is invalid"
        )
    return NotificationRecordSnapshot(int(row[0]), int(row[1]))


def parse_hook_result(payload: str, *, capability_sha256: str) -> dict:
    if len(payload.encode("utf-8")) > 4_096:
        raise NotificationQualificationError("notification hook output is oversized")
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise NotificationQualificationError(
            "notification hook output is invalid"
        ) from exc
    if not isinstance(value, dict):
        raise NotificationQualificationError(
            "notification hook output must be an object"
        )
    common = {
        "schema_version",
        "outcome",
        "identity",
        "capability_sha256",
    }
    outcome = value.get("outcome")
    expected_keys = common | (
        {"reason"} if outcome == "terminal" else {"permission_status"}
    )
    if set(value) != expected_keys:
        raise NotificationQualificationError(
            "notification hook output fields are invalid"
        )
    if value.get("schema_version") != SCHEMA_VERSION:
        raise NotificationQualificationError(
            "notification hook schema is invalid"
        )
    if outcome not in OUTCOMES:
        raise NotificationQualificationError(
            "notification hook outcome is invalid"
        )
    if value.get("identity") != BUNDLE_IDENTIFIER:
        raise NotificationQualificationError(
            "notification hook identity is invalid"
        )
    if value.get("capability_sha256") != capability_sha256:
        raise NotificationQualificationError(
            "notification hook capability binding failed"
        )
    if outcome == "terminal" and value.get("reason") not in TERMINAL_REASONS:
        raise NotificationQualificationError(
            "notification hook terminal reason is invalid"
        )
    if outcome != "terminal" and value.get("permission_status") not in {
        "allowed",
        "suppressed",
        "unknown",
    }:
        raise NotificationQualificationError(
            "notification hook permission status is invalid"
        )
    return value


def _terminal_hook_failure(hook_result: dict) -> NotificationQualificationError:
    reason = hook_result.get("reason")
    if reason not in TERMINAL_REASONS:
        return NotificationQualificationError(
            "native notification hook returned an invalid terminal outcome",
            failure_code="hook_launch_failed",
        )
    return NotificationQualificationError(
        "native notification hook returned a terminal outcome",
        failure_code=reason,
    )


def classify_os_observation(
    *,
    hook_result: dict,
    before: NotificationRecordSnapshot,
    after: NotificationRecordSnapshot,
) -> str:
    delta = after.record_count - before.record_count
    new_record = (
        delta == 1 and after.maximum_record_id > before.maximum_record_id
    )
    outcome = hook_result["outcome"]
    if outcome == "terminal":
        raise _terminal_hook_failure(hook_result)
    if delta < 0 or delta > 1:
        raise NotificationQualificationError(
            "notification attribution count changed unexpectedly",
            failure_code="os_attribution_invalid",
        )
    if new_record:
        return "submitted"
    if outcome == "submitted" and hook_result.get("permission_status") == "suppressed":
        return "permission_suppressed"
    raise NotificationQualificationError(
        "macOS did not record exactly one attributed notification",
        failure_code="os_attribution_missing",
    )


def _readline_bounded(
    stream: BinaryIO, *, timeout: float, maximum: int, label: str
) -> bytes:
    ready, _, _ = select.select([stream], [], [], timeout)
    if not ready:
        raise NotificationQualificationError(f"{label} timed out")
    line = stream.readline(maximum + 1)
    if not line or len(line) > maximum or not line.endswith(b"\n"):
        raise NotificationQualificationError(f"{label} is invalid")
    return line


def _reap_hook_after_failure(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        try:
            process.kill()
        except (PermissionError, ProcessLookupError):
            # The capability launcher is root only until it drops privileges
            # and execs the packaged app.  If that short phase prevents a
            # direct signal, its exact 30-second capability deadline still
            # bounds the process; keep observing it instead of abandoning it.
            pass
    try:
        process.communicate(
            timeout=(CAPABILITY_MAX_LIFETIME_MS / 1_000) + 5
        )
    except subprocess.TimeoutExpired as exc:
        raise NotificationQualificationError(
            "notification hook survived failed-launch cleanup",
            failure_code="hook_cleanup_failed",
        ) from exc


def _launch_hook(
    *,
    template: dict,
    monitor: VisibilityMonitor,
) -> tuple[dict, int]:
    command = (
        "/usr/bin/sudo",
        "-n",
        sys.executable,
        str(Path(__file__).resolve()),
        PRIVILEGED_MODE,
    )
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert process.stdin is not None
        assert process.stdout is not None
        process.stdin.write(_canonical_json(template))
        process.stdin.close()
        process.stdin = None
        handshake_line = _readline_bounded(
            process.stdout,
            timeout=5,
            maximum=1_024,
            label="privileged capability handshake",
        )
        try:
            handshake = json.loads(handshake_line)
        except json.JSONDecodeError as exc:
            raise NotificationQualificationError(
                "privileged capability handshake is invalid"
            ) from exc
        if (
            not isinstance(handshake, dict)
            or set(handshake)
            != {"schema_version", "pid", "capability_sha256"}
            or handshake.get("schema_version") != SCHEMA_VERSION
            or not isinstance(handshake.get("pid"), int)
            or handshake["pid"] <= 1
            or not isinstance(handshake.get("capability_sha256"), str)
            or not HEX_64.fullmatch(handshake["capability_sha256"])
        ):
            raise NotificationQualificationError(
                "privileged capability handshake fields are invalid"
            )
        monitor.set_pid(handshake["pid"])
        try:
            stdout, _stderr = process.communicate(
                timeout=HOOK_TIMEOUT_SECONDS
            )
        except subprocess.TimeoutExpired as exc:
            raise NotificationQualificationError(
                "notification hook exceeded its deadline"
            ) from exc
        if process.returncode != 0:
            raise NotificationQualificationError("notification hook failed")
        lines = stdout.splitlines()
        if len(lines) != 1:
            raise NotificationQualificationError(
                "notification hook emitted unexpected output"
            )
        result = parse_hook_result(
            lines[0].decode("utf-8", "strict"),
            capability_sha256=handshake["capability_sha256"],
        )
        return result, handshake["pid"]
    except BaseException as exc:
        try:
            _reap_hook_after_failure(process)
        except BaseException as cleanup_exc:
            raise _with_failure_code(
                cleanup_exc,
                failure_code="hook_cleanup_failed",
                message="notification hook cleanup failed",
            ) from exc
        raise _with_failure_code(
            exc,
            failure_code="hook_launch_failed",
            message="notification hook launch failed",
        ) from exc


def run_gate(
    *,
    candidate_dir: Path,
    app_bundle: Path,
    repository: str,
    source_commit: str,
    candidate_run_id: int,
    candidate_run_attempt: int,
) -> dict:
    _require_disposable_macos_ci()
    identity = _validated_candidate_identity(
        candidate_dir=candidate_dir,
        app_bundle=app_bundle,
        repository=repository,
        source_commit=source_commit,
        candidate_run_id=candidate_run_id,
        candidate_run_attempt=candidate_run_attempt,
    )
    try:
        _set_launch_services_registration(identity.app_bundle, register=True)
        home = Path.home().resolve(strict=True)
        uid = os.getuid()
        gid = os.getgid()
        nonce = os.urandom(32).hex()
        template = build_capability_template(
            identity,
            uid=uid,
            gid=gid,
            home=home,
            nonce=nonce,
            issued_at_unix_ms=time.time_ns() // 1_000_000,
        )
        before = _notification_record_snapshot(home)
        monitor = VisibilityMonitor(
            app_bundle=identity.app_bundle,
            executable=identity.executable,
        )
        monitor.start()
        failure: BaseException | None = None
        hook_result: dict | None = None
        after_records = before
        try:
            hook_result, _ = _launch_hook(template=template, monitor=monitor)
            if hook_result["outcome"] == "terminal":
                raise _terminal_hook_failure(hook_result)
            deadline = time.monotonic() + OS_OBSERVATION_TIMEOUT_SECONDS
            while time.monotonic() < deadline:
                after_records = _notification_record_snapshot(home)
                if after_records.record_count - before.record_count == 1:
                    break
                time.sleep(0.1)
        except BaseException as exc:
            failure = _with_failure_code(
                exc,
                failure_code="os_observation_failed",
                message="notification OS observation failed",
            )
        finally:
            try:
                visibility_after = monitor.close()
                visibility = monitor.assert_invisible(visibility_after)
            except BaseException as exc:
                if failure is None:
                    failure = _with_failure_code(
                        exc,
                        failure_code="visibility_violation",
                        message="notification visibility invariant failed",
                    )
        if failure is not None:
            raise failure
        if hook_result is None:
            raise NotificationQualificationError(
                "notification hook produced no result",
                failure_code="hook_launch_failed",
            )
        outcome = classify_os_observation(
            hook_result=hook_result,
            before=before,
            after=after_records,
        )
    finally:
        _set_launch_services_registration(identity.app_bundle, register=False)
    return {
        "schema_version": SCHEMA_VERSION,
        "candidate_id": identity.candidate_id,
        "candidate_manifest_sha256": identity.manifest_sha256,
        "app_tree_sha256": identity.app_tree_sha256,
        "executable_sha256": identity.executable_sha256,
        "notification": {
            "identity": BUNDLE_IDENTIFIER,
            "outcome": outcome,
            "permission_status": hook_result["permission_status"],
            "capability_sha256": hook_result["capability_sha256"],
            "os_attributed_record_delta": (
                after_records.record_count - before.record_count
            ),
            "visible_display_claimed": False,
        },
        "visibility": visibility,
    }


def _main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == PRIVILEGED_MODE:
        try:
            return _privileged_capability_exec()
        except Exception:
            print(
                json.dumps(
                    {"schema_version": SCHEMA_VERSION, "outcome": "terminal"}
                ),
                file=sys.stderr,
            )
            return 1

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--app-bundle", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--candidate-run-id", type=int, required=True)
    parser.add_argument("--candidate-run-attempt", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = run_gate(
            candidate_dir=args.candidate_dir,
            app_bundle=args.app_bundle,
            repository=args.repository,
            source_commit=args.source_commit,
            candidate_run_id=args.candidate_run_id,
            candidate_run_attempt=args.candidate_run_attempt,
        )
        release_candidate._write_json(args.output, report)
    except Exception as exc:
        failure_report = _failure_report(exc)
        try:
            release_candidate._write_json(args.output, failure_report)
        except Exception:
            pass
        print(json.dumps(failure_report, sort_keys=True), file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "outcome": report["notification"]["outcome"],
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
