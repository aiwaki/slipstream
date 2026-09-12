#!/usr/bin/env python3
"""Verify one built macOS app and, optionally, its local installation.

This is the canonical read-only boundary between daemon staging, Tauri
packaging, and workstation installation.  It deliberately does not claim
notarization or Gatekeeper compatibility; Slipstream's current macOS builds
are ad-hoc signed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from release_candidate import deterministic_tree_sha256  # noqa: E402


BUNDLE_IDENTIFIER = "dev.slipstream.tray"
APP_EXECUTABLE = "slipstream"
INSTALL_ATTESTATION_SCHEMA = 3
INSTALL_ATTESTATION_MAX_BYTES = 4096
INSTALL_ATTESTATION_MODE = 0o644
INSTALLED_DAEMON = Path("/usr/local/slipstream/slipstreamd")
INSTALLED_DAEMON_MODE = 0o700
INSTALLED_BROWSER_WORKER = Path(
    "/Applications/Slipstream.app/Contents/MacOS/slipstream-browser-probe"
)
LAUNCHD_LABEL = "dev.slipstream.tproxy"
LAUNCHD_PLIST_MODE = 0o644
LAUNCHD_WORKING_DIRECTORY = Path("/usr/local/slipstream")
LAUNCHD_PATH = "/sbin:/usr/sbin:/bin:/usr/bin"
LISTENER_HOSTS = ["127.0.0.1", "::1"]
LISTENER_PORT = 1080
STATUS_SCHEMA = 2
STATUS_PATH = Path("/var/run/slipstream.status")
STATUS_MAX_BYTES = 64 * 1024
STATUS_MODE = 0o644
STATUS_STALE_AFTER_SECS = 6.0
STATUS_PHASES = frozenset(("starting", "active", "recovering", "stopping"))
STATUS_STABLE_PHASE = "active"
GUI_FRAMEWORKS = ("AppKit.framework", "Cocoa.framework", "WebKit.framework")


class VerificationError(RuntimeError):
    """A deterministic app, build-chain, or installation check failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def regular_file(path: Path, *, executable: bool = False) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise VerificationError(f"required file is unavailable: {path}: {error}") from error
    require(stat.S_ISREG(metadata.st_mode), f"required path is not a regular file: {path}")
    if executable:
        require(os.access(path, os.X_OK), f"required file is not executable: {path}")


def verify_console_browser_access(app: Path) -> None:
    """Require browser access that survives installing the bundle as root.

    The daemon drops to the console user's UID before launching the worker.
    Build-owner os.access alone accepts 0744, whose execute permission is lost
    after chown. Check every POSIX access class as well as the caller's actual
    access, both on the candidate and on the installed copy.
    """
    chromium_dir = app / "Contents/Resources/chromium-headless-shell"
    helper = app / "Contents/MacOS/slipstream-browser-probe"
    chromium = chromium_dir / "chrome-headless-shell"
    directories = (app, app / "Contents", helper.parent, chromium_dir.parent, chromium_dir)
    for directory in directories:
        safe_directory(directory, "console browser directory")
        require(
            directory.lstat().st_mode & 0o555 == 0o555
            and os.access(directory, os.R_OK | os.X_OK),
            f"console browser directory is not accessible after root installation: {directory}",
        )
    regular_file(helper)
    regular_file(chromium)
    for path in (helper, *sorted(chromium_dir.rglob("*"))):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            required_mode = 0o555
            access = os.R_OK | os.X_OK
        else:
            regular_file(path)
            executable = path in (helper, chromium) or bool(metadata.st_mode & 0o111)
            required_mode = 0o555 if executable else 0o444
            access = os.R_OK | os.X_OK if executable else os.R_OK
        require(
            metadata.st_mode & required_mode == required_mode and os.access(path, access),
            f"console browser runtime is not accessible after root installation: {path}",
        )


def file_sha256(path: Path) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise VerificationError(f"cannot open regular file safely: {path}: {error}") from error
    digest = hashlib.sha256()
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode), f"required path is not a regular file: {path}")
        size = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
        after = os.fstat(descriptor)
        require(
            size == before.st_size
            and (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ),
            f"file changed while it was hashed: {path}",
        )
        return digest.hexdigest()
    except OSError as error:
        raise VerificationError(f"cannot hash {path}: {error}") from error
    finally:
        os.close(descriptor)


def run_checked(arguments: Sequence[str], *, timeout: float = 30.0) -> str:
    try:
        completed = subprocess.run(
            list(arguments),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise VerificationError(f"command failed to run: {' '.join(arguments)}: {error}") from error
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise VerificationError(
            f"command failed ({completed.returncode}): {' '.join(arguments)}"
            + (f": {detail}" if detail else "")
        )
    return completed.stdout + completed.stderr


def safe_directory(path: Path, description: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise VerificationError(f"{description} is unavailable: {path}: {error}") from error
    require(stat.S_ISDIR(metadata.st_mode), f"{description} is not a directory: {path}")


def materialized_tree_sha256(root: Path) -> str:
    """Hash the tree after Tauri's intentional in-tree symlink materialization."""

    safe_directory(root, "daemon tree")
    with tempfile.TemporaryDirectory(prefix="slipstream-daemon-materialized-") as temporary:
        # Snapshot links as links first.  Validating the caller-owned tree and
        # following it in a later copy would leave a swap window between those
        # operations.  The private snapshot makes validation and materialization
        # operate on one immutable namespace.
        snapshot = Path(temporary) / "snapshot"
        materialized = Path(temporary) / "materialized"
        shutil.copytree(root, snapshot, symlinks=True)
        resolved_snapshot = snapshot.resolve()
        for path in snapshot.rglob("*"):
            if not path.is_symlink():
                continue
            try:
                target = path.resolve(strict=True)
                target.relative_to(resolved_snapshot)
            except (OSError, ValueError) as error:
                raise VerificationError(f"daemon tree contains an unsafe symlink: {path}") from error
        shutil.copytree(snapshot, materialized, symlinks=False)
        return deterministic_tree_sha256(materialized)


def load_plist(path: Path) -> dict[str, Any]:
    regular_file(path)
    try:
        with path.open("rb") as handle:
            value = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException) as error:
        raise VerificationError(f"invalid plist: {path}: {error}") from error
    require(isinstance(value, dict), f"plist root is not a dictionary: {path}")
    return value


def verify_codesign(path: Path, *, deep: bool) -> dict[str, Any]:
    arguments = ["/usr/bin/codesign", "--verify"]
    if deep:
        arguments.append("--deep")
    arguments.extend(("--strict", str(path)))
    run_checked(arguments)
    display = run_checked(("/usr/bin/codesign", "-dv", "--verbose=2", str(path)))
    signature = "adhoc" if "Signature=adhoc" in display else "identity"
    team_identifier = None
    for line in display.splitlines():
        if line.startswith("TeamIdentifier="):
            candidate = line.partition("=")[2]
            team_identifier = None if candidate == "not set" else candidate
            break
    return {"valid": True, "kind": signature, "team_identifier": team_identifier}


def verify_architecture(path: Path, architecture: str) -> None:
    regular_file(path, executable=True)
    run_checked(("/usr/bin/lipo", str(path), "-verify_arch", architecture))


def verify_non_gui_helper(path: Path, architecture: str) -> None:
    verify_architecture(path, architecture)
    verify_codesign(path, deep=False)
    linked = run_checked(("/usr/bin/otool", "-L", str(path)))
    forbidden = [framework for framework in GUI_FRAMEWORKS if framework in linked]
    require(not forbidden, f"non-GUI helper links GUI frameworks: {path}: {forbidden}")


def quarantine_value(path: Path) -> str | None:
    try:
        payload = os.getxattr(path, "com.apple.quarantine", follow_symlinks=False)
    except (AttributeError, OSError):
        return None
    return payload.decode("utf-8", errors="replace")


def verify_app_bundle(
    app: Path,
    *,
    expected_version: str,
    architecture: str,
) -> dict[str, Any]:
    safe_directory(app, "app bundle")
    contents = app / "Contents"
    plist = load_plist(contents / "Info.plist")
    require(plist.get("CFBundleIdentifier") == BUNDLE_IDENTIFIER, "unexpected bundle identifier")
    require(plist.get("CFBundleExecutable") == APP_EXECUTABLE, "unexpected app executable")
    require(
        plist.get("CFBundleShortVersionString") == expected_version,
        "app version does not match VERSION",
    )
    require(
        plist.get("CFBundleVersion") == expected_version,
        "app bundle build version does not match VERSION",
    )
    require(plist.get("LSUIElement") is True, "packaged app must remain an LSUIElement")

    main = contents / "MacOS" / APP_EXECUTABLE
    daemon = contents / "Resources" / "slipstreamd" / "slipstreamd"
    geph = contents / "MacOS" / "geph5-client"
    helper = contents / "MacOS" / "slipstream-browser-probe"
    watchdog = contents / "MacOS" / "slipstream-update-watchdog"
    chromium_dir = contents / "Resources" / "chromium-headless-shell"
    chromium = chromium_dir / "chrome-headless-shell"

    # Authenticate the complete app before any bundled executable is invoked.
    signature = verify_codesign(app, deep=True)
    verify_console_browser_access(app)
    for binary in (main, daemon, geph, chromium):
        verify_architecture(binary, architecture)
    verify_non_gui_helper(helper, architecture)
    verify_non_gui_helper(watchdog, architecture)
    regular_file(chromium_dir / "LICENSE.headless_shell")
    manifest_path = chromium_dir / "manifest.json"
    regular_file(manifest_path)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"invalid Chromium manifest: {error}") from error
    require(isinstance(manifest, dict), "Chromium manifest root must be an object")

    classifications = {
        "rr1---sn-test.googlevideo.com": {
            "host": "rr1---sn-test.googlevideo.com",
            "route_class": "direct_first",
            "service_group": "youtube_video",
            "strategy_set": "direct_first",
        },
        "www.youtube.com": {
            "host": "www.youtube.com",
            "route_class": "local_bypass",
            "service_group": "youtube_video",
            "strategy_set": "fake_only",
        },
    }
    for host, expected in classifications.items():
        output = run_checked((str(daemon), "--classify-host", host), timeout=10.0).strip()
        try:
            actual = json.loads(output)
        except json.JSONDecodeError as error:
            raise VerificationError(f"daemon returned invalid classification JSON for {host}") from error
        require(actual == expected, f"daemon classification invariant failed for {host}")

    critical = {
        "main": file_sha256(main),
        "daemon": file_sha256(daemon),
        "geph": file_sha256(geph),
        "browser_probe": file_sha256(helper),
        "update_watchdog": file_sha256(watchdog),
        "chromium": file_sha256(chromium),
    }
    return {
        "path": str(app.resolve()),
        "bundle_identifier": BUNDLE_IDENTIFIER,
        "version": expected_version,
        "bundle_version": plist["CFBundleVersion"],
        "tree_sha256": deterministic_tree_sha256(app),
        "signature": signature,
        "quarantine": quarantine_value(app),
        "critical_sha256": critical,
    }


def verify_build_chain(
    *,
    fresh_daemon: Path,
    staged_daemon: Path,
    bundled_daemon: Path,
) -> dict[str, Any]:
    for daemon in (fresh_daemon, staged_daemon, bundled_daemon):
        regular_file(daemon, executable=True)
    hashes = {
        "fresh": file_sha256(fresh_daemon),
        "staged": file_sha256(staged_daemon),
        "bundled": file_sha256(bundled_daemon),
    }
    require(len(set(hashes.values())) == 1, f"frozen daemon SHA-256 mismatch: {hashes}")

    fresh_tree = deterministic_tree_sha256(fresh_daemon.parent)
    staged_tree = deterministic_tree_sha256(staged_daemon.parent)
    require(fresh_tree == staged_tree, "fresh and staged daemon trees differ")
    expected_bundled_tree = materialized_tree_sha256(fresh_daemon.parent)
    bundled_tree = deterministic_tree_sha256(bundled_daemon.parent)
    require(
        expected_bundled_tree == bundled_tree,
        "bundled daemon tree differs from the materialized fresh PyInstaller tree",
    )
    return {
        "sha256": hashes["fresh"],
        "copies": hashes,
        "fresh_tree_sha256": fresh_tree,
        "staged_tree_sha256": staged_tree,
        "materialized_tree_sha256": expected_bundled_tree,
        "bundled_tree_sha256": bundled_tree,
    }


def _stable_regular_json_file(
    path: Path,
    *,
    description: str,
    expected_uid: int,
    expected_mode: int,
    max_bytes: int,
) -> tuple[dict[str, Any], os.stat_result]:
    try:
        before = path.lstat()
    except OSError as error:
        raise VerificationError(f"{description} is unavailable: {path}: {error}") from error
    require(stat.S_ISREG(before.st_mode), f"{description} is not a regular file")
    require(before.st_uid == expected_uid, f"{description} has the wrong owner")
    require(stat.S_IMODE(before.st_mode) == expected_mode, f"{description} has the wrong mode")
    require(before.st_size <= max_bytes, f"{description} is oversized")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise VerificationError(f"cannot open {description} safely: {error}") from error
    try:
        opened = os.fstat(descriptor)
        payload = os.read(descriptor, max_bytes + 1)
        after = os.fstat(descriptor)
    except OSError as error:
        raise VerificationError(f"cannot read {description}: {error}") from error
    finally:
        os.close(descriptor)
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
    require(identity(before) == identity(opened) == identity(after), f"{description} changed while read")
    require(len(payload) <= max_bytes, f"{description} is oversized")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"invalid {description} JSON: {error}") from error
    require(isinstance(value, dict), f"{description} root must be an object")
    return value, after


def _stable_regular_json(path: Path, *, expected_uid: int, expected_mode: int) -> dict[str, Any]:
    value, _metadata = _stable_regular_json_file(
        path,
        description="install attestation",
        expected_uid=expected_uid,
        expected_mode=expected_mode,
        max_bytes=INSTALL_ATTESTATION_MAX_BYTES,
    )
    return value


def _strict_int(
    value: Any,
    description: str,
    *,
    minimum: int = 0,
    maximum: int = (1 << 64) - 1,
) -> int:
    require(type(value) is int, f"{description} must be an integer")
    require(minimum <= value <= maximum, f"{description} is out of range")
    return value


def _strict_bool(value: Any, description: str) -> bool:
    require(type(value) is bool, f"{description} must be a boolean")
    return value


def _strict_string(value: Any, description: str) -> str:
    require(type(value) is str and bool(value), f"{description} must be a non-empty string")
    return value


def _strict_sha256(value: Any, description: str) -> str:
    digest = _strict_string(value, description)
    require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, f"{description} is not SHA-256")
    return digest


def _strict_number(value: Any, description: str) -> float:
    require(type(value) in (int, float), f"{description} must be numeric")
    numeric = float(value)
    require(math.isfinite(numeric), f"{description} must be finite")
    return numeric


def verify_install_attestation(
    *,
    attestation_path: Path,
    launchd_plist: Path,
    expected_daemon_sha256: str,
    expected_uid: int = 0,
    expected_browser_worker: Path = INSTALLED_BROWSER_WORKER,
) -> dict[str, Any]:
    evidence = _stable_regular_json(
        attestation_path,
        expected_uid=expected_uid,
        expected_mode=INSTALL_ATTESTATION_MODE,
    )
    daemon = evidence.get("daemon")
    witness = evidence.get("witness")
    launchd = evidence.get("launchd")
    listener = evidence.get("listener")
    require(isinstance(daemon, dict), "attestation daemon identity is missing")
    require(isinstance(witness, dict), "attestation witness identity is missing")
    require(isinstance(launchd, dict), "attestation launchd identity is missing")
    require(isinstance(listener, dict), "attestation listener identity is missing")
    schema_version = _strict_int(
        evidence.get("schema_version"),
        "attestation schema_version",
        maximum=(1 << 32) - 1,
    )
    require(schema_version == INSTALL_ATTESTATION_SCHEMA, "wrong attestation schema")
    source_sha256 = _strict_sha256(evidence.get("source_sha256"), "attested source hash")
    daemon_sha256 = _strict_sha256(daemon.get("sha256"), "attested daemon hash")
    require(source_sha256 == expected_daemon_sha256, "stale attested source hash")
    require(daemon_sha256 == expected_daemon_sha256, "stale attested daemon hash")
    require(
        _strict_string(daemon.get("path"), "installed daemon path") == str(INSTALLED_DAEMON),
        "wrong installed daemon path",
    )
    daemon_uid = _strict_int(daemon.get("uid"), "installed daemon uid", maximum=(1 << 32) - 1)
    daemon_gid = _strict_int(daemon.get("gid"), "installed daemon gid", maximum=(1 << 32) - 1)
    daemon_mode = _strict_int(daemon.get("mode"), "installed daemon mode", maximum=(1 << 32) - 1)
    require(daemon_uid == 0, "wrong installed daemon owner")
    require(daemon_gid == 0, "wrong installed daemon group")
    require(daemon_mode == INSTALLED_DAEMON_MODE, "wrong installed daemon mode")
    require(_strict_string(launchd.get("label"), "launchd label") == LAUNCHD_LABEL, "wrong launchd label")
    launchd_pid = _strict_int(launchd.get("pid"), "attested PID", minimum=1)
    require(
        _strict_string(listener.get("host"), "listener host") == LISTENER_HOSTS[0],
        "wrong listener host",
    )
    hosts = listener.get("hosts")
    require(type(hosts) is list, "listener hosts must be an array")
    for index, host in enumerate(hosts):
        _strict_string(host, f"listener hosts[{index}]")
    require(hosts == LISTENER_HOSTS, "wrong listener host set")
    listener_port = _strict_int(listener.get("port"), "listener port", maximum=65535)
    require(listener_port == LISTENER_PORT, "wrong listener port")
    attested_state = _strict_string(evidence.get("state"), "attested state")
    pf_active = _strict_bool(evidence.get("pf_active"), "attested PF state")
    require(
        (attested_state, pf_active) in (("active", True), ("dormant", False)),
        "invalid attested state/PF pair",
    )

    expected_witness = Path(f"{attestation_path}.daemon")
    require(
        _strict_string(witness.get("path"), "attestation witness path") == str(expected_witness),
        "wrong attestation witness path",
    )
    witness_fields = {
        "dev": _strict_int(witness.get("dev"), "witness dev"),
        "ino": _strict_int(witness.get("ino"), "witness ino"),
        "size": _strict_int(witness.get("size"), "witness size"),
        "mtime": _strict_int(
            witness.get("mtime"),
            "witness mtime",
            minimum=-(1 << 63),
            maximum=(1 << 63) - 1,
        ),
        "mtime_nsec": _strict_int(
            witness.get("mtime_nsec"),
            "witness mtime_nsec",
            maximum=999_999_999,
        ),
    }
    try:
        metadata = expected_witness.lstat()
    except OSError as error:
        raise VerificationError(f"attestation witness is unavailable: {error}") from error
    require(stat.S_ISREG(metadata.st_mode), "attestation witness is not a regular file")
    require(metadata.st_uid == expected_uid, "attestation witness has the wrong owner")
    require(stat.S_IMODE(metadata.st_mode) == daemon_mode, "attestation witness has the wrong mode")
    expected_metadata = {
        "dev": metadata.st_dev,
        "ino": metadata.st_ino,
        "size": metadata.st_size,
        "mtime": metadata.st_mtime_ns // 1_000_000_000,
        "mtime_nsec": metadata.st_mtime_ns % 1_000_000_000,
    }
    require(
        witness_fields == expected_metadata,
        "attestation witness metadata does not match",
    )
    require(metadata.st_nlink >= 2, "attestation witness is no longer hard-linked")

    try:
        launchd_metadata = launchd_plist.lstat()
    except OSError as error:
        raise VerificationError(f"LaunchDaemon plist is unavailable: {error}") from error
    require(stat.S_ISREG(launchd_metadata.st_mode), "LaunchDaemon plist is not a regular file")
    require(launchd_metadata.st_uid == expected_uid, "LaunchDaemon plist has the wrong owner")
    require(
        stat.S_IMODE(launchd_metadata.st_mode) == LAUNCHD_PLIST_MODE,
        "LaunchDaemon plist has the wrong mode",
    )
    plist = load_plist(launchd_plist)
    expected_plist_keys = {
        "Label",
        "ProgramArguments",
        "RunAtLoad",
        "KeepAlive",
        "EnvironmentVariables",
        "SoftResourceLimits",
        "HardResourceLimits",
        "WorkingDirectory",
        "StandardOutPath",
        "StandardErrorPath",
    }
    require(
        set(plist) == expected_plist_keys,
        "LaunchDaemon plist does not use the exact production key set",
    )
    require(plist.get("Label") == LAUNCHD_LABEL, "LaunchDaemon plist has the wrong label")
    arguments = plist.get("ProgramArguments")
    expected_arguments = [str(INSTALLED_DAEMON), "--port", str(LISTENER_PORT)]
    require(
        "Program" not in plist,
        "LaunchDaemon plist must not override the frozen production executable",
    )
    require(
        arguments == expected_arguments,
        "LaunchDaemon plist does not use the exact frozen production arguments",
    )
    require(plist.get("RunAtLoad") is True, "LaunchDaemon plist must run at load")
    require(plist.get("KeepAlive") is True, "LaunchDaemon plist must keep the daemon alive")
    require(
        plist.get("WorkingDirectory") == str(LAUNCHD_WORKING_DIRECTORY),
        "LaunchDaemon plist has the wrong working directory",
    )
    require(plist.get("StandardOutPath") == "/dev/null", "LaunchDaemon stdout must be /dev/null")
    require(plist.get("StandardErrorPath") == "/dev/null", "LaunchDaemon stderr must be /dev/null")
    require(
        plist.get("EnvironmentVariables")
        == {
            "PATH": LAUNCHD_PATH,
            "PYTHONUNBUFFERED": "1",
            "SLIPSTREAM_PENDING_NAVIGATION_BROWSER_WORKER": str(expected_browser_worker),
        },
        "LaunchDaemon plist has the wrong production environment",
    )
    for limit_name in ("SoftResourceLimits", "HardResourceLimits"):
        limits = plist.get(limit_name)
        require(type(limits) is dict, f"LaunchDaemon plist is missing {limit_name}")
        require(
            set(limits) == {"NumberOfFiles"},
            f"LaunchDaemon {limit_name} does not use the exact production key set",
        )
        number_of_files = _strict_int(
            limits.get("NumberOfFiles"),
            f"LaunchDaemon {limit_name} NumberOfFiles",
        )
        require(number_of_files == 16384, f"LaunchDaemon {limit_name} has the wrong file limit")
    return {
        "path": str(attestation_path),
        "schema_version": INSTALL_ATTESTATION_SCHEMA,
        "daemon_sha256": expected_daemon_sha256,
        "witness": "valid",
        "launchd_plist": str(launchd_plist),
        "launchd_pid": launchd_pid,
        "state": attested_state,
        "pf_active": pf_active,
    }


def verify_status_v2(
    *,
    status_path: Path,
    expected_pid: int,
    expected_uid: int = 0,
    now: float | None = None,
) -> dict[str, Any]:
    status, metadata = _stable_regular_json_file(
        status_path,
        description="StatusV2",
        expected_uid=expected_uid,
        expected_mode=STATUS_MODE,
        max_bytes=STATUS_MAX_BYTES,
    )
    observed_at = time.time() if now is None else now
    file_age = observed_at - metadata.st_mtime
    require(-1.0 <= file_age <= STATUS_STALE_AFTER_SECS, "StatusV2 heartbeat file is stale")
    schema_version = _strict_int(status.get("schema_version"), "StatusV2 schema_version")
    require(schema_version == STATUS_SCHEMA, "wrong StatusV2 schema")
    daemon = status.get("daemon")
    require(type(daemon) is dict, "StatusV2 daemon identity is missing")
    daemon_pid = _strict_int(daemon.get("pid"), "StatusV2 daemon PID", minimum=1)
    require(daemon_pid == expected_pid, "StatusV2 PID does not match the attested launchd PID")
    state = _strict_string(daemon.get("state"), "StatusV2 daemon state")
    require(state in ("active", "dormant"), "StatusV2 daemon is not in a healthy installed state")
    phase = _strict_string(daemon.get("phase"), "StatusV2 daemon phase")
    require(phase in STATUS_PHASES, "StatusV2 daemon phase is invalid")
    require(phase == STATUS_STABLE_PHASE, "StatusV2 daemon is not in its stable phase")
    heartbeat_seq = _strict_int(
        daemon.get("heartbeat_seq"),
        "StatusV2 heartbeat_seq",
        minimum=1,
    )
    _strict_string(daemon.get("heartbeat_at"), "StatusV2 heartbeat_at")
    updated_at = _strict_number(daemon.get("updated_at"), "StatusV2 updated_at")
    status_age = observed_at - updated_at
    require(-1.0 <= status_age <= STATUS_STALE_AFTER_SECS, "StatusV2 daemon heartbeat is stale")

    environment = status.get("environment")
    require(type(environment) is dict, "StatusV2 environment is missing")
    pf = environment.get("pf")
    require(type(pf) is dict, "StatusV2 PF state is missing")
    applied = _strict_bool(pf.get("applied"), "StatusV2 PF applied")
    enabled = _strict_bool(pf.get("enabled"), "StatusV2 PF enabled")
    rules_loaded = _strict_bool(pf.get("rules_loaded"), "StatusV2 PF rules_loaded")
    require(rules_loaded == (state == "active"), "StatusV2 PF rules do not match daemon state")
    if state == "active":
        require(applied, "StatusV2 active daemon has not applied PF")
        require(enabled, "StatusV2 active daemon reports PF disabled")
    return {
        "path": str(status_path),
        "schema_version": schema_version,
        "pid": daemon_pid,
        "state": state,
        "phase": phase,
        "heartbeat_seq": heartbeat_seq,
        "file_age_seconds": round(file_age, 3),
        "status_age_seconds": round(status_age, 3),
        "pf": {
            "applied": applied,
            "enabled": enabled,
            "rules_loaded": rules_loaded,
        },
    }


def _validate_launchctl_envelope(payload: str) -> None:
    lines = payload.splitlines()
    nonempty_indexes = [index for index, line in enumerate(lines) if line.strip()]
    require(bool(nonempty_indexes), "launchctl output is empty")
    first = nonempty_indexes[0]
    last = nonempty_indexes[-1]
    require(
        lines[first].strip() == f"system/{LAUNCHD_LABEL} = {{",
        "launchctl reported the wrong service target",
    )
    depth = 0
    for index in nonempty_indexes:
        stripped = lines[index].strip()
        if re.fullmatch(r".+ = \{", stripped) is not None:
            depth += 1
            continue
        if stripped == "}":
            depth -= 1
            require(depth >= 0, "launchctl output has an unexpected closing block")
            if depth == 0:
                require(index == last, "launchctl output continues after the service block")
            continue
        require(depth > 0, "launchctl output contains data outside the service block")
    require(depth == 0, "launchctl output has an incomplete service block")


def _launchctl_first_scalar(payload: str, name: str) -> str:
    pattern = re.compile(rf"^\s*{re.escape(name)} = (.+?)\s*$")
    matches: list[str] = []
    depth = 0
    for line in payload.splitlines():
        stripped = line.strip()
        if stripped == "}":
            depth -= 1
            continue
        if depth == 1 and (match := pattern.match(line)) is not None:
            matches.append(match.group(1))
        if re.fullmatch(r".+ = \{", stripped) is not None:
            depth += 1
    require(len(matches) == 1, f"launchctl output must contain exactly one {name}")
    return matches[0]


def _launchctl_first_block(payload: str, name: str) -> list[str]:
    start = re.compile(rf"^\s*{re.escape(name)} = \{{\s*$")
    lines = payload.splitlines()
    starts: list[int] = []
    depth = 0
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped == "}":
            depth -= 1
            continue
        if depth == 1 and start.match(line) is not None:
            starts.append(index)
        if re.fullmatch(r".+ = \{", stripped) is not None:
            depth += 1
    require(len(starts) == 1, f"launchctl output must contain exactly one {name} block")
    values: list[str] = []
    for candidate in lines[starts[0] + 1 :]:
        stripped = candidate.strip()
        if stripped == "}":
            return values
        require("{" not in stripped, f"launchctl {name} block is nested unexpectedly")
        if stripped:
            values.append(stripped)
    raise VerificationError(f"launchctl output has an incomplete {name} block")


def parse_launchctl_print(payload: str, *, expected_pid: int) -> dict[str, Any]:
    _validate_launchctl_envelope(payload)
    program = _launchctl_first_scalar(payload, "program")
    require(program == str(INSTALLED_DAEMON), "launchctl is running the wrong daemon program")
    arguments = _launchctl_first_block(payload, "arguments")
    require(
        arguments == [str(INSTALLED_DAEMON), "--port", str(LISTENER_PORT)],
        "launchctl is running the wrong daemon arguments",
    )
    pid_text = _launchctl_first_scalar(payload, "pid")
    require(re.fullmatch(r"[1-9][0-9]*", pid_text) is not None, "launchctl reported an invalid PID")
    pid = int(pid_text)
    require(pid == expected_pid, "launchctl PID does not match the attested PID")
    state = _launchctl_first_scalar(payload, "state")
    require(state == "running", "launchctl service is not running")
    require(_launchctl_first_scalar(payload, "job state") == "running", "launchctl job is not running")
    require(
        _launchctl_first_scalar(payload, "working directory") == str(LAUNCHD_WORKING_DIRECTORY),
        "launchctl is using the wrong working directory",
    )
    return {
        "target": f"system/{LAUNCHD_LABEL}",
        "program": program,
        "arguments": arguments,
        "pid": pid,
        "state": state,
    }


def verify_live_launchd(*, expected_pid: int) -> dict[str, Any]:
    payload = run_checked(
        ("/bin/launchctl", "print", f"system/{LAUNCHD_LABEL}"),
        timeout=10.0,
    )
    return parse_launchctl_print(payload, expected_pid=expected_pid)


def verify_installed_app(
    *,
    built_report: dict[str, Any],
    installed_app: Path,
    attestation_path: Path,
    launchd_plist: Path,
    status_path: Path,
) -> dict[str, Any]:
    safe_directory(installed_app, "installed app bundle")
    verify_console_browser_access(installed_app)
    installed_tree = deterministic_tree_sha256(installed_app)
    require(installed_tree == built_report["tree_sha256"], "installed app tree differs from built app")
    installed_daemon = installed_app / "Contents/Resources/slipstreamd/slipstreamd"
    installed_daemon_sha256 = file_sha256(installed_daemon)
    expected_daemon_sha256 = built_report["critical_sha256"]["daemon"]
    require(installed_daemon_sha256 == expected_daemon_sha256, "installed app embeds another daemon")
    signature = verify_codesign(installed_app, deep=True)
    attestation = verify_install_attestation(
        attestation_path=attestation_path,
        launchd_plist=launchd_plist,
        expected_daemon_sha256=expected_daemon_sha256,
        expected_browser_worker=installed_app / "Contents/MacOS/slipstream-browser-probe",
    )
    status_v2 = verify_status_v2(
        status_path=status_path,
        expected_pid=attestation["launchd_pid"],
    )
    launchd_live = verify_live_launchd(expected_pid=attestation["launchd_pid"])
    return {
        "path": str(installed_app.resolve()),
        "tree_sha256": installed_tree,
        "signature": signature,
        "attestation": attestation,
        "status_v2": status_v2,
        "launchd_live": launchd_live,
        "privileged_runtime_checks": {
            "status": "not_run",
            "checks": [
                "installed_daemon_path_hash",
                "listener_owner",
                "pf_kernel_state",
                "pf_anchor_rules",
            ],
        },
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-bundle", required=True, type=Path)
    parser.add_argument("--fresh-daemon", type=Path)
    parser.add_argument("--staged-daemon", type=Path)
    parser.add_argument("--installed-app", type=Path)
    parser.add_argument(
        "--install-attestation",
        type=Path,
        default=Path("/Library/Application Support/dev.slipstream.tray/install-attestation.json"),
    )
    parser.add_argument(
        "--launchd-plist",
        type=Path,
        default=Path("/Library/LaunchDaemons/dev.slipstream.tproxy.plist"),
    )
    parser.add_argument("--status-path", type=Path, default=STATUS_PATH)
    parser.add_argument("--expected-version", default=(ROOT / "VERSION").read_text().strip())
    parser.add_argument("--architecture", default="arm64")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv)
    if (arguments.fresh_daemon is None) != (arguments.staged_daemon is None):
        raise VerificationError("--fresh-daemon and --staged-daemon must be supplied together")

    app = arguments.app_bundle.absolute()
    build_chain: dict[str, Any] = {"status": "not_run"}
    coverage: list[str] = []
    if arguments.fresh_daemon is not None:
        build_chain = {
            "status": "pass",
            **verify_build_chain(
                fresh_daemon=arguments.fresh_daemon.absolute(),
                staged_daemon=arguments.staged_daemon.absolute(),
                bundled_daemon=app / "Contents/Resources/slipstreamd/slipstreamd",
            ),
        }
        coverage.append("build-chain")
    artifact = verify_app_bundle(
        app,
        expected_version=arguments.expected_version,
        architecture=arguments.architecture,
    )
    if arguments.fresh_daemon is not None:
        require(
            build_chain["sha256"] == artifact["critical_sha256"]["daemon"],
            "verified build-chain daemon differs from the verified app daemon",
        )
    coverage.append("artifact")
    report: dict[str, Any] = {
        "schema_version": 1,
        "overall": "pass",
        "coverage": coverage,
        "artifact": artifact,
        "build_chain": build_chain,
        "installed": {"status": "not_run"},
    }
    if arguments.installed_app is not None:
        report["installed"] = {
            "status": "pass",
            **verify_installed_app(
                built_report=artifact,
                installed_app=arguments.installed_app.absolute(),
                attestation_path=arguments.install_attestation,
                launchd_plist=arguments.launchd_plist,
                status_path=arguments.status_path,
            ),
        }
        report["coverage"].append("installed-unprivileged")

    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(json.dumps({"schema_version": 1, "overall": "fail", "error": str(error)}))
        raise SystemExit(1)
