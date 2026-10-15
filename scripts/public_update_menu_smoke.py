#!/usr/bin/env python3
"""Inspect the real public .23 tray on a disposable hosted Mac; never update it."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
OLD_COMMIT = "6ba71ef75d821ee74cedcee5d8a9c83495da7c76"
VERSION = "0.1.9-preview.23"
ARCHIVE_SIZE = 152132503
ARCHIVE_SHA256 = "1eef5ce070a6bd96f2c077493dbff4e3b9fe84b4f7e823143b1f21bf630a6883"
PUBLIC = "https://github.com/aiwaki/slipstream/releases/download/v" + VERSION
APP = Path("/Applications/Slipstream.app")
TRAY = APP / "Contents/MacOS/slipstream"
BUNDLED_DAEMON = APP / "Contents/Resources/slipstreamd/slipstreamd"
INSTALLED_DAEMON = Path("/usr/local/slipstream/slipstreamd")
PLIST = Path("/Library/LaunchDaemons/dev.slipstream.tproxy.plist")
STATUS = Path("/var/run/slipstream.status")
JOB = "system/dev.slipstream.tproxy"
BASELINE_PATHS = (APP, Path("/usr/local/slipstream"), PLIST, STATUS,
                  Path("/var/run/slipstream.status.tmp"), Path("/var/run/slipstream.pid"),
                  Path("/var/run/slipstream-pf.token"), Path("/var/run/slipstream-pf-lo0-skip.json"),
                  Path("/Library/Application Support/dev.slipstream.tray"))


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def process_path(pid: int) -> str:
    lib = ctypes.CDLL("/usr/lib/libproc.dylib")
    lib.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    lib.proc_pidpath.restype = ctypes.c_int
    buf = ctypes.create_string_buffer(4096)
    if lib.proc_pidpath(pid, buf, len(buf)) <= 0:
        raise RuntimeError("process_identity_unavailable")
    return os.fsdecode(buf.value)


def run(output: Path) -> dict:
    report = {"schema_version": 1, "scope": "public_23_menu_only", "status": "blocked",
              "pair_qualified": False, "public_pair_qualified": False,
              "update_activated": False, "source_commit": os.environ.get("GITHUB_SHA"),
              "run_id": os.environ.get("GITHUB_RUN_ID"), "cleanup_errors": []}
    if not (sys.platform == "darwin" and os.environ.get("CI") == "true"
            and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("SLIPSTREAM_DISPOSABLE_CI") == "1"
            and os.environ.get("RUNNER_OS") == "macOS"):
        raise RuntimeError("requires_disposable_hosted_mac")
    uid = os.getuid()
    if uid == 0 or os.stat("/dev/console").st_uid != uid:
        raise RuntimeError("requires_nonroot_console_user")
    temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    output = output.resolve()
    if temp not in output.parents or output.exists():
        raise RuntimeError("output_must_be_new_directory_under_RUNNER_TEMP")
    output.mkdir(mode=0o700)
    env = {key: os.environ[key] for key in ("HOME", "USER", "LOGNAME", "TMPDIR", "LANG")
           if key in os.environ}
    env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
    helper_env = dict(env)
    helper_env.update({key: os.environ[key] for key in (
        "CI", "GITHUB_ACTIONS", "SLIPSTREAM_DISPOSABLE_CI", "RUNNER_OS",
        "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT") if key in os.environ})
    # Neither app nor daemon receives GH_TOKEN, Geph credentials, or test switches.
    started = time.monotonic()
    deadline = started + 480
    cleanup = False
    app_process = None
    created_app = None
    install_attempted = False
    daemon_hash = None
    stage = "preflight"

    def command(label: str, args: list[str], *, timeout: float = 30,
                check: bool = True, hosted_helper: bool = False) -> subprocess.CompletedProcess:
        remaining = deadline - time.monotonic() - (0 if cleanup else 60)
        if remaining <= 0:
            raise TimeoutError("eight_minute_budget")
        result = subprocess.run(args, cwd=ROOT, env=helper_env if hosted_helper else env, capture_output=True,
                                timeout=min(timeout, remaining))
        # Persist only bounded tails, with private permissions; never print child logs.
        path = output / (label + ".log")
        with path.open("xb") as stream:
            stream.write((result.stdout + result.stderr)[-16384:])
        path.chmod(0o600)
        if check and result.returncode:
            raise RuntimeError(label + "_failed")
        return result

    def installed_identity(label: str) -> None:
        digest = command(label, ["/usr/bin/sudo", "-n", "/usr/bin/shasum", "-a", "256",
                                 str(INSTALLED_DAEMON)]).stdout.decode().split()[0]
        if digest != daemon_hash:
            raise RuntimeError("installed_daemon_hash_mismatch")

    def healthy(label: str) -> dict:
        until = min(time.monotonic() + 75, deadline - 60)
        while time.monotonic() < until:
            try:
                if STATUS.stat().st_size > 1024 * 1024:
                    raise RuntimeError("oversized_status")
                value = json.loads(STATUS.read_text())
                daemon = value["daemon"] if value.get("schema_version") == 2 else value
                age = time.time() - float(daemon.get("updated_at", daemon.get("ts", 0)))
                pid = int(daemon.get("pid", 0))
                if daemon.get("state") == "active" and 0 <= age < 15 and pid > 1:
                    installed_identity(label + "-hash")
                    data = plistlib.loads(PLIST.read_bytes())
                    if data.get("ProgramArguments", [])[:1] != [str(INSTALLED_DAEMON)]:
                        raise RuntimeError("launchd_program_mismatch")
                    state = command(label + "-launchd", ["/bin/launchctl", "print", JOB]).stdout.decode()
                    if not re.search(r"^\s*pid = " + str(pid) + r"\s*$", state, re.M):
                        raise RuntimeError("status_launchd_pid_mismatch")
                    return {"pid": pid, "state": "active", "updated_at": daemon.get("updated_at", daemon.get("ts")),
                            "heartbeat_seq": daemon.get("heartbeat_seq"), "version": daemon.get("version"),
                            "installed_daemon_sha256": daemon_hash}
            except (OSError, ValueError, KeyError):
                pass
            time.sleep(0.5)
        raise RuntimeError("owned_daemon_not_healthy")

    def interrupted(signum, _frame):
        raise RuntimeError("interrupted_signal_" + str(signum))

    previous_term = signal.signal(signal.SIGTERM, interrupted)
    try:
        for path in BASELINE_PATHS:
            if os.path.lexists(path):
                raise RuntimeError("preexisting_owned_path:" + str(path))
        job = command("baseline-launchd", ["/bin/launchctl", "print", JOB], check=False)
        if job.returncode == 0 or b"could not find service" not in (job.stdout + job.stderr).lower():
            raise RuntimeError("daemon_absence_unproven")
        processes = command("baseline-processes", ["/usr/bin/pgrep", "-x", "slipstream(d)?"], check=False)
        if processes.returncode != 1:
            raise RuntimeError("preexisting_slipstream_process_or_probe_failure")
        command("console-bootstrap", ["/bin/launchctl", "print", f"gui/{uid}"])
        command("sudo-preflight", ["/usr/bin/sudo", "-n", "/usr/bin/true"])
        stage = "download_and_verify_public_23"
        archive = output / "Slipstream.app.tar.gz"
        signature = output / "Slipstream.app.tar.gz.sig"
        for name, path, limit in (("archive", archive, ARCHIVE_SIZE), ("signature", signature, 65536)):
            command("download-" + name, ["/usr/bin/curl", "--fail", "--silent", "--show-error",
                    "--location", "--proto", "=https", "--proto-redir", "=https", "--connect-timeout", "15",
                    "--max-time", "150", "--max-filesize", str(limit), "--output", str(path),
                    PUBLIC + "/" + path.name], timeout=155)
            path.chmod(0o600)
        if archive.stat().st_size != ARCHIVE_SIZE or sha256(archive) != ARCHIVE_SHA256:
            raise RuntimeError("public_archive_pin_mismatch")
        config = output / "old-tauri.conf.json"
        config.write_bytes(command("old-source-config", ["/usr/bin/git", "show",
                           OLD_COMMIT + ":app-tauri/src-tauri/tauri.conf.json"]).stdout)
        proof_result = command("verify-updater", [sys.executable, str(ROOT / "scripts/verify_updater_artifacts.py"),
                               "--release-dir", str(output), "--version", VERSION,
                               "--tauri-config", str(config)], timeout=60)
        proof = json.loads(proof_result.stdout)
        if proof.get("verified") is not True or proof["archive"]["sha256"] != ARCHIVE_SHA256:
            raise RuntimeError("canonical_verification_failed")
        report["public_archive"] = {"size": ARCHIVE_SIZE, "sha256": ARCHIVE_SHA256,
                                    "config_commit": OLD_COMMIT, "signature_verified": True}
        stage = "extract_public_bundle"
        APP.mkdir()  # Atomic exclusive claim: never replace a pre-existing installation.
        created_app = (APP.stat().st_dev, APP.stat().st_ino)
        command("extract", ["/usr/bin/tar", "-xpf", str(archive), "-C", "/Applications"], timeout=45)
        if APP.stat().st_uid != uid or sha256(TRAY) != proof["archive"]["executable_sha256"]:
            raise RuntimeError("extracted_bundle_identity_mismatch")
        # tar preserves the verified archive modes; no chmod/content/signature repair.
        daemon_hash = sha256(BUNDLED_DAEMON)
        report["tray_sha256"] = proof["archive"]["executable_sha256"]
        report["bundled_daemon_sha256"] = daemon_hash
        stage = "install_exact_23_daemon"
        install_attempted = True
        command("install", ["/usr/bin/sudo", "-n", str(BUNDLED_DAEMON), "--install"], timeout=90)
        report["daemon_before_launch"] = healthy("before-launch")
        stage = "launch_public_23"
        app_process = subprocess.Popen([str(TRAY)], cwd=APP.parent, env=env,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        report["app_pid"] = app_process.pid
        time.sleep(3)
        if app_process.poll() is not None or process_path(app_process.pid) != str(TRAY):
            raise RuntimeError("public_app_did_not_remain_alive")
        report["daemon_with_app"] = healthy("with-app")
        stage = "inspect_actual_menu"
        ax = [sys.executable, str(ROOT / "scripts/public_update_ax.py"), "--pid", str(app_process.pid),
              "--uid", str(uid), "--executable", str(TRAY), "--exe-sha256", report["tray_sha256"]]
        command("ax-inspect", ax + ["--output", str(output / "ax-inspect.json")],
                timeout=30, hosted_helper=True)
        command("ax-open-menu", ax + ["--output", str(output / "ax-open-menu.json"), "--open-menu"],
                timeout=30, hosted_helper=True)
        menu = json.loads((output / "ax-open-menu.json").read_text())
        if menu.get("owned_menu_present") is not True:
            raise RuntimeError("actual_owned_menu_not_proven")
        report.update(status="passed", owned_menu_present=True)
        report["daemon_before_cleanup"] = healthy("before-cleanup")
    except Exception as error:
        report.update(status="blocked", failed_stage=stage, error_type=type(error).__name__)
        if isinstance(error, RuntimeError):
            report["reason"] = str(error)
    finally:
        cleanup = True
        if app_process is not None and app_process.poll() is None:
            try:
                if process_path(app_process.pid) != str(TRAY) or sha256(TRAY) != report["tray_sha256"]:
                    raise RuntimeError("refusing_unowned_app_signal")
                app_process.terminate()
                try:
                    app_process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    if process_path(app_process.pid) != str(TRAY):
                        raise RuntimeError("refusing_replaced_app_signal")
                    app_process.kill()
                    app_process.wait(timeout=3)
            except Exception as error:
                report["cleanup_errors"].append("app:" + type(error).__name__)
        if install_attempted:
            try:
                if STATUS.exists() and STATUS.stat().st_size <= 1024 * 1024:
                    value = json.loads(STATUS.read_text())
                    daemon = value["daemon"] if value.get("schema_version") == 2 else value
                    report["daemon_cleanup_snapshot"] = {key: daemon.get(key) for key in
                                                         ("pid", "state", "updated_at", "heartbeat_seq", "version")}
            except (OSError, ValueError, KeyError, AttributeError):
                report["daemon_cleanup_snapshot_unavailable"] = True
            try:
                present = command("cleanup-daemon-present", ["/usr/bin/sudo", "-n", "/usr/bin/test", "-f",
                                  str(INSTALLED_DAEMON)], timeout=3, check=False)
                if present.returncode == 0:
                    installed_identity("cleanup-daemon-hash")
                    report["installed_daemon_sha256_before_cleanup"] = daemon_hash
                    command("uninstall", ["/usr/bin/sudo", "-n", str(INSTALLED_DAEMON), "--uninstall"], timeout=40)
                elif present.returncode != 1:
                    raise RuntimeError("installed_daemon_presence_unproven")
                job = command("cleanup-launchd", ["/bin/launchctl", "print", JOB], timeout=3, check=False)
                if job.returncode == 0 or b"could not find service" not in (job.stdout + job.stderr).lower():
                    raise RuntimeError("cleanup_daemon_absence_unproven")
            except Exception as error:
                report["cleanup_errors"].append("daemon:" + type(error).__name__)
        if created_app is not None:
            try:
                if APP.is_symlink() or (APP.stat().st_dev, APP.stat().st_ino) != created_app:
                    raise RuntimeError("created_app_identity_changed")
                if app_process is not None and app_process.poll() is None:
                    raise RuntimeError("created_app_still_running")
                shutil.rmtree(APP)
            except Exception as error:
                report["cleanup_errors"].append("bundle:" + type(error).__name__)
        report["residue"] = [str(p) for p in BASELINE_PATHS if os.path.lexists(p)]
        if report["cleanup_errors"] or report["residue"]:
            report["status"] = "blocked"
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        (output / "evidence.json").write_text(json.dumps(report, indent=2) + "\n")
        (output / "evidence.json").chmod(0o600)
        signal.signal(signal.SIGTERM, previous_term)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = run(args.output_dir)
    except Exception as error:
        report = {"status": "blocked", "pair_qualified": False, "public_pair_qualified": False,
                  "error_type": type(error).__name__}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
