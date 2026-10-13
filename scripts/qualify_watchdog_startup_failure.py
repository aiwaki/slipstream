#!/usr/bin/env python3
"""Exercise the packaged candidate watchdog against disposable startup fixtures.

This is helper-process coverage, not signed feed, launchd or real tray coverage.
Never run on a workstation: the helper's terminal cleanup invokes launchctl.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import time

from packaged_update_transaction_smoke import guard, require


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_case(root: Path, source: Path, case: str) -> dict:
    work = Path(tempfile.mkdtemp(prefix=f"watchdog-{case}-", dir=root)).resolve()
    state = work / "state"
    runtime = state / "runtime"
    runtime.mkdir(parents=True, mode=0o700)
    state.chmod(0o700)
    helper = runtime / "slipstream-update-watchdog"
    shutil.copy2(source, helper)
    require(digest(helper) == digest(source), "copied helper differs from packaged candidate")
    nonce = os.urandom(16).hex()
    target = work / "Slipstream.app"
    backup = work / f".Slipstream.app.slipstream-backup-{nonce}"
    stage = work / f".Slipstream.app.slipstream-stage-{nonce}"
    current = target / "Contents/MacOS/slipstream"
    old = backup / "Contents/MacOS/slipstream"
    current.parent.mkdir(parents=True)
    old.parent.mkdir(parents=True)
    marker = work / "old-relaunched"
    old.write_text(f"#!/bin/sh\nprintf 'restored\\n' >> {shlex.quote(str(marker))}\n")
    old.chmod(0o700)
    current.write_text("#!/bin/sh\nexit 1\n")
    current.chmod(0o600 if case == "spawn_refused" else 0o700)
    old_hash = digest(old)
    journal = state / "app-update-transaction-v1.json"
    value = dict(schema_version=1, nonce=nonce, uid=os.getuid(), initiator_pid=os.getpid(),
                 target=str(target), backup=str(backup), stage=str(stage), helper=str(helper),
                 launch_agent=str(work / "dev.slipstream.update-watchdog.plist"),
                 current_version="0.1.9-preview.23", expected_version="0.1.9-preview.24",
                 archive_sha256="b" * 64, watchdog_sha256=digest(helper),
                 old_executable_sha256=old_hash, new_executable_sha256=digest(current),
                 phase="successor_launch_planned", successor_pid=None, successor_started=None,
                 successor_deadline_unix=None, last_error=None)
    journal.write_text(json.dumps(value))
    journal.chmod(0o600)
    result = subprocess.run([str(helper), "--journal", str(journal)],
                            capture_output=True, text=True, timeout=15)
    (work / "helper.log").write_text(result.stdout + result.stderr)
    require(result.returncode == 0, "packaged watchdog did not complete rollback")
    deadline = time.monotonic() + 5
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(.05)
    require(marker.exists() and marker.read_text() == "restored\n", "old fixture was not relaunched exactly once")
    require(digest(current) == old_hash, "old executable was not restored")
    require(not journal.exists() and not backup.exists() and not stage.exists(), "transaction residue remains")
    failed = json.loads((state / f"app-update-transaction-failed-{nonce}.json").read_text())
    require(failed["nonce"] == nonce and failed["phase"] == "old_relaunched", "missing terminal rollback evidence")
    report = dict(case=case, status="pass", helper_sha256=digest(helper),
                  coverage="packaged-helper-startup-fixture-not-tray-or-feed")
    (work / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", required=True, type=Path)
    args = parser.parse_args()
    root = guard()  # Before any mutation or helper execution.
    source = args.helper.resolve(strict=True)
    require(source.is_relative_to(root) and source.is_file(), "helper must be from the disposable candidate")
    result = subprocess.run(["/bin/launchctl", "print", f"gui/{os.getuid()}/dev.slipstream.update-watchdog"],
                            capture_output=True, timeout=5)
    require(result.returncode != 0, "an update watchdog is already loaded")
    require(not (Path.home() / "Library/LaunchAgents/dev.slipstream.update-watchdog.plist").exists(),
            "an update LaunchAgent already exists")
    subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(source)], check=True, timeout=10)
    for case in ("spawn_refused", "early_exit"):
        print(json.dumps(run_case(root, source, case)), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
