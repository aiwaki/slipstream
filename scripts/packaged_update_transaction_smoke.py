#!/usr/bin/env python3
"""Real packaged successor/rollback gate, on a disposable Mac with active runtime.

This does not test signed feed discovery. It uses the production transaction
preparer, bundled watchdog and actual tray; no ACK is synthesized by the harness.
Run each case with a freshly qualified daemon and no running tray. Artifacts are
retained under RUNNER_TEMP for diagnosis, including on failure.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time

from verify_macos_app_bundle import deterministic_tree_sha256, verify_codesign, verify_status_v2


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def guard() -> Path:
    require(sys.platform == "darwin" and os.getuid() != 0
            and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("SLIPSTREAM_DISPOSABLE_CI") == "1",
            "refusing transaction injection outside unprivileged disposable macOS CI")
    root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    require(root.is_dir(), "RUNNER_TEMP must be a directory")
    return root


def snapshot(pid: int) -> tuple[int, str, str] | None:
    result = subprocess.run(["/bin/ps", "-ww", "-p", str(pid), "-o", "uid=",
                             "-o", "lstart=", "-o", "command="],
                            capture_output=True, text=True, timeout=5)
    if result.returncode:
        return None
    fields = result.stdout.strip().split(maxsplit=6)
    require(len(fields) == 7, "unparseable process identity")
    return int(fields[0]), " ".join(fields[1:6]), fields[6]


def stop_successor(journal: dict, executable: Path) -> None:
    pid = journal["successor_pid"]
    require(isinstance(pid, int) and pid > 1, "invalid successor PID")
    expected = (os.getuid(), journal["successor_started"], str(executable))
    require(snapshot(pid) == expected, "successor identity changed before SIGSTOP")
    os.kill(pid, signal.SIGSTOP)


def watchdog_payload_evidence(journal: dict, helper: Path, expected_sha256: str) -> dict:
    """Bind journal provenance to the previous bundle's actual runtime copy."""
    require(journal.get("helper") == str(helper), "unexpected transaction watchdog path")
    require(journal.get("watchdog_sha256") == expected_sha256,
            "transaction watchdog differs from previous bundle")
    require(not helper.is_symlink() and helper.is_file(), "unsafe runtime watchdog file")
    actual = hashlib.sha256(helper.read_bytes()).hexdigest()
    require(actual == expected_sha256, "runtime watchdog bytes differ from journal")
    return {"source": "previous-bundle", "sha256": actual, "runtime_path": str(helper)}


def observe(journal_path: Path, executable: Path, case: str,
            *, timeout: float = 90, traffic_health=None, expected_watchdog=None) -> dict:
    deadline = time.monotonic() + timeout
    phases: list[str] = []
    stopped = False
    successor_pid = None
    nonce = None
    expected_successor = None
    first_heartbeat = None
    successor_deadline = None
    live_traffic_failure = False
    watchdog = None
    while time.monotonic() < deadline:
        try:
            journal = json.loads(journal_path.read_text())
        except FileNotFoundError:
            require(bool(phases), "transaction disappeared before any phase was observed")
            failures = list(journal_path.parent.glob("app-update-transaction-failed-*.json"))
            if case in ("rollback", "traffic_failure"):
                require((stopped if case == "rollback" else live_traffic_failure)
                        and len(failures) == 1, "expected injected timeout rollback")
                if case == "traffic_failure":
                    require(successor_deadline is not None and time.time() >= successor_deadline,
                            "traffic rollback occurred before the ACK deadline")
                failed = json.loads(failures[0].read_text())
                require(failed["phase"] == "old_relaunched" and failed["nonce"] == nonce,
                        "rollback did not relaunch the exact transaction's old app")
            else:
                require(not failures, "successor was rejected and rolled back")
                require("successor_launched" in phases, "successor launch was not observed")
                actual = snapshot(successor_pid) if successor_pid is not None else None
                require(expected_successor is not None and actual == expected_successor,
                        f"accepted successor exited or changed identity: expected={expected_successor}, actual={actual}")
            return {"case": case, "phases": phases, "stopped": stopped,
                    "successor_pid": successor_pid, "transaction_removed": True,
                    "live_traffic_failure": live_traffic_failure, "watchdog_payload": watchdog}
        if expected_watchdog is not None and watchdog is None:
            watchdog = watchdog_payload_evidence(journal, *expected_watchdog)
        phase = journal["phase"]
        if not phases or phases[-1] != phase:
            phases.append(phase)
        nonce = journal["nonce"]
        if phase == "successor_launched":
            successor_pid = journal["successor_pid"]
            expected_successor = (os.getuid(), journal["successor_started"], str(executable))
            if case == "rollback" and not stopped:
                stop_successor(journal, executable)
                stopped = True
            if case == "traffic_failure":
                require(traffic_health is not None, "traffic failure requires live daemon evidence")
                heartbeat = traffic_health()
                if snapshot(successor_pid) == expected_successor:
                    successor_deadline = journal["successor_deadline_unix"]
                    if first_heartbeat is None:
                        first_heartbeat = heartbeat
                    elif time.time() >= successor_deadline - 1 and heartbeat > first_heartbeat:
                        # Observe a live successor and advancing daemon up to the
                        # deadline, not an early crash that also triggers rollback.
                        live_traffic_failure = True
        time.sleep(.02)
    raise RuntimeError(f"transaction did not terminate: {phases}")


def restored_app_pid(executable: Path, rejected_pid: int) -> int:
    result = subprocess.run(["/usr/bin/pgrep", "-x", "slipstream"],
                            capture_output=True, text=True, timeout=5)
    require(result.returncode in (0, 1), "cannot inspect restored tray")
    matches = []
    for token in result.stdout.split():
        pid = int(token)
        identity = snapshot(pid)
        if identity is not None and identity[0] == os.getuid() and identity[2] == str(executable):
            matches.append(pid)
    require(len(matches) == 1 and matches[0] != rejected_pid,
            "rollback did not leave one distinct live restored tray")
    return matches[0]


def require_surviving_process(pid: int, identity: tuple, duration: float = 2) -> None:
    # Journal removal precedes asynchronous launchd bootout. An instant snapshot
    # can pass immediately before launchd kills the watchdog's process group.
    deadline = time.monotonic() + duration
    while True:
        require(snapshot(pid) == identity, "terminal tray did not survive watchdog cleanup")
        if time.monotonic() >= deadline:
            return
        time.sleep(.05)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous-bundle", type=Path, required=True)
    parser.add_argument("--candidate-bundle", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--case", choices=("accept", "rollback", "traffic_failure", "primary_unavailable"), required=True)
    args = parser.parse_args()
    root = guard()  # Must precede every filesystem/process mutation.
    require(subprocess.run(["/usr/bin/pgrep", "-x", "slipstream"],
                           capture_output=True).returncode == 1, "a tray already exists")
    status_path = Path("/var/run/slipstream.status")
    status = json.loads(status_path.read_text())
    status = verify_status_v2(status_path=status_path, expected_pid=status["daemon"]["pid"])
    require(status["state"] == "active",
            "a freshly qualified active runtime is required before transaction injection")
    for bundle in (args.previous_bundle, args.candidate_bundle):
        verify_codesign(bundle.resolve(strict=True), deep=True)
    work = Path(tempfile.mkdtemp(prefix="slipstream-update-", dir=root))
    print(f"transaction evidence: {work}", flush=True)
    target = work / "Slipstream.app"
    shutil.copytree(args.previous_bundle, target, symlinks=True)
    old_tree = deterministic_tree_sha256(target)
    helper_name = "Contents/MacOS/slipstream-update-watchdog"
    previous_helper_sha256 = hashlib.sha256((target / helper_name).read_bytes()).hexdigest()
    candidate_helper_sha256 = hashlib.sha256(
        (args.candidate_bundle / helper_name).read_bytes()).hexdigest()
    new_tree = deterministic_tree_sha256(args.candidate_bundle)
    require(old_tree != new_tree, "previous and candidate bundles must be distinct")
    state = work / "state"
    state.mkdir(mode=0o700)
    archive = work / "candidate.tar.gz"
    with tarfile.open(archive, "w:gz") as out:
        out.add(args.candidate_bundle, arcname="Slipstream.app")
    executable = target / "Contents/MacOS/slipstream"
    # The driver bootstraps the real bundled watchdog. This harness never writes
    # an ACK, shortcuts the deadline, or substitutes a fake successor process.
    result = subprocess.run([str(args.driver.resolve(strict=True)), str(executable),
                             str(archive), str(state)], capture_output=True, text=True, timeout=45)
    (work / "prepare.log").write_text(result.stdout + result.stderr)
    require(result.returncode == 0, "production transaction preparation failed; inspect prepare.log")
    def traffic_health():
        current = verify_status_v2(status_path=status_path, expected_pid=status["pid"])
        require(current["state"] == "active", "daemon lost active state during traffic fault")
        return current["heartbeat_seq"]

    report = observe(state / "app-update-transaction-v1.json", executable, args.case,
                     traffic_health=traffic_health,
                     expected_watchdog=(state / "runtime/slipstream-update-watchdog",
                                        previous_helper_sha256))
    if args.case in ("rollback", "traffic_failure"):
        report["restored_pid"] = restored_app_pid(executable, report["successor_pid"])
    survivor_pid = report.get("restored_pid", report["successor_pid"])
    survivor_identity = snapshot(survivor_pid)
    require(survivor_identity is not None, "terminal tray already exited")
    require_surviving_process(survivor_pid, survivor_identity)
    expected = old_tree if args.case in ("rollback", "traffic_failure") else new_tree
    require(deterministic_tree_sha256(target) == expected, "terminal bundle tree mismatch")
    require(not list(work.glob(".Slipstream.app.slipstream-*")), "staging or backup remains")
    report.update(bundle_tree=expected, previous_tree=old_tree, candidate_tree=new_tree,
                  candidate_watchdog_sha256=candidate_helper_sha256,
                  coverage="current-preparer-previous-watchdog-not-signed-feed")
    (work / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
