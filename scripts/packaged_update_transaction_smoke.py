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

from verify_macos_app_bundle import VerificationError, deterministic_tree_sha256, verify_codesign, verify_status_v2


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
        require(result.returncode == 1 and not result.stdout.strip(), "cannot inspect process absence")
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


def watchdog_payload_evidence(journal: dict, helper: Path, expected_sha256: str,
                              source: str = "previous-bundle") -> dict:
    """Bind journal provenance to the previous bundle's actual runtime copy."""
    require(journal.get("helper") == str(helper), "unexpected transaction watchdog path")
    require(journal.get("watchdog_sha256") == expected_sha256,
            "transaction watchdog differs from previous bundle")
    require(not helper.is_symlink() and helper.is_file(), "unsafe runtime watchdog file")
    actual = hashlib.sha256(helper.read_bytes()).hexdigest()
    require(actual == expected_sha256, "runtime watchdog bytes differ from journal")
    return {"source": source, "sha256": actual, "runtime_path": str(helper)}


def observe(journal_path: Path, executable: Path, case: str,
            *, timeout: float = 90, traffic_health=None, expected_watchdog=None,
            watchdog_source="previous-bundle", expect_legacy_defect=False) -> dict:
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
    successor_observed_live = False
    require(not expect_legacy_defect or (case in ("accept", "rollback") and expected_watchdog is not None
                                       and watchdog_source == "previous-bundle"),
            "legacy defect assertion requires historical watchdog evidence")
    while time.monotonic() < deadline:
        try:
            journal = json.loads(journal_path.read_text())
        except FileNotFoundError:
            failures = list(journal_path.parent.glob("app-update-transaction-failed-*.json"))
            if case == "startup_failure" and not phases:
                # Spawn refusal may finish before the first observer read. The
                # state directory is fresh; bind its sole record to this target
                # and the already verified candidate helper, never any old log.
                require(len(failures) == 1 and expected_watchdog is not None,
                        "missing exact startup failure record")
                failed = json.loads(failures[0].read_text())
                require(failed.get("target") == str(executable.parents[2])
                        and failed.get("successor_pid") is None,
                        "startup failure target or process identity mismatch")
                watchdog = watchdog_payload_evidence(failed, *expected_watchdog,
                                                     source=watchdog_source)
                nonce = failed["nonce"]
                phases.append(failed["phase"])
            require(bool(phases), "transaction disappeared before any phase was observed")
            if case in ("rollback", "traffic_failure", "startup_failure"):
                injected = (case == "startup_failure" or
                            (stopped if case == "rollback" else live_traffic_failure))
                require(injected and len(failures) == 1, "expected injected rollback")
                if case == "traffic_failure":
                    require(successor_deadline is not None and time.time() >= successor_deadline,
                            "traffic rollback occurred before the ACK deadline")
                failed = json.loads(failures[0].read_text())
                if case == "startup_failure":
                    require(failed.get("successor_pid") is None and successor_pid is None,
                            "startup failure unexpectedly launched a successor")
                require(failed["phase"] == "old_relaunched" and failed["nonce"] == nonce,
                        "rollback did not relaunch the exact transaction's old app")
            else:
                require(not failures, "successor was rejected and rolled back")
                require("successor_launched" in phases, "successor launch was not observed")
                actual = snapshot(successor_pid) if successor_pid is not None else None
                require(expected_successor is not None, "missing launched successor identity")
                if not expect_legacy_defect:
                    require(actual == expected_successor,
                            f"accepted successor exited or changed identity: expected={expected_successor}, actual={actual}")
            if expect_legacy_defect:
                require(successor_observed_live, "legacy successor was never observed alive")
            return {"case": case, "phases": phases, "stopped": stopped,
                    "successor_pid": successor_pid, "transaction_removed": True,
                    "live_traffic_failure": live_traffic_failure, "watchdog_payload": watchdog}
        if expected_watchdog is not None and watchdog is None:
            watchdog = watchdog_payload_evidence(journal, *expected_watchdog, source=watchdog_source)
        phase = journal["phase"]
        if not phases or phases[-1] != phase:
            phases.append(phase)
        nonce = journal["nonce"]
        if phase == "successor_launched":
            successor_pid = journal["successor_pid"]
            expected_successor = (os.getuid(), journal["successor_started"], str(executable))
            if expect_legacy_defect and snapshot(successor_pid) == expected_successor:
                successor_observed_live = True
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


def matching_app_pids(executable: Path) -> list[int]:
    result = subprocess.run(["/usr/bin/pgrep", "-x", "slipstream"],
                            capture_output=True, text=True, timeout=5)
    require(result.returncode in (0, 1), "cannot inspect restored tray")
    matches = []
    for token in result.stdout.split():
        pid = int(token)
        identity = snapshot(pid)
        if identity is not None and identity[0] == os.getuid() and identity[2] == str(executable):
            matches.append(pid)
    return matches


def restored_app_pid(executable: Path, rejected_pid: int | None) -> int:
    matches = matching_app_pids(executable)
    require(len(matches) == 1 and matches[0] != rejected_pid,
            "rollback did not leave one distinct live restored tray")
    return matches[0]


def require_legacy_terminal_loss(executable: Path, successor_pid: int) -> None:
    # The defect is asynchronous launchd process-group teardown. Require the
    # exact observed successor AND any restored target tray to be absent.
    deadline = time.monotonic() + 5
    while snapshot(successor_pid) is not None or matching_app_pids(executable):
        require(time.monotonic() < deadline, "historical terminal-tray-loss defect was not reproduced")
        time.sleep(.05)
    for _ in range(10):
        require(snapshot(successor_pid) is None and not matching_app_pids(executable),
                "historical terminal tray reappeared")
        time.sleep(.05)


def require_surviving_process(pid: int, identity: tuple, duration: float = 2) -> None:
    # Journal removal precedes asynchronous launchd bootout. An instant snapshot
    # can pass immediately before launchd kills the watchdog's process group.
    deadline = time.monotonic() + duration
    while True:
        require(snapshot(pid) == identity, "terminal tray did not survive watchdog cleanup")
        if time.monotonic() >= deadline:
            return
        time.sleep(.05)


def remove_successor_execute(member: tarfile.TarInfo) -> tarfile.TarInfo:
    """Fault only the private archive's main executable, preserving its bytes."""
    if member.name == "Slipstream.app/Contents/MacOS/slipstream":
        require(member.isfile(), "successor archive entry is not a regular file")
        member.mode &= ~0o111
    return member


def read_advancing_status(status_path: Path, expected_pid: int) -> dict:
    # Atomic heartbeat publication can race a read. Retry only that explicit
    # unstable-snapshot result; every attempt repeats canonical validation.
    for attempt in range(3):
        try:
            return verify_status_v2(status_path=status_path, expected_pid=expected_pid)
        except VerificationError as error:
            if str(error) != "StatusV2 changed while read" or attempt == 2:
                raise
            time.sleep(.01)
    raise AssertionError("unreachable")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous-bundle", type=Path, required=True)
    parser.add_argument("--candidate-bundle", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--case", choices=("accept", "rollback", "traffic_failure", "primary_unavailable", "startup_failure"), required=True)
    parser.add_argument("--legacy-migration", action="store_true")
    parser.add_argument("--running-legacy", action="store_true")
    parser.add_argument("--expect-legacy-defect", action="store_true")
    args = parser.parse_args()
    root = guard()  # Must precede every filesystem/process mutation.
    require(not args.expect_legacy_defect or (
        args.driver.name == "prepare_legacy23_update" and not args.legacy_migration
        and not args.running_legacy and args.case in ("accept", "rollback")),
        "expected defect applies only to the pinned historical driver")
    require(not args.running_legacy or args.legacy_migration, "running tray requires migration")
    require(args.case != "startup_failure" or args.legacy_migration,
            "startup failure is an external migration qualification case")
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
        out.add(args.candidate_bundle, arcname="Slipstream.app",
                filter=remove_successor_execute if args.case == "startup_failure" else None)
    executable = target / "Contents/MacOS/slipstream"
    old_process = None
    old_identity = None
    if args.running_legacy:
        # This packaged previous-version tray is private to this disposable job.
        log = (work / "legacy-tray.log").open("wb")
        old_process = subprocess.Popen([str(executable)], stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True)
        log.close()
        time.sleep(2)
        require(old_process.poll() is None, "published tray did not survive startup")
        old_identity = snapshot(old_process.pid)
        require(old_identity is not None and old_identity[0] == os.getuid()
                and old_identity[2] == str(executable), "published tray identity mismatch")
        # Reject a nonexistent input before preparation, proving the external
        # launcher does not stop the tray on a preflight failure.
        preflight = subprocess.run([str(args.driver.resolve(strict=True)), "--legacy-migration",
                                   "--running-legacy-pid", str(old_process.pid), str(executable),
                                   str(work / "missing-archive.tar.gz"), str(state)],
                                  capture_output=True, text=True, timeout=15)
        (work / "preflight-refusal.log").write_text(preflight.stdout + preflight.stderr)
        require(preflight.returncode != 0, "missing archive unexpectedly admitted")
        require(old_process.poll() is None and snapshot(old_process.pid) == old_identity,
                "failed preflight disturbed the old tray")
        require(deterministic_tree_sha256(target) == old_tree and not list(state.iterdir()),
                "failed preflight mutated bundle or transaction state")
    # The driver bootstraps the real bundled watchdog. This harness never writes
    # an ACK, shortcuts the deadline, or substitutes a fake successor process.
    result = subprocess.run([str(args.driver.resolve(strict=True)),
                             *(["--legacy-migration"] if args.legacy_migration else []),
                             *(["--running-legacy-pid", str(old_process.pid)] if old_process else []), str(executable),
                             str(archive), str(state)], capture_output=True, text=True, timeout=45)
    (work / "prepare.log").write_text(result.stdout + result.stderr)
    require(result.returncode == 0, "production transaction preparation failed; inspect prepare.log")
    def traffic_health():
        current = read_advancing_status(status_path, status["pid"])
        require(current["state"] == "active", "daemon lost active state during traffic fault")
        return current["heartbeat_seq"]

    report = observe(state / "app-update-transaction-v1.json", executable, args.case,
                     traffic_health=traffic_health,
                     expected_watchdog=(state / "runtime/slipstream-update-watchdog",
                                        candidate_helper_sha256 if args.legacy_migration else previous_helper_sha256),
                     watchdog_source="verified-candidate" if args.legacy_migration else "previous-bundle",
                     expect_legacy_defect=args.expect_legacy_defect)
    if old_process is not None:
        require(old_process.wait(timeout=5) == -signal.SIGTERM,
                "bound published tray was not terminated by the watchdog")
        report["legacy_tray"] = {"pid": old_process.pid, "identity": old_identity,
                                 "exit_code": old_process.returncode,
                                 "preflight_refusal_preserved_tray": True}
    if args.expect_legacy_defect:
        require_legacy_terminal_loss(executable, report["successor_pid"])
        report["terminal_contract"] = "known-legacy-terminal-tray-loss-reproduced"
    else:
        if args.case in ("rollback", "traffic_failure", "startup_failure"):
            report["restored_pid"] = restored_app_pid(executable, report["successor_pid"])
        survivor_pid = report.get("restored_pid", report["successor_pid"])
        survivor_identity = snapshot(survivor_pid)
        require(survivor_identity is not None, "terminal tray already exited")
        require_surviving_process(survivor_pid, survivor_identity)
    expected = old_tree if args.case in ("rollback", "traffic_failure", "startup_failure") else new_tree
    require(deterministic_tree_sha256(target) == expected, "terminal bundle tree mismatch")
    require(not list(work.glob(".Slipstream.app.slipstream-*")), "staging or backup remains")
    report.update(bundle_tree=expected, previous_tree=old_tree, candidate_tree=new_tree,
                  candidate_watchdog_sha256=candidate_helper_sha256,
                  preparer={"name": args.driver.name,
                            "sha256": hashlib.sha256(args.driver.read_bytes()).hexdigest()},
                  coverage=("pinned-legacy-defect-reproduction-not-update-success" if args.expect_legacy_defect
                            else "running-legacy-migration-watchdog-stop-not-signed-feed" if args.running_legacy
                            else "external-migration-candidate-watchdog-not-signed-feed" if args.legacy_migration
                            else "selected-preparer-previous-watchdog-not-signed-feed"))
    (work / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
