#!/usr/bin/env python3
"""Provision one packaged updater case on a clean disposable macOS CI runner."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import plistlib
import signal
import subprocess
import sys
import tempfile
import time

import packaged_update_transaction_smoke as transaction
import pf_installed_lifecycle_smoke as lifecycle


def stop_owned_trays(root: Path, uid: int) -> None:
    result = subprocess.run(["/usr/bin/pgrep", "-x", "slipstream"],
                            capture_output=True, text=True, timeout=5)
    transaction.require(result.returncode in (0, 1), "cannot enumerate qualification trays")
    for item in result.stdout.split():
        pid = int(item)
        identity = transaction.snapshot(pid)
        if identity is None or identity[0] != uid:
            continue
        command = Path(identity[2])
        if not command.is_relative_to(root) or command.parts[-4:] != (
            "Slipstream.app", "Contents", "MacOS", "slipstream"
        ):
            continue
        # Never signal a reused PID. All targets are copies below our fresh root.
        for sig in (signal.SIGTERM, signal.SIGCONT):
            if transaction.snapshot(pid) != identity:
                break
            os.kill(pid, sig)
        deadline = time.monotonic() + 3
        while transaction.snapshot(pid) == identity and time.monotonic() < deadline:
            time.sleep(.05)
        if transaction.snapshot(pid) == identity:
            os.kill(pid, signal.SIGKILL)


def cleanup_watchdog(root: Path, home: Path, uid: int) -> None:
    plist = home / "Library/LaunchAgents/dev.slipstream.update-watchdog.plist"
    if not plist.exists():
        return
    metadata = plist.lstat()
    transaction.require(not plist.is_symlink() and metadata.st_uid == uid,
                        "unowned update LaunchAgent during cleanup")
    value = plistlib.loads(plist.read_bytes())
    helper = Path(value["ProgramArguments"][0]).resolve(strict=True)
    transaction.require(helper.is_relative_to(root), "watchdog is outside qualification root")
    subprocess.run(["/bin/launchctl", "bootout", f"gui/{uid}/dev.slipstream.update-watchdog"],
                   capture_output=True, timeout=10)
    plist.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous-bundle", required=True, type=Path)
    parser.add_argument("--candidate-bundle", required=True, type=Path)
    parser.add_argument("--driver", required=True, type=Path)
    parser.add_argument("--case", required=True, choices=("accept", "rollback", "traffic_failure"))
    args = parser.parse_args()
    lifecycle._require_disposable_ci()
    runner = lifecycle.pf.PfctlRunner()
    before, uid, gid = lifecycle._preflight(runner)
    environment, home = lifecycle._user_environment(uid)
    launch_agent = home / "Library/LaunchAgents/dev.slipstream.update-watchdog.plist"
    transaction.require(not launch_agent.is_symlink() and not launch_agent.exists(),
                        "existing update LaunchAgent")
    loaded = subprocess.run(["/bin/launchctl", "print", f"gui/{uid}/dev.slipstream.update-watchdog"],
                            capture_output=True, timeout=10)
    transaction.require(loaded.returncode != 0, "existing update watchdog")
    root = Path(tempfile.mkdtemp(prefix="update-case-", dir=os.environ["RUNNER_TEMP"])).resolve()
    os.chown(root, uid, gid)
    environment["RUNNER_TEMP"] = str(root)
    print(f"qualification root: {root}", flush=True)
    target = lifecycle.packaged_app_target(args.candidate_bundle)
    system = lifecycle.SystemRunner(target)
    failure = None
    resolver = None
    cleanup_errors = []
    try:
        system.run(target.install_command)
        lifecycle._wait_for_status("active", timeout=90)
        lifecycle._assert_installed_payload(target)
        lifecycle._assert_local_routing_without_geph()
        if args.case == "traffic_failure":
            # Disposable runner only: keep status/heartbeat healthy while the
            # real successor cannot resolve its public traffic-proof endpoint.
            resolver = lifecycle.StalledSystemResolver(domain="media.discordapp.net")
            resolver.start()
        result = subprocess.run([
            sys.executable, str(Path(__file__).with_name("packaged_update_transaction_smoke.py")),
            "--previous-bundle", str(args.previous_bundle.resolve()),
            "--candidate-bundle", str(args.candidate_bundle.resolve()),
            "--driver", str(args.driver.resolve()), "--case", args.case,
        ], env=environment, user=uid, group=gid,
            extra_groups=lifecycle._user_supplementary_groups(uid, gid),
            capture_output=True, text=True, timeout=180)
        (root / "harness.log").write_text(result.stdout + result.stderr)
        print(result.stdout, flush=True)
        transaction.require(result.returncode == 0, "packaged transaction failed; inspect harness.log")
        if resolver is not None:
            transaction.require(resolver.query_event.is_set(), "traffic fault never received a DNS query")
    except Exception as exc:
        failure = exc
    finally:
        # Stop the private watchdog before its trays so no cleanup can relaunch one.
        for action in (lambda: cleanup_watchdog(root, home, uid),
                       lambda: stop_owned_trays(root, uid)):
            try:
                action()
            except Exception as exc:
                cleanup_errors.append(str(exc))
        if resolver is not None:
            try:
                resolver.stop()
            except Exception as exc:
                cleanup_errors.append(str(exc))
        cleanup_errors.extend(lifecycle._fallback_uninstall(system, runner, target))
    lifecycle.pf._assert_same_snapshot(before, lifecycle.pf._pf_snapshot(runner))
    lifecycle._assert_clean_install_state(runner)
    report = {"case": args.case, "result": "fail" if failure or cleanup_errors else "pass",
              "error": str(failure) if failure else None, "cleanup_errors": cleanup_errors}
    (root / "provision-result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report), flush=True)
    return int(bool(failure or cleanup_errors))


if __name__ == "__main__":
    raise SystemExit(main())
